import argparse
import hashlib
import ipaddress
import json
import shutil
import socket
import subprocess
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, parse, request

import dns.resolver
import yaml

UA = "AuthorizedBugBountySafeProbe/1.0"
ATTACKER_ORIGIN = "https://attacker.invalid"
SAFE_PATHS = [
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/swagger.json",
    "/openapi.json",
    "/actuator/health",
    "/server-status",
]
REDIRECT_PARAMS = ["redirect", "redirect_uri", "next", "url", "return"]

class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_host(value):
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = parse.urlparse(value).hostname or ""
    return value


def host_in_scope(host, patterns):
    host = normalize_host(host)
    for raw in patterns:
        pat = normalize_host(raw.replace("*.", ""))
        if raw.startswith("*.") and (host == pat or host.endswith("." + pat)):
            return True
        if host == pat:
            return True
    return False


def base_domain(host):
    parts = normalize_host(host).split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def safe_head(url, extra_headers=None, timeout=8):
    headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    if extra_headers:
        headers.update(extra_headers)
    req = request.Request(url, headers=headers, method="HEAD")
    opener = request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), None
    except error.HTTPError as exc:
        return exc.code, dict(exc.headers), None
    except Exception as exc:
        return None, {}, f"{type(exc).__name__}: {exc}"


def crtsh_names(domain, timeout=12):
    url = "https://crt.sh/?q=%25." + parse.quote(domain) + "&output=json"
    req = request.Request(url, headers={"User-Agent": UA})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            rows = json.loads(resp.read(2_000_000).decode("utf-8", "replace"))
    except Exception:
        return []
    names = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = normalize_host(name.replace("*.", ""))
            if name and name.endswith("." + domain):
                names.add(name)
    return sorted(names)
def subfinder_names(domain, timeout=90):
    exe = shutil.which("subfinder")
    if not exe:
        candidate = Path.home() / "go" / "bin" / "subfinder.exe"
        exe = str(candidate) if candidate.exists() else None
    if not exe:
        return []
    try:
        cp = subprocess.run([exe, "-silent", "-d", domain], capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    names = set()
    for line in cp.stdout.splitlines():
        host = normalize_host(line)
        if host and (host == domain or host.endswith("." + domain)):
            names.add(host)
    return sorted(names)


def doh_answers(host, rtype):
    url = "https://dns.google/resolve?" + parse.urlencode({"name": host, "type": rtype})
    req = request.Request(url, headers={"User-Agent": UA, "Accept": "application/dns-json"})
    try:
        with request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read(200_000).decode("utf-8", "replace"))
    except Exception:
        return None, []
    return data.get("Status"), data.get("Answer") or []


def dns_snapshot(host):
    result = {"host": host, "a": [], "aaaa": [], "cname": [], "dangling_cname": False, "resolver": "dns.google-doh"}
    for rtype, code, key in (("A", 1, "a"), ("AAAA", 28, "aaaa"), ("CNAME", 5, "cname")):
        status, answers = doh_answers(host, rtype)
        if status is None:
            continue
        result[key] = sorted({str(x.get("data", "")).rstrip(".") for x in answers if x.get("type") == code and x.get("data")})
    for target in result["cname"]:
        a_status, a_answers = doh_answers(target, "A")
        aaaa_status, aaaa_answers = doh_answers(target, "AAAA")
        has_addr = any(x.get("type") in {1, 28} for x in (a_answers or []) + (aaaa_answers or []))
        if a_status == 3 and aaaa_status == 3 and not has_addr:
            result["dangling_cname"] = True
    return result


def _is_global_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def limited_headers(headers):
    keep = [
        "server", "location", "access-control-allow-origin",
        "access-control-allow-credentials", "content-type",
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
    ]
    lowered = {k.lower(): v for k, v in headers.items()}
    return {k: lowered[k] for k in keep if k in lowered}
def probe_discovered_root(host, program, budget):
    patterns = program.get("scope", {}).get("include", [])
    if not host_in_scope(host, patterns):
        return {"host": host, "blocked": "out_of_scope"}, []
    if budget["remaining"] < 2:
        return {"host": host, "blocked": "request_budget"}, []
    delay = float(program.get("delay_seconds", 2.0))
    base = "https://" + host
    budget["remaining"] -= 1; budget["used"] += 1
    status, headers, err = safe_head(base + "/")
    time.sleep(delay)
    budget["remaining"] -= 1; budget["used"] += 1
    cors_status, cors_headers, cors_err = safe_head(base + "/", {"Origin": ATTACKER_ORIGIN})
    findings = []
    acao = cors_headers.get("Access-Control-Allow-Origin", "")
    acac = cors_headers.get("Access-Control-Allow-Credentials", "").lower()
    if cors_status == 200 and acao == ATTACKER_ORIGIN and acac == "true" and "json" in cors_headers.get("Content-Type", "").lower():
        findings.append({"kind": "cors-reflection-with-credentials", "host": host,
                         "url": base + "/", "confidence": "medium",
                         "safe_evidence": {"acao": acao, "acac": acac},
                         "manual_verification_required": True})
    return {"host": host, "reachable": status is not None, "base": base,
            "root_status": status, "root_error": err, "cors_error": cors_err}, findings


def probe_host(host, program, budget):
    patterns = program.get("scope", {}).get("include", [])
    if not host_in_scope(host, patterns):
        return {"host": host, "blocked": "out_of_scope"}, []
    delay = float(program.get("delay_seconds", 2.0))
    events, findings = [], []

    def do_head(url, headers=None):
        if budget["remaining"] <= 0:
            return None, {}, "request_budget_exhausted"
        if budget["used"]:
            time.sleep(delay)
        budget["remaining"] -= 1
        budget["used"] += 1
        status, resp_headers, err = safe_head(url, headers)
        events.append({"url": url, "status": status, "headers": limited_headers(resp_headers), "error": err})
        return status, resp_headers, err

    base = "https://" + host
    status, root_headers, root_err = do_head(base + "/")
    if status is None:
        base = "http://" + host
        status, root_headers, root_err = do_head(base + "/")
    if status is None:
        return {"host": host, "reachable": False, "events": events}, findings

    cors_status, cors_headers, _ = do_head(base + "/", {"Origin": ATTACKER_ORIGIN})
    acao = cors_headers.get("Access-Control-Allow-Origin", "")
    acac = cors_headers.get("Access-Control-Allow-Credentials", "").lower()
    if cors_status == 200 and acao == ATTACKER_ORIGIN and acac == "true" and "json" in cors_headers.get("Content-Type", "").lower():
        findings.append({
            "kind": "cors-reflection-with-credentials",
            "host": host,
            "url": base + "/",
            "confidence": "medium",
            "safe_evidence": {"acao": acao, "acac": acac},
            "manual_verification_required": True,
        })

    for param in REDIRECT_PARAMS:
        q = parse.urlencode({param: ATTACKER_ORIGIN + "/proof"})
        s, h, _ = do_head(base + "/?" + q)
        loc = h.get("Location", "")
        loc_host = parse.urlparse(loc).hostname if loc else None
        if s in {301, 302, 303, 307, 308} and loc_host == "attacker.invalid":
            findings.append({
                "kind": "open-redirect",
                "host": host,
                "url": base + "/?" + q,
                "confidence": "high",
                "safe_evidence": {"status": s, "location": loc},
                "manual_verification_required": True,
            })

    root_len = root_headers.get("Content-Length")
    root_type = root_headers.get("Content-Type", "")
    for path in SAFE_PATHS:
        s, h, _ = do_head(base + path)
        if s not in {200, 206}:
            continue
        if path in {"/.well-known/security.txt", "/robots.txt", "/sitemap.xml"}:
            continue
        same_shape = root_len and h.get("Content-Length") == root_len and h.get("Content-Type", "") == root_type
        findings.append({
            "kind": "sensitive-path-head-positive",
            "host": host,
            "url": base + path,
            "confidence": "low" if same_shape else "medium",
            "safe_evidence": {
                "status": s,
                "content_type": h.get("Content-Type"),
                "content_length": h.get("Content-Length"),
                "body_retrieved": False,
            },
            "manual_verification_required": True,
        })

    return {
        "host": host,
        "reachable": True,
        "base": base,
        "root_status": status,
        "events": events,
    }, findings
def run_program(program):
    mode = program.get("automation_mode", "blocked")
    patterns = program.get("scope", {}).get("include", [])
    passive_domains = list(program.get("passive_seed_domains", []))
    if not passive_domains:
        passive_domains = sorted({base_domain(x) for x in program.get("active_seed_hosts", [])})

    discovered = set()
    dns_results, findings = [], []
    for domain in passive_domains[:3]:
        names = set(crtsh_names(domain)[:300])
        names.update(subfinder_names(domain)[:300])
        for host in sorted(names):
            if host_in_scope(host, patterns):
                discovered.add(host)
        time.sleep(1.0)

    ordered = sorted(discovered)
    selected = []
    if ordered:
        window = min(40, len(ordered))
        slot = int(time.time() // (6 * 3600))
        start = (slot * window) % len(ordered)
        selected = (ordered[start:] + ordered[:start])[:window]
    for host in selected:
        snap = dns_snapshot(host)
        dns_results.append(snap)
        if snap.get("dangling_cname"):
            findings.append({
                "kind": "possible-dangling-cname",
                "host": host,
                "confidence": "medium",
                "safe_evidence": snap,
                "manual_verification_required": True,
            })

    probes = []
    budget = {
        "remaining": int(program.get("max_requests_per_run", 0)),
        "used": 0,
    }
    if mode == "low_impact_read_only":
        curated = {normalize_host(x) for x in program.get("active_seed_hosts", [])}
        for host in program.get("active_seed_hosts", []):
            if budget["remaining"] <= 0:
                break
            probe, new_findings = probe_host(normalize_host(host), program, budget)
            probes.append(probe)
            findings.extend(new_findings)
        if program.get("probe_discovered_roots", False):
            limit = int(program.get("max_discovered_active_hosts", 0))
            public_live = []
            for snap in dns_results:
                addresses = list(snap.get("a", [])) + list(snap.get("aaaa", []))
                if any(_is_global_ip(x) for x in addresses):
                    public_live.append(snap.get("host", ""))
            for host in [x for x in public_live if x and x not in curated][:limit]:
                if budget["remaining"] < 2:
                    break
                probe, new_findings = probe_discovered_root(host, program, budget)
                probes.append(probe)
                findings.extend(new_findings)

    return {
        "program_id": program.get("id"),
        "program_name": program.get("program_name"),
        "platform": program.get("platform"),
        "automation_mode": mode,
        "rules_source": program.get("rules_source"),
        "passive_discovered_count": len(discovered),
        "passive_discovered_sample": sorted(discovered)[:100],
        "dns_checked_count": len(dns_results),
        "dns_results": dns_results,
        "direct_requests_used": budget["used"],
        "probes": probes,
        "findings": findings,
    }
def write_outputs(root, payload):
    state_dir = root / "state"
    cand_dir = state_dir / "candidates"
    state_dir.mkdir(parents=True, exist_ok=True)
    cand_dir.mkdir(parents=True, exist_ok=True)
    latest = state_dir / "latest.json"
    latest.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# Safe Bug-Bounty Run", "", f"Time: {payload['run_at']}", ""]
    total = 0
    for item in payload["programs"]:
        count = len(item.get("findings", []))
        total += count
        lines += [
            f"## {item['platform']} / {item['program_name']}",
            f"- Mode: {item['automation_mode']}",
            f"- Passive discoveries: {item['passive_discovered_count']}",
            f"- Direct requests: {item['direct_requests_used']}",
            f"- Candidate findings: {count}",
            "",
        ]
    lines += ["## Submission status", "", "No automatic submission is permitted.", f"Candidates awaiting review: {total}"]
    (state_dir / "latest.md").write_text("\n".join(lines), encoding="utf-8")

    for program in payload["programs"]:
        for finding in program.get("findings", []):
            key = "|".join([
                str(program["program_id"]), str(finding.get("kind")),
                str(finding.get("host")), str(finding.get("url", "")),
            ])
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
            out_path = cand_dir / f"{program['program_id']}-{digest}.json"
            previous = {}
            if out_path.exists():
                try:
                    previous = json.loads(out_path.read_text(encoding="utf-8"))
                except Exception:
                    previous = {}
            record = {
                "program_id": program["program_id"], "platform": program["platform"],
                "program_name": program["program_name"], "rules_source": program["rules_source"],
                "rules_checked_at": payload["run_at"], "first_seen": previous.get("first_seen", payload["run_at"]),
                "last_seen": payload["run_at"], "target": finding.get("host"), "finding": finding,
                "in_scope": True, "reproducible": previous.get("reproducible", False),
                "clear_security_impact": previous.get("clear_security_impact", False),
                "evidence_complete": previous.get("evidence_complete", False),
                "duplicate_check_complete": previous.get("duplicate_check_complete", False),
                "human_verified": previous.get("human_verified", False),
                "destructive_test": False, "out_of_scope": False,
            }
            out_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(Path(__file__).with_name("live_targets.yml")))
    args = ap.parse_args()
    cfg_path = Path(args.config)
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))

    verified_raw = cfg.get("verified_at")
    try:
        verified_dt = datetime.fromisoformat(str(verified_raw).replace("Z", "+00:00"))
        if verified_dt.tzinfo is None:
            verified_dt = verified_dt.replace(tzinfo=timezone.utc)
        rules_stale = (datetime.now(timezone.utc) - verified_dt.astimezone(timezone.utc)).total_seconds() > 7 * 86400
    except Exception:
        rules_stale = True

    results = []
    for source_program in cfg.get("programs", []):
        program = dict(source_program)
        if rules_stale and program.get("automation_mode") == "low_impact_read_only":
            program["automation_mode"] = "passive_only"
        results.append(run_program(program))

    payload = {
        "run_at": now_iso(),
        "config_verified_at": verified_raw,
        "rules_stale": rules_stale,
        "safety": {
            "read_only": True,
            "no_sensitive_bodies_stored": True,
            "no_exploitation": True,
            "no_auto_submission": True,
        },
        "programs": results,
    }
    root = Path(__file__).resolve().parents[1]
    write_outputs(root, payload)
    print(json.dumps({
        "run_at": payload["run_at"],
        "programs": [{"id": x["program_id"], "findings": len(x["findings"]), "direct_requests": x["direct_requests_used"]} for x in results],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
