import hashlib
import ipaddress
import json
import re
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib import parse, request, error

import yaml

UA = "AuthorizedBugBountyPublicAssetAudit/1.0"
MAX_HTML = 350_000
MAX_JS = 800_000
MAX_HOSTS = 5
MAX_SCRIPTS_PER_HOST = 4

SECRET_PATTERNS = {
    "aws-access-key-id": re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "google-api-key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "stripe-live-secret": re.compile(r"sk_live_[0-9A-Za-z]{20,}"),
    "github-token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
    "private-key-marker": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
API_PATH = re.compile(r"[\"'](/(?:api|v\d+|graphql|oauth|auth)/[^\"'\\\s]{1,180})[\"']")
SOURCE_MAP = re.compile(r"sourceMappingURL=([^\s*]+)")


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.scripts = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            src = dict(attrs).get("src")
            if src: self.scripts.append(src)

def fetch_limited(url, limit, method="GET"):
    headers = {
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if method == "GET":
        headers["Range"] = f"bytes=0-{limit-1}"
    req = request.Request(url, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=8) as resp:
            body = b"" if method == "HEAD" else resp.read(limit)
            return resp.status, dict(resp.headers), body, resp.geturl()
    except error.HTTPError as exc:
        return exc.code, dict(exc.headers), b"", url
    except Exception:
        return None, {}, b"", url


def same_host_url(base, raw, host):
    url = parse.urljoin(base, raw)
    p = parse.urlparse(url)
    if p.scheme not in {"http", "https"} or (p.hostname or "").lower() != host.lower():
        return None
    return url


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


def candidate_path(root, program_id, kind, host, url):
    key = "|".join([program_id, kind, host, url])
    return root / "state" / "candidates" / f"{program_id}-{hashlib.sha256(key.encode()).hexdigest()[:16]}.json"

def save_candidate(root, program, finding):
    out = candidate_path(root, program["id"], finding["kind"], finding["host"], finding["url"])
    out.parent.mkdir(parents=True, exist_ok=True)
    previous = {}
    if out.exists():
        try: previous = json.loads(out.read_text(encoding="utf-8"))
        except Exception: previous = {}
    now = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
    record = {
        "program_id": program["id"], "platform": program["platform"],
        "program_name": program["program_name"], "rules_source": program["rules_source"],
        "rules_checked_at": now, "first_seen": previous.get("first_seen", now), "last_seen": now,
        "target": finding["host"], "finding": finding, "in_scope": True,
        "reproducible": previous.get("reproducible", False),
        "clear_security_impact": previous.get("clear_security_impact", False),
        "evidence_complete": previous.get("evidence_complete", False),
        "duplicate_check_complete": previous.get("duplicate_check_complete", False),
        "human_verified": previous.get("human_verified", False),
        "destructive_test": False, "out_of_scope": False,
    }
    out.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def choose_hosts(root, program):
    seeds = []
    for host in program.get("active_seed_hosts", []):
        host = host.strip().lower().rstrip('.')
        if host and host not in seeds:
            seeds.append(host)
    pool = []
    latest = root / "state" / "latest.json"
    if latest.exists():
        data = json.loads(latest.read_text(encoding="utf-8"))
        for item in data.get("programs", []):
            if item.get("program_id") == program.get("id"):
                source_hosts = []
                for x in item.get("dns_results", []):
                    addresses = list(x.get("a", [])) + list(x.get("aaaa", []))
                    public = False
                    for addr in addresses:
                        try:
                            public = public or ipaddress.ip_address(addr).is_global
                        except ValueError:
                            pass
                    if public:
                        source_hosts.append(x.get("host", ""))
                source_hosts += item.get("passive_discovered_sample", [])
                for host in source_hosts:
                    host = host.strip().lower().rstrip('.')
                    if host and host not in seeds and host not in pool:
                        pool.append(host)
    cursor_path = root / "state" / "public_asset_cursor.json"
    try:
        cursors = json.loads(cursor_path.read_text(encoding="utf-8")) if cursor_path.exists() else {}
    except Exception:
        cursors = {}
    slots = max(0, MAX_HOSTS - len(seeds[:MAX_HOSTS]))
    offset = int(cursors.get(program.get("id"), 0)) % len(pool) if pool else 0
    rotated = pool[offset:] + pool[:offset]
    chosen = seeds[:MAX_HOSTS] + rotated[:slots]
    if pool and slots:
        cursors[program.get("id")] = (offset + slots) % len(pool)
        cursor_path.write_text(json.dumps(cursors, ensure_ascii=False, indent=2), encoding="utf-8")
    return chosen[:MAX_HOSTS]

def audit_host(root, program, host, endpoints):
    base = f"https://{host}/"
    status, headers, body, final_url = fetch_limited(base, MAX_HTML)
    if status not in {200, 206} or not body:
        return 0
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        return 0
    parser = ScriptParser()
    try: parser.feed(text)
    except Exception: pass
    scripts = []
    for raw in parser.scripts:
        url = same_host_url(final_url, raw, host)
        if url and url not in scripts: scripts.append(url)
    findings = 0
    for js_url in scripts[:MAX_SCRIPTS_PER_HOST]:
        time.sleep(float(program.get('delay_seconds', 2.0)))
        js_status, js_headers, js_body, js_final = fetch_limited(js_url, MAX_JS)
        if js_status not in {200, 206} or not js_body: continue
        js = js_body.decode("utf-8", "replace")
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(js):
                finding = {
                    "kind": "public-js-secret-pattern", "host": host, "url": js_final,
                    "confidence": "medium", "manual_verification_required": True,
                    "safe_evidence": {"secret_type": secret_type, "fingerprint": fingerprint(match.group(0)), "secret_value_stored": False},
                }
                save_candidate(root, program, finding); findings += 1
        for m in API_PATH.finditer(js):
            endpoints.add(parse.urljoin(js_final, m.group(1)))
        for m in SOURCE_MAP.finditer(js):
            raw_map = m.group(1).strip().strip('"\'')
            map_url = same_host_url(js_final, raw_map, host)
            if not map_url: continue
            map_status, _, _, _ = fetch_limited(map_url, 0, method="HEAD")
            if map_status == 200:
                finding = {
                    "kind": "public-source-map", "host": host, "url": map_url,
                    "confidence": "low", "manual_verification_required": True,
                    "safe_evidence": {"referenced_by": js_final, "body_retrieved": False},
                }
                save_candidate(root, program, finding); findings += 1
    return findings

def main():
    root = Path(__file__).resolve().parents[1]
    cfg = yaml.safe_load((root / "bounty" / "live_targets.yml").read_text(encoding="utf-8-sig"))
    endpoints = set(); total = 0; audited = []
    for program in cfg.get("programs", []):
        if program.get("automation_mode") != "low_impact_read_only":
            continue
        for host in choose_hosts(root, program):
            total += audit_host(root, program, host, endpoints)
            audited.append(host)
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "public_endpoints.json").write_text(
        json.dumps({"hosts": audited, "endpoints": sorted(endpoints)[:300]}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps({"public_asset_hosts": len(audited), "new_signal_events": total, "public_endpoints": len(endpoints)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

