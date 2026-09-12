import hashlib
import json
from pathlib import Path
from urllib import parse, request, error

import yaml

UA = "AuthorizedBugBountyEndpointBaseline/1.0"
ATTACKER_ORIGIN = "https://attacker.invalid"
MAX_BODY = 12_000
SENSITIVE_KEYS = {"email", "phone", "mobile", "address", "token", "access_token", "refresh_token", "userid", "user_id", "memberid", "member_id", "orderid", "order_id"}
SAFE_READ_HINTS = ("/api/public/", "/query", "/list", "/fetch")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def host_in_scope(host, patterns):
    host = host.lower().rstrip('.')
    for raw in patterns:
        pat = raw.lower().replace('*.', '').rstrip('.')
        if raw.startswith('*.') and (host == pat or host.endswith('.' + pat)):
            return True
        if host == pat:
            return True
    return False


def fetch(url, method="HEAD", origin=False):
    headers = {"User-Agent": UA, "Accept": "application/json,text/plain,*/*", "Accept-Encoding": "identity", "Connection": "close"}
    if origin: headers["Origin"] = ATTACKER_ORIGIN
    req = request.Request(url, headers=headers, method=method)
    opener = request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=8) as resp:
            body = b"" if method == "HEAD" else resp.read(MAX_BODY)
            return resp.status, dict(resp.headers), body
    except error.HTTPError as exc:
        return exc.code, dict(exc.headers), b""
    except Exception:
        return None, {}, b""

def walk_sensitive(obj, found):
    if isinstance(obj, dict):
        for key, value in obj.items():
            lk = str(key).lower()
            if lk in SENSITIVE_KEYS and value not in (None, "", [], {}, 0, False):
                found.add(lk)
            walk_sensitive(value, found)
    elif isinstance(obj, list):
        for value in obj[:20]: walk_sensitive(value, found)


def save_candidate(root, program, finding):
    key = "|".join([program["id"], finding["kind"], finding["host"], finding["url"]])
    out = root / "state" / "candidates" / f"{program['id']}-{hashlib.sha256(key.encode()).hexdigest()[:16]}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    previous = {}
    if out.exists():
        try: previous = json.loads(out.read_text(encoding="utf-8"))
        except Exception: previous = {}
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    record = {
        "program_id": program["id"], "platform": program["platform"], "program_name": program["program_name"],
        "rules_source": program["rules_source"], "rules_checked_at": now,
        "first_seen": previous.get("first_seen", now), "last_seen": now,
        "target": finding["host"], "finding": finding, "in_scope": True,
        "reproducible": previous.get("reproducible", False), "clear_security_impact": previous.get("clear_security_impact", False),
        "evidence_complete": previous.get("evidence_complete", False), "duplicate_check_complete": previous.get("duplicate_check_complete", False),
        "human_verified": previous.get("human_verified", False), "destructive_test": False, "out_of_scope": False,
    }
    out.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

def main():
    root = Path(__file__).resolve().parents[1]
    cfg = yaml.safe_load((root / "bounty" / "live_targets.yml").read_text(encoding="utf-8-sig"))
    ep_path = root / "state" / "public_endpoints.json"
    if not ep_path.exists():
        print(json.dumps({"endpoints_checked": 0, "signals": 0})); return
    endpoints = json.loads(ep_path.read_text(encoding="utf-8")).get("endpoints", [])[:30]
    signals = 0; checked = 0
    for program in cfg.get("programs", []):
        if program.get("automation_mode") != "low_impact_read_only": continue
        patterns = program.get("scope", {}).get("include", [])
        for url in endpoints:
            p = parse.urlparse(url); host = (p.hostname or "").lower()
            if p.scheme != "https" or not host_in_scope(host, patterns): continue
            checked += 1
            status, headers, _ = fetch(url, "HEAD", origin=True)
            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()
            if status and acao == ATTACKER_ORIGIN and acac == "true":
                save_candidate(root, program, {"kind": "endpoint-cors-reflection-with-credentials", "host": host, "url": url,
                    "confidence": "high", "manual_verification_required": True,
                    "safe_evidence": {"status": status, "acao": acao, "acac": acac, "body_stored": False}}); signals += 1
            if not any(hint in p.path.lower() for hint in SAFE_READ_HINTS): continue
            g_status, g_headers, body = fetch(url, "GET", origin=False)
            if g_status not in {200, 206} or not body: continue
            ctype = g_headers.get("Content-Type", "").lower()
            if "json" not in ctype and not body.lstrip().startswith((b"{", b"[")): continue
            try: obj = json.loads(body.decode("utf-8", "replace"))
            except Exception: continue
            found = set(); walk_sensitive(obj, found)
            if found:
                save_candidate(root, program, {"kind": "unauthenticated-sensitive-json-suspected", "host": host, "url": url,
                    "confidence": "medium", "manual_verification_required": True,
                    "safe_evidence": {"status": g_status, "sensitive_keys": sorted(found), "values_stored": False, "body_stored": False}}); signals += 1
    print(json.dumps({"endpoints_checked": checked, "signals": signals}, ensure_ascii=False))


if __name__ == "__main__":
    main()
