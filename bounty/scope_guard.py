import argparse
import fnmatch
from pathlib import Path
from urllib.parse import urlparse

import yaml


def load_program(program_id: str):
    cfg = yaml.safe_load(Path(__file__).with_name("programs.yml").read_text(encoding="utf-8")) or {}
    for item in cfg.get("programs", []):
        if item.get("id") == program_id:
            return item
    raise SystemExit(f"BLOCKED: unknown program: {program_id}")


def normalize_target(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise SystemExit("BLOCKED: invalid target")
    return host


def matches(host: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        p = str(pattern).strip().lower().rstrip(".")
        if p and fnmatch.fnmatch(host, p):
            return True
    return False


def validate(program: dict, target: str, require_automation: bool = False) -> str:
    rules_url = str(program.get("rules_url") or "")
    if not rules_url or "REPLACE_WITH_" in rules_url:
        raise SystemExit("BLOCKED: official rules URL not configured")
    if not program.get("last_verified"):
        raise SystemExit("BLOCKED: program scope has not been verified")

    host = normalize_target(target)
    scope = program.get("scope") or {}
    included = scope.get("include") or []
    excluded = scope.get("exclude") or []

    if matches(host, excluded):
        raise SystemExit(f"BLOCKED: {host} is explicitly excluded")
    if not matches(host, included):
        raise SystemExit(f"BLOCKED: {host} is not explicitly in scope")
    if require_automation and not program.get("automation_allowed", False):
        raise SystemExit("BLOCKED: program rules do not explicitly allow automated testing")

    return host


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--program", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--require-automation", action="store_true")
    args = p.parse_args()

    program = load_program(args.program)
    host = validate(program, args.target, args.require_automation)
    mode = "active automation permitted" if program.get("automation_allowed") else "passive/manual validation only"
    print(f"OK: {host} is explicitly in scope; mode={mode}")


if __name__ == "__main__":
    main()
