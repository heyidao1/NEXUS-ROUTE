import json
import sys
from pathlib import Path

from bounty.quality_gate import evaluate

REQUIRED = [
    "program_id", "target", "title", "vulnerability_type",
    "impact_fact", "reproduction_steps", "scope_proof", "rules_checked_at",
]


def validate(data: dict, manifest: dict) -> dict:
    missing = [key for key in REQUIRED if not data.get(key)]
    if missing:
        raise SystemExit("BLOCKED: missing fields: " + ", ".join(missing))
    if data.get("destructive_test"):
        raise SystemExit("BLOCKED: destructive testing is not allowed")
    if data.get("out_of_scope"):
        raise SystemExit("BLOCKED: out-of-scope candidate")
    steps = data.get("reproduction_steps")
    if not isinstance(steps, list) or len(steps) < 2:
        raise SystemExit("BLOCKED: reproduction_steps must contain at least two concrete steps")
    quality = evaluate(data, manifest)
    if quality["verdict"] != "REPORT_READY":
        raise SystemExit("BLOCKED: quality verdict is not REPORT_READY")
    return quality


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: python bounty/report_gate_v3.py finding.json manifest.json")
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    validate(data, manifest)
    print("READY_FOR_MANUAL_SUBMISSION")


if __name__ == "__main__":
    main()
