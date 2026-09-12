import json
import sys
from pathlib import Path

REQUIRED = [
    "program_id",
    "target",
    "title",
    "vulnerability_type",
    "impact",
    "reproduction_steps",
    "evidence",
    "scope_proof",
    "rules_checked_at",
]

REQUIRED_TRUE = [
    "reproducible",
    "clear_security_impact",
    "in_scope",
    "evidence_complete",
    "duplicate_check_complete",
    "human_verified",
]


def validate(data: dict) -> None:
    missing = [key for key in REQUIRED if not data.get(key)]
    if missing:
        raise SystemExit("BLOCKED: missing fields: " + ", ".join(missing))

    false_flags = [key for key in REQUIRED_TRUE if data.get(key) is not True]
    if false_flags:
        raise SystemExit("BLOCKED: verification flags not true: " + ", ".join(false_flags))

    if data.get("destructive_test"):
        raise SystemExit("BLOCKED: destructive testing is not allowed")
    if data.get("out_of_scope"):
        raise SystemExit("BLOCKED: out-of-scope candidate")

    steps = data.get("reproduction_steps")
    evidence = data.get("evidence")
    if not isinstance(steps, list) or len(steps) < 2:
        raise SystemExit("BLOCKED: reproduction_steps must contain at least two concrete steps")
    if not isinstance(evidence, list) or len(evidence) < 1:
        raise SystemExit("BLOCKED: evidence must contain at least one artifact/reference")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python bounty/report_gate.py finding.json")
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    validate(data)
    print("READY_FOR_MANUAL_SUBMISSION")


if __name__ == "__main__":
    main()
