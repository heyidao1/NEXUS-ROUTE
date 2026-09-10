import json
import sys
from pathlib import Path

WEIGHTS = {
    "reproducible": 30,
    "clear_security_impact": 25,
    "in_scope": 20,
    "evidence_complete": 15,
    "duplicate_check_complete": 10,
}


def score(data: dict) -> tuple[int, list[str]]:
    total = 0
    reasons = []
    for key, weight in WEIGHTS.items():
        if data.get(key) is True:
            total += weight
        else:
            reasons.append(f"missing/false: {key}")

    if data.get("destructive_test"):
        total = 0
        reasons.append("destructive_test=true forces score to 0")
    if data.get("out_of_scope"):
        total = 0
        reasons.append("out_of_scope=true forces score to 0")
    return total, reasons


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python bounty/risk_score.py finding.json")
    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))
    total, reasons = score(data)
    verdict = "REVIEW" if total >= 80 else "HOLD"
    print(json.dumps({"score": total, "verdict": verdict, "reasons": reasons}, ensure_ascii=False, indent=2))
    if verdict != "REVIEW":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
