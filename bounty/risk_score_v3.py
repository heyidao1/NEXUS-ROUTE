import json
import sys
from pathlib import Path

from bounty.quality_gate import evaluate


def score(report: dict, manifest: dict) -> dict:
    return evaluate(report, manifest)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: python bounty/risk_score_v3.py report.json manifest.json")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    result = score(report, manifest)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["verdict"] != "REPORT_READY":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
