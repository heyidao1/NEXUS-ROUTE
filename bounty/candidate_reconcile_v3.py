import json
from pathlib import Path

from bounty.candidate_store_v3 import merge_candidate


def reconcile_dir(candidate_dir):
    candidate_dir = Path(candidate_dir)
    count = 0
    for path in candidate_dir.glob("*.json"):
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        finding = previous.get("finding") or {}
        metadata = {
            "program_id": previous.get("program_id"),
            "platform": previous.get("platform"),
            "program_name": previous.get("program_name"),
            "rules_source": previous.get("rules_source"),
            "run_at": previous.get("last_seen") or previous.get("rules_checked_at"),
            "target": previous.get("target"),
        }
        record = merge_candidate(previous, finding, metadata)
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        count += 1
    return count


def main():
    root = Path(__file__).resolve().parents[1]
    count = reconcile_dir(root / "state" / "candidates")
    print(json.dumps({"reconciled": count}, ensure_ascii=False))


if __name__ == "__main__":
    main()
