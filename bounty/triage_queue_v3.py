import json
from pathlib import Path

ORDER = {"high": 0, "medium": 1, "low": 2}


def load_candidates(candidate_dir):
    rows = []
    candidate_dir = Path(candidate_dir)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    for path in candidate_dir.glob("*.json"):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        finding = item.get("finding") or {}
        review = item.get("review") if isinstance(item.get("review"), dict) else {}
        quality = item.get("quality") if isinstance(item.get("quality"), dict) else {}
        decision = review.get("decision")
        ready = decision == "verified" and quality.get("verdict") == "REPORT_READY"
        rows.append({
            "path": path,
            "program": item.get("program_name", ""),
            "platform": item.get("platform", ""),
            "kind": finding.get("kind", "unknown"),
            "confidence": finding.get("confidence", "low"),
            "host": finding.get("host") or item.get("target", ""),
            "url": finding.get("url", ""),
            "first_seen": item.get("first_seen", ""),
            "last_seen": item.get("last_seen", ""),
            "review_decision": decision,
            "quality_verdict": quality.get("verdict"),
            "pending": not ready,
        })
    return rows


def main():
    root = Path(__file__).resolve().parents[1]
    rows = load_candidates(root / "state" / "candidates")
    rows.sort(key=lambda x: (ORDER.get(x["confidence"], 9), x["program"], x["host"], x["kind"]))
    pending = [x for x in rows if x["pending"]]
    lines = [
        "# Bug-Bounty Review Queue V3", "",
        f"Persistent candidates: {len(rows)}",
        f"Awaiting evidence/review: {len(pending)}", "",
        "Nothing is submission-ready without structured review + REPORT_READY quality verdict.", "",
    ]
    for i, row in enumerate(pending, 1):
        lines += [
            f"## {i}. [{row['confidence'].upper()}] {row['kind']}",
            f"- Program: {row['platform']} / {row['program']}",
            f"- Host: {row['host']}",
            f"- URL: {row['url'] or '(passive finding)'}",
            f"- Review: {row['review_decision'] or 'unreviewed'}",
            f"- Quality: {row['quality_verdict'] or 'not-scored'}",
            f"- Candidate file: {row['path'].name}", "",
        ]
    out = root / "state" / "review_queue_v3.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"candidates": len(rows), "pending": len(pending)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
