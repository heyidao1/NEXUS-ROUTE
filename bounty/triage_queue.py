import json
from pathlib import Path

ORDER = {"high": 0, "medium": 1, "low": 2}


def load_candidates(root):
    rows = []
    cand_dir = root / "state" / "candidates"
    cand_dir.mkdir(parents=True, exist_ok=True)
    for path in cand_dir.glob("*.json"):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        finding = item.get("finding", {})
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
            "human_verified": bool(item.get("human_verified")),
        })
    return rows


def main():
    root = Path(__file__).resolve().parents[1]
    rows = load_candidates(root)
    rows.sort(key=lambda x: (ORDER.get(x["confidence"], 9), x["program"], x["host"], x["kind"]))
    pending = [x for x in rows if not x["human_verified"]]
    lines = [
        "# Bug-Bounty Review Queue", "",
        f"Persistent candidates: {len(rows)}",
        f"Awaiting manual verification: {len(pending)}", "",
        "Nothing here is submission-ready until the existing report gate passes.", "",
    ]
    for i, row in enumerate(pending, 1):
        lines += [
            f"## {i}. [{row['confidence'].upper()}] {row['kind']}",
            f"- Program: {row['platform']} / {row['program']}",
            f"- Host: {row['host']}",
            f"- URL: {row['url'] or '(passive finding)'}",
            f"- First seen: {row['first_seen']}",
            f"- Last seen: {row['last_seen']}",
            f"- Candidate file: {row['path'].name}", "",
        ]
    out = root / "state" / "review_queue.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"candidates": len(rows), "pending": len(pending)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
