import json
import re
from pathlib import Path


def _extract_count(text, label):
    m = re.search(rf"{re.escape(label)}:\s*(\d+)", text)
    return int(m.group(1)) if m else 0


def build_summary(state_dir):
    state = Path(state_dir)
    logs = state / "logs"
    cycles = 0
    failures = 0
    stage_runs = 0
    for path in sorted(logs.glob("overnight-*.json")) if logs.exists() else []:
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            failures += 1
            continue
        cycles += 1
        stage_runs += len(rows)
        failures += sum(1 for row in rows if int(row.get("returncode", 1)) != 0)
    queue_path = state / "review_queue_v3.md"
    queue = queue_path.read_text(encoding="utf-8") if queue_path.exists() else ""
    persistent = _extract_count(queue, "Persistent candidates")
    pending = _extract_count(queue, "Awaiting evidence/review")
    return "\n".join([
        "# Overnight Bounty Summary", "",
        f"- Overnight cycles: {cycles}",
        f"- Stage executions: {stage_runs}",
        f"- Stage failures: {failures}",
        f"- Persistent candidates: {persistent}",
        f"- Pending review: {pending}",
        "",
        "No reports are submitted by overnight mode.",
    ])


def main():
    root = Path(__file__).resolve().parents[1]
    state = root / "state"
    out = state / "morning-summary.md"
    out.write_text(build_summary(state), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
