import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SAFE_STAGES = (
    "bounty/safe_hunter.py",
    "bounty/public_asset_audit.py",
    "bounty/endpoint_audit.py",
    "bounty/candidate_reconcile_v3.py",
    "bounty/triage_queue_v3.py",
)


def validate_interval_minutes(value):
    value = int(value)
    if value < 90:
        raise ValueError("overnight interval must be at least 90 minutes")
    return value


def parse_until(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def run_cycle(root, run_id):
    logs = Path(root) / "state" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    rows = []
    for stage in SAFE_STAGES:
        path = Path(root) / stage
        if not path.exists():
            rows.append({"stage": stage, "returncode": 127, "error": "missing stage"})
            continue
        cp = subprocess.run([sys.executable, str(path)], cwd=root, capture_output=True, text=True)
        rows.append({"stage": stage, "returncode": cp.returncode, "stdout": cp.stdout[-4000:], "stderr": cp.stderr[-4000:]})
    (logs / f"overnight-{run_id}.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--until", required=True)
    ap.add_argument("--interval-minutes", type=int, default=90)
    args = ap.parse_args()
    interval = validate_interval_minutes(args.interval_minutes)
    until = parse_until(args.until)
    root = Path(__file__).resolve().parents[1]
    cycle = 0
    while datetime.now(timezone.utc) < until:
        cycle += 1
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{cycle:02d}"
        run_cycle(root, run_id)
        if datetime.now(timezone.utc) >= until:
            break
        sleep_for = min(interval * 60, max(0, (until - datetime.now(timezone.utc)).total_seconds()))
        if sleep_for <= 0:
            break
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
