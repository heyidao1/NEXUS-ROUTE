from pathlib import Path


def test_windows_runner_reconciles_v3_before_triage():
    text = (Path(__file__).resolve().parents[1] / "run_safe_hunter.ps1").read_text(encoding="utf-8")
    reconcile = text.index("candidate_reconcile_v3.py")
    v3_queue = text.index("triage_queue_v3.py")
    assert reconcile < v3_queue
    assert "report_gate" not in text.lower()
    assert "submit" not in text.lower()
