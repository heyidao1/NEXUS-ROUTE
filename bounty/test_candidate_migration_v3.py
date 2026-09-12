import json

from bounty.candidate_store_v3 import merge_candidate
from bounty.triage_queue_v3 import load_candidates


def test_legacy_rejection_is_migrated_to_structured_review():
    previous = {
        "review_status": "rejected_false_positive",
        "rejection_reason": "library code only",
        "verified_at": "2026-09-11T00:00:00Z",
    }
    observation = {"kind": "secret-pattern", "host": "a.example.com", "confidence": "medium"}
    record = merge_candidate(previous, observation, {"program_id": "p", "run_at": "2026-09-12T00:00:00Z"})
    assert record["review"]["decision"] == "rejected"
    assert record["review"]["notes"] == "library code only"


def test_rejected_review_is_resolved_not_pending(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({
        "program_name": "P", "platform": "v",
        "finding": {"kind": "x", "confidence": "medium", "host": "a"},
        "review": {"decision": "rejected", "notes": "false positive"},
    }), encoding="utf-8")
    assert load_candidates(tmp_path)[0]["pending"] is False
