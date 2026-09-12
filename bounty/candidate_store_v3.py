def _legacy_review(previous):
    review = previous.get("review")
    if isinstance(review, dict):
        return dict(review)
    status = str(previous.get("review_status") or "")
    if status.startswith("rejected"):
        return {
            "decision": "rejected",
            "verified_at": previous.get("verified_at"),
            "notes": previous.get("rejection_reason") or status,
            "migrated_from": status,
        }
    return None


def merge_candidate(previous: dict, observation: dict, metadata: dict) -> dict:
    previous = previous or {}
    observation = dict(observation or {})
    metadata = dict(metadata or {})
    run_at = metadata.get("run_at")
    record = {
        "program_id": metadata.get("program_id"),
        "platform": metadata.get("platform"),
        "program_name": metadata.get("program_name"),
        "rules_source": metadata.get("rules_source"),
        "rules_checked_at": run_at,
        "first_seen": previous.get("first_seen", run_at),
        "last_seen": run_at,
        "target": observation.get("host") or metadata.get("target"),
        "finding": observation,
        "in_scope": True,
        "reproducible": False,
        "clear_security_impact": False,
        "evidence_complete": False,
        "duplicate_check_complete": False,
        "human_verified": False,
        "destructive_test": False,
        "out_of_scope": False,
        "state": "DISCOVERED",
    }
    review = _legacy_review(previous)
    if review:
        record["review"] = review
    return record
