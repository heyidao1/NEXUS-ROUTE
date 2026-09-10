import pytest

from bounty.risk_score import score
from bounty.scope_guard import normalize_target, validate


def test_normalize_target():
    assert normalize_target("HTTPS://Example.COM/path") == "example.com"
    assert normalize_target("sub.example.com") == "sub.example.com"


def test_scope_allows_explicit_pattern():
    program = {
        "rules_url": "https://platform.example/rules",
        "last_verified": "2026-09-10T00:00:00Z",
        "automation_allowed": True,
        "scope": {"include": ["*.example.com"], "exclude": ["admin.example.com"]},
    }
    assert validate(program, "https://api.example.com", True) == "api.example.com"


def test_scope_blocks_excluded_target():
    program = {
        "rules_url": "https://platform.example/rules",
        "last_verified": "2026-09-10T00:00:00Z",
        "automation_allowed": True,
        "scope": {"include": ["*.example.com"], "exclude": ["admin.example.com"]},
    }
    with pytest.raises(SystemExit):
        validate(program, "admin.example.com", True)


def test_scope_blocks_automation_without_permission():
    program = {
        "rules_url": "https://platform.example/rules",
        "last_verified": "2026-09-10T00:00:00Z",
        "automation_allowed": False,
        "scope": {"include": ["api.example.com"], "exclude": []},
    }
    with pytest.raises(SystemExit):
        validate(program, "api.example.com", True)


def test_candidate_score_requires_strong_evidence():
    finding = {
        "reproducible": True,
        "clear_security_impact": True,
        "in_scope": True,
        "evidence_complete": True,
        "duplicate_check_complete": True,
        "destructive_test": False,
        "out_of_scope": False,
    }
    total, reasons = score(finding)
    assert total == 100
    assert reasons == []


def test_destructive_candidate_scores_zero():
    total, _ = score({
        "reproducible": True,
        "clear_security_impact": True,
        "in_scope": True,
        "evidence_complete": True,
        "duplicate_check_complete": True,
        "destructive_test": True,
    })
    assert total == 0
