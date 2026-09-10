import pytest

from bounty.report_gate import validate as validate_report
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


def complete_finding():
    return {
        "program_id": "demo",
        "target": "api.example.com",
        "title": "Validated issue",
        "vulnerability_type": "authorization",
        "impact": "Concrete security impact",
        "reproduction_steps": ["Step one", "Step two"],
        "evidence": ["artifact.txt"],
        "scope_proof": "Official scope reference",
        "rules_checked_at": "2026-09-10T00:00:00Z",
        "reproducible": True,
        "clear_security_impact": True,
        "in_scope": True,
        "evidence_complete": True,
        "duplicate_check_complete": True,
        "human_verified": True,
        "destructive_test": False,
        "out_of_scope": False,
    }


def test_candidate_score_requires_strong_evidence():
    total, reasons = score(complete_finding())
    assert total == 100
    assert reasons == []


def test_destructive_candidate_scores_zero():
    finding = complete_finding()
    finding["destructive_test"] = True
    total, _ = score(finding)
    assert total == 0


def test_report_gate_passes_complete_finding():
    validate_report(complete_finding())


def test_report_gate_blocks_without_human_verification():
    finding = complete_finding()
    finding["human_verified"] = False
    with pytest.raises(SystemExit):
        validate_report(finding)
