import json
import zipfile
from pathlib import Path

import pytest

from bounty.build_evidence_pack import build_pack
from bounty.candidate_reconcile_v3 import reconcile_dir
from bounty.evidence_manifest import build_artifact, write_manifest
from bounty.morning_summary import build_summary
from bounty.overnight_runner import SAFE_STAGES, validate_interval_minutes
from bounty.platforms.oppo_form import expected_form_snapshot, validate_live_snapshot
from bounty.platforms.oppo_receipt import verify_receipt
from bounty.quality_gate import evaluate
from bounty.report_gate_v3 import validate as validate_report_v3
from bounty.submission_state import SubmissionState, transition
from bounty.triage_queue_v3 import load_candidates


def _base_report():
    return {
        "in_scope": True, "reproducible": True, "human_verified": True,
        "impact_fact": "password is placed in URL query",
        "impact_inference": "proxy logs may record request URLs",
        "reproduction_count": 2, "severity": "medium",
        "duplicate_check_complete": True, "destructive_test": False,
        "out_of_scope": False,
    }


def test_state_machine_refuses_skip():
    assert transition(SubmissionState.REPORT_READY, SubmissionState.RECEIPT_VERIFIED) == SubmissionState.SUBMISSION_FAILED


def test_manifest_hashes_bytes(tmp_path):
    p = tmp_path / "e.txt"; p.write_bytes(b"abc")
    a = build_artifact(p, "https://example.com/e", "2026-09-12T00:00:00Z", 200, "GET")
    assert a["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    out = tmp_path / "manifest.json"; write_manifest("c1", [a], out)
    assert json.loads(out.read_text())["candidate_id"] == "c1"


def test_quality_gate_blocks_flags_without_artifacts():
    result = evaluate(_base_report(), {"artifacts": []})
    assert result["verdict"] == "HOLD"
    assert "evidence artifacts missing" in result["blockers"]


def test_inference_only_impact_never_auto_promotes():
    manifest = {"artifacts": [
        {"sha256": "a" * 64, "source_url": "https://e/a", "sensitive": False},
        {"sha256": "b" * 64, "source_url": "https://e/b", "sensitive": False},
    ]}
    result = evaluate(_base_report(), manifest)
    assert result["score"] >= 85
    assert result["verdict"] == "REVIEW"
    assert "impact is inference-only" in result["reasons"]


def test_same_source_files_count_as_one_evidence_source():
    report = _base_report(); report["impact_demonstrated"] = True
    manifest = {"artifacts": [
        {"sha256": "a" * 64, "source_url": "https://e/app.js", "sensitive": False},
        {"sha256": "b" * 64, "source_url": "https://e/app.js", "sensitive": False},
    ]}
    result = evaluate(report, manifest)
    assert result["score"] == 87
    assert "single independent evidence source" in result["reasons"]


def test_demonstrated_impact_can_reach_report_ready():
    report = _base_report(); report["impact_demonstrated"] = True
    manifest = {"artifacts": [
        {"sha256": "a" * 64, "source_url": "https://e/a", "sensitive": False},
        {"sha256": "b" * 64, "source_url": "https://e/b", "sensitive": False},
    ]}
    assert evaluate(report, manifest)["verdict"] == "REPORT_READY"


def test_reconcile_resets_legacy_promoted_flags(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({
        "program_id": "p", "platform": "v", "program_name": "P", "rules_source": "u",
        "rules_checked_at": "x", "first_seen": "x", "last_seen": "y", "target": "a",
        "finding": {"kind": "x", "host": "a", "confidence": "medium"},
        "human_verified": True, "reproducible": True, "clear_security_impact": True,
    }))
    reconcile_dir(tmp_path)
    data = json.loads(p.read_text())
    assert data["human_verified"] is False
    assert data["reproducible"] is False


def test_triage_ignores_legacy_human_verified(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"finding": {"kind": "x", "host": "a", "confidence": "high"}, "human_verified": True}))
    assert load_candidates(tmp_path)[0]["pending"] is True


def test_evidence_pack_has_required_files_and_provenance(tmp_path):
    c = tmp_path / "candidate.json"; c.write_text(json.dumps({"candidate_id": "c1"}))
    r = tmp_path / "report.json"; r.write_text(json.dumps({"title": "Issue", "summary": "Summary"}))
    e = tmp_path / "evidence.txt"; e.write_text("proof")
    out = tmp_path / "pack.zip"
    build_pack(c, r, [{
        "path": e, "source_url": "https://e/source", "captured_at": "2026-09-12T00:00:00Z",
        "http_status": 200, "method": "GET", "evidence_group": "source-a", "sensitive": False,
    }], out)
    with zipfile.ZipFile(out) as z:
        assert {"manifest.json", "report.md", "README.txt", "evidence/evidence.txt"} <= set(z.namelist())
        artifact = json.loads(z.read("manifest.json"))["artifacts"][0]
        assert artifact["source_url"] == "https://e/source"
        assert artifact["evidence_group"] == "source-a"


def test_oppo_form_detects_duplicate_body():
    report = {"title": "Issue", "severity": "medium", "primary_type": "web漏洞", "subtype": "信息泄漏", "target": "gkm-portal.oppo.com", "body": "A" * 200}
    expected = expected_form_snapshot(report, {"name": "e.zip", "size": 100})
    observed = dict(expected, editor_text=report["body"] * 2)
    assert "editor hash mismatch" in validate_live_snapshot(expected, observed)


def test_oppo_snapshot_transport_is_read_only():
    path = Path(__file__).with_name("platforms") / "oppo_snapshot.mjs"
    text = path.read_text(encoding="utf-8")
    assert "Runtime.evaluate" in text
    for field in ("title", "severity", "primary_type", "subtype", "domain", "editor_text", "validation_errors", "attachment_name", "attachment_size", "agreement_selected"):
        assert field in text
    assert all(token not in text for token in (".click(", "Page.navigate", "Input.dispatch", "Runtime.callFunctionOn"))


def test_receipt_requires_new_matching_record():
    before = {"url": "https://security.oppo.com/cn/add", "reports": []}
    after = {"url": "https://security.oppo.com/cn/add", "reports": [], "toast": "success"}
    assert verify_receipt(before, after, "abc")["verified"] is False
    after = {"url": "https://security.oppo.com/cn/userInfo/report/123", "reports": [{"id": "123", "fingerprint": "abc"}]}
    assert verify_receipt(before, after, "abc")["verified"] is True


def test_report_gate_requires_report_ready():
    data = {"program_id": "p", "target": "a", "title": "t", "vulnerability_type": "v", "impact_fact": "f", "reproduction_steps": ["1", "2"], "scope_proof": "s", "rules_checked_at": "r", "quality_verdict": "REVIEW"}
    with pytest.raises(SystemExit): validate_report_v3(data)


def test_overnight_mode_excludes_submission_and_enforces_interval():
    joined = " ".join(SAFE_STAGES).lower()
    assert "submit" not in joined and "receipt" not in joined and "form" not in joined
    with pytest.raises(ValueError): validate_interval_minutes(30)


def test_morning_summary_counts_failures(tmp_path):
    logs = tmp_path / "logs"; logs.mkdir()
    (logs / "overnight-1.json").write_text(json.dumps([{"stage": "a", "returncode": 1}]))
    (tmp_path / "review_queue_v3.md").write_text("Persistent candidates: 3\nAwaiting evidence/review: 2\n")
    text = build_summary(tmp_path)
    assert "Overnight cycles: 1" in text and "Stage failures: 1" in text and "Pending review: 2" in text
