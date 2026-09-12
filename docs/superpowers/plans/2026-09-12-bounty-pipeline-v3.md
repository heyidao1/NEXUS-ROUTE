# Bug-Bounty Pipeline V3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an evidence-driven, stateful bounty workflow that cannot claim successful submission without a verified platform receipt and can safely run discovery overnight.

**Architecture:** Keep `safe_hunter.py` as the bounded discovery engine, then pass candidates through immutable evidence manifests, an evidence-based quality gate, deterministic form preflight, and receipt verification. Submission remains human-gated at terms acceptance; overnight mode never submits.

**Tech Stack:** Python 3.13, PyYAML, pytest, Windows PowerShell, Chromium CDP for platform form verification.

**Spec:** `docs/superpowers/specs/2026-09-12-bounty-pipeline-v3-design.md`

## Global Constraints
- Do not hide or bypass safety controls.
- Only active-test targets explicitly allowed by current program configuration.
- No brute force, denial of service, state-changing exploitation, persistence, data export, command execution, or destructive validation.
- Overnight mode never submits reports.
- `RECEIPT_VERIFIED` is the only success state after a submit attempt.
- OPPO request budget remains 36 direct requests/run with 2.0 s delay unless official rules are re-verified.

---

### Task 1: Explicit submission state machine

**Files:**
- Create: `bounty/submission_state.py`
- Create: `bounty/test_submission_state.py`

**Interfaces:**
- Produces: `SubmissionState` enum and `transition(current, target) -> SubmissionState`.

- [ ] **Step 1: Write failing tests**
```python
from bounty.submission_state import SubmissionState, transition

def test_valid_progression():
    assert transition(SubmissionState.DISCOVERED, SubmissionState.VERIFIED) == SubmissionState.VERIFIED

def test_cannot_skip_to_receipt_verified():
    assert transition(SubmissionState.REPORT_READY, SubmissionState.RECEIPT_VERIFIED) == SubmissionState.SUBMISSION_FAILED
```
- [ ] **Step 2: Run** `python -m pytest -q bounty/test_submission_state.py` and confirm failure because module is absent.
- [ ] **Step 3: Implement** an enum with `DISCOVERED, VERIFIED, REPORT_READY, FORM_VERIFIED, TERMS_ACCEPTED, SUBMITTING, RECEIPT_VERIFIED, HOLD, SUBMISSION_FAILED`, plus an allowlist of adjacent transitions.
- [ ] **Step 4: Re-run the test and require PASS.**
- [ ] **Step 5: Commit** `feat: add explicit bounty submission state machine`.

### Task 2: Immutable evidence manifests

**Files:**
- Create: `bounty/evidence_manifest.py`
- Create: `bounty/test_evidence_manifest.py`

**Interfaces:**
- Produces: `build_artifact(path, source_url, captured_at, http_status, method, sensitive=False) -> dict` and `write_manifest(candidate_id, artifacts, out_path) -> Path`.

- [ ] **Step 1: Write failing tests**
```python
from pathlib import Path
from bounty.evidence_manifest import build_artifact

def test_artifact_hashes_exact_bytes(tmp_path):
    p = tmp_path / "e.txt"
    p.write_bytes(b"abc")
    a = build_artifact(p, "https://example.com/e", "2026-09-12T00:00:00Z", 200, "GET")
    assert a["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert a["sensitive"] is False
```
- [ ] **Step 2: Run the test and confirm failure.**
- [ ] **Step 3: Implement stable manifest JSON with relative artifact path, byte size, SHA-256, source URL, capture time, HTTP status, method, and sensitivity flag.**
- [ ] **Step 4: Test and require PASS.**
- [ ] **Step 5: Commit** `feat: add immutable evidence manifests`.

### Task 3: Replace boolean scoring with evidence-based quality gate

**Files:**
- Create: `bounty/quality_gate.py`
- Create: `bounty/test_quality_gate.py`
- Modify: `bounty/risk_score.py`
- Modify: `bounty/report_gate.py`

**Interfaces:**
- Produces: `evaluate(report: dict, manifest: dict) -> {score:int, verdict:str, blockers:list[str], reasons:list[str]}`.
- `verdict` is one of `HOLD`, `REVIEW`, `REPORT_READY`.

- [ ] **Step 1: Write failing tests**
```python
from bounty.quality_gate import evaluate

def test_flags_alone_cannot_reach_report_ready():
    report = {"in_scope": True, "reproducible": True, "human_verified": True,
              "impact_fact": "password is placed in URL query",
              "impact_inference": "proxy logs may record request URLs",
              "reproduction_count": 1, "severity": "medium"}
    result = evaluate(report, {"artifacts": []})
    assert result["verdict"] == "HOLD"
    assert "evidence artifacts missing" in result["blockers"]
```
- [ ] **Step 2: Confirm the test fails.**
- [ ] **Step 3: Implement score components:** scope 20, repeatability 20, artifact quality 25, demonstrated impact 20, duplicate review 10, conservative severity 5. Require no blockers and score >= 85 for `REPORT_READY`.
- [ ] **Step 4: Update `risk_score.py` to call the new gate and update `report_gate.py` to require `quality_verdict == REPORT_READY`, not merely boolean flags.**
- [ ] **Step 5: Run `python -m pytest -q bounty/test_pipeline.py bounty/test_quality_gate.py`.**
- [ ] **Step 6: Commit** `feat: gate reports on evidence quality`.

### Task 4: Candidate provenance and review integrity

**Files:**
- Modify: `bounty/safe_hunter.py`
- Modify: `bounty/triage_queue.py`
- Create: `bounty/test_candidate_provenance.py`

**Interfaces:**
- Discovery may write `human_verified: false` only.
- Manual review writes a separate `review` object with reviewer, verified_at, decision, evidence references, and notes.

- [ ] **Step 1: Write a failing test asserting `safe_hunter.write_outputs()` cannot preserve a stale `human_verified: true` from an older candidate file.**
- [ ] **Step 2: Run and confirm failure.**
- [ ] **Step 3: Change candidate persistence so discovery updates observations but never promotes verification state. Preserve prior review under `review` without copying its decision into new discovery truth fields.**
- [ ] **Step 4: Change `triage_queue.py` to list candidates by `review.decision` and quality verdict.**
- [ ] **Step 5: Run affected tests and commit** `fix: separate discovery facts from human review`.

### Task 5: Evidence package V2

**Files:**
- Create: `bounty/build_evidence_pack.py`
- Create: `bounty/test_evidence_pack.py`

**Interfaces:**
- `build_pack(candidate_json, report_json, artifact_paths, out_zip) -> Path`.
- ZIP must contain `manifest.json`, `report.md`, `README.txt`, and referenced evidence files.

- [ ] **Step 1: Write a failing test that opens the ZIP and checks all mandatory members plus SHA-256 consistency.**
- [ ] **Step 2: Confirm failure.**
- [ ] **Step 3: Implement deterministic ZIP ordering, UTF-8 text, manifest hashes, and refusal to include files marked sensitive.**
- [ ] **Step 4: Test and commit** `feat: build reviewer-grade evidence packs`.

### Task 6: Deterministic OPPO form preflight

**Files:**
- Create: `bounty/platforms/__init__.py`
- Create: `bounty/platforms/oppo_form.py`
- Create: `bounty/test_oppo_form.py`

**Interfaces:**
- `expected_form_snapshot(report, attachment) -> dict`.
- `validate_live_snapshot(expected, observed) -> list[str]` returns zero errors only when every required field, editor state, attachment metadata, and validation status match.

- [ ] **Step 1: Write tests covering empty domain, duplicated editor body, stale validation error, wrong category, and mismatched attachment name.**
- [ ] **Step 2: Confirm failure.**
- [ ] **Step 3: Implement pure validation logic first; keep browser/CDP transport separate from business rules.**
- [ ] **Step 4: Add a read-only CDP snapshot script that returns title, severity, primary type, subtype, domain, editor text/hash, visible validation errors, attachment name/size, agreement state, and current URL.**
- [ ] **Step 5: Never click submit from this module. It may only emit `FORM_VERIFIED` when validation errors are empty.**
- [ ] **Step 6: Test and commit** `feat: add deterministic OPPO form preflight`.

### Task 7: Receipt verifier

**Files:**
- Create: `bounty/platforms/oppo_receipt.py`
- Create: `bounty/test_oppo_receipt.py`

**Interfaces:**
- `verify_receipt(before: dict, after: dict, report_fingerprint: str) -> dict` returns `verified`, `report_id`, `detail_url`, `reason`.

- [ ] **Step 1: Write tests proving that a button click, unchanged `/cn/add` URL, or generic success toast is insufficient.**
- [ ] **Step 2: Add a passing case requiring a new report ID or a matching submitted-report list entry plus a non-form detail URL.**
- [ ] **Step 3: Implement and test.**
- [ ] **Step 4: Commit** `feat: verify platform receipt before marking submitted`.

### Task 8: Re-audit the current GKM candidate

**Files:**
- Modify: `state/reports/gkm-password-query.report.json` locally only
- Rebuild: `state/reports/gkm-password-query-evidence-v2.zip` locally only

**Interfaces:**
- Must distinguish `impact_fact` from `impact_inference`.
- Must include two-entry reproduction evidence already observed for `gkm-portal.oppo.com` and `gkm-portal-sg.oppo.com` if the production bundle remains unchanged.

- [ ] **Step 1: Re-fetch only the two public affected pages/bundles and verify current SHA-256; do not use real credentials or access user data.**
- [ ] **Step 2: Record two independent timestamps and exact public artifacts.**
- [ ] **Step 3: Reword impact so unverified logging is explicitly inference, not a claimed leak.**
- [ ] **Step 4: Run the new quality gate. If verdict is not `REPORT_READY`, leave it on HOLD and do not submit.**
- [ ] **Step 5: If it passes, build Evidence Pack V2 and run OPPO form preflight.**

### Task 9: Overnight safe orchestrator and morning summary

**Files:**
- Create: `bounty/overnight_runner.py`
- Create: `bounty/morning_summary.py`
- Create: `bounty/test_overnight_runner.py`
- Modify: `run_safe_hunter.ps1`

**Interfaces:**
- `overnight_runner.py --until <ISO8601>` invokes only existing safe discovery/audit stages, sleeps between cycles, and never imports submission modules.
- `morning_summary.py` writes `state/morning-summary.md`.

- [ ] **Step 1: Write a failing test verifying the overnight stage allowlist excludes all submission modules and respects per-program request budgets.**
- [ ] **Step 2: Implement a minimum 90-minute cycle interval and stop at the requested end time.**
- [ ] **Step 3: Add per-cycle run IDs, logs, candidate counts, false-positive rejection counts, and failure capture.**
- [ ] **Step 4: Implement morning summary generation.**
- [ ] **Step 5: Run tests and commit** `feat: add safe overnight bounty orchestration`.

### Task 10: Full verification and CI

**Files:**
- Modify: `.github/workflows/bounty-safe-pipeline.yml`

**Interfaces:**
- CI runs all new unit tests but never executes external target testing or platform submission.

- [ ] **Step 1: Add the new test files to the existing pytest step.**
- [ ] **Step 2: Run locally:** `python -m pytest -q bounty/test_pipeline.py bounty/test_safe_hunter.py bounty/test_submission_state.py bounty/test_evidence_manifest.py bounty/test_quality_gate.py bounty/test_candidate_provenance.py bounty/test_evidence_pack.py bounty/test_oppo_form.py bounty/test_oppo_receipt.py bounty/test_overnight_runner.py`.
- [ ] **Step 3: Require zero failures before claiming the upgrade complete.**
- [ ] **Step 4: Push to `bounty-safe-pipeline`, check the GitHub Actions run, and keep PR #1 draft/unmerged.**
- [ ] **Step 5: After CI passes, sync the remote Windows runner to the verified branch and perform one dry run with submission disabled.**
