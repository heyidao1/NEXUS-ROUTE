# Bug Bounty Safe Pipeline

This directory contains a safety-gated workflow for authorized bug-bounty work. It is designed to reduce false positives and prevent accidental out-of-scope testing or low-quality submissions.

## What is automated now

- GitHub Actions runs repository-focused Semgrep, Trivy and Gitleaks checks.
- Scanner output is normalized into `artifacts/candidates.json` for triage.
- `scope_guard.py` blocks targets that are not explicitly configured as in-scope.
- `risk_score.py` holds weak candidates below the review threshold.
- `report_gate.py` requires reproduction evidence, impact, scope proof, duplicate checking and human verification.
- `render_report.py` produces a clean Markdown report artifact for final human review.

## Hard rules

- Never auto-submit a report to a bounty platform.
- Never test a target not explicitly listed in `programs.yml` from current official rules.
- Never run active automation unless the official program rules explicitly permit it.
- Never perform destructive testing, credential attacks, denial-of-service, persistence, data exfiltration or exploit chaining.
- Scanner findings are candidates only, not vulnerabilities until reproduced and validated.

## Program setup

Edit `programs.yml` using the official Butian or Vulbox program page. Replace the placeholder program name and rules URL, fill the exact include/exclude scope, set `last_verified`, and keep `automation_allowed: false` unless the current official rules explicitly allow automation.

## Local gates

```bash
pip install -r bounty/requirements.txt
python bounty/scope_guard.py --program <id> --target <host>
python bounty/risk_score.py <finding.json>
python bounty/report_gate.py <finding.json>
python bounty/render_report.py <finding.json> bounty/final-report.md
```

Use `finding.template.json` as the starting point for each candidate.

## GitHub Actions

The `Bounty Safe Pipeline` workflow runs automatically on this branch and on pull requests. A manual `workflow_dispatch` can also validate a prepared finding. The `submission-gate` job only creates a report artifact after all configured gates pass; submission remains a deliberate human action on the official platform.

## Intended end-to-end flow

Official program rules -> scope configuration -> passive/repository analysis -> candidate triage -> reproducibility check -> impact validation -> duplicate check -> human verification -> gated report artifact -> manual platform submission.
