# Bug Bounty Safe Pipeline

This directory contains a safety-gated workflow for authorized bug-bounty work.

## Design goals

- Only operate on targets that are explicitly listed as in-scope by the bounty program.
- Block any target whose program rules cannot be verified.
- Never auto-submit findings.
- Never run destructive checks, credential attacks, denial-of-service, persistence, data exfiltration, or exploit chains.
- Require a human approval gate before any active validation step.
- Require evidence quality checks before a report can be marked ready for submission.

## Workflow

1. Add or update a program entry in `programs.yml` from the official bounty page.
2. Run `python bounty/scope_guard.py --program <id> --target <host>`.
3. Collect passive evidence and create a candidate finding locally.
4. Run `python bounty/report_gate.py <finding.json>`.
5. If the gate passes, review the report manually against the current program rules.
6. Submit manually through the official bounty platform.

The pipeline intentionally does not include automatic exploitation or automatic report submission. Program scope and automation rules can change, so the current official rules must always be checked before testing.