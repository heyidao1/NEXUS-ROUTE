# Bug-Bounty Pipeline V3 Design

## Goal
Upgrade the current bounty workflow into an evidence-driven, auditable pipeline that cannot claim successful submission without a verified platform receipt.

## Non-goals
- Do not evade or hide ChatGPT/platform safety controls.
- Do not actively scan targets without explicit program authorization.
- Do not use brute force, DoS, persistence, data exfiltration, command execution, or destructive validation.
- Overnight mode never submits reports automatically.

## State machine
`DISCOVERED -> VERIFIED -> REPORT_READY -> FORM_VERIFIED -> TERMS_ACCEPTED -> SUBMITTING -> RECEIPT_VERIFIED`.
Any failed check moves the candidate to `HOLD` or `SUBMISSION_FAILED`. A click is never treated as a successful submission.

## Evidence model
Every factual claim binds to an artifact with source URL, capture time, HTTP status, SHA-256, file path, verification method, and sensitivity flag. Facts and impact inference are stored separately.

## Quality gate
A report must pass scope, repeatability, evidence completeness, impact strength, duplicate-risk, and severity-conservatism checks. Boolean flags alone cannot create a perfect score.

## Platform adapter
The adapter reads the live form schema, writes one field at a time, reads it back, and verifies editor internal state, visible text, and validation errors agree. Before submission it emits a `FORM_VERIFIED` snapshot with title, severity, types, domain, report hash, and attachment metadata.

Terms acceptance remains a user action. After submit, success requires a verifiable receipt such as a report ID, issue detail URL, or matching entry in the user's submitted-report list.

## Overnight mode
Overnight jobs run only configured passive discovery and explicitly allowed low-impact read-only checks within existing budgets. High-confidence candidates are queued for review; nothing is submitted overnight. A morning summary records runs, coverage, candidates, rejected false positives, and runner failures.
