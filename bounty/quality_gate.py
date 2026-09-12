def _independent_artifact_count(artifacts):
    keys = set()
    for artifact in artifacts:
        group = str(artifact.get("evidence_group") or "").strip()
        source = str(artifact.get("source_url") or "").strip()
        digest = str(artifact.get("sha256") or "").strip()
        key = ("group", group) if group else (("source", source) if source else ("sha256", digest))
        keys.add(key)
    return len(keys)


def evaluate(report: dict, manifest: dict) -> dict:
    blockers = []
    reasons = []
    score = 0

    if report.get("out_of_scope") or not report.get("in_scope"):
        blockers.append("target not confirmed in scope")
    else:
        score += 20

    if report.get("destructive_test"):
        blockers.append("destructive validation used")

    if not report.get("human_verified"):
        blockers.append("human verification missing")

    reproductions = int(report.get("reproduction_count") or 0)
    if report.get("reproducible") and reproductions >= 2:
        score += 20
    elif report.get("reproducible"):
        score += 10
        reasons.append("only one reproduction recorded")
    else:
        blockers.append("candidate not reproducible")

    artifacts = [a for a in (manifest or {}).get("artifacts", []) if not a.get("sensitive")]
    independent = _independent_artifact_count(artifacts)
    if not artifacts:
        blockers.append("evidence artifacts missing")
    elif independent == 1:
        score += 12
        reasons.append("single independent evidence source")
    else:
        score += 25

    inference_only = False
    if not report.get("impact_fact"):
        blockers.append("impact fact missing")
    elif report.get("impact_demonstrated") is True:
        score += 20
    elif report.get("impact_inference"):
        score += 8
        inference_only = True
        reasons.append("security impact is inferred, not directly demonstrated")
        reasons.append("impact is inference-only")
    else:
        score += 4
        reasons.append("impact statement lacks demonstrated consequence")

    if report.get("duplicate_check_complete") is True:
        score += 10
    else:
        reasons.append("duplicate review incomplete")

    severity = str(report.get("severity", "")).lower()
    if report.get("impact_demonstrated") is True or severity in {"low", "medium"}:
        score += 5
    else:
        reasons.append("severity may overstate demonstrated impact")

    if blockers:
        verdict = "HOLD"
    elif inference_only:
        verdict = "REVIEW"
    elif score >= 85:
        verdict = "REPORT_READY"
    else:
        verdict = "REVIEW"
    return {"score": score, "verdict": verdict, "blockers": blockers, "reasons": reasons}
