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
    if not artifacts:
        blockers.append("evidence artifacts missing")
    elif len(artifacts) == 1:
        score += 12
        reasons.append("single evidence artifact")
    else:
        score += 25

    if not report.get("impact_fact"):
        blockers.append("impact fact missing")
    elif report.get("impact_demonstrated") is True:
        score += 20
    elif report.get("impact_inference"):
        score += 8
        reasons.append("security impact is inferred, not directly demonstrated")
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
    elif score >= 85:
        verdict = "REPORT_READY"
    else:
        verdict = "REVIEW"
    return {"score": score, "verdict": verdict, "blockers": blockers, "reasons": reasons}
