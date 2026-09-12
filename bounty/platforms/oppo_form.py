import hashlib


_SEVERITY = {
    "low": "低危漏洞",
    "medium": "中危漏洞",
    "high": "高危漏洞",
    "critical": "严重漏洞",
    "严重": "严重漏洞",
    "高危": "高危漏洞",
    "中危": "中危漏洞",
    "低危": "低危漏洞",
}


def _sha256_text(text):
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def expected_form_snapshot(report, attachment):
    body = str(report.get("body") or report.get("detail") or "")
    return {
        "title": str(report.get("title") or ""),
        "severity": _SEVERITY.get(str(report.get("severity", "")).lower(), str(report.get("severity") or "")),
        "primary_type": str(report.get("primary_type") or "web漏洞"),
        "subtype": str(report.get("subtype") or report.get("vulnerability_type") or ""),
        "domain": str(report.get("target") or ""),
        "editor_text": body,
        "editor_hash": _sha256_text(body),
        "attachment_name": str((attachment or {}).get("name") or ""),
        "attachment_size": int((attachment or {}).get("size") or 0),
        "validation_errors": [],
    }


def validate_live_snapshot(expected, observed):
    errors = []
    for key in ("title", "severity", "primary_type", "subtype", "domain"):
        if str(observed.get(key) or "") != str(expected.get(key) or ""):
            errors.append(f"{key} mismatch")

    observed_text = str(observed.get("editor_text") or "")
    observed_hash = _sha256_text(observed_text)
    if observed_hash != expected.get("editor_hash"):
        errors.append("editor hash mismatch")

    if str(observed.get("attachment_name") or "") != str(expected.get("attachment_name") or ""):
        errors.append("attachment name mismatch")
    if int(observed.get("attachment_size") or 0) != int(expected.get("attachment_size") or 0):
        errors.append("attachment size mismatch")
    if list(observed.get("validation_errors") or []):
        errors.append("visible validation errors present")
    return errors
