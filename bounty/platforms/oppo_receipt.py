from urllib.parse import urlparse


def _report_map(rows):
    out = {}
    for row in rows or []:
        rid = str(row.get("id") or "")
        if rid:
            out[rid] = row
    return out


def verify_receipt(before: dict, after: dict, report_fingerprint: str) -> dict:
    before_reports = _report_map(before.get("reports"))
    after_reports = _report_map(after.get("reports"))
    new_ids = [rid for rid in after_reports if rid not in before_reports]

    for rid in new_ids:
        row = after_reports[rid]
        if str(row.get("fingerprint") or "") != str(report_fingerprint):
            continue
        url = str(after.get("url") or "")
        path = urlparse(url).path
        if path == "/cn/add" or not path:
            continue
        return {
            "verified": True,
            "report_id": rid,
            "detail_url": url,
            "reason": "new matching submitted-report record and non-form detail URL",
        }

    return {
        "verified": False,
        "report_id": None,
        "detail_url": str(after.get("url") or ""),
        "reason": "no verifiable new matching report receipt",
    }
