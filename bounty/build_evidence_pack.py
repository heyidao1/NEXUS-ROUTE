import hashlib
import json
import zipfile
from pathlib import Path


def _render_report(data):
    return "# {title}\n\n{summary}\n".format(
        title=data.get("title", "Untitled finding"),
        summary=data.get("summary", ""),
    )


def build_pack(candidate_json, report_json, artifact_paths, out_zip):
    candidate = json.loads(Path(candidate_json).read_text(encoding="utf-8"))
    report = json.loads(Path(report_json).read_text(encoding="utf-8"))
    artifacts = []
    source_paths = []
    for item in artifact_paths:
        meta = dict(item) if isinstance(item, dict) else {}
        if meta.get("sensitive"):
            raise ValueError("sensitive artifacts cannot be packed")
        p = Path(meta.get("path") if meta else item)
        data = p.read_bytes()
        arc = f"evidence/{p.name}"
        artifact = {
            "path": arc,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sensitive": False,
        }
        for key in ("source_url", "captured_at", "http_status", "method", "evidence_group"):
            if meta.get(key) is not None:
                artifact[key] = meta[key]
        if "method" in artifact:
            artifact["method"] = str(artifact["method"]).upper()
        artifacts.append(artifact)
        source_paths.append((arc, p))

    manifest = {
        "candidate_id": candidate.get("candidate_id") or candidate.get("program_id") or "unknown",
        "report_title": report.get("title", ""),
        "artifacts": sorted(artifacts, key=lambda a: a["path"]),
    }
    readme = "Evidence package generated for reviewer reproduction. No sensitive user data is included.\n"
    out = Path(out_zip)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        z.writestr("report.md", _render_report(report))
        z.writestr("README.txt", readme)
        for arc, p in sorted(source_paths):
            z.write(p, arc)
    return out
