import hashlib
import json
from pathlib import Path


def build_artifact(path, source_url, captured_at, http_status, method, sensitive=False):
    p = Path(path)
    data = p.read_bytes()
    return {
        "path": p.name,
        "source_url": str(source_url),
        "captured_at": str(captured_at),
        "http_status": int(http_status) if http_status is not None else None,
        "method": str(method).upper(),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sensitive": bool(sensitive),
    }


def write_manifest(candidate_id, artifacts, out_path):
    out = Path(out_path)
    payload = {
        "candidate_id": str(candidate_id),
        "artifacts": sorted(list(artifacts), key=lambda item: (item.get("path", ""), item.get("sha256", ""))),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
