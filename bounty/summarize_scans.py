import json
import sys
from pathlib import Path


def load_json(path: Path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def semgrep_findings(data: dict):
    out = []
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        out.append({
            "source": "semgrep",
            "rule": item.get("check_id"),
            "path": item.get("path"),
            "line": (item.get("start") or {}).get("line"),
            "severity": extra.get("severity"),
            "message": extra.get("message"),
            "status": "candidate_only",
        })
    return out


def trivy_findings(data: dict):
    out = []
    for result in data.get("Results", []) or []:
        target = result.get("Target")
        for item in result.get("Vulnerabilities", []) or []:
            out.append({
                "source": "trivy",
                "rule": item.get("VulnerabilityID"),
                "path": target,
                "severity": item.get("Severity"),
                "message": item.get("Title") or item.get("Description"),
                "status": "candidate_only",
            })
    return out


def main():
    artifacts = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    findings = []
    findings += semgrep_findings(load_json(artifacts / "semgrep.json"))
    findings += trivy_findings(load_json(artifacts / "trivy.json"))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: severity_order.get(str(x.get("severity", "")).upper(), 9))

    output = {
        "notice": "Scanner output is triage input only. Do not submit without scope proof, reproduction, impact validation, duplicate check, and human verification.",
        "count": len(findings),
        "findings": findings,
    }
    out = artifacts / "candidates.json"
    out.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
