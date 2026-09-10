import json
import sys
from pathlib import Path


def bullet_lines(value):
    if isinstance(value, list):
        return "\n".join(f"{i + 1}. {item}" for i, item in enumerate(value))
    return str(value or "")


def render(data: dict) -> str:
    return f"""# {data.get('title', 'Untitled finding')}

## Program
- Platform: {data.get('platform', '')}
- Program ID: {data.get('program_id', '')}
- Target: {data.get('target', '')}
- Vulnerability type: {data.get('vulnerability_type', '')}

## Summary
{data.get('summary', '')}

## Security impact
{data.get('impact', '')}

## Reproduction steps
{bullet_lines(data.get('reproduction_steps'))}

## Evidence
{bullet_lines(data.get('evidence'))}

## Scope proof
{data.get('scope_proof', '')}

## Safety notes
- Rules checked at: {data.get('rules_checked_at', '')}
- Destructive test used: {bool(data.get('destructive_test'))}
- Human verified: {bool(data.get('human_verified'))}
- Duplicate check complete: {bool(data.get('duplicate_check_complete'))}

## Suggested remediation
{data.get('remediation', '')}
"""


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: python bounty/render_report.py finding.json [report.md]")
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) == 3 else src.with_suffix(".md")
    data = json.loads(src.read_text(encoding="utf-8"))
    out.write_text(render(data), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
