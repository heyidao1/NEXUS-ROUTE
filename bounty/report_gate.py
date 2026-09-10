import json
import sys
from pathlib import Path

REQUIRED = [
    'program_id',
    'target',
    'title',
    'vulnerability_type',
    'impact',
    'reproduction_steps',
    'evidence',
    'scope_proof',
    'rules_checked_at',
]


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: python bounty/report_gate.py finding.json')
    data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    missing = [k for k in REQUIRED if not data.get(k)]
    if missing:
        raise SystemExit('BLOCKED: missing fields: ' + ', '.join(missing))
    if data.get('destructive_test'):
        raise SystemExit('BLOCKED: destructive testing is not allowed')
    if not data.get('human_verified'):
        raise SystemExit('BLOCKED: human verification required before submission')
    if not data.get('duplicate_check_complete'):
        raise SystemExit('BLOCKED: duplicate check required before submission')
    print('READY_FOR_MANUAL_SUBMISSION')


if __name__ == '__main__':
    main()
