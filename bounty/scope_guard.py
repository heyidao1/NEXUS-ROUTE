import argparse
from pathlib import Path
import yaml


def load_program(program_id: str):
    cfg = yaml.safe_load(Path(__file__).with_name('programs.yml').read_text(encoding='utf-8'))
    for item in cfg.get('programs', []):
        if item.get('id') == program_id:
            return item
    raise SystemExit(f'Unknown program: {program_id}')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--program', required=True)
    p.add_argument('--target', required=True)
    args = p.parse_args()

    program = load_program(args.program)
    included = set(program.get('scope', {}).get('include', []))
    excluded = set(program.get('scope', {}).get('exclude', []))

    if not program.get('rules_url') or 'REPLACE_WITH_' in str(program.get('rules_url')):
        raise SystemExit('BLOCKED: official rules URL not configured')
    if not program.get('last_verified'):
        raise SystemExit('BLOCKED: program scope has not been verified')
    if args.target in excluded:
        raise SystemExit('BLOCKED: target is explicitly excluded')
    if args.target not in included:
        raise SystemExit('BLOCKED: target is not explicitly in scope')

    mode = 'active validation permitted' if program.get('automation_allowed') else 'passive-only / manual validation required'
    print(f'OK: {args.target} is explicitly in scope; mode={mode}')


if __name__ == '__main__':
    main()
