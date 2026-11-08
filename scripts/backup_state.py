#!/usr/bin/env python3
"""Local-only backup, verification, restore and reconciliation of the SQLite state database.

Recovers *state* (runs, receipts, events, quotas, usage); it does not recover a VM or containers.
Works on local files only (URLs and UNC paths are refused), never reads .env or credentials, never
overwrites an existing file, and a restored database stays blocked for new runs until
`reconcile` is given counters that are not below the copy's. There is no command that simply
deletes the block. Backups are private operational copies: do not publish them.

  backup_state.py backup    --db LIVE.sqlite --out COPY.sqlite [--manifest M.json]
  backup_state.py verify    --backup COPY.sqlite [--manifest M.json] [--rpo-seconds N]
  backup_state.py restore   --backup COPY.sqlite --to NEW.sqlite [--manifest M.json]
  backup_state.py status    --db DB.sqlite
  backup_state.py counters  --db DB.sqlite
  backup_state.py reconcile --db RESTORED.sqlite --block-id ID --evidence TEXT
                            (--current-db OTHER.sqlite | --runs N --calls N --output-tokens N)

Every command prints one JSON document; exit status 0 on success, 2 on a refused operation.
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent import recovery  # noqa: E402


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    backup = commands.add_parser('backup')
    backup.add_argument('--db', required=True)
    backup.add_argument('--out', required=True)
    backup.add_argument('--manifest')
    verify = commands.add_parser('verify')
    verify.add_argument('--backup', required=True)
    verify.add_argument('--manifest')
    verify.add_argument('--rpo-seconds', type=float)
    restore = commands.add_parser('restore')
    restore.add_argument('--backup', required=True)
    restore.add_argument('--to', required=True)
    restore.add_argument('--manifest')
    for name in ('status', 'counters'):
        commands.add_parser(name).add_argument('--db', required=True)
    reconcile = commands.add_parser('reconcile')
    reconcile.add_argument('--db', required=True)
    reconcile.add_argument('--block-id', required=True)
    reconcile.add_argument('--evidence', required=True)
    reconcile.add_argument('--current-db')
    reconcile.add_argument('--runs', type=int)
    reconcile.add_argument('--calls', type=int)
    reconcile.add_argument('--output-tokens', type=int)
    return parser


def run(args):
    if args.command == 'backup':
        return recovery.backup_database(args.db, args.out, args.manifest)
    if args.command == 'verify':
        return recovery.verify_backup(args.backup, args.manifest, args.rpo_seconds)
    if args.command == 'restore':
        return recovery.restore_database(args.backup, args.to, args.manifest)
    if args.command == 'status':
        return recovery.database_status(args.db)
    if args.command == 'counters':
        return recovery.counters_of_database(args.db)
    explicit = (args.runs, args.calls, args.output_tokens)
    if args.current_db:
        if any(value is not None for value in explicit):
            raise recovery.RecoveryError('Use --current-db or explicit counters, not both')
        if Path(args.current_db).resolve() == Path(args.db).resolve():
            raise recovery.RecoveryError('--current-db must be a different database than the one being reconciled')
        counters = recovery.counters_of_database(args.current_db)
    elif all(value is not None for value in explicit):
        counters = {'runs': args.runs, 'calls': args.calls, 'output_tokens_reserved': args.output_tokens}
    else:
        raise recovery.RecoveryError('Give --current-db or all of --runs, --calls and --output-tokens')
    return recovery.reconcile_restored(args.db, args.block_id, counters, args.evidence)


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except recovery.RecoveryError as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, sort_keys=True))
        return 2
    except (sqlite3.Error, OSError) as exc:
        # Message only: never echo paths or database content beyond the exception class.
        print(json.dumps({'ok': False, 'error': 'Operation refused: ' + type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(result if isinstance(result, dict) and 'ok' in result else {'ok': True, **result}, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
