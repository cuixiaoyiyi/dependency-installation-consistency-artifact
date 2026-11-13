"""Retriage saved cases into a new directory, preserving all source evidence.

Usage: python scripts/retriage.py --results-dir results/projects --out work/retriage-new
All saved cases are considered; --all remains an accepted compatibility flag.
"""
from __future__ import annotations
import argparse
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results-dir', default=str(ROOT / 'results' / 'projects'))
    parser.add_argument('--out', help='New output directory; defaults to a new work/experiments run')
    parser.add_argument('--project')
    parser.add_argument('--max-mb', type=int, default=400)
    parser.add_argument('--all', action='store_true', help='Compatibility flag; all saved cases are considered')
    parser.add_argument('--no-content', action='store_true')
    parser.add_argument('--minimize', action='store_true')
    parser.add_argument('--max-probes', type=int, default=12)
    parser.add_argument('--max-per-project', type=int, default=0)
    parser.add_argument('--include-consequential', action='store_true')
    args = parser.parse_args(argv)
    if args.max_mb <= 0:
        parser.error('--max-mb must be positive')
    os.environ['DRC_TRIAGE_MAX_MB'] = str(args.max_mb)
    from drc import triage
    triage.MAX_DOWNLOAD = args.max_mb * 1024 * 1024
    from drc.cli import cmd_post
    args.force = False
    return cmd_post(args)


if __name__ == '__main__':
    main()