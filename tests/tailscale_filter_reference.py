#!/usr/bin/env python3
"""Compare a policy fixture to an independently built pinned Go oracle."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('oracle', type=Path)
    args = parser.parse_args()
    actual = subprocess.check_output([str(args.fixture.resolve(strict=True)), '--reference'], text=True)
    expected = subprocess.check_output([str(args.oracle.resolve(strict=True))], text=True)
    if actual != expected:
        raise SystemExit(f'packet-filter differential mismatch\nNexus:\n{actual}Go:\n{expected}')
    print(f'{len(actual.splitlines())} ordered updates match pinned Tailscale rule conversion')


if __name__ == '__main__':
    main()
