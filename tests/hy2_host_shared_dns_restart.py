#!/usr/bin/env python3
"""Run production Hy2 host restart and bind-failure checks with real credentials."""
import argparse
from pathlib import Path
import subprocess
import tempfile
from udp_bind_port_network import certificate

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('fixture', type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='hy2-host-restart-') as directory:
    root = Path(directory); certificate(root)
    subprocess.run([str(args.fixture.resolve(strict=True)), str(root / 'cert'), str(root / 'key')], check=True, timeout=20)
