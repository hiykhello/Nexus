#!/usr/bin/env python3
"""Check Nexus candidate client against the fixed sing-box server."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'tests'))
from quic_udp_network import credential

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('patched_test', type=Path)
parser.add_argument('--family', choices=('4', '6'), default='4')
parser.add_argument('--backend', choices=('0', '1'), default='0')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('hy2_test_peer', args.patched_test.resolve(strict=True))
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
version = subprocess.check_output(['sing-box', 'version'], text=True)
if f'Revision: {mod.REVISION}' not in version: raise RuntimeError('sing-box revision mismatch')
os.environ['NEXUS_TEST_BRUTAL'] = '500000'
with tempfile.TemporaryDirectory(prefix='nexus-hy2-brutal-peer-') as directory:
    temp = Path(directory)
    cert, key = credential(temp, 'p256', 'EC', ['-pkeyopt', 'ec_paramgen_curve:P-256'])
    subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', cert, '-out', temp / 'cert.pem'], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', key, '-out', temp / 'key.pem'], check=True, capture_output=True)
    result = mod.pair(args.binary.resolve(strict=True), temp, cert, key, '0x0403', 'client', args.family, args.backend, 65537)
    if 'BRUTAL role=client' not in result['stdout']: raise RuntimeError('controller was not installed')
    print(json.dumps(result, indent=2))
