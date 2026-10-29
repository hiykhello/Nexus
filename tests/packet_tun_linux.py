"""Test TUN ownership in a disposable user and network namespace."""
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1]).resolve()
subprocess.run(['unshare', '-Urn', str(binary)], check=True, timeout=15)
