#!/usr/bin/env python3
"""Real IPv4/IPv6 UDP requests against pinned official Tailscale STUN package."""
import argparse
import pathlib
import select
import subprocess

from tailscale_reference import COMMIT, VERSION, reference_binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    args = parser.parse_args()
    reference = reference_binary()
    for family in (4, 6):
        server = subprocess.Popen([reference, "server", str(family)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if not select.select([server.stdout], [], [], 8)[0]:
                raise RuntimeError(f"official STUN server did not start, family={family}")
            line = server.stdout.readline().strip()
            if not line.isdigit():
                raise RuntimeError(f"invalid official STUN port: {line!r}")
            checked = subprocess.run([args.fixture.resolve(), str(family), line.decode()], capture_output=True, timeout=12)
            if checked.returncode or checked.stdout.strip() != b"stun-network-passed":
                raise RuntimeError(f"Nexus STUN family={family}: {checked.returncode}, {checked.stdout!r}, {checked.stderr!r}")
            stdout, stderr = server.communicate(timeout=5)
            if server.returncode or stdout.strip() != b"stun-complete:4":
                raise RuntimeError(f"official STUN server family={family}: {server.returncode}, {stdout!r}, {stderr!r}")
            print(f"STUN actual UDP family={family}, 4 unique transactions, official {VERSION} ({COMMIT}) passed", flush=True)
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=3)


if __name__ == "__main__":
    main()

