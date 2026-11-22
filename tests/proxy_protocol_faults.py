#!/usr/bin/env python3
"""Drive proxy lifecycle fixtures that need temporary VLESS credentials."""

import argparse
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vless-accept", type=Path)
    parser.add_argument("--vless-abandon", type=Path)
    parser.add_argument("--vless-reconfigure", type=Path)
    parser.add_argument("--tunnel-abandon", type=Path)
    parser.add_argument("--detour-factory", type=Path)
    args = parser.parse_args()
    if not any(vars(args).values()):
        parser.error("supply at least one fixture")

    with tempfile.TemporaryDirectory(prefix="nexus-proxy-faults-") as directory:
        root = Path(directory)
        cert, key, user = root / "cert.pem", root / "key.pem", root / "user.uuid"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        user.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
        user.chmod(0o600)
        credentials = [str(cert), str(key), str(user)]
        for fixture in (args.vless_accept, args.vless_abandon, args.vless_reconfigure):
            if fixture:
                subprocess.run([str(fixture.resolve()), *credentials], check=True, timeout=15)
        if args.tunnel_abandon:
            fixture = str(args.tunnel_abandon.resolve())
            subprocess.run([fixture], check=True, timeout=15)
            subprocess.run([fixture, *credentials], check=True, timeout=15)
        if args.detour_factory:
            subprocess.run([str(args.detour_factory.resolve()), str(user), str(cert)], check=True, timeout=15)


if __name__ == "__main__":
    main()
