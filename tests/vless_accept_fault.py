#!/usr/bin/env python3
"""Exercise VLESS profile ownership after an accept task launch failure."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    fixture = parser.parse_args().fixture.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-vless-accept-") as directory:
        root = Path(directory)
        def openssl(*args):
            subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key.pem",
                "-out", root / "cert.pem", "-subj", "/CN=localhost", "-days", "1")
        openssl("pkey", "-in", root / "key.pem", "-outform", "DER", "-out", root / "key.der")
        openssl("x509", "-in", root / "cert.pem", "-outform", "DER", "-out", root / "cert.der")
        (root / "key.der").chmod(0o600)
        (root / "uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
        (root / "uuid").chmod(0o600)
        subprocess.run([fixture, root / "cert.der", root / "key.der", root / "uuid"], check=True, timeout=15)


if __name__ == "__main__":
    main()
