"""Exercise VLESS profile replacement with a pending TLS connection."""
import pathlib
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="nexus-vless-reconfigure-") as directory:
    root = pathlib.Path(directory)
    key, cert = root / "key.pem", root / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1"],
                   check=True, capture_output=True, timeout=10)
    key.chmod(0o600)
    uuid = root / "uuid"
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
    uuid.chmod(0o600)
    subprocess.run([binary, cert, key, uuid], check=True, timeout=10)
