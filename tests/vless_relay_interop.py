"""Exercise VLESS relay EOF, cancellation and rejection with a local TLS peer."""
import pathlib
import subprocess
import tempfile

from vless_fixture_interop import vless_tls


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


with tempfile.TemporaryDirectory(prefix="nexus-vless-relay-") as directory:
    root = pathlib.Path(directory)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "root.key",
        "-out", root / "root.pem", "-days", "2", "-subj", "/CN=Nexus relay CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "server.key",
        "-out", root / "server.csr", "-subj", "/CN=server.example")
    (root / "ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n")
    run("openssl", "x509", "-req", "-in", root / "server.csr", "-CA", root / "root.pem",
        "-CAkey", root / "root.key", "-set_serial", "2", "-days", "1", "-extfile", root / "ext",
        "-out", root / "server.pem")
    user = root / "user.uuid"
    user.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
    user.chmod(0o600)
    vless_tls(root, relay=True)
    vless_tls(root, cancel=True)
    vless_tls(root, invalid=True)
