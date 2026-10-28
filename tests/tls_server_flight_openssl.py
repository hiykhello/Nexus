#!/usr/bin/env python3
"""Authenticate Nexus TLS 1.3 server flights and exercise client Finished rejection."""
import pathlib
import socket
import subprocess
import sys
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()
def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)

with tempfile.TemporaryDirectory(prefix="nexus-server-flight-") as directory:
    root = pathlib.Path(directory)
    for algorithm, options, suite in [("RSA", ["-pkeyopt", "rsa_keygen_bits:2048"], "TLS_AES_128_GCM_SHA256"),
                                      ("EC", ["-pkeyopt", "ec_paramgen_curve:P-256"], "TLS_AES_256_GCM_SHA384"),
                                      ("ED25519", [], "TLS_CHACHA20_POLY1305_SHA256")]:
        key = root / "key.pem"; key_der = root / "key.der"; cert = root / "cert.pem"; cert_der = root / "cert.der"
        run("openssl", "genpkey", "-algorithm", algorithm, *options, "-out", str(key))
        run("openssl", "req", "-x509", "-new", "-key", str(key), "-out", str(cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost", "-days", "1")
        run("openssl", "pkey", "-in", str(key), "-outform", "DER", "-out", str(key_der))
        run("openssl", "x509", "-in", str(cert), "-outform", "DER", "-out", str(cert_der))
        run(str(fixture), str(cert_der), str(key_der), "bad-finished")
        for corrupt in ([False, True] if algorithm == "RSA" else [False]):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0)); listener.listen(1)
                args = [fixture, cert_der, key_der, str(listener.fileno())] + (["corrupt"] if corrupt else [])
                server = subprocess.Popen(args, pass_fds=(listener.fileno(),))
                try:
                    result = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{listener.getsockname()[1]}",
                                             "-tls1_3", "-groups", "X25519", "-ciphersuites", suite, "-servername", "localhost",
                                             "-verify_hostname", "localhost", "-verify_return_error", "-CAfile", str(cert), "-quiet"],
                                            input=b"hello", capture_output=True, timeout=8)
                    code = server.wait(timeout=5)
                    if code or (not corrupt and (result.returncode or result.stdout != b"hello")) or (corrupt and result.returncode == 0):
                        raise RuntimeError(f"server={code} openssl={result.returncode} output={result.stdout!r} error={result.stderr!r}")
                    print(f"{algorithm} {suite}: {'corrupt Finished rejected' if corrupt else 'authenticated TLS data exchange passed'}")
                finally:
                    if server.poll() is None:
                        server.kill(); server.wait()
