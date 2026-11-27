#!/usr/bin/env python3
"""Exercise configured VLESS TLS certificate chain limits and record fragmentation."""
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time

nexus = pathlib.Path(sys.argv[1]).resolve()

with tempfile.TemporaryDirectory(prefix="nexus-chain-limits-") as directory:
    root = pathlib.Path(directory)
    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=15)

    ca, ca_key = root / "ca.pem", root / "ca.key"
    key, csr, cert = root / "server.key", root / "server.csr", root / "server.pem"
    issuer_key, issuer_csr = root / "issuer.key", root / "issuer.csr"
    issuer_ext, leaf_ext = root / "issuer.ext", root / "leaf.ext"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca,
            "-subj", "/CN=Test Root", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", issuer_key, "-out", issuer_csr,
            "-subj", "/CN=Test Intermediate")
    issuer_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                          + "1.2.3.4=ASN1:UTF8String:" + "x" * 1000 + "\n")
    issuers = []
    for number in range(1, 17):
        issuer = root / f"issuer-{number}.pem"
        openssl("x509", "-req", "-in", issuer_csr, "-CA", ca, "-CAkey", ca_key,
                "-set_serial", number, "-out", issuer, "-days", "1", "-extfile", issuer_ext)
        issuers.append(issuer.read_text())
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr,
            "-subj", "/CN=localhost")
    leaf_ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    openssl("x509", "-req", "-in", csr, "-CA", root / "issuer-1.pem", "-CAkey", issuer_key,
            "-set_serial", 100, "-out", cert, "-days", "1", "-extfile", leaf_ext)
    key.chmod(0o600)
    uuid = root / "uuid"
    uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
    uuid.chmod(0o600)
    chain = root / "chain.pem"
    chain.write_text(cert.read_text() + "".join(issuers[:15]))
    if len(ssl.PEM_cert_to_DER_cert(cert.read_text())) + sum(len(ssl.PEM_cert_to_DER_cert(i)) for i in issuers[:15]) <= 16384:
        raise RuntimeError("fixture does not span multiple TLS records")
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    config = root / "server.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbounds {{ vless "edge" {{ listen host="127.0.0.1" port={port}; authentication {{ user "client" uuid-file="{uuid}"; }}; tls {{ certificate-file "{chain}"; private-key-file "{key}"; }}; }} }}
outbounds {{ direct "direct"; }}
routing {{ final "direct"; }}
''')
    server = subprocess.Popen([nexus, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if server.poll() is not None:
                raise RuntimeError(server.stderr.read().decode())
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        context = ssl.create_default_context(cafile=str(ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with raw, context.wrap_socket(raw, server_hostname="localhost") as peer:
            if peer.version() != "TLSv1.3":
                raise RuntimeError("unexpected TLS version")
            if len(peer._sslobj.get_unverified_chain()) != 16:
                raise RuntimeError("server did not send all 16 certificates")
        chain.write_text(cert.read_text() + "".join(issuers))
        rejected = subprocess.run([nexus, "run", "--config", config], capture_output=True, timeout=5)
        if rejected.returncode == 0:
            raise RuntimeError("17 certificates unexpectedly accepted")
        if b"invalid or mismatched TLS credential" not in rejected.stderr:
            raise RuntimeError(f"unexpected rejection: {rejected.stderr.decode()}")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
    if server.returncode != 0:
        raise RuntimeError(f"server did not stop cleanly: {server.returncode}")
    print("16-certificate fragmented TLS flight accepted; 17 certificates rejected")
