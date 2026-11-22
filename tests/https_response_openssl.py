#!/usr/bin/env python3
"""Exercise HTTPS response framing against an independent TLS peer."""
import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


def framed_https(client, directory, case, response, expected, clean=True):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / "server.pem", directory / "server.key")
    context.set_alpn_protocols(["http/1.1"])
    context.set_ecdh_curve("X25519")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    errors = []

    def server():
        try:
            with listener.accept()[0] as raw:
                raw.settimeout(10)
                with context.wrap_socket(raw, server_side=True) as conn:
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        block = conn.recv(4096)
                        if not block or len(request) + len(block) > 30000:
                            raise RuntimeError("incomplete HTTPS request")
                        request += block
                    for offset in range(0, len(response), 7):
                        conn.sendall(response[offset:offset + 7])
                    if clean:
                        try:
                            conn.unwrap().close()
                        except (ssl.SSLError, OSError):
                            if expected == 0:
                                raise
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()

    port = listener.getsockname()[1]
    thread = threading.Thread(target=server)
    thread.start()
    try:
        command = [client, str(port), directory / "root.pem", "x25519"]
        if case is not None:
            command += ["server.example", case]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if result.returncode != expected:
            raise RuntimeError(f"HTTPS {case} expected exit {expected}, got {result.returncode}: {result.stderr.decode(errors='replace')}")
    finally:
        thread.join(timeout=12)
    if thread.is_alive() or errors:
        raise RuntimeError(f"HTTPS {case} server failed: {errors}")
    print(f"HTTPS {case or 'close-delimited'}{' without close_notify' if not clean else ''} framing passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", type=Path)
    client = parser.parse_args().client.resolve()
    with tempfile.TemporaryDirectory(prefix="nexus-https-response-") as directory:
        root = Path(directory)
        def openssl(*args):
            subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "root.key"),
                "-out", str(root / "root.pem"), "-days", "2", "-subj", "/CN=Nexus interop CA",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "server.key"),
                "-out", str(root / "server.csr"), "-subj", "/CN=server.example")
        (root / "ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                  "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n")
        openssl("x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "root.pem"),
                "-CAkey", str(root / "root.key"), "-set_serial", "2", "-days", "1",
                "-extfile", str(root / "ext"), "-out", str(root / "server.pem"))
        framed_https(client, root, "fixed", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 0)
        framed_https(client, root, "chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-T: z\r\n\r\n", 0)
        framed_https(client, root, "empty", b"HTTP/1.1 204 No Content\r\n\r\n", 0)
        framed_https(client, root, "truncated", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab", 11)
        framed_https(client, root, "malformed", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naX", 12)
        framed_https(client, root, None, b"HTTP/1.0 200 ok\r\n\r\nhello", 0)
        # An unclean TCP close is surfaced as a TLS transport failure by this
        # fixture; it must never complete a close-delimited response.
        framed_https(client, root, None, b"HTTP/1.0 200 ok\r\n\r\nhello", 7, clean=False)


if __name__ == "__main__":
    main()
