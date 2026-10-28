"""Local TLS 1.3 integration against an independent OpenSSL s_server."""
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from interop_common import ROOT, CLIENT, ASYNC_CLIENT, VLESS_CLIENT
from vless_fixture_interop import vless_tls, vless_bad_response, vless_stalled_handshake
from vless_singbox_interop import vless_singbox

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def framed_https(directory, case, response, expected):
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
                    try:
                        conn.unwrap().close()
                    except (ssl.SSLError, OSError):
                        if expected == 0:
                            raise
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()
    thread = threading.Thread(target=server)
    thread.start()
    try:
        result = subprocess.run([ASYNC_CLIENT, str(listener.getsockname()[1]), directory / "root.pem", "x25519", "server.example", case],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if result.returncode != expected:
            raise RuntimeError(f"HTTPS {case} expected exit {expected}, got {result.returncode}: {result.stderr.decode(errors='replace')}")
    finally:
        thread.join(timeout=12)
    if thread.is_alive() or errors:
        raise RuntimeError(f"HTTPS {case} server failed: {errors}")
    print(f"HTTPS {case} framing passed")


def test(directory, group, mode, cipher, failure=None, identity="server", asynchronous=False, sni_test=False, ip_test=False, exchange_failure=None):
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    server = subprocess.Popen([
        "openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3",
        "-cert", str(directory / (("other" if sni_test else identity) + ".pem")),
        "-key", str(directory / (("other" if sni_test else identity) + ".key")),
        "-groups", group, "-ciphersuites", cipher, "-alpn", "http/1.1", "-num_tickets", "2", "-www", "-state",
        *(["-servername", "server.example", "-servername_fatal",
           "-cert2", str(directory / (("other" if ip_test else identity) + ".pem")),
           "-key2", str(directory / (("other" if ip_test else identity) + ".key"))] if sni_test or ip_test else []),
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                break
            except ConnectionRefusedError:
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("OpenSSL server failed to start")
                time.sleep(0.05)
        if asynchronous:
            sock.close()
            root = directory / ("other.pem" if failure == "untrusted" else "root.pem")
            name = ("127.0.0.2" if failure == "wrong" else "127.0.0.1") if ip_test else ("wrong.example" if failure == "wrong" else "server.example")
            extra = exchange_failure or ("sni-test" if sni_test else None)
            result = subprocess.run([ASYNC_CLIENT, str(port), root, mode, name, *([extra] if extra else [])],
                                    stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=20)
            if exchange_failure:
                expected = 10 if exchange_failure == "alpn-required" else 9
                if result.returncode != expected:
                    raise RuntimeError(f"HTTPS {exchange_failure} expected exit {expected}, got {result.returncode}: {result.stderr.decode(errors='replace')}")
                print(f"HTTPS {exchange_failure} rejected")
                return
            if failure:
                if result.returncode != 8:
                    raise RuntimeError(f"async {failure} expected handshake rejection, exit {result.returncode}: {result.stderr.decode(errors='replace')}")
                print(f"Corosio TLS {mode} {'IP ' if ip_test else ''}{failure} rejected")
                return
        else:
            with sock:
                sock.settimeout(None)
                root = directory / ("other.der" if failure == "untrusted" else "root.der")
                result = subprocess.run([CLIENT, mode, root, failure or "valid"], stdin=sock, stdout=sock,
                                        stderr=subprocess.PIPE, timeout=20)
        if result.returncode:
            server.terminate()
            _, server_errors = server.communicate(timeout=5)
            raise RuntimeError(f"{mode} client exited {result.returncode}: {result.stderr.decode(errors='replace')} server: {server_errors.decode(errors='replace')}")
        message = result.stdout if asynchronous else result.stderr
        print(f"OpenSSL {mode} {failure} rejected" if failure else message.decode().strip() + " " + cipher + (" IP identity " if ip_test else " SNI " if sni_test else " ALPN ") + identity)
    finally:
        server.terminate()
        try:
            server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate()


def main():
    with tempfile.TemporaryDirectory(prefix="nexus-tls-interop-") as tmp:
        p = Path(tmp)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(p / "root.key"),
            "-out", str(p / "root.pem"), "-days", "2", "-subj", "/CN=Nexus interop CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(p / "server.key"),
            "-out", str(p / "server.csr"), "-subj", "/CN=server.example")
        (p / "ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                               "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example,IP:127.0.0.1\n")
        run("openssl", "x509", "-req", "-in", str(p / "server.csr"), "-CA", str(p / "root.pem"),
            "-CAkey", str(p / "root.key"), "-set_serial", "2", "-days", "1", "-extfile", str(p / "ext"),
            "-out", str(p / "server.pem"))
        run("openssl", "x509", "-in", str(p / "root.pem"), "-outform", "DER", "-out", str(p / "root.der"))
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(p / "other.key"),
            "-out", str(p / "other.pem"), "-days", "2", "-subj", "/CN=Other CA", "-addext", "basicConstraints=critical,CA:TRUE")
        run("openssl", "x509", "-in", str(p / "other.pem"), "-outform", "DER", "-out", str(p / "other.der"))
        user = p / "user.uuid"
        user.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
        user.chmod(0o600)
        malformed = p / "malformed.uuid"
        malformed.write_text("not-a-uuid\n")
        malformed.chmod(0o600)
        public = p / "public.uuid"
        public.write_text(user.read_text())
        public.chmod(0o644)
        link = p / "link.uuid"
        link.symlink_to(user)
        for secret, ca in ((malformed, p / "root.pem"), (public, p / "root.pem"),
                           (link, p / "root.pem"), (user, p / "missing-ca.pem")):
            result = subprocess.run([VLESS_CLIENT, "1", ca, secret, "valid"], capture_output=True, timeout=5)
            if result.returncode != 3:
                raise RuntimeError(f"VLESS profile accepted invalid input: {secret}, {ca}, exit {result.returncode}")
        for cipher in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"):
            test(p, "X25519", "x25519", cipher)
            test(p, "X25519MLKEM768", "hybrid", cipher)
            test(p, "X25519", "x25519-retry", cipher)
            test(p, "X25519MLKEM768", "hybrid-retry", cipher)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", asynchronous=True)
        test(p, "X25519MLKEM768", "hybrid", "TLS_AES_256_GCM_SHA384", asynchronous=True)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", asynchronous=True, sni_test=True)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", failure="wrong", asynchronous=True, sni_test=True)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", failure="untrusted", asynchronous=True, sni_test=True)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", asynchronous=True, ip_test=True)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", failure="wrong", asynchronous=True, ip_test=True)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", asynchronous=True, sni_test=True, exchange_failure="alpn-required")
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", asynchronous=True, exchange_failure="reject-output")
        framed_https(p, "fixed", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 0)
        framed_https(p, "chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-T: z\r\n\r\n", 0)
        framed_https(p, "empty", b"HTTP/1.1 204 No Content\r\n\r\n", 0)
        framed_https(p, "truncated", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab", 11)
        framed_https(p, "malformed", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naX", 12)
        vless_tls(p)
        vless_tls(p, invalid=True)
        vless_tls(p, relay=True)
        vless_tls(p, cancel=True)
        vless_bad_response(p)
        vless_bad_response(p, truncated=True)
        vless_bad_response(p, close_delimited=True)
        vless_bad_response(p, close_delimited=True, clean=True)
        vless_stalled_handshake(p)
        vless_stalled_handshake(p, expire=True)
        if "--sing-box" in sys.argv[1:]:
            vless_singbox(p)
        for identity, keyargs in (("ecdsa", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]), ("ed25519", ["ed25519"])):
            run("openssl", "genpkey", "-algorithm", *keyargs, "-out", str(p / (identity + ".key")))
            run("openssl", "req", "-new", "-key", str(p / (identity + ".key")), "-out", str(p / (identity + ".csr")), "-subj", "/CN=server.example")
            run("openssl", "x509", "-req", "-in", str(p / (identity + ".csr")), "-CA", str(p / "root.pem"), "-CAkey", str(p / "root.key"),
                "-set_serial", "3", "-days", "1", "-extfile", str(p / "ext"), "-out", str(p / (identity + ".pem")))
            run("openssl", "x509", "-in", str(p / (identity + ".pem")), "-outform", "DER", "-out", str(p / (identity + ".der")))
            (p / "sign-input").write_bytes(b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + bytes([0x42]) * 32)
            if identity == "ecdsa":
                run("openssl", "dgst", "-sha256", "-sign", str(p / (identity + ".key")), "-out", str(p / "signature"), str(p / "sign-input"))
            else:
                run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(p / (identity + ".key")), "-in", str(p / "sign-input"), "-out", str(p / "signature"))
            subprocess.run([ROOT / "build/linux/x86_64/debug/nexus-tls-signature-interop-test", p / (identity + ".der"), p / "signature", identity], check=True)
            test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", identity=identity)
            test(p, "X25519MLKEM768", "hybrid", "TLS_AES_256_GCM_SHA384", identity=identity)
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", failure="wrong")
        test(p, "X25519", "x25519", "TLS_AES_128_GCM_SHA256", failure="untrusted")


if __name__ == "__main__":
    if any(arg != "--sing-box" for arg in sys.argv[1:]):
        raise SystemExit("usage: tls_openssl_interop.py [--sing-box]")
    main()
