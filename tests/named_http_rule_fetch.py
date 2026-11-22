#!/usr/bin/env python3
"""Verify named DNS, physical egress, TLS and atomic rule publication."""
from pathlib import Path
import hashlib
import os
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, free_port
from ordered_tcp_network import headers
from udp_bind_port_network import certificate


RULES = b'schema-version 2\nkind "predicate"\nrule type="domain" value="fresh.test"\n'


class Origin:
    def __init__(self, root, tls12=False):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        if tls12:
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.context.maximum_version = ssl.TLSVersion.TLSv1_2
            self.context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.load_cert_chain(root / "cert", root / "key")
        self.seen, self.names, self.errors = [], [], []
        self.context.set_servername_callback(lambda _, name, __: self.names.append(name))
        self.stopping = threading.Event()
        self.release = threading.Event()
        self.refreshes = 0
        self.conditional_status = []
        self.alternative_port = None
        self.thread = threading.Thread(target=self.serve)

    def serve(self):
        while not self.stopping.is_set():
            try:
                raw, source = self.socket.accept()
            except TimeoutError:
                continue
            try:
                with raw:
                    raw.settimeout(2)
                    with self.context.wrap_socket(raw, server_side=True) as peer:
                        request = headers(peer)
                        method, target, version = request.split(b"\r\n", 1)[0].split(b" ")
                        self.seen.append((source[0], method, target, version))
                        if target == b"/persistent-redirect":
                            peer.sendall(b"HTTP/1.1 302 Found\r\nLocation: /persistent-final\r\nContent-Length: 0\r\n\r\n")
                            request = headers(peer)
                            if not request.startswith(b"GET /persistent-final HTTP/1.1\r\n"):
                                raise RuntimeError("redirect did not reuse the authenticated TLS stream")
                            if b"\r\nx-nexus-test: custom value\r\n" not in request:
                                raise RuntimeError("redirect lost the configured header")
                            self.seen.append((source[0], method, b"/persistent-final", version))
                            peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(RULES)}\r\nConnection: close\r\n\r\n".encode() + RULES)
                        elif target == b"/start/redirect":
                            peer.sendall(b"HTTP/1.1 302 Found\r\nLocation: ../with-header#ignored\r\nContent-Length: 0\r\n\r\n")
                        elif target == b"/cross-origin":
                            peer.sendall(f"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:{self.port}/with-header\r\nContent-Length: 0\r\n\r\n".encode())
                        elif target == b"/redirect-loop":
                            peer.sendall(b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /redirect-loop\r\nContent-Length: 0\r\n\r\n")
                        elif target == b"/conditional-start":
                            if b"\r\nif-none-match: " in request:
                                peer.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                            else:
                                peer.sendall(b"HTTP/1.1 303 See Other\r\nLocation: /conditional\r\nContent-Length: 0\r\n\r\n")
                        elif target == b"/conditional":
                            if b'\r\nif-none-match: W/"rules-1"\r\n' in request:
                                self.conditional_status.append(304)
                                peer.sendall(b'HTTP/1.1 304 Not Modified\r\nETag: "rules-1"\r\nContent-Length: 32768\r\n\r\n')
                            else:
                                self.conditional_status.append(200)
                                peer.sendall(f'HTTP/1.1 200 OK\r\nETag: W/"rules-1"\r\nContent-Length: {len(RULES)}\r\n\r\n'.encode() + RULES)
                        elif target == b"/with-header":
                            if b"\r\nx-nexus-test: custom value\r\n" not in request:
                                peer.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                            else:
                                peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(RULES)}\r\n\r\n".encode() + RULES)
                        elif target == b"/changing":
                            self.refreshes += 1
                            data = RULES.replace(b"fresh", b"wrong") if self.refreshes == 1 else RULES
                            if self.refreshes >= 3:
                                self.release.wait(4)
                            peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(data)}\r\n\r\n".encode() + data)
                        elif target in (b"/chunked", b"/bad-trailer", b"/chunk-limit", b"/chunk-truncated"):
                            data = bytes(600) if target == b"/chunk-limit" else RULES
                            peer.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                            for chunk in (data[:17], data[17:]):
                                peer.sendall(f"{len(chunk):x};example=yes\r\n".encode())
                                peer.sendall(chunk)
                                peer.sendall(b"\r\n")
                            trailer = b"Content-Length: 0" if target == b"/bad-trailer" else b"X-Complete: yes"
                            if target != b"/chunk-truncated":
                                peer.sendall(b"0\r\n" + trailer + b"\r\n\r\n")
                        elif target in (b"/close", b"/raw-eof"):
                            peer.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + RULES)
                            if target == b"/raw-eof":
                                os.close(peer.detach())
                                continue
                        else:
                            data, length = {
                                b"/rules": (RULES, len(RULES)),
                                b"/truncated": (RULES, len(RULES)+9),
                                b"/invalid": (b"invalid", 7),
                                b"/large": (bytes(600), 600),
                                b"/slow": (RULES, len(RULES)),
                                b"/encoded": (RULES, len(RULES)),
                            }[target]
                            if target == b"/slow":
                                time.sleep(.8)
                            encoding = b"Content-Encoding: gzip\r\n" if target == b"/encoded" else b""
                            alternative = (f'Alt-Svc: h3=":{self.alternative_port}"; ma=60\r\n'.encode()
                                           if target == b"/rules" and self.alternative_port else b"")
                            peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n".encode() +
                                         encoding + alternative + b"Connection: close\r\n\r\n" + data)
                        peer.unwrap()
            except (ssl.SSLError, OSError):
                pass
            except Exception as exc:
                self.errors.append(exc)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stopping.set()
        self.release.set()
        self.thread.join(3)
        self.socket.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f"HTTPS fixture cleanup: {self.errors!r}")


def conditional_peer_event(peer):
    if not select.select([peer.stdout], [], [], 4)[0]:
        raise RuntimeError("no conditional request reached the peer")
    prefix, code = peer.stdout.readline().split()
    if prefix != b"conditional":
        raise RuntimeError(f"unexpected peer output: {prefix!r} {code!r}")
    return int(code)


def watch_conditional(binary, config, output, port, rules, status, target="/conditional"):
    def wait_for_output():
        deadline = time.monotonic() + 4
        while not output.exists() or output.read_bytes() != rules:
            if time.monotonic() >= deadline:
                raise RuntimeError("watcher did not publish the complete response")
            time.sleep(.01)

    output.unlink(missing_ok=True)
    args = [binary, "rule", "watch", "180", config, "updates",
            f"https://localhost:{port}{target}", "kdl", output]
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
        try:
            if status() != 200:
                raise RuntimeError("first watch request must fetch a complete response")
            wait_for_output()
            before = output.stat()
            if status() != 304 or status() != 304:
                raise RuntimeError("watcher did not keep and send the accepted ETag")
            after = output.stat()
            if (before.st_ino, before.st_mtime_ns) != (after.st_ino, after.st_mtime_ns):
                raise RuntimeError("304 republished the existing rule file")
            output.unlink()
            for _ in range(4):
                if status() == 200:
                    break
            else:
                raise RuntimeError("watcher did not refetch a missing file")
            wait_for_output()
        finally:
            if watcher.poll() is None:
                watcher.terminate()
            _, warnings = watcher.communicate(timeout=3)
            if watcher.returncode:
                raise RuntimeError(f"watcher failed to stop: {warnings!r}")


def main(binary):
    with tempfile.TemporaryDirectory() as folder, DnsPeer() as fallback, DnsPeer() as selected:
        root = Path(folder)
        certificate(root)
        wrong = root / "untrusted"
        wrong.mkdir()
        certificate(wrong)
        output = root / "published.kdl"
        output.write_bytes(b"prior version")
        cfg = root / "nexus.kdl"
        front = free_port()

        def configure(ca, resolver="selected", outbound="physical", protocol="http/1.1"):
            cfg.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; }}
dns {{
  server "fallback" type="udp" host="127.0.0.1" port={fallback.port}
  server "selected" type="udp" host="127.0.0.1" port={selected.port}
  final "fallback"
  strategy "ipv4_only"
}}
http-clients {{
  updates {{
    outbound "{outbound}"
    domain-resolver "{resolver}"
    ca-file "{ca}"
    protocol "{protocol}"
    timeout-ms 550
    max-response-bytes 512
  }}
}}
routing {{ default-outbound "physical"; }}
''')

        configure(root / "cert")
        with Origin(root) as origin:
            def fetch(path, *options):
                return subprocess.run([binary, "rule", "fetch", cfg, "updates",
                                       f"https://localhost:{origin.port}{path}", "kdl", output, *options],
                                      capture_output=True, text=True, timeout=4)

            good = fetch("/rules")
            if good.returncode or output.read_bytes() != RULES:
                raise RuntimeError(f"valid rules were not published: {good.stderr}")
            if fallback.seen or not selected.seen or origin.seen != [("127.0.0.2", b"GET", b"/rules", b"HTTP/1.1")] or origin.names != ["localhost"]:
                raise RuntimeError(f"wrong resolver, egress or SNI: {fallback.seen}, {selected.seen}, {origin.seen}, {origin.names}")
            original = cfg.read_text()
            marker = "    max-response-bytes 512"
            for bad in ('header "HOST" "other.test"', 'header "x-test" "one"; header "X-Test" "two"',
                        'header "x-test" "bad\\r\\n"'):
                cfg.write_text(original.replace(marker, marker + "\n    " + bad))
                count = len(selected.seen)
                rejected = fetch("/with-header")
                if not rejected.returncode or "request header" not in rejected.stderr or len(selected.seen) != count:
                    raise RuntimeError(f"invalid request header reached DNS: {rejected.stderr}")
            cfg.write_text(original.replace(marker, marker + '\n    header "X-Nexus-Test" "custom value"'))
            good = fetch("/with-header")
            if good.returncode or output.read_bytes() != RULES:
                raise RuntimeError(f"configured HTTP/1.1 request header missing: {good.stderr}")
            if not fetch("/start/redirect").returncode:
                raise RuntimeError("default HTTP client followed a redirect")
            with_redirect = cfg.read_text().replace(marker, marker + "\n    max-redirects 2")
            cfg.write_text(with_redirect)
            success = fetch("/start/redirect")
            if success.returncode or origin.seen[-1][2] != b"/with-header":
                raise RuntimeError(f"same-origin relative redirect failed: {success.stderr}")
            before = len(origin.names)
            success = fetch("/persistent-redirect")
            if (success.returncode or len(origin.names) != before + 1 or
                    [item[2] for item in origin.seen[-2:]] != [b"/persistent-redirect", b"/persistent-final"]):
                raise RuntimeError(f"HTTP/1.1 redirect did not reuse its TLS connection: {success.stderr}")
            for path in ("/cross-origin", "/redirect-loop"):
                count = len(origin.seen)
                rejected = fetch(path)
                if not rejected.returncode or "invalid, cross-origin or repeated" not in rejected.stderr or len(origin.seen) != count + 1:
                    raise RuntimeError(f"unsafe redirect continued: {rejected.stderr}")
            cfg.write_text(original)
            for path in ("/chunked", "/close"):
                output.write_bytes(b"old rules")
                good = fetch(path, "--sha256", hashlib.sha256(RULES).hexdigest())
                if good.returncode or output.read_bytes() != RULES:
                    raise RuntimeError(f"{path} did not decode and publish valid rules: {good.stderr}")
            configure(root / "cert", protocol="auto")
            if fetch("/rules").returncode:
                raise RuntimeError("auto did not negotiate HTTP/1.1")
            previous = len(origin.seen)
            previous_dns = list(selected.seen)
            result = fetch("/rules", "--sha256", "x" * 64)
            if result.returncode != 2 or len(origin.seen) != previous or selected.seen != previous_dns:
                raise RuntimeError("invalid SHA-256 did not fail before I/O")
            result = fetch("/rules", "--sha256", "0" * 64)
            if not result.returncode or "does not match" not in result.stderr or output.read_bytes() != RULES:
                raise RuntimeError("mismatched SHA-256 replaced the rules")
            for path in ("/truncated", "/invalid", "/large", "/slow", "/bad-trailer", "/chunk-limit",
                         "/chunk-truncated", "/raw-eof", "/encoded"):
                if not fetch(path).returncode or output.read_bytes() != RULES:
                    raise RuntimeError(f"invalid fetch changed the published file: {path}")
            configure(wrong / "cert")
            if not fetch("/rules").returncode or output.read_bytes() != RULES:
                raise RuntimeError("untrusted TLS connection replaced the rules")
            before = list(selected.seen)
            configure(root / "cert", resolver="missing")
            result = fetch("/rules")
            if not result.returncode or "domain-resolver not found" not in result.stderr:
                raise RuntimeError("dangling resolver was accepted")
            configure(root / "cert", outbound="missing")
            result = fetch("/rules")
            if not result.returncode or "HTTP client outbound is not available" not in result.stderr or selected.seen != before:
                raise RuntimeError("invalid egress configured or generated network I/O")
            configure(root / "cert")
            def status():
                deadline = time.monotonic() + 4
                while not origin.conditional_status:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("no conditional HTTP/1.1 request")
                    time.sleep(.01)
                return origin.conditional_status.pop(0)
            watch_conditional(binary, cfg, output, origin.port, RULES, status)
            cfg.write_text(cfg.read_text().replace(marker, marker + "\n    max-redirects 1"))
            origin.conditional_status.clear()
            watch_conditional(binary, cfg, output, origin.port, RULES, status, "/conditional-start")
        content = cfg.read_text()
        cfg.write_text(content.replace('protocol "http/1.1"', 'protocol "h3"\n    fingerprint "tls12"'))
        with Origin(root, tls12=True) as origin:
            args = [binary, "rule", "fetch", cfg, "updates",
                    f"https://localhost:{origin.port}/rules", "kdl", output]
            rejected = subprocess.run(args, capture_output=True, text=True, timeout=4)
            if not rejected.returncode or "HTTP client TLS 1.2 requires" not in rejected.stderr or origin.seen:
                raise RuntimeError(f"QUIC did not reject TLS 1.2 before I/O: {rejected.stderr}")
            cfg.write_text(content.replace('protocol "http/1.1"', 'protocol "http/1.1"\n    fingerprint "tls12"'))
            result = subprocess.run(args, capture_output=True, text=True, timeout=4)
            if result.returncode or not origin.seen or output.read_bytes() != RULES:
                raise RuntimeError(f"explicit HTTP TLS 1.2 download failed: {result.stderr}")
        print("Named HTTPS resolver, direct source binding, TLS, bounded HTTP/1.1 framing, SHA-256 and atomic updates passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve(strict=True)))
