#!/usr/bin/env python3
"""Batch 147 live blackbox integration tests:
1. Zero implicit DNS assertion during traffic rule matching
2. Passive dns.reverse-mapping routing + HTTPS(65)/SVCB(64) empty NOERROR
3. Managed remote rule-set + ETag 304 + atomic background hot-swap + offline cache
4. -D working root + -C config dir (.bak ignored, duplicate tag reports both files)
"""
import argparse
import http.server
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from detour_network import exact, reserve
from dns_rule_support import Echo, nexus_process


def socks5_connect(socks_port: int, host: str, dst_port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=5.0)
    s.settimeout(5.0)
    try:
        s.sendall(b"\x05\x01\x00")
        assert exact(s, 2) == b"\x05\x00"
        try:
            addr = b"\x01" + socket.inet_aton(host)
        except OSError:
            raw = host.encode("ascii")
            addr = bytes([3, len(raw)]) + raw
        s.sendall(b"\x05\x01\x00" + addr + dst_port.to_bytes(2, "big"))
        hdr = exact(s, 4)
        if hdr[1] != 0:
            raise RuntimeError(f"SOCKS5 rejected: rep={hdr[1]}")
        if hdr[3] == 1:
            exact(s, 6)
        elif hdr[3] == 4:
            exact(s, 18)
        elif hdr[3] == 3:
            n = exact(s, 1)[0]
            exact(s, n + 2)
        return s
    except Exception:
        s.close()
        raise


def build_dns_query(txid: int, domain: str, qtype: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in domain.rstrip(".").split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def parse_qname_and_qtype(pkt: bytes):
    off = 12
    parts = []
    while off < len(pkt) and pkt[off] != 0:
        ln = pkt[off]
        parts.append(pkt[off + 1 : off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    off += 1
    qtype, qclass = struct.unpack("!HH", pkt[off : off + 4])
    return ".".join(parts).lower(), qtype, qclass, off + 4


def build_dns_a_reply(query: bytes, ip_bytes: bytes, ttl: int = 60) -> bytes:
    txid = struct.unpack("!H", query[:2])[0]
    _, qtype, qclass, qend = parse_qname_and_qtype(query)
    question = query[12:qend]
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", qtype, qclass, ttl, len(ip_bytes)) + ip_bytes
    return header + question + ans


class SpyDnsServer:
    def __init__(self, answers: dict[str, bytes]):
        self.answers = answers
        self.queries: list[tuple[str, int]] = []
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            name, qtype, _, _ = parse_qname_and_qtype(data)
            with self.lock:
                self.queries.append((name, qtype))
            if qtype == 1 and name in self.answers:
                self.sock.sendto(build_dns_a_reply(data, self.answers[name]), peer)
            else:
                txid = struct.unpack("!H", data[:2])[0]
                _, _, _, qend = parse_qname_and_qtype(data)
                flags = 0x8180 if name in self.answers else 0x8183
                soa = b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(16) + struct.pack("!I", 60)
                self.sock.sendto(struct.pack("!HHHHHH", txid, flags, 1, 0, 1, 0) + data[12:qend] + soa, peer)

    def count(self) -> int:
        with self.lock:
            return len(self.queries)

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def dns_udp_exchange(port: int, pkt: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3.0)
        s.sendto(pkt, ("127.0.0.1", port))
        return s.recvfrom(4096)[0]


def make_self_signed_cert(root: Path):
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1",
    ], check=True, capture_output=True)
    key.chmod(0o600)
    return cert, key


def test_zero_implicit_dns_and_reverse_mapping(nexus_bin: Path, root: Path):
    spy = SpyDnsServer({"vip.reverse.test": socket.inet_aton("127.0.0.1")})
    socks_port = reserve()
    dns_port = reserve()
    cfg_path = root / "reverse.kdl"
    cfg_path.write_text(f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{
    listen host="127.0.0.1" port={socks_port}
    authentication "none"
}}
outbound "direct" type="direct"
outbound "block" type="block"
dns {{
    listen host="127.0.0.1" port={dns_port}
    reverse-mapping #true
    server "spy" type="udp" host="127.0.0.1" port={spy.port}
    rule domain-suffix="reverse.test" query-type="HTTPS" action="predefined" predefined-rcode="NOERROR"
    rule domain-suffix="reverse.test" query-type="SVCB" action="predefined" predefined-rcode="NOERROR"
    final "spy"
}}
routing {{
    rulesets {{
        geoip-like {{
            ip-cidr "10.0.0.0/8"
        }}
        vip-domains {{
            domain "vip.reverse.test"
        }}
        blocked-explicit {{
            domain "never-dns.test"
        }}
    }}
    tcp-program sniff-timeout-ms=500 unknown="skip" {{
        rule action="route" rule-set="geoip-like" outbound="block"
        rule action="route" rule-set="blocked-explicit" outbound="block"
        rule action="route" rule-set="vip-domains" domain-source="reverse" outbound="block"
    }}
    final "direct"
}}
''')
    try:
        with Echo() as echo, nexus_process(nexus_bin, cfg_path):
            # 1. Zero implicit DNS: domain target traverses ip-cidr rule BEFORE explicit domain block rule.
            # Must be rejected by blocked-explicit with ZERO DNS queries sent to spy!
            before = spy.count()
            try:
                s = socks5_connect(socks_port, "never-dns.test", echo.port)
                s.close()
                raise AssertionError("never-dns.test should have been blocked")
            except RuntimeError:
                pass
            assert spy.count() == before, f"Implicit DNS query leaked during route matching: {spy.queries}"

            # 2. HTTPS (65) and SVCB (64) return instant empty NOERROR with zero upstream DNS queries!
            for qtype in (65, 64):
                reply = dns_udp_exchange(dns_port, build_dns_query(0x4200 + qtype, "vip.reverse.test", qtype))
                flags, qd, an = struct.unpack("!HHH", reply[2:8])
                assert (flags & 0x000F) == 0 and an == 0, f"expected empty NOERROR for qtype={qtype}"
            assert spy.count() == before, f"predefined HTTPS/SVCB leaked to upstream: {spy.queries}"

            # 3. Before DNS A query, numeric 127.0.0.1:<echo> is NOT in reverse cache -> direct succeeds!
            s = socks5_connect(socks_port, "127.0.0.1", echo.port)
            s.sendall(b"before-rev")
            assert exact(s, 10) == b"before-rev"
            s.close()

            # 4. Perform real DNS A query for vip.reverse.test -> passively records 127.0.0.1 -> vip.reverse.test
            reply = dns_udp_exchange(dns_port, build_dns_query(0x4301, "vip.reverse.test", 1))
            flags, qd, an = struct.unpack("!HHH", reply[2:8])
            assert (flags & 0x000F) == 0 and an == 1
            assert spy.count() == before + 1

            # 5. Now numeric 127.0.0.1:<echo> matches domain-source="reverse" rule-set "vip-domains" -> BLOCKED!
            # And STILL emits zero additional DNS queries!
            try:
                s = socks5_connect(socks_port, "127.0.0.1", echo.port)
                s.close()
                raise AssertionError("127.0.0.1 should be blocked via passive reverse-mapping")
            except RuntimeError:
                pass
            assert spy.count() == before + 1, "reverse lookup unexpectedly emitted DNS traffic!"
        print("147.1+147.2 Zero implicit DNS + HTTPS/SVCB predefined NOERROR + passive reverse-mapping PASSED", flush=True)
    finally:
        spy.close()


def test_remote_ruleset_etag_hotswap_and_offline_cache(nexus_bin: Path, root: Path):
    cert, key = make_self_signed_cert(root)
    state = {"etag": '"v1"', "body": b'schema-version 2\nkind "predicate"\ndomain "blocked-v1.test"\n', "hits": 0, "not_modified": 0}
    state_lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with state_lock:
                state["hits"] += 1
                inm = self.headers.get("If-None-Match")
                if inm == state["etag"]:
                    state["not_modified"] += 1
                    self.send_response(304)
                    self.send_header("ETag", state["etag"])
                    self.end_headers()
                    return
                body = state["body"]
                etag = state["etag"]
            self.send_response(200)
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    http_port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    spy = SpyDnsServer({"localhost": socket.inet_aton("127.0.0.1"),
                        "blocked-v1.test": socket.inet_aton("127.0.0.1"),
                        "blocked-v2.test": socket.inet_aton("127.0.0.1")})
    cache_dir = root / "cache"
    cache_dir.mkdir(mode=0o700)
    socks_port = reserve()
    cfg_path = root / "remote.kdl"
    cfg_path.write_text(f'''schema-version 1
role "client"
log {{
    level "debug"
    privacy "verbose"
}}
state {{
    cache-directory "{cache_dir}"
}}
inbound "socks" type="socks5" {{
    listen host="127.0.0.1" port={socks_port}
    authentication "none"
}}
outbound "direct" type="direct"
outbound "block" type="block"
dns {{
    server "spy" type="udp" host="127.0.0.1" port={spy.port}
    final "spy"
}}
http-clients {{
    default "direct-http"
    direct-http {{
        outbound "direct"
        domain-resolver "spy"
        ca-file "{cert}"
        protocol "http/1.1"
    }}
}}
routing {{
    rulesets {{
        dyn url="https://127.0.0.1:{http_port}/rules.kdl" format="kdl" update-interval-ms=1000
    }}
    tcp-program sniff-timeout-ms=500 unknown="skip" {{
        rule action="route" rule-set="dyn" outbound="block"
    }}
    final "direct"
}}
''')
    try:
        with Echo() as echo:
            with nexus_process(nexus_bin, cfg_path):
                # v1 active: blocked-v1.test blocked, blocked-v2.test allowed
                try:
                    socks5_connect(socks_port, "blocked-v1.test", echo.port).close()
                    raise AssertionError("blocked-v1.test must be blocked initially")
                except RuntimeError:
                    pass
                s = socks5_connect(socks_port, "blocked-v2.test", echo.port)
                s.sendall(b"ok-v1")
                assert exact(s, 5) == b"ok-v1"
                s.close()

                # Wait for at least one ETag 304 poll
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline:
                    with state_lock:
                        if state["not_modified"] >= 1:
                            break
                    time.sleep(0.1)
                with state_lock:
                    assert state["not_modified"] >= 1, f"Expected ETag 304 poll, state={state}"
                    state["etag"] = '"v2"'
                    state["body"] = b'schema-version 2\nkind "predicate"\ndomain "blocked-v2.test"\n'

                # Wait for background hot-swap to activate v2
                swapped = False
                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline:
                    try:
                        socks5_connect(socks_port, "blocked-v2.test", echo.port).close()
                    except RuntimeError:
                        swapped = True
                        break
                    time.sleep(0.15)
                assert swapped, "Remote rule-set background atomic hot-swap to v2 did not activate!"
                s = socks5_connect(socks_port, "blocked-v1.test", echo.port)
                s.sendall(b"ok-v2")
                assert exact(s, 5) == b"ok-v2"
                s.close()

            # Shut down HTTPS server completely -> restart nexus -> MUST boot from persisted offline cache!
            httpd.shutdown()
            httpd.server_close()
            with nexus_process(nexus_bin, cfg_path):
                try:
                    socks5_connect(socks_port, "blocked-v2.test", echo.port).close()
                    raise AssertionError("blocked-v2.test must stay blocked from offline persisted cache!")
                except RuntimeError:
                    pass
                s = socks5_connect(socks_port, "blocked-v1.test", echo.port)
                s.sendall(b"offline")
                assert exact(s, 7) == b"offline"
                s.close()
        print("147.3 Remote rule-set + ETag 304 + atomic hot-swap + offline cache fallback PASSED", flush=True)
    finally:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
        spy.close()


def test_working_dir_and_config_dir_cli(nexus_bin: Path, root: Path):
    wd = root / "state-wd"
    cfgd = root / "conf.d"
    wd.mkdir()
    cfgd.mkdir()
    (wd / "rel-rules.kdl").write_text('schema-version 2\nkind "predicate"\ndomain "rel.example"\n')
    (cfgd / "00-base.kdl").write_text('schema-version 1\nrole "client"\n')
    (cfgd / "10-main.kdl").write_text('''inbound "socks" type="socks5" {
    listen host="127.0.0.1" port=18080
    authentication "none"
}
outbound "direct" type="direct"
outbound "block" type="block"
routing {
    rulesets { local path="rel-rules.kdl" format="kdl"; }
    rules { - kind="rule-set" value="local" outbound="block"; }
    final "direct"
}
''')
    (cfgd / "10-main.kdl.bak").write_text("CORRUPT BACKUP IGNORED {{{")
    res = subprocess.run([str(nexus_bin), "-D", str(wd), "check", "-C", str(cfgd)],
                         capture_output=True, text=True)
    assert res.returncode == 0 and "configuration valid" in res.stdout, f"check failed: {res.stdout} {res.stderr}"
    (cfgd / "20-dup.kdl").write_text('inbound "socks" type="socks5" { listen host="127.0.0.1" port=18081; authentication "none"; }\n')
    dup = subprocess.run([str(nexus_bin), "-D", str(wd), "check", "-C", str(cfgd)],
                         capture_output=True, text=True)
    assert dup.returncode != 0 and "20-dup.kdl" in dup.stderr and "10-main.kdl" in dup.stderr, dup.stderr
    print("147.4 -D working root + -C config dir (.bak ignored & duplicate diagnostics) PASSED", flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    args = p.parse_args()
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-batch147-") as d:
        root = Path(d)
        test_zero_implicit_dns_and_reverse_mapping(binary, root)
        test_remote_ruleset_etag_hotswap_and_offline_cache(binary, root)
        test_working_dir_and_config_dir_cli(binary, root)
    print(f"ALL BATCH 147 LIVE INTEGRATION TESTS PASSED [{binary.name}]", flush=True)


if __name__ == "__main__":
    main()
