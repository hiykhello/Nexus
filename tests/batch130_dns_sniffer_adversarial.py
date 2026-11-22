#!/usr/bin/env python3
"""Batch 130: DNS, FakeIP & fragmented TLS/HTTP sniffer adversarial conformance suite."""
import argparse
import concurrent.futures
import hashlib
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from detour_network import exact, reserve, socks
from dns_rule_support import DnsPeer, nexus_process, question, wire_name


def make_cert(root):
    cert, key = root / "sniff.crt", root / "sniff.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=allowed.example",
        "-addext", "subjectAltName=DNS:allowed.example,DNS:blocked.example,IP:127.0.0.1", "-days", "1",
    ], check=True, capture_output=True)
    key.chmod(0o600)
    return cert, key


def build_tls_client_hello(sni: str) -> bytes:
    # Minimal valid TLS 1.2/1.3 ClientHello with SNI extension for raw fragmented write test
    name = sni.encode("ascii")
    sni_list = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext_data = struct.pack("!H", len(sni_list)) + sni_list
    ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    body = (
        b"\x03\x03"
        + os.urandom(32)
        + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(ext)) + ext
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def dns_query_packet(txid: int, name: str, qtype: int = 1, edns: int = 0) -> bytes:
    ar = 1 if edns else 0
    pkt = struct.pack("!6H", txid, 0x0100, 1, 0, 0, ar) + wire_name(name) + struct.pack("!HH", qtype, 1)
    if edns:
        pkt += struct.pack("!BHHIH", 0, 41, edns, 0, 0)
    return pkt


def udp_dns_ask(port: int, pkt: bytes, timeout: float = 3.0) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, ("127.0.0.1", port))
        return s.recv(4096)


def test_suite(binary: Path):
    with tempfile.TemporaryDirectory(prefix="nexus-b130-") as d:
        root = Path(d)
        cert, key = make_cert(root)

        # Raw TCP echo origin (captures exact replayed bytes for HTTP & TLS frag tests)
        raw_srv = socket.socket()
        raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_srv.bind(("127.0.0.1", 0))
        raw_srv.listen(32)
        raw_port = raw_srv.getsockname()[1]
        stop_raw = threading.Event()

        def serve_raw():
            raw_srv.settimeout(0.2)
            while not stop_raw.is_set():
                try:
                    c, _ = raw_srv.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                def _echo(conn):
                    try:
                        conn.settimeout(5)
                        while data := conn.recv(65536):
                            conn.sendall(data)
                    except OSError:
                        pass
                    finally:
                        conn.close()
                threading.Thread(target=_echo, args=(c,), daemon=True).start()

        threading.Thread(target=serve_raw, daemon=True).start()

        # Real TLS echo origin for end-to-end TLS handshake + SNI sniff replay
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(cert), str(key))
        tls_srv = socket.socket()
        tls_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tls_srv.bind(("127.0.0.1", 0))
        tls_srv.listen(16)
        tls_port = tls_srv.getsockname()[1]
        stop_tls = threading.Event()

        def serve_tls():
            tls_srv.settimeout(0.2)
            while not stop_tls.is_set():
                try:
                    c, _ = tls_srv.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                def _tls_echo(raw_c):
                    try:
                        with sctx.wrap_socket(raw_c, server_side=True) as s:
                            s.settimeout(5)
                            while data := s.recv(16384):
                                s.sendall(data)
                    except OSError:
                        raw_c.close()
                threading.Thread(target=_tls_echo, args=(c,), daemon=True).start()

        threading.Thread(target=serve_tls, daemon=True).start()

        # Custom UDP upstream that injects TXID mismatch + TC=1 truncation fallback + blackhole peer
        bad_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bad_udp.bind(("127.0.0.1", 0))
        bad_port = bad_udp.getsockname()[1]
        stop_dns_custom = threading.Event()

        def serve_blackhole():
            bad_udp.settimeout(0.2)
            while not stop_dns_custom.is_set():
                try:
                    bad_udp.recvfrom(4096)  # deliberately drop (blackhole!)
                except TimeoutError:
                    continue
                except OSError:
                    break

        threading.Thread(target=serve_blackhole, daemon=True).start()

        # Spoof+TC upstream (UDP injects wrong TXID first then TC=1; TCP returns genuine A record)
        tc_port = reserve()
        tc_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tc_udp.bind(("127.0.0.1", tc_port))
        tc_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tc_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tc_tcp.bind(("127.0.0.1", tc_port))
        tc_tcp.listen(16)

        def build_a_resp(req, ip_str, tc=False, txid_override=None):
            txid = txid_override if txid_override is not None else struct.unpack("!H", req[:2])[0]
            name, qtype, _ = question(req)
            flags = 0x8180 | (0x0200 if tc else 0)
            qsec = wire_name(name) + struct.pack("!HH", qtype, 1)
            if tc:
                return struct.pack("!6H", txid, flags, 1, 0, 0, 0) + qsec
            ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip_str)
            return struct.pack("!6H", txid, flags, 1, 1, 0, 0) + qsec + ans

        def serve_tc_udp():
            tc_udp.settimeout(0.2)
            while not stop_dns_custom.is_set():
                try:
                    pkt, addr = tc_udp.recvfrom(4096)
                    txid = struct.unpack("!H", pkt[:2])[0]
                    # 1. Inject spoofed wrong-TXID answer first!
                    tc_udp.sendto(build_a_resp(pkt, "198.51.100.99", tc=False, txid_override=(txid ^ 0x5555)), addr)
                    # 2. Send real TXID with TC=1 forcing TCP fallback!
                    tc_udp.sendto(build_a_resp(pkt, "198.51.100.42", tc=True), addr)
                except TimeoutError:
                    continue
                except OSError:
                    break

        def serve_tc_tcp():
            tc_tcp.settimeout(0.2)
            while not stop_dns_custom.is_set():
                try:
                    c, _ = tc_tcp.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                try:
                    c.settimeout(3)
                    n = struct.unpack("!H", exact(c, 2))[0]
                    req = exact(c, n)
                    resp = build_a_resp(req, "198.51.100.42", tc=False)
                    c.sendall(struct.pack("!H", len(resp)) + resp)
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve_tc_udp, daemon=True).start()
        threading.Thread(target=serve_tc_tcp, daemon=True).start()

        try:
            with DnsPeer() as good_dns:
                fwd_raw, fwd_tls, mixed_port, dns_port = reserve(), reserve(), reserve(), reserve()
                cfg = root / "b130.kdl"
                cfg.write_text(f'''schema-version 1
role "client"
workers 2
inbound "fwd-raw" type="fixed-tcp" {{ listen host="127.0.0.1" port={fwd_raw}; target host="127.0.0.1" port={raw_port}; }}
inbound "fwd-tls" type="fixed-tcp" {{ listen host="127.0.0.1" port={fwd_tls}; target host="127.0.0.1" port={tls_port}; }}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={mixed_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "good" type="udp" host="127.0.0.1" port={good_dns.port}
    server "blackhole" type="udp" host="127.0.0.1" port={bad_port}
    server "tc-spoof" type="udp" host="127.0.0.1" port={tc_port}
    rule domain-suffix="race.test" action="evaluate" server="blackhole" tag="slow" timeout-ms=120
    rule domain-suffix="race.test" action="route" server="good"
    rule domain-suffix="tc.test" action="route" server="tc-spoof"
    final "good"
    strategy "ipv4_only"
    disable-cache #true
}}
routing {{
    tcp-program sniff-timeout-ms=1000 unknown="skip" {{
        rule action="sniff"
        rule action="reject" domain-source="sniffed" {{ domain "blocked.example"; }}
        rule action="route" outbound="direct" domain-source="sniffed" {{ domain "allowed.example"; }}
        rule action="reject"
    }}
    default-outbound "direct"
}}
''')
                with nexus_process(str(binary), str(cfg)):
                    # 1. Fragmented raw TLS ClientHello SNI sniff (3-byte segments!) -> lossless replay
                    ch_ok = build_tls_client_hello("allowed.example")
                    with socket.create_connection(("127.0.0.1", fwd_raw), timeout=5) as s:
                        s.settimeout(8)
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        for off in range(0, len(ch_ok), 3):
                            s.sendall(ch_ok[off : off + 3])
                            time.sleep(0.001)
                        assert exact(s, len(ch_ok)) == ch_ok, "fragmented TLS ClientHello replay corrupted"

                    # 2. Fragmented TLS ClientHello for blocked.example -> MUST be rejected!
                    ch_bad = build_tls_client_hello("blocked.example")
                    with socket.create_connection(("127.0.0.1", fwd_raw), timeout=5) as s:
                        s.settimeout(3)
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        rejected = False
                        try:
                            for off in range(0, len(ch_bad), 3):
                                s.sendall(ch_bad[off : off + 3])
                                time.sleep(0.001)
                            if not s.recv(16):
                                rejected = True
                        except OSError:
                            rejected = True
                        assert rejected, "fragmented blocked.example TLS SNI was NOT rejected"

                    # 3. Full real TLS handshake through sniffer + 64 KiB echo
                    cctx = ssl.create_default_context(cafile=str(cert))
                    raw_s = socket.create_connection(("127.0.0.1", fwd_tls), timeout=5)
                    with cctx.wrap_socket(raw_s, server_hostname="allowed.example") as ts:
                        ts.settimeout(8)
                        blob = os.urandom(65536)
                        ts.sendall(blob)
                        assert hashlib.sha256(exact(ts, len(blob))).digest() == hashlib.sha256(blob).digest()

                    # 4. Fragmented HTTP/1.1 Host sniffing (mixed case + port stripping)
                    http_ok = b"GET /test HTTP/1.1\r\nHoSt: allowed.example:8080\r\nUser-Agent: b130\r\n\r\n"
                    with socket.create_connection(("127.0.0.1", fwd_raw), timeout=5) as s:
                        s.settimeout(8)
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        for off in range(0, len(http_ok), 4):
                            s.sendall(http_ok[off : off + 4])
                            time.sleep(0.001)
                        assert exact(s, len(http_ok)) == http_ok, "fragmented HTTP sniff replay corrupted"

                    http_bad = b"GET /deny HTTP/1.1\r\nHoSt: blocked.example:80\r\n\r\n"
                    with socket.create_connection(("127.0.0.1", fwd_raw), timeout=5) as s:
                        s.settimeout(3)
                        rejected = False
                        try:
                            for off in range(0, len(http_bad), 4):
                                s.sendall(http_bad[off : off + 4])
                                time.sleep(0.001)
                            if not s.recv(16):
                                rejected = True
                        except OSError:
                            rejected = True
                        assert rejected, "fragmented blocked.example HTTP Host was NOT rejected"

                    # 4b. HTTP CONNECT prefetched Host sniff -> honest 403 Forbidden!
                    with socket.create_connection(("127.0.0.1", mixed_port), timeout=5) as s:
                        s.settimeout(4)
                        s.sendall(f"CONNECT 127.0.0.1:{raw_port} HTTP/1.1\r\nHost: 127.0.0.1:{raw_port}\r\n\r\n".encode() + http_bad)
                        resp = b""
                        while b"\r\n\r\n" not in resp:
                            c = s.recv(1024)
                            if not c:
                                break
                            resp += c
                        assert resp.startswith(b"HTTP/1.1 403 "), resp

                    # 5. DNS malformed/truncated packet fuzzing (must NOT crash or wedge!)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fuzz:
                        for bad in (
                            b"", b"\x00", b"\x12\x34\x01\x00",
                            struct.pack("!6H", 0x1111, 0x0100, 0, 0, 0, 0),
                            struct.pack("!6H", 0x2222, 0x0100, 1, 0, 0, 0) + b"\x3fbad",
                            struct.pack("!6H", 0x3333, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01",
                            b"\xff" * 600,
                        ):
                            fuzz.sendto(bad, ("127.0.0.1", dns_port))

                    # 6. DNS TXID spoof rejection + TC=1 automatic TCP fallback
                    resp = udp_dns_ask(dns_port, dns_query_packet(0x4242, "fallback.tc.test"))
                    assert struct.unpack("!H", resp[:2])[0] == 0x4242
                    assert resp[-4:] == socket.inet_aton("198.51.100.42"), f"wrong IP / accepted spoof: {resp[-4:]!r}"

                    # 7. Concurrent burst (16 simultaneous queries) racing past blackhole evaluate to fast fallback
                    t0 = time.perf_counter()
                    def ask_one(i):
                        r = udp_dns_ask(dns_port, dns_query_packet(0x5000 + i, f"h{i}.race.test"), timeout=4.0)
                        assert struct.unpack("!H", r[:2])[0] == 0x5000 + i
                        assert (r[3] & 0x0F) == 0, r[:12]
                    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                        list(pool.map(ask_one, range(16)))
                    elapsed = time.perf_counter() - t0
                    assert elapsed < 2.5, f"slow upstream caused head-of-line stall: {elapsed:.2f}s"

        finally:
            stop_raw.set(); raw_srv.close()
            stop_tls.set(); tls_srv.close()
            stop_dns_custom.set(); bad_udp.close(); tc_udp.close(); tc_tcp.close()

    print(f"BATCH 130 DNS/SNIFFER FRAGMENTATION & ADVERSARIAL CONFORMANCE PASSED [{binary.name}]", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    test_suite(p.parse_args().binary.resolve(strict=True))
