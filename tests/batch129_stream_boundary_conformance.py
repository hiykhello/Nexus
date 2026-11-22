#!/usr/bin/env python3
"""Batch 129: Stream boundary, 1-byte fragmentation, half-close & malformed protocol fuzz conformance."""
import argparse
import hashlib
import os
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

from detour_network import exact, reserve
from dns_rule_support import nexus_process, udp_client


def start_halfclose_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    stop = threading.Event()
    uploads = {}
    lock = threading.Lock()

    def handle(conn):
        try:
            conn.settimeout(10)
            mode = exact(conn, 4)
            if mode == b"ECHO":
                while chunk := conn.recv(65536):
                    conn.sendall(chunk)
            elif mode == b"CFIN":
                # Client sends all bytes + SHUT_WR; server echoes back full payload + SHUT_WR
                buf = bytearray()
                while chunk := conn.recv(65536):
                    buf.extend(chunk)
                conn.sendall(buf)
                conn.shutdown(socket.SHUT_WR)
            elif mode == b"SFIN":
                # Server immediately sends 64 KiB + SHUT_WR; then still reads client upload!
                tag = exact(conn, 8)
                payload = b"S" * 65536
                conn.sendall(payload)
                conn.shutdown(socket.SHUT_WR)
                rx = bytearray()
                while chunk := conn.recv(65536):
                    rx.extend(chunk)
                with lock:
                    uploads[tag] = hashlib.sha256(rx).digest()
            elif mode == b"HTTP":
                # Not reached directly; HTTP forward sends raw HTTP
                pass
        except OSError:
            pass
        finally:
            conn.close()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop, uploads, lock


def start_http_origin():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(32)
    stop = threading.Event()

    def read_line(conn, buf):
        while b"\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None, buf
            buf.extend(chunk)
        idx = buf.index(b"\r\n")
        line = bytes(buf[:idx])
        del buf[: idx + 2]
        return line, buf

    def handle(conn):
        try:
            conn.settimeout(8)
            buf = bytearray()
            req_line, buf = read_line(conn, buf)
            if not req_line:
                return
            headers = {}
            while True:
                line, buf = read_line(conn, buf)
                if line is None or line == b"":
                    break
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.strip().lower()] = v.strip().lower()
            body = bytearray()
            if headers.get(b"transfer-encoding") == b"chunked":
                while True:
                    sz_line, buf = read_line(conn, buf)
                    if sz_line is None:
                        break
                    sz = int(sz_line.split(b";")[0], 16)
                    if sz == 0:
                        read_line(conn, buf)
                        break
                    while len(buf) < sz + 2:
                        c = conn.recv(4096)
                        if not c:
                            break
                        buf.extend(c)
                    body.extend(buf[:sz])
                    del buf[: sz + 2]
            elif b"content-length" in headers:
                need = int(headers[b"content-length"])
                while len(buf) < need:
                    c = conn.recv(4096)
                    if not c:
                        break
                    buf.extend(c)
                body.extend(buf[:need])
            digest = hashlib.sha256(body).hexdigest().encode()
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(digest)}\r\nConnection: close\r\n\r\n".encode()
                + digest
            )
            conn.sendall(resp)
        except OSError:
            pass
        finally:
            conn.close()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], stop


def send_byte_by_byte(sock, data, pause=0.0005):
    for i in range(len(data)):
        sock.sendall(data[i : i + 1])
        if pause:
            time.sleep(pause)


def socks5_connect(port, dst_port, byte_by_byte=False):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    hello = b"\x05\x01\x00"
    req = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", dst_port)
    if byte_by_byte:
        send_byte_by_byte(s, hello)
        assert exact(s, 2) == b"\x05\x00"
        send_byte_by_byte(s, req)
    else:
        s.sendall(hello)
        assert exact(s, 2) == b"\x05\x00"
        s.sendall(req)
    rep = exact(s, 10)
    assert rep[:2] == b"\x05\x00", rep
    return s


def test_suite(binary):
    srv, tcp_port, stop_tcp, uploads, lock = start_halfclose_server()
    hsrv, http_port, stop_http = start_http_origin()
    usrv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usrv.bind(("127.0.0.1", 0))
    udp_port = usrv.getsockname()[1]
    stop_udp = threading.Event()

    def serve_udp():
        usrv.settimeout(0.2)
        while not stop_udp.is_set():
            try:
                d, a = usrv.recvfrom(65535)
                usrv.sendto(d, a)
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=serve_udp, daemon=True).start()

    try:
        with tempfile.TemporaryDirectory(prefix="nexus-b129-") as d:
            front = reserve()
            cfg = Path(d) / "mixed.kdl"
            cfg.write_text(f'''schema-version 1
role "client"
workers 2
inbound "mixed" type="mixed" {{
    listen host="127.0.0.1" port={front}
    authentication "none"
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
            with nexus_process(str(binary), str(cfg)):
                # 1. 1-byte fragmented SOCKS5 handshake + 128 KiB echo
                with socks5_connect(front, tcp_port, byte_by_byte=True) as s:
                    blob = os.urandom(131072)
                    s.sendall(b"ECHO" + blob)
                    assert hashlib.sha256(exact(s, len(blob))).digest() == hashlib.sha256(blob).digest()

                # 2. 1-byte fragmented HTTP CONNECT + 128 KiB echo
                with socket.create_connection(("127.0.0.1", front), timeout=5) as s:
                    s.settimeout(10)
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    req = f"CONNECT 127.0.0.1:{tcp_port} HTTP/1.1\r\nHoSt: 127.0.0.1:{tcp_port}\r\n\r\n".encode()
                    send_byte_by_byte(s, req)
                    resp = b""
                    while b"\r\n\r\n" not in resp:
                        c = s.recv(4096)
                        assert c, "EOF waiting for CONNECT"
                        resp += c
                    assert resp.startswith(b"HTTP/1.1 200") or resp.startswith(b"HTTP/1.0 200"), resp
                    blob = os.urandom(131072)
                    s.sendall(b"ECHO" + blob)
                    assert hashlib.sha256(exact(s, len(blob))).digest() == hashlib.sha256(blob).digest()

                # 3. Mixed-port HTTP/1.1 Forward (Content-Length + Chunked)
                for chunked in (False, True):
                    body = os.urandom(24576)
                    with socket.create_connection(("127.0.0.1", front), timeout=5) as s:
                        s.settimeout(10)
                        if not chunked:
                            hdr = (
                                f"POST http://127.0.0.1:{http_port}/cl HTTP/1.1\r\n"
                                f"Host: 127.0.0.1:{http_port}\r\n"
                                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                            ).encode()
                            send_byte_by_byte(s, hdr[:32], pause=0.0002)
                            s.sendall(hdr[32:] + body)
                        else:
                            hdr = (
                                f"POST http://127.0.0.1:{http_port}/ch HTTP/1.1\r\n"
                                f"Host: 127.0.0.1:{http_port}\r\n"
                                f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                            ).encode()
                            s.sendall(hdr)
                            for off in range(0, len(body), 4096):
                                part = body[off : off + 4096]
                                s.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                            s.sendall(b"0\r\n\r\n")
                        raw = bytearray()
                        while c := s.recv(4096):
                            raw.extend(c)
                        assert b"\r\n\r\n" in raw, raw[:120]
                        _, rbody = bytes(raw).split(b"\r\n\r\n", 1)
                        assert rbody.strip().decode() == hashlib.sha256(body).hexdigest(), rbody

                # 4. Bidirectional independent TCP half-close (client FIN first & server FIN first)
                with socks5_connect(front, tcp_port) as s:
                    payload = os.urandom(262144)
                    s.sendall(b"CFIN" + payload)
                    s.shutdown(socket.SHUT_WR)
                    echoed = exact(s, len(payload))
                    assert hashlib.sha256(echoed).digest() == hashlib.sha256(payload).digest()
                    assert s.recv(1) == b""

                tag = os.urandom(8)
                up_payload = os.urandom(131072)
                with socks5_connect(front, tcp_port) as s:
                    s.sendall(b"SFIN" + tag)
                    down = exact(s, 65536)
                    assert down == b"S" * 65536
                    assert s.recv(1) == b""  # server FIN observed cleanly!
                    s.sendall(up_payload)
                    s.shutdown(socket.SHUT_WR)
                for _ in range(50):
                    with lock:
                        if tag in uploads:
                            break
                    time.sleep(0.02)
                with lock:
                    assert uploads.get(tag) == hashlib.sha256(up_payload).digest(), "server-FIN-first upload mismatch"

                # 5. Adversarial malformed protocol fuzzing storm + rapid RSTs
                bad_payloads = [
                    b"",
                    b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00",
                    b"\x05",
                    b"\x05\x00",
                    b"\x05\x01\xff",
                    b"\x05\x01\x00\x05\x01\x00\x09\x00\x00",
                    b"\x05\x01\x00\x05\x01\x00\x03\x00\x00\x50",
                    b"\xff\xfe\xfd\xfc\x00\x01",
                    b"CONNECT badhost HTTP/1.1\r\n\r\n",
                    b"GET /relative-only HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                    b"POST http://127.0.0.1:80/ HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
                    b"POST http://127.0.0.1:80/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n",
                    b"GARBAGE " * 2048,
                ]
                for payload in bad_payloads * 3:
                    try:
                        s = socket.create_connection(("127.0.0.1", front), timeout=2)
                        s.settimeout(0.3)
                        if payload:
                            s.sendall(payload)
                        try:
                            s.recv(64)
                        except OSError:
                            pass
                        s.close()
                    except OSError:
                        pass

                # Rapid SO_LINGER RST storm (30 connections)
                for _ in range(30):
                    s = socket.create_connection(("127.0.0.1", front), timeout=2)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    s.sendall(b"\x05\x01")
                    s.close()

                # 6. Post-fuzz health verification (TCP + UDP)
                with socks5_connect(front, tcp_port) as s:
                    s.sendall(b"ECHOpost-fuzz-ok")
                    assert exact(s, 12) == b"post-fuzz-ok"
                with udp_client(front) as (u, relay):
                    u.settimeout(3)
                    pkt = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_port) + b"udp-post-fuzz"
                    u.sendto(pkt, relay)
                    assert u.recv(1024) == pkt

        print(f"BATCH 129 STREAM BOUNDARY, 1-BYTE FRAG, HALF-CLOSE & FUZZ CONFORMANCE PASSED [{binary.name}]", flush=True)
    finally:
        stop_tcp.set(); srv.close()
        stop_http.set(); hsrv.close()
        stop_udp.set(); usrv.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("binary", type=Path)
    test_suite(p.parse_args().binary.resolve(strict=True))
