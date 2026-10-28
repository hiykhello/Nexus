"""VLESS proxy traffic and HTTP interoperability fixtures."""
import socket
import subprocess
import threading
import time

from interop_common import PROXY_WORKERS, NEXUS

def vless_proxy(directory, upstream_port, rule_action=None):
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    config = directory / "nexus-vless.kdl"
    routing = 'default-outbound "edge";'
    if rule_action:
        (directory / "route-rules.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
        (directory / "unmatched-rules.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="192.0.2.0/24"\n')
        default = "direct" if rule_action == "edge" else "edge"
        routing = (f'rule-set "unmatched" path="unmatched-rules.kdl" format="kdl"; '
                   f'rule-set "selected" path="route-rules.kdl" format="kdl"; '
                   f'rule kind="rule-set" value="unmatched" outbound="{default}"; '
                   f'rule kind="rule-set" value="selected" outbound="{rule_action}"; default-outbound "{default}";')
    config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={upstream_port}
  authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
  tls {{ server-name "server.example"; ca-file "{directory / 'root.pem'}"; verify #true; }}
}}
routing {{ {routing} }}
''')
    process = subprocess.Popen([NEXUS, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    def exact(sock, size):
        result = bytearray()
        while len(result) < size:
            data = sock.recv(size - len(result))
            if not data:
                raise RuntimeError("proxy closed early")
            result += data
        return bytes(result)
    try:
        deadline = time.monotonic() + 5
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"nexus failed: {process.stderr.read().decode()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        for protocol in ("socks", "connect"):
            with socket.socket() as origin:
                origin.bind(("127.0.0.1", 0))
                origin.listen(1)
                origin.settimeout(8)
                origin_port = origin.getsockname()[1]
                errors = []
                def serve():
                    try:
                        with origin.accept()[0] as conn:
                            conn.settimeout(8)
                            if exact(conn, 5) != b"hello":
                                raise RuntimeError("incorrect origin payload")
                            conn.sendall(b"world")
                    except Exception as exc:
                        errors.append(exc)
                thread = threading.Thread(target=serve)
                thread.start()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=8) as client:
                        client.settimeout(8)
                        if protocol == "socks":
                            client.sendall(b"\x05\x01\x00")
                            if exact(client, 2) != b"\x05\x00": raise RuntimeError("SOCKS greeting failed")
                            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin_port.to_bytes(2, "big") + b"hello")
                            if exact(client, 10)[:2] != b"\x05\x00": raise RuntimeError("SOCKS connect failed")
                        else:
                            client.sendall(f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n".encode() + b"hello")
                            header = bytearray()
                            while not header.endswith(b"\r\n\r\n"):
                                header += exact(client, 1)
                                if len(header) > 4096: raise RuntimeError("oversized CONNECT response")
                            if not header.startswith(b"HTTP/1.1 200 "): raise RuntimeError(f"CONNECT failed: {header!r}")
                        if exact(client, 5) != b"world": raise RuntimeError("incorrect proxy payload")
                finally:
                    thread.join(timeout=9)
                if thread.is_alive() or errors: raise RuntimeError(f"origin failure: {errors}")
        for early in (False, True):
            with socket.socket() as origin:
                origin.bind(("127.0.0.1", 0))
                origin.listen(1)
                origin.settimeout(8)
                origin_port = origin.getsockname()[1]
                errors = []
                def http_origin():
                    try:
                        with origin.accept()[0] as conn:
                            conn.settimeout(8)
                            header = bytearray()
                            while not header.endswith(b"\r\n\r\n"):
                                header += exact(conn, 1)
                                if len(header) > 16384: raise RuntimeError("oversized HTTP request")
                            if not header.startswith(b"POST /upload HTTP/1.1\r\n"):
                                raise RuntimeError(f"incorrect HTTP request: {header!r}")
                            if not early and exact(conn, 5) != b"hello": raise RuntimeError("incorrect HTTP body")
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld")
                    except Exception as exc:
                        errors.append(exc)
                thread = threading.Thread(target=http_origin)
                thread.start()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=8) as client:
                        client.settimeout(8)
                        length = 1000 if early else 5
                        request = (f"POST http://127.0.0.1:{origin_port}/upload HTTP/1.1\r\n"
                                   f"Host: 127.0.0.1:{origin_port}\r\nContent-Length: {length}\r\n\r\n").encode()
                        client.sendall(request + (b"" if early else b"hello"))
                        response = bytearray()
                        while not response.endswith(b"\r\n\r\n"):
                            response += exact(client, 1)
                            if len(response) > 16384: raise RuntimeError("oversized HTTP response")
                        if not response.startswith(b"HTTP/1.1 200 ") or exact(client, 5) != b"world":
                            raise RuntimeError(f"HTTP over VLESS failed: {response!r}")
                finally:
                    thread.join(timeout=9)
                if thread.is_alive() or errors: raise RuntimeError(f"HTTP origin failure: {errors}")
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(8)
            origin_port = origin.getsockname()[1]
            errors = []
            def chunked_origin():
                try:
                    with origin.accept()[0] as conn:
                        conn.settimeout(8)
                        header = bytearray()
                        while not header.endswith(b"\r\n\r\n"):
                            header += exact(conn, 1)
                            if len(header) > 16384: raise RuntimeError("oversized chunked request")
                        if b"expect: 100-continue\r\n" not in header.lower(): raise RuntimeError("missing Expect")
                        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                        body = bytearray()
                        while not body.endswith(b"0\r\n\r\n"):
                            body += exact(conn, 1)
                            if len(body) > 100: raise RuntimeError("oversized chunked body")
                        if body != b"5\r\nhello\r\n0\r\n\r\n": raise RuntimeError(f"incorrect chunked body: {body!r}")
                        conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nworld\r\n0\r\n\r\n")
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=chunked_origin)
            thread.start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=8) as client:
                    client.settimeout(8)
                    client.sendall((f"POST http://127.0.0.1:{origin_port}/upload HTTP/1.1\r\n"
                                    f"Host: 127.0.0.1:{origin_port}\r\nTransfer-Encoding: chunked\r\n"
                                    "Expect: 100-continue\r\n\r\n").encode())
                    interim = bytearray()
                    while not interim.endswith(b"\r\n\r\n"):
                        interim += exact(client, 1)
                    if not interim.startswith(b"HTTP/1.1 100 "): raise RuntimeError(f"missing 100: {interim!r}")
                    for part in (b"5\r", b"\nhello\r\n", b"0\r\n\r\n"):
                        client.sendall(part)
                    header = bytearray()
                    while not header.endswith(b"\r\n\r\n"):
                        header += exact(client, 1)
                    if not header.startswith(b"HTTP/1.1 200 ") or exact(client, 15) != b"5\r\nworld\r\n0\r\n\r\n":
                        raise RuntimeError(f"chunked response failed: {header!r}")
            finally:
                thread.join(timeout=9)
            if thread.is_alive() or errors: raise RuntimeError(f"chunked origin failure: {errors}")
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0))
            origin.listen(8)
            origin.settimeout(10)
            origin_port = origin.getsockname()[1]
            errors = []
            workers = []
            payload_size = 256 * 1024
            def echo(conn):
                try:
                    with conn:
                        conn.settimeout(10)
                        remaining = payload_size
                        while remaining:
                            data = conn.recv(min(8192, remaining))
                            if not data: raise RuntimeError("truncated concurrent upload")
                            conn.sendall(data)
                            remaining -= len(data)
                except Exception as exc:
                    errors.append(exc)
            def accept_all():
                try:
                    for _ in range(4):
                        conn, _ = origin.accept()
                        worker = threading.Thread(target=echo, args=(conn,))
                        workers.append(worker)
                        worker.start()
                except Exception as exc:
                    errors.append(exc)
            def concurrent_client(index):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=10) as client:
                        client.settimeout(10)
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00": raise RuntimeError("concurrent greeting failed")
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin_port.to_bytes(2, "big"))
                        if exact(client, 10)[:2] != b"\x05\x00": raise RuntimeError("concurrent connect failed")
                        data = bytes([index + 1]) * payload_size
                        send_errors = []
                        def send():
                            try: client.sendall(data)
                            except Exception as exc: send_errors.append(exc)
                        sender = threading.Thread(target=send)
                        sender.start()
                        received = exact(client, payload_size)
                        sender.join(timeout=10)
                        if sender.is_alive() or send_errors or received != data:
                            raise RuntimeError(f"concurrent stream mismatch: {send_errors}")
                except Exception as exc:
                    errors.append(exc)
            acceptor = threading.Thread(target=accept_all)
            acceptor.start()
            clients = [threading.Thread(target=concurrent_client, args=(i,)) for i in range(4)]
            for client in clients: client.start()
            for client in clients: client.join(timeout=15)
            acceptor.join(timeout=12)
            for worker in workers: worker.join(timeout=12)
            if any(client.is_alive() for client in clients) or acceptor.is_alive() or any(worker.is_alive() for worker in workers) or errors:
                raise RuntimeError(f"concurrent VLESS transfer failed: {errors}")
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(5)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as stalled:
                stalled.settimeout(5)
                stalled.sendall(b"\x05\x01\x00")
                if exact(stalled, 2) != b"\x05\x00": raise RuntimeError("stalled SOCKS greeting failed")
                stalled.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin.getsockname()[1].to_bytes(2, "big") + b"x")
                if exact(stalled, 10)[:2] != b"\x05\x00": raise RuntimeError("stalled SOCKS connect failed")
                with origin.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream, 1) != b"x": raise RuntimeError("stalled tunnel did not start")
                    process.terminate()
                    process.wait(timeout=5)
                    if stalled.recv(1) != b"": raise RuntimeError("stop did not close client")
                    if upstream.recv(1) != b"": raise RuntimeError("stop did not close upstream")
        if process.returncode != 0: raise RuntimeError(f"nexus exit {process.returncode}: {process.stderr.read().decode()}")
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stderr.close()
