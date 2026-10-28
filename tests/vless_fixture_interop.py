"""Controlled TLS and VLESS failure fixtures."""
import socket
import ssl
import subprocess
import threading
import time

from interop_common import PROXY_WORKERS, NEXUS, VLESS_CLIENT

def vless_tls(directory, invalid=False, relay=False, cancel=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / "server.pem", directory / "server.key")
    context.set_ecdh_curve("X25519")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(1)
    listener.settimeout(10)
    expected = bytes([0]) + bytes(range(16)) + bytes([0, 1, 1, 187, 2, 11]) + b"example.comhello"
    errors = []
    def server():
        try:
            with listener.accept()[0] as raw:
                raw.settimeout(10)
                with context.wrap_socket(raw, server_side=True) as conn:
                    if cancel:
                        try:
                            while conn.recv(4096):
                                pass
                        except (ssl.SSLError, OSError):
                            pass
                        return
                    request = bytearray()
                    while len(request) < len(expected):
                        block = conn.recv(len(expected)-len(request))
                        if not block:
                            raise RuntimeError("truncated VLESS request")
                        request += block
                    if request != expected:
                        raise RuntimeError(f"unexpected VLESS request: {request!r}")
                    conn.sendall(b"\x00")
                    time.sleep(0.02)
                    conn.sendall(b"\x01" if invalid else b"\x00world")
                    try:
                        conn.unwrap().close()
                    except (ssl.SSLError, OSError):
                        if not invalid:
                            raise
        except Exception as exc:
            errors.append(exc)
        finally:
            listener.close()
    thread = threading.Thread(target=server)
    thread.start()
    try:
        mode = "relay-cancel" if cancel else "invalid" if invalid else "relay" if relay else "valid"
        result = subprocess.run([VLESS_CLIENT, str(port), directory / "root.pem", directory / "user.uuid", mode],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if result.returncode:
            raise RuntimeError(f"VLESS client exit {result.returncode}: {result.stderr.decode(errors='replace')}")
    finally:
        thread.join(timeout=12)
    if thread.is_alive() or errors:
        raise RuntimeError(f"VLESS TLS server failed: {errors}")
    print(f"VLESS TLS {'invalid response rejected' if invalid else 'header and payload passed'}")


def vless_identity_failure(directory, upstream_port, selected=False):
    routing = 'default-outbound "edge";'
    if selected:
        (directory / "route-rules.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
        routing = ('rule-set "selected" path="route-rules.kdl" format="kdl"; '
                   'rule kind="rule-set" value="selected" outbound="edge"; default-outbound "direct";')
    for name, ca in (("wrong.example", directory / "root.pem"), ("server.example", directory / "other.pem")):
        with socket.socket() as origin, socket.socket() as reservation:
            origin.bind(("127.0.0.1", 0))
            origin.listen(1)
            origin.settimeout(1)
            origin_port = origin.getsockname()[1]
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            reservation.close()
            config = directory / "bad-identity.kdl"
            config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={upstream_port}
  authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
  tls {{ server-name "{name}"; ca-file "{ca}"; verify #true; }}
}}
routing {{ {routing} }}
''')
            process = subprocess.Popen([NEXUS, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                    try:
                        client = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline: raise
                        time.sleep(0.05)
                with client:
                    client.settimeout(8)
                    client.sendall((f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
                                    f"Host: 127.0.0.1:{origin_port}\r\n\r\n").encode())
                    response = bytearray()
                    while not response.endswith(b"\r\n\r\n"):
                        data = client.recv(1)
                        if not data or len(response)>4096: raise RuntimeError("missing identity failure response")
                        response += data
                    if not response.startswith(b"HTTP/1.1 502 "):
                        raise RuntimeError(f"identity failure bypass: {response!r}")
                try: accepted, _ = origin.accept()
                except TimeoutError: pass
                else:
                    accepted.close()
                    raise RuntimeError("TLS identity failure reached origin")
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process.stderr.close()
            if process.returncode != 0: raise RuntimeError("identity failure proxy did not stop cleanly")


def vless_bad_response(directory, truncated=False, close_delimited=False, clean=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / "server.pem", directory / "server.key")
    context.set_ecdh_curve("X25519")
    with socket.socket() as upstream, socket.socket() as reservation:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(8)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        errors = []
        def peer():
            try:
                with upstream.accept()[0] as raw:
                    raw.settimeout(8)
                    with context.wrap_socket(raw, server_side=True) as conn:
                        data = bytearray()
                        while len(data) < 28:
                            part = conn.recv(28-len(data))
                            if not part: raise RuntimeError("truncated VLESS request")
                            data += part
                        if data[:18] != bytes([0]) + bytes(range(16)) + b"\x00":
                            raise RuntimeError("invalid VLESS request")
                        if close_delimited:
                            conn.sendall(b"\x00\x00HTTP/1.0 200 OK\r\n\r\nhello")
                            if clean:
                                try: conn.unwrap().close()
                                except (ssl.SSLError, OSError): pass
                            else:
                                socket.socket(fileno=conn.detach()).close()
                        elif truncated:
                            conn.sendall(b"\x00\x00HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab")
                            # Detach and close the TCP socket without TLS close_notify.
                            socket.socket(fileno=conn.detach()).close()
                        else:
                            conn.sendall(b"\x00\x01")
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=peer)
        thread.start()
        config = directory / "bad-response.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={upstream.getsockname()[1]}
  authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
  tls {{ server-name "server.example"; ca-file "{directory / 'root.pem'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')
        process = subprocess.Popen([NEXUS, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try:
                    client = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(0.05)
            with client:
                client.settimeout(8)
                client.sendall(b"GET http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                response = bytearray()
                while not response.endswith(b"\r\n\r\n"):
                    data = client.recv(1)
                    if not data or len(response)>4096: raise RuntimeError("missing malformed VLESS response")
                    response += data
                if close_delimited:
                    if not response.startswith(b"HTTP/1.1 200 ") or b"transfer-encoding: chunked\r\n" not in response.lower():
                        raise RuntimeError(f"close-delimited header not reframed: {response!r}")
                    body=bytearray()
                    while True:
                        data=client.recv(4096)
                        if not data: break
                        body+=data
                        if len(body)>100: raise RuntimeError("oversized reframed body")
                    expected=b"5\r\nhello\r\n" + (b"0\r\n\r\n" if clean else b"")
                    if body!=expected: raise RuntimeError(f"incorrect reframed body: {body!r}")
                elif truncated:
                    if not response.startswith(b"HTTP/1.1 200 ") or b"content-length: 5\r\n" not in response.lower():
                        raise RuntimeError(f"truncated response header: {response!r}")
                    body=bytearray()
                    while True:
                        data=client.recv(4096)
                        if not data: break
                        body+=data
                        if len(body)>5: raise RuntimeError("unexpected truncated body")
                    if body!=b"ab": raise RuntimeError(f"incorrect truncated response: {body!r}")
                elif not response.startswith(b"HTTP/1.1 502 "):
                    raise RuntimeError(f"malformed VLESS response accepted: {response!r}")
            thread.join(timeout=9)
            if thread.is_alive() or errors: raise RuntimeError(f"VLESS peer failed: {errors}")
        finally:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stderr.close()
            thread.join(timeout=9)
        if process.returncode != 0: raise RuntimeError("malformed response proxy did not stop cleanly")


def vless_stalled_handshake(directory, expire=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / "server.pem", directory / "server.key")
    context.set_ecdh_curve("X25519")
    with socket.socket() as upstream, socket.socket() as reservation:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(4)
        upstream.settimeout(8)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        config = directory / "stalled-handshake.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={upstream.getsockname()[1]}
  authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
  tls {{ server-name "server.example"; ca-file "{directory / 'root.pem'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')
        process = subprocess.Popen([NEXUS, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        errors = []
        peer_thread = None
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try:
                    stalled = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(0.05)
            with stalled:
                stalled.settimeout(13)
                stalled.sendall(b"GET http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                with upstream.accept()[0] as held:
                    held.settimeout(8)
                    if not held.recv(1): raise RuntimeError("missing stalled TLS ClientHello")
                    def serve_second():
                        try:
                            with upstream.accept()[0] as raw:
                                raw.settimeout(8)
                                with context.wrap_socket(raw, server_side=True) as conn:
                                    data = bytearray()
                                    while b"\r\n\r\n" not in data:
                                        part=conn.recv(4096)
                                        if not part or len(data)>20000: raise RuntimeError("truncated second request")
                                        data += part
                                    if data[:18] != bytes([0]) + bytes(range(16)) + b"\x00":
                                        raise RuntimeError("invalid second VLESS request")
                                    conn.sendall(b"\x00\x00HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        except Exception as exc:
                            errors.append(exc)
                    peer_thread = threading.Thread(target=serve_second)
                    peer_thread.start()
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as second:
                        second.settimeout(8)
                        second.sendall(b"GET http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                        response=bytearray()
                        while b"\r\n\r\n" not in response or not response.endswith(b"ok"):
                            data=second.recv(4096)
                            if not data or len(response)>4096: raise RuntimeError("second request failed")
                            response+=data
                        if not response.startswith(b"HTTP/1.1 200 "): raise RuntimeError(f"second response: {response!r}")
                    peer_thread.join(timeout=9)
                    if peer_thread.is_alive() or errors: raise RuntimeError(f"second TLS peer failed: {errors}")
                    if expire:
                        started=time.monotonic()
                        response=bytearray()
                        while True:
                            data=stalled.recv(4096)
                            if not data: break
                            response+=data
                            if len(response)>4096: raise RuntimeError("oversized expiration response")
                        if response and not response.startswith(b"HTTP/1.1 502 "):
                            raise RuntimeError(f"unexpected expiration response: {response!r}")
                        elapsed=time.monotonic()-started
                        if elapsed>12: raise RuntimeError(f"handshake expiration took {elapsed:.1f}s")
                    process.terminate()
                    process.wait(timeout=5)
                    if not expire and stalled.recv(1) != b"": raise RuntimeError("stalled client remained open")
                    while held.recv(4096): pass
            if process.returncode != 0: raise RuntimeError(f"stalled handshake stop failed: {process.returncode}")
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stderr.close()
            if peer_thread: peer_thread.join(timeout=9)
