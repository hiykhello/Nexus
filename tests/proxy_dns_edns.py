"""Exercise EDNS negotiation through the actual proxy and a loopback DNS peer."""
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()
guard = pathlib.Path(sys.argv[2]).resolve()


def exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def scenario(mode, tcp, workers):
    stop = threading.Event()
    queries = []
    retried = threading.Event()
    retry_closed = threading.Event()
    errors = []
    accepted = []
    sockets = []
    threads = []

    def listen(kind, port=0):
        sock = socket.socket(socket.AF_INET, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        if kind == socket.SOCK_STREAM:
            sock.listen(8)
        sock.settimeout(0.1)
        sockets.append(sock)
        return sock

    def launch(function, *args):
        thread = threading.Thread(target=function, args=args)
        thread.start()
        threads.append(thread)

    def respond(query, transport):
        question = b"\x06target\x04test\x00\x00\x01\x00\x01"
        if query[12:12+len(question)] != question:
            raise RuntimeError("unexpected question")
        tail = query[12+len(question):]
        edns = query[10:12] == b"\x00\x01"
        if edns and tail != b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00":
            raise RuntimeError("bad EDNS query")
        if not edns and (query[10:12] != b"\x00\x00" or tail):
            raise RuntimeError("bad plain query")
        queries.append((transport, edns))
        result = bytearray(query[:12+len(question)])
        result[2:4] = b"\x81\x80"
        result[6:12] = bytes(6)
        if mode in ("fallback", "fallback-timeout", "fallback-stop") and edns:
            if mode == "fallback-timeout":
                stop.wait(2)
            result[3] = 0x81
            return result
        if mode == "formerr-opt":
            result[3] = 0x81
        elif mode in ("nxdomain", "servfail", "nxdomain-cache", "nodata-cache"):
            result[3] = 0x83 if mode in ("nxdomain", "nxdomain-cache") else 0x82 if mode == "servfail" else 0x80
            if mode.endswith("-cache"):
                result[9] = 1
                result.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(16) + (60).to_bytes(4, "big"))
        elif mode == "badvers":
            pass
        elif mode == "truncated" and transport == "udp":
            result[2] |= 2
            return result
        else:
            result[7] = 1
            result.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
        if edns and mode != "missing-opt":
            result[11] = 1
            ext = 1 if mode == "badvers" else 0
            options = b"\x00\x08\x00\x00" if mode == "unsupported-option" else b""
            result.extend(b"\x00\x00\x29\x04\xd0" + bytes([ext, 0, 0, 0]) + len(options).to_bytes(2, "big") + options)
        return result

    def udp_server(sock):
        try:
            while not stop.is_set():
                try:
                    query, peer = sock.recvfrom(512)
                except TimeoutError:
                    continue
                result = respond(query, "udp")
                if mode in ("fallback-timeout", "fallback-stop") and query[10:12] == b"\x00\x00":
                    retried.set()
                    continue
                sock.sendto(result, peer)
        except Exception as exc:
            errors.append(exc)

    def tcp_server(sock):
        try:
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                with conn:
                    conn.settimeout(2)
                    query = exact(conn, int.from_bytes(exact(conn, 2), "big"))
                    result = respond(query, "tcp")
                    if mode == "fallback-stop" and query[10:12] == b"\x00\x00":
                        retried.set()
                        conn.settimeout(0.1)
                        while not stop.is_set():
                            try:
                                if not conn.recv(1):
                                    retry_closed.set()
                                    break
                            except TimeoutError:
                                continue
                        continue
                    frame = len(result).to_bytes(2, "big") + result
                    conn.sendall(frame[:1])
                    conn.sendall(frame[1:])
        except Exception as exc:
            errors.append(exc)

    def target_server(sock):
        try:
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                with conn:
                    accepted.append(True)
                    conn.sendall(b"ok")
        except Exception as exc:
            errors.append(exc)

    try:
        dns_tcp = listen(socket.SOCK_STREAM)
        dns_udp = listen(socket.SOCK_DGRAM, dns_tcp.getsockname()[1])
        target = listen(socket.SOCK_STREAM)
        probe = listen(socket.SOCK_STREAM)
        port = probe.getsockname()[1]
        sockets.remove(probe)
        probe.close()
        launch(udp_server, dns_udp)
        launch(tcp_server, dns_tcp)
        launch(target_server, target)
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "proxy.kdl"
            config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{ servers {{ server "upstream" type="{'tcp' if tcp else 'udp'}" host="127.0.0.1" port={dns_tcp.getsockname()[1]}; }}; strategy "ipv4_only"; edns #true; }}
inbounds {{ inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}; }}
outbounds {{ outbound "direct" type="direct"; }}
routing {{ default-outbound "direct"; }}
''')
            env = os.environ.copy()
            env["LD_PRELOAD"] = str(guard)
            proc = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if proc.poll() is not None:
                        raise RuntimeError(f"proxy exited: {proc.stderr.read()!r}")
                    try:
                        client = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                success = mode in ("success", "fallback", "truncated")
                for index in range(2 if mode in ("success", "nxdomain-cache", "nodata-cache") and workers == 1 else 1):
                    if index:
                        client = socket.create_connection(("127.0.0.1", port), timeout=2)
                    with client:
                        client.settimeout(13)
                        client.sendall(b"\x05\x01\x00")
                        assert exact(client, 2) == b"\x05\x00"
                        name = b"target.test"
                        client.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target.getsockname()[1].to_bytes(2, "big"))
                        started = time.monotonic()
                        if mode == "fallback-stop":
                            if not retried.wait(3):
                                raise RuntimeError("plain retry was not sent")
                            proc.terminate()
                            proc.wait(timeout=5)
                        reply = exact(client, 10) if mode != "fallback-stop" else client.recv(10)
                        if mode == "fallback-stop":
                            assert reply == b""
                            if tcp and not retry_closed.wait(2):
                                raise RuntimeError("TCP retry was not closed on stop")
                            continue
                        if mode == "fallback-timeout" and not 8 <= time.monotonic() - started <= 12:
                            raise RuntimeError("fallback did not share the original deadline")
                        assert reply[:4] == (b"\x05\x00\x00\x01" if success else b"\x05\x04\x00\x01")
                        if success:
                            assert exact(client, 2) == b"ok"
                protocol = "tcp" if tcp else "udp"
                expected = [(protocol, True), (protocol, False)] if mode in ("fallback", "fallback-timeout", "fallback-stop") else (
                    [("udp", True), ("tcp", True)] if mode == "truncated" else [(protocol, True)])
                if queries != expected or errors or bool(accepted) != success:
                    raise RuntimeError(f"mode={mode} queries={queries} errors={errors} accepted={accepted}")
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=5)
                stderr = proc.stderr.read()
                if proc.returncode or b"unexpected-system-resolver" in stderr:
                    raise RuntimeError(f"proxy exit {proc.returncode}: {stderr!r}")
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
        for sock in sockets:
            sock.close()


for workers in (1, 2):
    for tcp in (False, True):
        for mode in ("success", "fallback", "missing-opt", "unsupported-option", "badvers", "formerr-opt", "nxdomain", "servfail"):
            scenario(mode, tcp, workers)
    scenario("truncated", False, workers)
    scenario("fallback-timeout", False, workers)
    scenario("fallback-stop", False, workers)
    scenario("fallback-stop", True, workers)
    if workers == 1:
        scenario("nxdomain-cache", False, workers)
        scenario("nodata-cache", True, workers)
print("EDNS proxy negotiation and boundaries passed")
