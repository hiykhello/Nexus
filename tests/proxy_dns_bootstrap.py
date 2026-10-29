"""Exercise DNS bootstrap server address retry and response boundaries."""
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
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result += part
    return result


def scenario(mode, workers):
    stop = threading.Event()
    errors = []
    calls = [[], [], []]
    targets = []
    sockets = []
    threads = []

    def bind(kind, host, port=0):
        sock = socket.socket(socket.AF_INET, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        if kind == socket.SOCK_STREAM:
            sock.listen(8)
        sock.settimeout(0.1)
        sockets.append(sock)
        return sock

    def launch(fn, *args):
        thread = threading.Thread(target=fn, args=args)
        thread.start()
        threads.append(thread)

    def root_server(sock):
        try:
            while not stop.is_set():
                try:
                    query, peer = sock.recvfrom(512)
                except TimeoutError:
                    continue
                if query[12:-4] != b"\x04leaf\x04test\x00" or query[-4:-2] != b"\x00\x01":
                    raise RuntimeError("unexpected bootstrap query")
                calls[0].append(query)
                answer = bytearray(query)
                answer[2:4] = b"\x81\x80"
                addresses = [b'\x00\x00\x00\x00'] if mode == 'unspecified' else [b'\x7f\x00\x00\x02', b'\x7f\x00\x00\x01']
                answer[7] = len(addresses)
                for address in addresses:
                    answer.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + address)
                sock.sendto(answer, peer)
        except Exception as exc:
            errors.append(exc)

    def leaf_server(sock, index):
        try:
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                with conn:
                    conn.settimeout(2)
                    size = int.from_bytes(exact(conn, 2), "big")
                    query = exact(conn, size)
                    if query[12:-4] != b"\x06target\x04test\x00" or query[-4:-2] != b"\x00\x01":
                        raise RuntimeError("unexpected leaf query")
                    calls[index].append(query)
                    reply = bytearray(query)
                    reply[2:4] = b"\x81\x82" if mode == "servfail" and index == 1 else b"\x81\x80"
                    if reply[3] == 0x80:
                        reply[7] = 1
                        reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                    conn.sendall(len(reply).to_bytes(2, "big") + reply)
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
                    targets.append(True)
                    conn.sendall(b"ok")
        except Exception as exc:
            errors.append(exc)

    try:
        root = bind(socket.SOCK_DGRAM, "127.0.0.1")
        leaf = bind(socket.SOCK_STREAM, "127.0.0.1")
        if mode == "servfail":
            first = bind(socket.SOCK_STREAM, "127.0.0.2", leaf.getsockname()[1])
            launch(leaf_server, first, 1)
        target = bind(socket.SOCK_STREAM, "127.0.0.1")
        probe = bind(socket.SOCK_STREAM, "127.0.0.1")
        port = probe.getsockname()[1]
        sockets.remove(probe)
        probe.close()
        launch(root_server, root)
        launch(leaf_server, leaf, 2)
        launch(target_server, target)
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "proxy.kdl"
            config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{
    server "leaf" type="tcp" host="leaf.test" port={leaf.getsockname()[1]} domain-resolver="root"
    server "root" type="udp" host="127.0.0.1" port={root.getsockname()[1]}
    strategy "ipv4_only"
}}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
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
                        sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                with sock:
                    sock.settimeout(3)
                    sock.sendall(b"\x05\x01\x00")
                    assert exact(sock, 2) == b"\x05\x00"
                    name = b"target.test"
                    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target.getsockname()[1].to_bytes(2, "big"))
                    reply = exact(sock, 10)
                    if mode in ("servfail", "unspecified"):
                        assert reply[:4] == b"\x05\x04\x00\x01"
                    else:
                        assert reply[:4] == b"\x05\x00\x00\x01"
                        assert exact(sock, 2) == b"ok"
                expected_calls = [1, 1, 0] if mode == "servfail" else [1, 0, 0] if mode == 'unspecified' else [1, 0, 1]
                if errors or [len(c) for c in calls] != expected_calls:
                    raise RuntimeError(f"unexpected server calls: {[len(c) for c in calls]}, errors={errors}")
                if bool(targets) != (mode == "retry"):
                    raise RuntimeError(f"unexpected target connections: {targets}")
            finally:
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


for count in (1, 2):
    scenario("retry", count)
    scenario("servfail", count)
    scenario("unspecified", count)
print("DNS bootstrap address retry and failure boundary passed")
