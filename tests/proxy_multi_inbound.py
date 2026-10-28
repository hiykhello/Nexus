"""Exercise multiple configured listeners, authentication and startup rollback."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(workers, occupied=False, bad_credentials=False):
    ports = [free_port() for _ in range(3)]
    if len(set(ports)) != len(ports):
        return run(workers, occupied, bad_credentials)
    with tempfile.TemporaryDirectory() as tmp, socket.socket() as target:
        password = pathlib.Path(tmp) / "password"
        password.write_text("secret\n")
        password.chmod(0o644 if bad_credentials else 0o600)
        (pathlib.Path(tmp) / "blocked.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\n')
        target.bind(("127.0.0.1", 0))
        target.listen(8)
        target.settimeout(3)
        config = pathlib.Path(tmp) / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{
  socks5 "plain" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
  mixed "mixed" {{ listen host="127.0.0.1" port={ports[1]}; authentication "none"; }}
  socks5 "password" {{ listen host="127.0.0.1" port={ports[2]}; authentication "password" username="alice" password-file="{password}"; }}
}}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ rule-set "blocked" path="blocked.kdl" format="kdl"; rules {{ - kind="rule-set" value="blocked" outbound="reject"; }}; default-outbound "direct"; }}
''')
        blocker = socket.socket()
        if occupied:
            blocker.bind(("127.0.0.1", ports[1]))
            blocker.listen(1)
        process = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            if occupied or bad_credentials:
                process.wait(timeout=5)
                if process.returncode == 0:
                    raise RuntimeError("invalid startup accepted")
                with socket.socket() as check:
                    check.bind(("127.0.0.1", ports[0]))
                if bad_credentials:
                    for port in ports[1:]:
                        with socket.socket() as check:
                            check.bind(("127.0.0.1", port))
                return
            for port in ports:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"proxy exited: {process.stderr.read()!r}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
            for index, port in enumerate(ports):
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.settimeout(3)
                    if index == 1:
                        client.sendall(f"CONNECT 127.0.0.1:{target.getsockname()[1]} HTTP/1.1\r\nHost: 127.0.0.1:{target.getsockname()[1]}\r\n\r\n".encode())
                        response = b""
                        while b"\r\n\r\n" not in response:
                            response += client.recv(1)
                        assert response.startswith(b"HTTP/1.1 200 ")
                    else:
                        client.sendall(b"\x05\x01" + (b"\x02" if index == 2 else b"\x00"))
                        assert exact(client, 2) == (b"\x05\x02" if index == 2 else b"\x05\x00")
                        if index == 2:
                            client.sendall(b"\x01\x05alice\x06secret")
                            assert exact(client, 2) == b"\x01\x00"
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
                        assert exact(client, 10)[:2] == b"\x05\x00"
                    with target.accept()[0] as upstream:
                        upstream.sendall(b"ok")
                        assert exact(client, 2) == b"ok"
            for index, port in enumerate(ports):
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.settimeout(3)
                    if index == 1:
                        client.sendall(b"CONNECT blocked.test:80 HTTP/1.1\r\nHost: blocked.test:80\r\n\r\n")
                        assert exact(client, 12) == b"HTTP/1.1 403"
                    else:
                        client.sendall(b"\x05\x01" + (b"\x02" if index == 2 else b"\x00"))
                        assert exact(client, 2) == (b"\x05\x02" if index == 2 else b"\x05\x00")
                        if index == 2:
                            client.sendall(b"\x01\x05alice\x06secret")
                            assert exact(client, 2) == b"\x01\x00"
                        client.sendall(b"\x05\x01\x00\x03\x0cblocked.test\x00\x50")
                        assert exact(client, 10)[:2] == b"\x05\x02"
            pending = [socket.create_connection(("127.0.0.1", port), timeout=3) for port in ports]
            try:
                for client in pending:
                    client.settimeout(3)
                    client.sendall(b"\x05")
                process.terminate()
                process.wait(timeout=5)
                for client in pending:
                    try:
                        if client.recv(1) != b"":
                            raise RuntimeError("incomplete session not closed on stop")
                    except ConnectionResetError:
                        pass
            finally:
                for client in pending:
                    client.close()
        finally:
            blocker.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            if not occupied and not bad_credentials and process.returncode:
                raise RuntimeError(f"proxy exit {process.returncode}: {process.stderr.read()!r}")


for workers in (1, 2):
    run(workers)
    run(workers, occupied=True)
    run(workers, bad_credentials=True)
print("multiple listeners, separate authentication, shared blocking, forwarding and rollback passed")
