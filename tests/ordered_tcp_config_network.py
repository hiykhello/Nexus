import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from ordered_tcp_network import exact, headers


def main():
    peer = socket.socket()
    peer.bind(("127.0.0.1", 0))
    peer.listen(1)
    peer.settimeout(5)
    destination = peer.getsockname()[1]
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    errors = []
    payload = b"GET / HTTP/1.1\r\nHost: ok.example\r\n\r\nbody"

    def serve():
        try:
            conn, _ = peer.accept()
            with conn:
                conn.settimeout(5)
                assert exact(conn, len(payload)) == payload
                conn.sendall(b"OK")
            conn, _ = peer.accept()
            with conn:
                conn.settimeout(5)
                forwarded = headers(conn)
                assert forwarded.startswith(b"POST /path HTTP/1.1\r\n"), forwarded
                assert exact(conn, 4) == b"body"
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "blocked.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.example"\n')
        direct_options = '{ tcp-fast-open #true; }' if os.getenv("NEXUS_TEST_TFO_DIRECT") else ""
        (root / "config.kdl").write_text(f'''schema-version 1
role "client"
inbounds {{
    mixed "local" {{
        listen host="127.0.0.1" port={port}
        authentication "none"
    }}
}}
outbounds {{ direct "direct" {direct_options}; }}
routing {{
    rule-set "blocked" path="blocked.kdl" format="kdl"
    tcp-program sniff-timeout-ms=100 unknown="skip" {{
        rule action="sniff"
        rule action="reject" rule-set="blocked" domain-source="sniffed"
        rule action="route" outbound="direct"
    }}
    default-outbound "direct"
}}
''')
        proc = subprocess.Popen([sys.argv[1], "run", "--config", str(root / "config.kdl")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if proc.poll() is not None:
                    raise AssertionError(proc.stderr.read().decode())
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=.1)
                    break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError("listener did not start")
            with sock:
                sock.settimeout(5)
                sock.sendall(f"CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n".encode() + payload)
                assert headers(sock).startswith(b"HTTP/1.1 200 ")
                assert exact(sock, 2) == b"OK"
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(f"POST http://127.0.0.1:{destination}/path HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\nContent-Length: 4\r\n\r\nbody".encode())
                assert headers(sock).startswith(b"HTTP/1.1 200 ")
                assert exact(sock, 2) == b"OK"
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(b"GET http://blocked.example/ HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
                assert headers(sock).startswith(b"HTTP/1.1 403 ")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(f"CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n".encode() + b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
                assert headers(sock).startswith(b"HTTP/1.1 403 ")
            thread.join(5)
            assert not thread.is_alive() and not errors, errors
            print("ordered TCP configuration, CONNECT replay, HTTP forward and reject passed")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            peer.close()
            thread.join(5)


if __name__ == "__main__":
    main()
