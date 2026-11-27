"""Verify MPTCP reaches a real TLS Trojan peer, including direct detour."""
import hashlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from dns_rule_support import exact, free_port, stream_request

binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="nexus-mptcp-tls-") as directory:
    root = Path(directory)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(root / "key"), "-out", str(root / "cert")],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    (root / "password").write_text("secret\n")
    (root / "password").chmod(0o600)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(root / "cert", root / "key")
    for direct_detour in (False, True):
        front = free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262) as listener:
            listener.bind(("127.0.0.1", 0));listener.listen(1);listener.settimeout(8)
            peer_port = listener.getsockname()[1]
            direct_options = "multipath-tcp #true;" if direct_detour else ""
            node_options = 'detour "direct";' if direct_detour else "multipath-tcp #true;"
            config = root / "config.kdl"
            config.write_text(f'''schema-version 1
role "client"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ {direct_options} }}
outbound "remote" type="trojan" {{ server host="127.0.0.1" port={peer_port}; authentication {{ password-file "{root / 'password'}"; }}; tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}; {node_options} }}
routing {{ final "remote"; }}
''')
            failures = []
            def serve():
                try:
                    raw, _ = listener.accept()
                    with raw:
                        info = raw.getsockopt(284, 1, 128)
                        flags = struct.unpack_from("=I", info, 8)[0]
                        assert flags & 2 and not flags & 1, flags
                        with tls.wrap_socket(raw, server_side=True) as conn:
                            conn.settimeout(5)
                            assert exact(conn, 56) == hashlib.sha224(b"secret").hexdigest().encode()
                            assert exact(conn, 3) == b"\r\n\x01"
                            kind = exact(conn, 1)[0]
                            if kind == 3:
                                exact(conn, exact(conn, 1)[0])
                            else:
                                exact(conn, 4 if kind == 1 else 16)
                            exact(conn, 2)
                            assert exact(conn, 2) == b"\r\n"
                            conn.sendall(exact(conn, 15))
                except Exception as error:
                    failures.append(error)
            worker = threading.Thread(target=serve);worker.start()
            process = subprocess.Popen([str(binary), "run", "--config", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError(process.stderr.read().decode())
                    try:
                        with socket.create_connection(("127.0.0.1", front), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("listener did not start")
                stream_request(front, 443, "127.0.0.1")
                worker.join(timeout=8)
                assert not worker.is_alive() and not failures, failures
            finally:
                process.terminate();_, stderr = process.communicate(timeout=5)
                if process.returncode:
                    raise RuntimeError(stderr.decode())
print("MPTCP Trojan TLS and explicit direct detour passed")
