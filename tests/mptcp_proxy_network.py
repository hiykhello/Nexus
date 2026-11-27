"""Verify direct outbound negotiates MPTCP and can reach an ordinary TCP peer."""
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from dns_rule_support import free_port, stream_request

binary = Path(sys.argv[1]).resolve()
front = free_port()
with tempfile.TemporaryDirectory(prefix="nexus-mptcp-") as directory:
    config = Path(directory) / "config.kdl"
    config.write_text(f'''schema-version 1
role "client"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ multipath-tcp #true; }}
routing {{ final "direct"; }}
''')
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
        for protocol in (262, socket.IPPROTO_TCP):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol) as listener:
                listener.bind(("127.0.0.1", 0));listener.listen(1);listener.settimeout(5)
                errors = []
                def serve():
                    try:
                        conn, _ = listener.accept()
                        with conn:
                            conn.settimeout(5)
                            if protocol == 262:
                                info = conn.getsockopt(284, 1, 128)
                                flags = struct.unpack_from("=I", info, 8)[0]
                                assert flags & 2 and not flags & 1, flags
                            data = conn.recv(64)
                            conn.sendall(data)
                    except Exception as error:
                        errors.append(error)
                thread = threading.Thread(target=serve);thread.start()
                stream_request(front, listener.getsockname()[1], "127.0.0.1")
                thread.join(timeout=6)
                assert not thread.is_alive() and not errors, errors
    finally:
        process.terminate();_, stderr = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError(stderr.decode())
print("MPTCP direct negotiation and ordinary TCP fallback passed")
