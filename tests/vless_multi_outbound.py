"""Route two addresses to different VLESS instances against a real TLS peer."""
import socket
import subprocess
import time

from interop_common import NEXUS, PROXY_WORKERS


def multi_outbound(directory, upstream_port):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        closed_port = reserve.getsockname()[1]
    (directory / "multi-rules.kdl").write_text(
        'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.1/32"\n')
    for first, fallback in (("good", "closed"), ("closed", "good")):
        with socket.socket() as origin, socket.socket() as reservation:
            origin.bind(("0.0.0.0", 0))
            origin.listen(2)
            origin.settimeout(3)
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            reservation.close()
            target = origin.getsockname()[1]
            config = directory / "multi-outbound.kdl"
            def outbound(name, upstream):
                return f'''vless "{name}" {{
 server host="127.0.0.1" port={upstream}
 authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
 tls {{ server-name "server.example"; ca-file "{directory / 'root.pem'}"; verify #true; }}
}}'''
            config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; {outbound("good", upstream_port)}; {outbound("closed", closed_port)}; }}
routing {{
 rulesets {{ "selected" path="multi-rules.kdl" format="kdl"; }}
 rules {{ - rule-set="selected" to="{first}"; }}
 final "{fallback}"
}}
''')
            proc = subprocess.Popen([NEXUS, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if proc.poll() is not None:
                        raise RuntimeError(proc.stderr.read().decode())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.02)
                for host, selected in (("127.0.0.1", first), ("127.0.0.2", fallback)):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                        client.settimeout(5)
                        client.sendall(f"CONNECT {host}:{target} HTTP/1.1\r\nHost: {host}:{target}\r\n\r\n".encode())
                        header = bytearray()
                        while not header.endswith(b"\r\n\r\n"):
                            part = client.recv(1)
                            if not part or len(header)>4096: raise RuntimeError("missing CONNECT response")
                            header += part
                        expected = b"200" if selected == "good" else b"502"
                        if header.split(b" ")[1] != expected: raise RuntimeError(f"wrong outbound: {header!r}")
                        if selected == "good":
                            with origin.accept()[0] as peer:
                                peer.settimeout(5)
                                client.sendall(b"ping")
                                if peer.recv(4) != b"ping": raise RuntimeError("wrong upstream payload")
                                peer.sendall(b"pong")
                                if client.recv(4) != b"pong": raise RuntimeError("wrong downstream payload")
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                if proc.returncode != 0: raise RuntimeError(proc.stderr.read().decode())
                proc.stderr.close()
