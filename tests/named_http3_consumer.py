from pathlib import Path
import os
import select
import subprocess
import sys
import tempfile

from dns_rule_support import DnsPeer, free_port
from udp_bind_port_network import certificate

resume = sys.argv[3] if len(sys.argv) == 4 else None

with tempfile.TemporaryDirectory(prefix="nexus-named-http-") as temp, DnsPeer() as dns:
    root = Path(temp)
    certificate(root)
    config, rules = root / "client.kdl", root / "rules.kdl"
    rules.write_bytes(b'schema-version 2\nkind "predicate"\nrule type="domain" value="test.invalid"\n' + b'\n' * 140000)
    config.write_text(f'''schema-version 1
role "client"
inbound "input" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "physical" type="direct" {{ inet4-bind-address "127.0.0.2"; }}
dns {{ server "bootstrap" type="udp" host="127.0.0.1" port={dns.port}; final "bootstrap"; strategy "ipv4_only"; }}
http-clients {{
    updates {{ outbound "physical"; domain-resolver "bootstrap"; ca-file "{root / 'cert'}"; protocol "h3"; }}
}}
routing {{ default-outbound "physical"; }}
''')
    env = dict(os.environ, NEXUS_TEST_MAX_PACKET="1500")
    with subprocess.Popen([sys.argv[2], root/"cert", root/"key", rules], env=env,
                          stdout=subprocess.PIPE, bufsize=0) as peer:
        try:
            if not select.select([peer.stdout], [], [], 4)[0]:
                raise RuntimeError("HTTP/3 peer did not start")
            port = peer.stdout.readline().decode().strip()
            port = port.rsplit(":", 1)[1]
            command = [sys.argv[1], config, f"localhost:{port}", rules]
            if resume:
                subprocess.run([*command, "--resume"], check=True, timeout=23)
                reports = []
                for _ in range(2):
                    if not select.select([peer.stdout], [], [], 2)[0]:
                        raise RuntimeError("missing HTTP/3 ticket report")
                    reports.append(peer.stdout.readline().split())
                first, second = reports
                if (len(first) != 3 or len(second) != 3 or first[0] != b"resume" or second[0] != b"resume" or
                        first[1] == second[1] or first[2] != b"false" or second[2] != resume.encode()):
                    raise RuntimeError(f"unexpected HTTP/3 recovery events: {reports}")
                print(f"HTTP/3 idle retirement opened a new connection, resumed={resume}")
            else:
                subprocess.run(command, check=True, timeout=6)
                expected = {b"/consumer-warm", b"/consumer-slow", b"/consumer-reject",
                            b"stream-canceled", b"/consumer-after"}
                connections = set()
                for _ in range(len(expected)):
                    if not select.select([peer.stdout], [], [], 2)[0]:
                        raise RuntimeError("missing HTTP/3 peer event")
                    label, connection = peer.stdout.readline().split()
                    expected.remove(label)
                    connections.add(connection)
                if len(connections) != 1:
                    raise RuntimeError(f"requests used several QUIC connections: {connections}")
                print("Independent peer observed one QUIC connection and a canceled request stream")
        finally:
            if peer.poll() is None:
                peer.terminate()
                peer.wait(timeout=3)
