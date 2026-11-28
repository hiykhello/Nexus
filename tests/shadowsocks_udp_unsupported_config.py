"""A UDP route to an unimplemented tunnel must not fall back to direct."""
import base64
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile

nexus = pathlib.Path(sys.argv[1]).resolve()
client = nexus.with_name("nexus-shadowsocks-udp-rebind-test")
with tempfile.TemporaryDirectory(prefix="nexus-udp-outbound-") as directory:
    root = pathlib.Path(directory)
    (root / "direct.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.1/32"\n')
    for size in (16, 32):
        key = root / "key"
        key.write_text(base64.b64encode(bytes(range(size))).decode() + "\n")
        key.chmod(0o600)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outbound:
            outbound.bind(("127.0.0.1", 0))
            config = root / "server.kdl"
            config.write_text(f'''schema-version 1
role "server"
workers 2
inbound "ss-in" type="shadowsocks" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
outbound "ss-out" type="shadowsocks" {{ server host="127.0.0.1" port={outbound.getsockname()[1]}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }}
routing {{ rulesets {{ "allow" path="direct.kdl" format="kdl"; }}; rules {{ - rule-set="allow" to="direct"; }}; final "ss-out"; }}
''')
            server = subprocess.Popen(["stdbuf", "-oL", nexus, "run", "--config", config],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            try:
                if not select.select([server.stdout], [], [], 10)[0] or b"listening" not in server.stdout.readline():
                    raise RuntimeError("listener failed to start")
                subprocess.run([client, str(port), str(size), "unsupported"], check=True, timeout=10)
                if select.select([outbound], [], [], .1)[0]:
                    raise RuntimeError("unimplemented UDP tunnel unexpectedly sent data")
                server.send_signal(signal.SIGTERM)
                _, error = server.communicate(timeout=10)
                if server.returncode:
                    raise RuntimeError(f"server failed: {error!r}")
            finally:
                if server.poll() is None:
                    server.kill()
                    server.communicate()
print("SS-2022 configured UDP rejects unsupported outbound without direct fallback")
