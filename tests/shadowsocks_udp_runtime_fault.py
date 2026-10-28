"""Force an invalid wall clock after startup and check UDP failure propagation."""
import base64
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile

nexus, shim = (pathlib.Path(arg).resolve() for arg in sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix="nexus-udp-clock-") as directory:
    root = pathlib.Path(directory)
    key = root / "key"
    key.write_text(base64.b64encode(bytes(range(16))).decode() + "\n")
    key.chmod(0o600)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = root / "server.kdl"
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ default-outbound "direct"; }}
''')
    marker = root / "bad-clock"
    env = os.environ.copy()
    env.update(LD_PRELOAD=str(shim), NEXUS_TEST_BAD_WALL_CLOCK=str(marker))
    server = subprocess.Popen(["stdbuf", "-oL", nexus, "run", "--config", config],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        if not select.select([server.stdout], [], [], 10)[0] or b"listening" not in server.stdout.readline():
            raise RuntimeError("listener failed to start")
        marker.touch()
        _, error = server.communicate(timeout=10)
        if server.returncode == 0 or b"shadowsocks UDP listener failed" not in error:
            raise RuntimeError(f"UDP fault not reported: {server.returncode}, {error!r}")
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as probe:
                probe.bind(("127.0.0.1", port))
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()
print("SS-2022 configured UDP runtime failure and cleanup passed")
