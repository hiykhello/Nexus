"""Check stopping while a system DNS call is blocked."""
import os
import base64
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile

listener, client, shim = (pathlib.Path(arg).resolve() for arg in sys.argv[1:4])
configured = len(sys.argv) > 4 and sys.argv[4] == "config"
ready_r, ready_w = os.pipe()
gate_r, gate_w = os.pipe()
env = os.environ.copy()
env.update(LD_PRELOAD=str(shim), NEXUS_TEST_RESOLVER_READY_FD=str(ready_w), NEXUS_TEST_RESOLVER_GATE_FD=str(gate_r))
directory = tempfile.TemporaryDirectory(prefix="nexus-udp-stall-")
if configured:
    root = pathlib.Path(directory.name)
    key = root / "key"; key.write_text(base64.b64encode(bytes(range(16))).decode() + "\n"); key.chmod(0o600)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
    config = root / "server.kdl"
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; block "reject"; }}
routing {{ final "direct"; }}
dns {{ server "system" type="local"; }}
''')
    command = ["stdbuf", "-oL", listener, "run", "--config", config]
else:
    command = [listener, "16", "53", "system-stall"]
server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, env=env, pass_fds=(ready_w, gate_r))
os.close(ready_w); os.close(gate_r)
try:
    if configured:
        if not select.select([server.stdout], [], [], 10)[0] or "listening" not in server.stdout.readline():
            raise RuntimeError("configured listener failed to start")
    else:
        port = int(server.stdout.readline())
    subprocess.run([client, str(port), "16", "system-stall"], check=True, timeout=2)
    if not select.select([ready_r], [], [], 2)[0] or os.read(ready_r, 1) != b"x":
        raise RuntimeError("system resolver did not enter the gate")
    if configured: server.send_signal(signal.SIGTERM)
    try:
        server.wait(timeout=3.5)
    except subprocess.TimeoutExpired:
        pass
    else:
        raise RuntimeError(f"listener exited while resolver was gated: {server.returncode}, {server.stderr.read()}")
    os.write(gate_w, b"x")
    if server.wait(timeout=5):
        raise RuntimeError(f"listener failed: {server.returncode}, {server.stderr.read()}")
finally:
    if server.poll() is None:
        try: os.write(gate_w, b"x")
        except OSError: pass
        try: server.wait(timeout=5)
        except subprocess.TimeoutExpired: server.kill(); server.wait()
    os.close(ready_r); os.close(gate_w)
    directory.cleanup()
print("SS-2022 UDP system DNS gated stop and drain passed")
