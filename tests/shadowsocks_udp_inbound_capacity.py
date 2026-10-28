"""Exercise the configured maximum number of same-key UDP listeners."""
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
with tempfile.TemporaryDirectory(prefix="nexus-udp-inbounds-") as directory:
    root = pathlib.Path(directory)
    key = root / "key"
    key.write_text(base64.b64encode(bytes(range(16))).decode() + "\n")
    key.chmod(0o600)
    sockets = [socket.socket() for _ in range(16)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()
    config = root / "server.kdl"
    entries = [f'shadowsocks "s{i}" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}' for i, port in enumerate(ports)]
    def write_config(items):
        config.write_text('schema-version 1\nrole "server"\nworkers 1\ninbounds {\n' + '\n'.join(items) + '\n}\noutbounds { direct "direct"; block "reject"; }\nrouting { default-outbound "direct"; }\n')
    write_config(entries + [f'shadowsocks "overflow" {{ listen host="127.0.0.1" port=65535; method "2022-blake3-aes-128-gcm"; key-file "{key}"; }}'])
    if subprocess.run([nexus, "run", "--config", config], capture_output=True, timeout=10).returncode == 0:
        raise RuntimeError("17 inbounds accepted")
    write_config(entries)
    server = subprocess.Popen(["stdbuf", "-oL", nexus, "run", "--config", config], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        for _ in ports:
            if not select.select([server.stdout], [], [], 15)[0] or b"listening" not in server.stdout.readline():
                raise RuntimeError("listener startup failed")
        subprocess.run([client, str(ports[0]), "16", "multi", str(ports[-1])], check=True, timeout=10)
        server.send_signal(signal.SIGTERM)
        _, error = server.communicate(timeout=15)
        if server.returncode:
            raise RuntimeError(f"stop failed: {error!r}")
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate()
print("SS-2022 16 same-key listeners and inbound limit passed")
