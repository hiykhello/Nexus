#!/usr/bin/env python3
"""Check native SS-2022 UDP generation handoff with local authenticated peers."""
import base64
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from dns_rule_support import nexus_process
from proxy_listener_reload_network import refused, reload


def configure(root, key, ports):
    config = root / "config.kdl"
    source = '''schema-version 1
role "server"
workers 2
shutdown-grace-ms 2000
outbound "direct" type="direct"
routing { default-outbound "direct"; }
'''
    for index, port in enumerate(ports):
        source += f'''inbound "edge-{index}" type="shadowsocks" {{
  listen host="127.0.0.1" port={port}
  method "2022-blake3-aes-128-gcm"
  key-file "{key}"
}}
'''
    candidate = config.with_suffix(".candidate")
    candidate.write_text(source)
    candidate.replace(config)
    return config


def step(client, expected):
    if not select.select([client.stdout], [], [], 4)[0] or client.stdout.readline() != expected:
        details = client.stderr.read() if client.poll() is not None else b""
        raise AssertionError(f"client did not reach {expected!r}, exit={client.poll()}, {details!r}")


def test(binary, client_binary, root, same_binding):
    key = root / "ss.key"
    key.write_bytes(base64.b64encode(bytes(range(16))))
    key.chmod(0o600)
    with (socket.socket() as initial, socket.socket() as replacement, socket.socket() as occupied_port,
          socket.socket(type=socket.SOCK_DGRAM) as blocked):
        for reserve in (initial, replacement, occupied_port):
            reserve.bind(("127.0.0.1", 0))
        old, new, conflict = [reserve.getsockname()[1] for reserve in (initial, replacement, occupied_port)]
        blocked.bind(("127.0.0.1", conflict))
        initial.close()
        replacement.close()
        occupied_port.close()
        if same_binding:
            new = old
        path = configure(root, key, [old])
        with nexus_process(binary, path) as proxy, subprocess.Popen(
                [client_binary, str(old), "16", "generation"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0) as client:
            try:
                step(client, b"ready\n")
                configure(root, key, [old, conflict])
                reload(proxy, b"cannot stage Shadowsocks UDP listeners")
                refused(conflict)
                client.stdin.write(b"c\n")
                step(client, b"before-publish\n")

                configure(root, key, [new])
                assert reload(proxy) == 2
                client.stdin.write(f"{new}\n".encode())
                step(client, b"draining\n")
                time.sleep(2.2)
                if not same_binding:
                    refused(old)
                    with socket.socket(type=socket.SOCK_DGRAM) as retired:
                        retired.bind(("127.0.0.1", old))
                out, errors = client.communicate(b"x\n", timeout=4)
                assert client.returncode == 0, (client.returncode, out, errors)
            finally:
                if client.poll() is None:
                    client.terminate()
                    client.wait(timeout=3)


if __name__ == "__main__":
    binary, client = (str(Path(value).resolve()) for value in sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix="nexus-native-reload-") as directory:
        for same_binding in (True, False):
            test(binary, client, Path(directory), same_binding)
    print("Native SS-2022 UDP same-bind/moved-bind admission, active relay, replay, drain and bind rollback passed")
