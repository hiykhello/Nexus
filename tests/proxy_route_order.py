#!/usr/bin/env python3
"""Exercise ordered rule sets through the real proxy and startup validation."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()

def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError("unexpected EOF")
        data += part
    return data

def run(root, first, second, expected):
    with socket.socket() as target, socket.socket() as reserve:
        target.bind(("127.0.0.1", 0))
        target.listen(4)
        target.settimeout(1)
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        reserve.close()
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbounds {{ mixed "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; block "reject"; }}
routing {{
 rulesets {{
     "a" path="a.kdl" format="kdl"
     "b" path="b.kdl" format="kdl"
 }}
 rules {{ - rule-set="a" to="{first}"; - rule-set="b" to="{second}"; }}
 final "direct"
}}
''')
        proc = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise AssertionError(proc.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                assert exact(client, 2) == b"\x05\x00"
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.getsockname()[1].to_bytes(2, "big"))
                response = exact(client, 10)
                assert response[1] == (0 if expected else 2), response
                if expected:
                    with target.accept()[0] as peer:
                        client.sendall(b"hello")
                        assert exact(peer, 5) == b"hello"
                        peer.sendall(b"world")
                        assert exact(client, 5) == b"world"
                else:
                    try:
                        target.accept()[0].close()
                    except TimeoutError:
                        pass
                    else:
                        raise AssertionError("blocked request reached target")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            assert proc.returncode == 0, proc.stderr.read().decode()

with tempfile.TemporaryDirectory(prefix="nexus-route-order-") as directory:
    root = pathlib.Path(directory)
    for name in ("a", "b"):
        (root / f"{name}.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
    run(root, "direct", "reject", True)
    run(root, "reject", "direct", False)
    (root / "b.kdl").write_text("invalid")
    result = subprocess.run([binary, "run", "--config", root / "config.kdl"], capture_output=True, timeout=5)
    assert result.returncode != 0 and (b"invalid routing" in result.stderr or b"routing rules" in result.stderr), result.stderr
    large = 'schema-version 2\nkind "predicate"\n' + 'rule type="ip-cidr" value="127.0.0.0/8"\n' * 9000
    (root / "a.kdl").write_text(large)
    (root / "b.kdl").write_text(large)
    run(root, "direct", "reject", True)
print("ordered routing and startup validation passed")
