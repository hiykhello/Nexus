#!/usr/bin/env python3
"""Exercise the real CLI, its config-relative rule file, and SOCKS5 traffic."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

server = pathlib.Path(sys.argv[1]).resolve()
crypto = len(sys.argv) > 2 and sys.argv[2] == "--crypto"
converter = server


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError("unexpected EOF")
        data += part
    return data


def greet(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    sock.sendall(b"\x05\x01\x00")
    assert exact(sock, 2) == b"\x05\x00"
    return sock


def configuration(port, rule_format):
    return f'''schema-version 1
role "client"
inbound "local" type="socks5" {{
  listen host="127.0.0.1" port={port}
  authentication "none"
}}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{
  rule-set "blocked" path="rules/blocked.{rule_format}" format="{rule_format}"
  rules {{ - kind="rule-set" value="blocked" outbound="reject"; }}
  default-outbound "direct"
}}
'''


def run_valid(root, rule_format):
    port = unused_port()
    config = root / "config.kdl"
    config.write_text(configuration(port, rule_format))
    proc = subprocess.Popen([server, "run", "--config", config], cwd="/", stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if proc.poll() is not None:
                raise AssertionError("server exited: " + proc.stderr.read().decode())
            try:
                client = greet(port)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        with client:
            client.sendall(b"\x05\x01\x00\x03\x0cblocked.test\x00\x50")
            assert exact(client, 10)[:4] == b"\x05\x02\x00\x01"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            target_port = listener.getsockname()[1]
            target_result = []

            def target():
                try:
                    with listener.accept()[0] as peer:
                        peer.settimeout(3)
                        payload = exact(peer, 5)
                        peer.sendall(payload.upper())
                        target_result.append(True)
                except Exception as error:
                    target_result.append(error)

            thread = threading.Thread(target=target)
            thread.start()
            try:
                with greet(port) as client:
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big") + b"hello")
                    assert exact(client, 10)[:4] == b"\x05\x00\x00\x01"
                    assert exact(client, 5) == b"HELLO"
            finally:
                thread.join(timeout=4)
            assert not thread.is_alive() and target_result == [True], target_result
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        assert proc.returncode == 0, proc.stderr.read().decode()


def run_invalid(root):
    port = unused_port()
    config = root / "invalid.kdl"
    for text in (configuration(port, "kdl").replace('type="socks5"', 'type="http"'),
                 configuration(port, "kdl").replace('rules/blocked.kdl', 'rules/missing.kdl'),
                 configuration(port, "kdl").replace('value="blocked"', 'value="missing"')):
        config.write_text(text)
        result = subprocess.run([server, "run", "--config", config], cwd="/", capture_output=True, timeout=5)
        assert result.returncode != 0
        with socket.socket() as probe:
            probe.settimeout(0.5)
            assert probe.connect_ex(("127.0.0.1", port)) != 0, "invalid config opened listener"

    vless = '''outbound "edge" type="vless" {
  server host="127.0.0.1" port=443
  authentication { uuid-file "/tmp/edge.uuid"; }
  tls { server-name "edge.example"; ca-file "/tmp/ca.pem"; verify #true; }
}
'''
    text = configuration(port, "kdl").replace('routing {', vless + 'routing {')
    config.write_text(text.replace('default-outbound "direct"', 'default-outbound "edge"'))
    result = subprocess.run([server, "run", "--config", config], cwd="/", capture_output=True, timeout=5)
    expected = b"UUID file:" if crypto else b"VLESS outbound is not yet available"
    assert result.returncode != 0 and expected in result.stderr, result.stderr
    with socket.socket() as probe:
        probe.settimeout(0.5)
        assert probe.connect_ex(("127.0.0.1", port)) != 0, "unavailable VLESS opened listener"
    if crypto:
        uuid = root / "user.uuid"
        uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n")
        uuid.chmod(0o600)
        ca = root / "ca.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", root / "ca.key", "-out", ca, "-days", "1", "-subj", "/CN=Test CA"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run([server.with_name("nexus-vless-server-test"), uuid, ca], check=True, timeout=5)
        config.write_text(config.read_text().replace("/tmp/edge.uuid", str(uuid)).replace("/tmp/ca.pem", str(ca)))
        valid_text = config.read_text()
        bad_outbound = vless.replace('"edge"', '"bad"').replace('/tmp/ca.pem', str(ca))
        config.write_text(valid_text.replace('routing {', bad_outbound + 'routing {').replace('outbound="reject"', 'outbound="bad"'))
        failed = subprocess.run([server, "run", "--config", config], cwd="/", capture_output=True, timeout=5)
        assert failed.returncode != 0 and b"UUID file:" in failed.stderr, failed.stderr
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", port)) != 0, "failed second outbound opened listener"
        config.write_text(valid_text)
        proc = subprocess.Popen([server, "run", "--config", config], cwd="/", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise AssertionError(proc.stderr.read().decode())
                try:
                    with greet(port):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            assert proc.returncode == 0, proc.stderr.read().decode()


with tempfile.TemporaryDirectory(prefix="nexus-config-test-") as tmp:
    root = pathlib.Path(tmp)
    (root / "rules").mkdir()
    rule = root / "rules/blocked.kdl"
    rule.write_text('schema-version 2\nkind "predicate"\nrule type="domain-suffix" value="blocked.test"\n')
    subprocess.run([converter, "rule", "convert", "kdl", "beve", rule, root / "rules/blocked.beve"], check=True)
    # A parsed VLESS inbound must never silently start as an unauthenticated SOCKS listener.
    port = unused_port()
    config = root / "vless-inbound.kdl"
    config.write_text(f'''schema-version 1
role "server"
inbounds {{ vless "edge" {{
    listen host="127.0.0.1" port={port}
    authentication {{ user "alice" uuid-file="/tmp/user"; }}
    tls {{ certificate-file "/tmp/cert.der"; private-key-file "/tmp/key.der"; }}
}} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
    rejected = subprocess.run([server, "run", "--config", config], capture_output=True, timeout=5)
    assert rejected.returncode != 0 and b"VLESS inbound:" in rejected.stderr, rejected.stderr
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0, "invalid inbound opened listener"
    run_invalid(root)
    run_valid(root, "kdl")
    run_valid(root, "beve")
print("KDL configuration CLI, relative paths, block and direct passed")
