#!/usr/bin/env python3
"""Observe TLS version, exact browser offers, TCP resumption and H3 interop."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha224
from pathlib import Path
import select
import socket
import ssl
import subprocess
import tempfile

from batch94b_xhttp_network import (
    credentials, exchange, nexus_command, reserve_edge, running_edge, xray_command,
)
from detour_network import exact, reserve, running, socks
from dns_rule_support import DnsPeer, nexus_process
from quic_ech_cli import certificate, generate, go_peer, make_config, open_socks
from tls_fingerprint_cli import Observer, grease

PROFILES = ("chrome", "chrome-133", "edge", "firefox", "firefox-135", "safari", "safari-18")
PASSWORD = "utls-network-fixture"
LEGACY_SUITES = {0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca8, 0xcca9}


def create_certificate(root):
    (root / "password").write_text(PASSWORD)
    (root / "password").chmod(0o600)
    for prefix in ("origin", "extra"):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-keyout", root / f"{prefix}.key", "-out", root / f"{prefix}.crt", "-days", "1",
            "-subj", f"/CN={prefix}", "-addext", "subjectAltName=DNS:localhost,DNS:alternate.local",
        ], check=True, capture_output=True)
    (root / "bundle.crt").write_bytes((root / "origin.crt").read_bytes() + (root / "extra.crt").read_bytes())


def command(binary, root, front, upstream, fingerprint, name, ca):
    config = root / "trojan.kdl"
    config.write_text(f'''schema-version 1
role "client"
outbound "direct" type="direct"
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "node" type="trojan" {{
  server host="127.0.0.1" port={upstream}
  authentication {{ password-file "{root / "password"}"; }}
  tls {{ server-name "{name}"; ca-file "{root / ca}"; verify #true; fingerprint "{fingerprint}"; }}
}}
routing {{ default-outbound "node"; }}
''')
    return [binary, "run", "--config", config]


def version_context(root, version, cipher=None, reuse=True):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = server.maximum_version = version
    server.load_cert_chain(root / "origin.crt", root / "origin.key")
    if cipher:
        server.set_ciphers(cipher)
    if version == ssl.TLSVersion.TLSv1_3:
        server.num_tickets = 2 if reuse else 0
    return server


def relay(peer):
    assert exact(peer, 58) == sha224(PASSWORD.encode()).hexdigest().encode() + b"\r\n"
    assert exact(peer, 2) == b"\x01\x01"
    assert exact(peer, 8) == b"\x7f\x00\x00\x01\x1f\x90\r\n"
    data = exact(peer, 262144)
    peer.sendall(data[::-1])
    return peer.version(), peer.cipher()[0], peer.session_reused


def accept_one(listener, server):
    conn, _ = listener.accept()
    with conn:
        conn.settimeout(7)
        with server.wrap_socket(conn, server_side=True) as peer:
            return relay(peer)


def test_once(front, listener, server, pool):
    job = pool.submit(accept_one, listener, server)
    with socks(front, 1, ("127.0.0.1", 8080))[0] as tunnel:
        tunnel.settimeout(7)
        data = bytes(range(256)) * 1024
        tunnel.sendall(data)
        assert exact(tunnel, len(data)) == data[::-1]
    return job.result(timeout=8)


def tcp_matrix(binary, root):
    with ThreadPoolExecutor(max_workers=1) as pool:
        for version in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
            server = version_context(root, version, reuse=False)
            for profile in PROFILES:
                tcp_case(binary, root, pool, server, version, profile)
        chacha = version_context(root, ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-CHACHA20-POLY1305")
        tcp_case(binary, root, pool, chacha, ssl.TLSVersion.TLSv1_2, "chrome-133")


def tcp_case(binary, root, pool, server, version, profile):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(7)
        with Observer(listener.getsockname()[1]) as observer:
            front = reserve()
            config = command(binary, root, front, observer.port, profile, "localhost", "origin.crt")
            with running(config, front, root / "tcp.log"):
                negotiated, cipher, reused = test_once(front, listener, server, pool)
        assert negotiated == version.name.replace("TLSv1_", "TLSv1.") and not reused
        assert len(observer.messages) == 1, observer.messages
        suites, extensions, session_id, _ = observer.messages[0]
        assert {suite for suite in suites if not grease(suite)} == LEGACY_SUITES | {0x1301, 0x1302, 0x1303}
        assert session_id == 32 and {5, 11, 18, 23, 35, 43, 0xff01} <= set(extensions)
        print(f"{profile} {negotiated} {cipher}: one ClientHello, authenticated 256 KiB each direction")
        print("  suites:", " ".join(f"{suite:04x}" for suite in suites))
        print("  extensions:", " ".join(f"{extension:04x}" for extension in extensions))


def resumption(binary, root):
    context = version_context(root, ssl.TLSVersion.TLSv1_3)
    listeners = []
    with ExitStack() as stack:
        for _ in range(2):
            listener = stack.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(7)
            listeners.append(listener)
        cases = ((0, "localhost", "origin.crt"), (0, "alternate.local", "origin.crt"),
                 (0, "localhost", "bundle.crt"), (1, "localhost", "origin.crt"))
        observers = [stack.enter_context(Observer(listener.getsockname()[1])) for listener in listeners]
        fronts = [reserve() for _ in cases]
        entries = []
        for index, (target, name, ca) in enumerate(cases):
            entries.append(f'''
outbound "node{index}" type="trojan" {{
  server host="127.0.0.1" port={observers[target].port}
  authentication {{ password-file "{root / "password"}"; }}
  tls {{ server-name "{name}"; ca-file "{root / ca}"; verify #true; fingerprint "native"; }}
}}
inbound "in{index}" type="socks5" {{
  listen host="127.0.0.1" port={fronts[index]}; authentication "none";
}}
''')
        config = root / "psk.kdl"
        config.write_text('schema-version 1\nrole "client"\noutbound "direct" type="direct"\n' + "".join(entries) +
                          'routing {\n tcp-program sniff-timeout-ms=1000 unknown="skip" {\n' + "".join(
                              f'  rule action="route" outbound="node{i}" {{ inbound "in{i}"; }}\n'
                              for i in range(len(cases)))
                          + ' }\n default-outbound "node0";\n}\n')
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=1))
        stack.enter_context(running([binary, "run", "--config", config], fronts[0], root / "psk.log"))
        for i, label in enumerate(("original", "alternate SNI", "different trust anchors", "different endpoint")):
            listener = listeners[cases[i][0]]
            observer = observers[cases[i][0]]
            offset = len(observer.messages)
            assert not test_once(fronts[i], listener, context, pool)[2], label
            assert test_once(fronts[i], listener, context, pool)[2], label
            first, second = (entry[1] for entry in observer.messages[offset:])
            assert 41 not in first and second[-1] == 41 and 42 not in first + second
            print(f"TLS 1.3 {label}: full handshake then authenticated 1-RTT PSK")


def quic_matrix(binary, xray, root):
    credentials(root)
    for profile in PROFILES:
        edge, front = reserve_edge("h3"), reserve()
        server = xray_command(xray, root, "server", edge, edge, "h3", "stream-one")
        client = nexus_command(binary, root, "client", front, edge, "h3", "stream-one")
        path = client[-1]
        path.write_text(path.read_text().replace('tls { server-name', f'tls {{ fingerprint "{profile}"; server-name'))
        with running_edge(server, edge, root / "h3.log", "h3"), running(client, front, root / "client.log"):
            exchange(front, False, 1)
        print(f"{profile} QUIC/H3 authenticated large transfer")


def alps_exchange(binary, fixture, root):
    config = root / "alps.kdl"
    output = root / "alps-rules.kdl"
    with DnsPeer() as dns:
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={reserve()}; authentication "none"; }}
outbound "physical" type="direct"
dns {{
  server "bootstrap" type="udp" host="127.0.0.1" port={dns.port}
  final "bootstrap"
  strategy "ipv4_only"
}}
http-clients {{
  updates {{
    outbound "physical"
    domain-resolver "bootstrap"
    ca-file "{root / 'origin.crt'}"
    protocol "h2"
    fingerprint "chrome-133"
    timeout-ms 3000
  }}
}}
routing {{ default-outbound "physical"; }}
''')
        with subprocess.Popen([fixture, root / "origin.crt", root / "origin.key"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, bufsize=0) as peer:
            try:
                assert select.select([peer.stdout], [], [], 5)[0], "ALPS server startup timed out"
                port = int(peer.stdout.readline())
                result = subprocess.run([binary, "rule", "fetch", config, "updates",
                                         f"https://localhost:{port}/rules", "kdl", output],
                                        capture_output=True, text=True, timeout=8)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                proof, errors = peer.communicate(timeout=5)
                assert peer.returncode == 0 and b"client EncryptedExtensions and Finished" in proof, errors
                assert b'value="alps.test"' in output.read_bytes()
                print(proof.decode().strip())
            finally:
                if peer.poll() is None:
                    peer.kill()
                    peer.wait()


def quic_real_ech(binary, peer, root):
    root = root / "real-ech"
    root.mkdir()
    certificate(root)
    (root / "password").write_text("test-password\n")
    (root / "password").chmod(0o600)
    config, keys = generate(root, "ech")
    for retry in (False, True):
        with go_peer(root, peer, keys, retry=retry) as port:
            cfg, front = make_config(root, "hysteria2", port,
                                     f'ech-config-file "{config}"; fingerprint "chrome-133"')
            with nexus_process(str(binary), str(cfg)), open_socks(front) as tunnel:
                assert exact(tunnel, 10)[1] == 0
                tunnel.sendall(b"real-ech")
                assert exact(tunnel, 8) == b"real-ech"
        print(f"Chrome-133 Hysteria 2 real ECH authenticated through Go, HRR={retry}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nexus", type=Path)
    parser.add_argument("xray", type=Path)
    parser.add_argument("--case", choices=("tcp", "psk", "h3", "alps", "ech"), action="append")
    parser.add_argument("--alps-peer", type=Path)
    parser.add_argument("--ech-peer", type=Path)
    args = parser.parse_args()
    if args.case and "alps" in args.case and not args.alps_peer:
        parser.error("--case alps requires --alps-peer")
    if args.case and "ech" in args.case and not args.ech_peer:
        parser.error("--case ech requires --ech-peer")
    with tempfile.TemporaryDirectory(prefix="nexus-94c-utls-") as name:
        root = Path(name)
        create_certificate(root)
        cases = args.case or ("tcp", "psk", "h3") + (("alps",) if args.alps_peer else ()) + (("ech",) if args.ech_peer else ())
        try:
            if "tcp" in cases:
                tcp_matrix(args.nexus.resolve(), root)
            if "psk" in cases:
                resumption(args.nexus.resolve(), root)
            if "h3" in cases:
                quic_matrix(args.nexus.resolve(), args.xray.resolve(), root)
            if "alps" in cases:
                alps_exchange(args.nexus.resolve(), args.alps_peer.resolve(), root)
            if "ech" in cases:
                quic_real_ech(args.nexus.resolve(), args.ech_peer.resolve(), root)
        except Exception:
            for log in root.glob("*.log"):
                print(log.name, log.read_text())
            raise


if __name__ == "__main__":
    main()
