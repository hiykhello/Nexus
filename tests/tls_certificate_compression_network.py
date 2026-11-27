#!/usr/bin/env python3
"""Use an OpenSSL peer to observe compressed certificate negotiation and TLS data."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile

from dns_rule_support import connect, exact, free_port, nexus_process
from anytls_cli_network import Origin, begin, client_config
from detour_network import running
from udp_bind_port_network import certificate


def check(binary, peer, root, fingerprint, algorithm, expected, name="localhost", success=None):
    if success is None:
        success = name == "localhost"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        front = free_port()
        password = root / "password"
        password.write_text("secret\n")
        password.chmod(0o600)
        config = root / "trojan.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="trojan" {{
    server host="127.0.0.1" port={listener.getsockname()[1]};
    authentication {{ password-file "{password}"; }}
    tls {{ server-name "{name}"; ca-file "{root / 'cert'}"; fingerprint "{fingerprint}"; verify #true; }}
}}
routing {{ final "edge"; }}
''')
        with nexus_process(binary, config), connect(front) as client:
            client.sendall(b"\x05\x01\0")
            assert exact(client, 2) == b"\x05\0"
            client.sendall(b"\x05\x01\0\x01\x7f\0\0\x01\0\x09")
            incoming, _ = listener.accept()
            with incoming, subprocess.Popen(
                [peer, root / "cert", root / "key", str(algorithm), str(incoming.fileno())],
                pass_fds=(incoming.fileno(),), stderr=subprocess.PIPE,
            ) as server:
                try:
                    header = exact(client, 4)
                    assert header[0] == 5 and header[3] in (1, 4), header
                    exact(client, 6 if header[3] == 1 else 18)
                    if success:
                        assert header[1] == 0, header
                        client.sendall(b"authenticatedTLS")
                        assert exact(client, 16) == b"authenticatedTLS"
                    else:
                        assert header[1] != 0, header
                    _, report = server.communicate(timeout=5)
                finally:
                    if server.poll() is None:
                        server.kill()
                        server.wait()
                assert (server.returncode == 0) == success, (server.returncode, report)
                if isinstance(expected, int):
                    expected = f"compressed algorithm={expected}\n".encode() if expected else b""
                assert expected == report, report
    print(f"{fingerprint}, OpenSSL algorithm {algorithm}, sent {expected}, certificate name {name}: passed")


def check_quic(binary, peer, root, fingerprint, algorithm, host="127.0.0.1", cipher=None):
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind((host, 0))
        front = free_port()
        password = root / "password"
        password.write_text("secret\n")
        password.chmod(0o600)
        config = root / "hy2.kdl"
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{
    server host="{host}" port={listener.getsockname()[1]};
    authentication {{ password-file "{password}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; fingerprint "{fingerprint}"; verify #true; }}
}}
routing {{ final "edge"; }}
''')
        args = [peer, root / "cert", root / "key", str(1000 + algorithm), str(listener.fileno())]
        if cipher:
            args.append(cipher)
        with subprocess.Popen(args, pass_fds=(listener.fileno(),), stderr=subprocess.PIPE) as server:
            try:
                with nexus_process(binary, config), connect(front) as client:
                    client.sendall(b"\x05\x01\0")
                    assert exact(client, 2) == b"\x05\0"
                    client.sendall(b"\x05\x01\0\x01\x7f\0\0\x01\0\x09")
                    _, report = server.communicate(timeout=5)
            finally:
                if server.poll() is None:
                    server.kill()
                    server.wait()
            expected = f"compressed algorithm={algorithm}\n" if algorithm else ""
            if cipher:
                expected += f"QUIC cipher={cipher}\n"
            expected += "authenticated QUIC TLS\n"
            assert server.returncode == 0 and report == expected.encode(), (server.returncode, report)
    print(f"{host} {fingerprint}, OpenSSL QUIC {cipher or 'default cipher'}, compression {algorithm}: passed")


def check_tls12_anytls(binary, sing_box, root):
    front, remote = free_port(), free_port()
    password = root / "bob"
    password.write_text("anytls-network-secret\n")
    password.chmod(0o600)
    service = root / "anytls-peer.json"
    service.write_text(json.dumps({
        "inbounds": [{
            "type": "anytls", "listen": "127.0.0.1", "listen_port": remote,
            "users": [{"name": "bob", "password": "anytls-network-secret"}],
            "tls": {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key"),
                    "min_version": "1.2", "max_version": "1.2"},
        }],
        "outbounds": [{"type": "direct"}],
    }))
    config = client_config(root, front, remote, 1)
    config.write_text(config.read_text().replace("verify #true;", 'verify #true; fingerprint "tls12";'))
    with running([sing_box, "run", "-c", service], remote, root / "anytls-peer.log"):
        with nexus_process(binary, config), Origin(expected=2) as origin:
            for index in range(2):
                with begin(front, origin.port) as client:
                    payload = bytes([index]) + bytes(range(256)) * 128
                    client.sendall(payload)
                    assert exact(client, len(payload)) == payload
                    client.shutdown(socket.SHUT_WR)
                    assert client.recv(1) == b""
            origin.wait()
    print("tls12, TLS 1.2-only sing-box AnyTLS peer: TCP relay, record splitting and logical FIN passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("peer", type=Path)
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--tls12", action="store_true")
    parser.add_argument("--tls12-ecdsa", action="store_true")
    parser.add_argument("--sing-box", type=Path)
    parser.add_argument("--quic", action="store_true")
    parser.add_argument("--quic-ciphers", action="store_true")
    options = parser.parse_args()
    binary, peer = options.binary.resolve(strict=True), options.peer.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-tls-cert-compression-") as directory:
        root = Path(directory)
        if options.tls12_ecdsa:
            for mode, curve, suite in (
                (228, "prime256v1", "AES128-GCM-SHA256"),
                (356, "secp384r1", "AES256-GCM-SHA384"),
                (521, "secp521r1", "AES256-GCM-SHA384"),
            ):
                subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    f"ec_paramgen_curve:{curve}", "-noenc", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost", "-keyout", root / "key", "-out", root / "cert"],
                    check=True, capture_output=True)
                check(binary, peer, root, "tls12", mode, f"TLS 1.2 ECDHE-ECDSA-{suite}\n".encode())
            return
        certificate(root)
        if options.quic_ciphers:
            for host in ("127.0.0.1", "::1"):
                for cipher in ("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"):
                    check_quic(binary, peer, root, "firefox", 0, host, cipher)
            return
        if options.quic:
            check_quic(binary, peer, root, "safari", 1)
            check_quic(binary, peer, root, "chrome", 2)
            check_quic(binary, peer, root, "tls13-randomized", 3)
            return
        if options.tls12:
            for width, digest in ((128, "SHA256"), (256, "SHA384")):
                report = f"TLS 1.2 ECDHE-RSA-AES{width}-GCM-{digest}\n".encode()
                check(binary, peer, root, "tls12", width, report)
            check(binary, peer, root, "tls12", 128, b"", "wrong.example")
            check(binary, peer, root, "native", 128, b"", success=False)
            check(binary, peer, root, "tls12", 0, b"", success=False)
            if options.sing_box:
                check_tls12_anytls(binary, options.sing_box.resolve(strict=True), root)
            return
        check(binary, peer, root, "native", 1, 0)
        check(binary, peer, root, "safari", 1, 0 if options.disabled else 1)
        if not options.disabled:
            check(binary, peer, root, "chrome", 2, 2)
            check(binary, peer, root, "tls13-randomized", 3, 3)
            check(binary, peer, root, "safari", 0, 0)
            check(binary, peer, root, "chrome", 2, 2, "wrong.example")


if __name__ == "__main__":
    main()
