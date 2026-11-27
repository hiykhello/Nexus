#!/usr/bin/env python3
"""Exercise shaped VLESS Reality through physical and proxy connections."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import Dns, exact, exchange, reserve, running
from record_limit_password_cli import Observer, grease


def configuration(root, ports, chain, port, dns, workers, public, fingerprint="tls13-randomized", fast=False, group="x25519"):
    text = f'''schema-version 1
role "client"
workers {workers}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns}; strategy "ipv4_only"; }}
inbound "in" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
'''
    for index, kind in enumerate(chain):
        text += f'outbound "n{index}" type="{"trojan" if kind == "trojan" else "vless"}" {{ server host="{kind}.test" port={ports[kind]}; bootstrap-resolver "boot";'
        if fast and not index:
            text += 'tcp-fast-open #true;'
        if index:
            text += f'detour "n{index - 1}";'
        if kind == "trojan":
            text += f'authentication {{ password-file "{root / "psk"}"; }}; tls {{ server-name "cover.example"; ca-file "{root / "cert"}"; verify #true; }};'
        else:
            auth = f'reality {{ public-key "{public}"; short-id "0123456789abcdef"; }};' if kind.startswith("reality") else f'ca-file "{root / "cert"}"; verify #true;'
            text += f'authentication {{ uuid-file "{root / "uuid"}"; }}; tls {{ server-name "cover.example"; fingerprint "{fingerprint}"; record-size-limit 1024; key-exchange "{group}"; {auth} }};'
            if kind.endswith("vision"):
                text += 'flow "xtls-rprx-vision";'
        text += "}\n"
    return text + f'routing {{ final "n{len(chain) - 1}"; }}\n'


def main():
    binary = pathlib.Path(sys.argv[1]).resolve()
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    output = subprocess.run(["sing-box", "generate", "reality-keypair"], check=True, capture_output=True, text=True).stdout
    keys = dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)
    public = base64.urlsafe_b64decode(keys["PublicKey"] + "=").hex()
    with tempfile.TemporaryDirectory(prefix="nexus-detour-reality-") as directory:
        root = pathlib.Path(directory)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "key", "-out", root / "cert",
                        "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        user = "00010203-0405-0607-0809-0a0b0c0d0e0f"
        (root / "uuid").write_text(user)
        (root / "psk").write_text("nexus-password\n")
        for name in ("uuid", "psk"):
            (root / name).chmod(0o600)
        ports = {kind: reserve() for kind in ("trojan", "tls", "reality", "reality-vision")}
        cover_port = reserve()
        cover = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", str(cover_port), "-cert", root / "cert",
                                  "-key", root / "key", "-groups", "X25519"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dns = Dns()
        try:
            limit = time.monotonic() + 5
            while True:
                if cover.poll() is not None:
                    raise RuntimeError("Reality handshake target exited")
                try:
                    with socket.create_connection(("127.0.0.1", cover_port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= limit:
                        raise
                    time.sleep(.02)
            inbounds = []
            for kind, port in ports.items():
                entry = {"type": "trojan" if kind == "trojan" else "vless", "tag": kind,
                         "listen": "127.0.0.1", "listen_port": port}
                if kind == "trojan":
                    entry.update(users=[{"password": "nexus-password"}], tls={"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")})
                else:
                    tls = {"enabled": True}
                    if kind.startswith("reality"):
                        tls.update(server_name="cover.example", reality={"enabled": True,
                                   "handshake": {"server": "127.0.0.1", "server_port": cover_port},
                                   "private_key": keys["PrivateKey"], "short_id": ["0123456789abcdef"]})
                    else:
                        tls.update(certificate_path=str(root / "cert"), key_path=str(root / "key"))
                    entry.update(users=[{"uuid": user, **({"flow": "xtls-rprx-vision"} if kind.endswith("vision") else {})}], tls=tls)
                inbounds.append(entry)
            box = root / "box.json"
            box.write_text(json.dumps({"log": {"level": "info"}, "inbounds": inbounds,
                                      "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}))
            subprocess.run(["sing-box", "check", "-c", box], check=True, capture_output=True)
            log = root / "box.log"
            with running(["sing-box", "run", "-c", box], ports["trojan"], log):
                for fingerprint in ("tls13-grease", "tls13-randomized"):
                    for chain, fast in ((("reality",), False), (("reality",), True), (("trojan", "reality"), False), (("reality-vision",), False)):
                        port = reserve()
                        config = root / "config.kdl"
                        target_kind = chain[-1]
                        with Observer(ports[target_kind]) as observer:
                            observed_ports = dict(ports, **{target_kind: observer.port})
                            config.write_text(configuration(root, observed_ports, chain, port, dns.port, 1, public, fingerprint, fast))
                            dns.names.clear()
                            offset = log.stat().st_size
                            with running([binary, "run", "--config", config], port, root / "nexus.log"):
                                exchange(port)
                            if not observer.messages:
                                raise RuntimeError("no Reality ClientHello observed")
                            for suites, extensions, session_size, sni, record_limit in observer.messages:
                                if (record_limit != 1024 or not grease(suites[0]) or not grease(extensions[0]) or not grease(extensions[-1]) or
                                    session_size != 32 or sni != b"\x00\x10\x00\x00\x0dcover.example"):
                                    raise RuntimeError("unexpected Reality ClientHello")
                        if not {kind + ".test" for kind in chain} <= dns.names:
                            raise RuntimeError(f"missing Reality chain bootstrap: {dns.names}")
                        lines = log.read_bytes()[offset:].decode().splitlines()
                        for kind in chain:
                            protocol = "trojan" if kind == "trojan" else "vless"
                            if not any(f"inbound/{protocol}[{kind}]: " in line and "inbound connection to " in line for line in lines):
                                raise RuntimeError(f"chain skipped {kind}")
                        print(f"{fingerprint} {' -> '.join(chain)} fast={fast}: record-size-limit=1024 observed; authenticated TCP, half-close, UDP and drain passed", flush=True)
                port = reserve()
                wrong_public = bytearray.fromhex(public)
                wrong_public[0] ^= 1
                config.write_text(configuration(root, ports, ("trojan", "reality"), port, dns.port, 2, wrong_public.hex()))
                with running([binary, "run", "--config", config], port, root / "nexus.log"):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00":
                            raise RuntimeError("Reality failure negotiation failed")
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                        if exact(client, 10)[1] == 0:
                            raise RuntimeError("bad Reality identity was accepted through detour")
                print("Reality identity rejection through Trojan detour passed", flush=True)
        finally:
            dns.close()
            cover.terminate()
            cover.wait(timeout=5)


if __name__ == "__main__":
    main()
