#!/usr/bin/env python3
"""Exercise Reality above and below other configured proxy transports."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import Dns, exact, exchange, reserve, running


def configuration(root, ports, chain, port, dns, workers, public):
    text = f'''schema-version 1
role "client"
workers {workers}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns}; strategy "ipv4_only"; }}
inbound "in" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
'''
    for index, kind in enumerate(chain):
        text += f'outbound "n{index}" type="{"shadowsocks" if kind == "ss" else "vless"}" {{ server host="{kind}.test" port={ports[kind]}; bootstrap-resolver "boot";'
        if index:
            text += f'detour "n{index - 1}";'
        if kind == "ss":
            text += f'method "2022-blake3-aes-128-gcm"; key-file "{root / "psk"}"; udp-over-tcp "v2";'
        else:
            auth = f'reality {{ public-key "{public}"; short-id "0123456789abcdef"; }};' if kind.startswith("reality") else f'ca-file "{root / "cert"}"; verify #true;'
            text += f'authentication {{ uuid-file "{root / "uuid"}"; }}; tls {{ server-name "cover.example"; {auth} }};'
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
        password = base64.b64encode(bytes(range(16))).decode()
        (root / "uuid").write_text(user)
        (root / "psk").write_text(password)
        for name in ("uuid", "psk"):
            (root / name).chmod(0o600)
        ports = {kind: reserve() for kind in ("ss", "tls", "reality", "reality-vision")}
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
                entry = {"type": "shadowsocks" if kind == "ss" else "vless", "tag": kind,
                         "listen": "127.0.0.1", "listen_port": port}
                if kind == "ss":
                    entry.update(method="2022-blake3-aes-128-gcm", password=password)
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
            with running(["sing-box", "run", "-c", box], ports["ss"], log):
                chains = [("ss", "reality"), ("ss", "reality-vision"), ("reality", "ss"), ("reality-vision", "ss"),
                          ("reality", "tls"), ("tls", "reality-vision"), ("ss", "reality", "ss"), ("reality", "ss", "reality-vision")]
                for workers in (1, 2):
                    for chain in chains:
                        port = reserve()
                        config = root / "config.kdl"
                        config.write_text(configuration(root, ports, chain, port, dns.port, workers, public))
                        dns.names.clear()
                        offset = log.stat().st_size
                        with running([binary, "run", "--config", config], port, root / "nexus.log"):
                            exchange(port)
                        if not {kind + ".test" for kind in chain} <= dns.names:
                            raise RuntimeError(f"missing Reality chain bootstrap: {dns.names}")
                        lines = log.read_bytes()[offset:].decode().splitlines()
                        for kind in chain:
                            protocol = "shadowsocks" if kind == "ss" else "vless"
                            if not any(f"inbound/{protocol}[{kind}]: " in line and "inbound connection to " in line for line in lines):
                                raise RuntimeError(f"chain skipped {kind}")
                        print(f"{workers} workers {' -> '.join(chain)}: TCP, half-close, UDP and drain passed", flush=True)
                port = reserve()
                wrong_public = bytearray.fromhex(public)
                wrong_public[0] ^= 1
                config.write_text(configuration(root, ports, ("ss", "reality"), port, dns.port, 2, wrong_public.hex()))
                with running([binary, "run", "--config", config], port, root / "nexus.log"):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                        client.sendall(b"\x05\x01\x00")
                        if exact(client, 2) != b"\x05\x00":
                            raise RuntimeError("Reality failure negotiation failed")
                        client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2")
                        if exact(client, 10)[1] == 0:
                            raise RuntimeError("bad Reality identity was accepted through detour")
                print("Reality identity rejection through SS detour passed", flush=True)
        finally:
            dns.close()
            cover.terminate()
            cover.wait(timeout=5)


if __name__ == "__main__":
    main()
