#!/usr/bin/env python3
"""Exercise XHTTP on every carrier against the pinned Xray CLI."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, suppress
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from detour_network import exact, reserve, running, socks
from batch94a_reality_network import SHORT, encode
from batch94b_xhttp_extensions import (
    download_settings, h3_reclaim, mixed_download, pairing_and_abort, running_edge, xmux_reset, xmux_reuse,
)

UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
HOST = "127.0.0.1"
PATH = "/edge/"
PROFILES = (
    ("h1", "packet-up"),
    ("h2", "packet-up"),
    ("h2", "stream-one"),
    ("h2", "stream-up"),
    ("h3", "packet-up"),
    ("h3", "stream-one"),
    ("h3", "stream-up"),
)


def credentials(root):
    (root / "uuid").write_text(UUID + "\n")
    (root / "uuid").chmod(0o600)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-keyout", root / "key", "-out", root / "cert", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    ], check=True, capture_output=True)
    (root / "key").chmod(0o600)
    seed = bytes.fromhex("25" + "00" * 31)
    (root / "secret").write_text(seed.hex())
    (root / "secret").chmod(0o600)
    key_der = bytes.fromhex("302e020100300506032b656e04220420") + seed
    public = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                            input=key_der, check=True, capture_output=True).stdout[-32:]
    return seed, public


def nexus_command(binary, root, role, port, edge, protocol, mode, cover=None, keys=None, extra=""):
    transport = f'transport "xhttp" {{ protocol "{protocol}"; mode "{mode}"; path "{PATH}"; {extra} }}'
    direct = 'outbound "direct" type="direct"'
    if role == "server":
        security = f'tls {{ certificate-file "{root / "cert"}"; private-key-file "{root / "key"}"; }}'
        if cover:
            security = f'''tls {{ reality {{
              private-key-file "{root / "secret"}"; server-name "localhost"; short-id "{SHORT}";
              max-time-difference 15; fallback host="{HOST}" port={cover};
            }}; }}'''
        config = f'''
inbound "edge" type="vless" {{
  listen host="{HOST}" port={port}
  authentication {{ user "test" uuid-file="{root / 'uuid'}"; }}
  {security}
  {transport}
}}
{direct}
routing {{ default-outbound "direct"; }}
'''
    else:
        security = f'tls {{ server-name "localhost"; ca-file "{root / "cert"}"; verify #true; }}'
        if cover:
            security = f'''tls {{ server-name "localhost"; fingerprint "chrome"; key-exchange "x25519-mlkem768";
              reality {{ public-key "{keys[1].hex()}"; short-id "{SHORT}"; }}; }}'''
        config = f'''
inbound "local" type="socks5" {{ listen host="{HOST}" port={port}; authentication "none"; }}
{direct}
outbound "edge" type="vless" {{
  server host="{HOST}" port={edge}
  authentication {{ uuid-file "{root / 'uuid'}"; }}
  {security}
  {transport}
}}
routing {{ default-outbound "edge"; }}
'''
    file = root / f"nexus-{role}.kdl"
    file.write_text(f'schema-version 1\nrole "{role}"\n' + config)
    return [binary, "run", "--config", file]


def xray_command(binary, root, role, port, edge, protocol, mode, cover=None, keys=None):
    tls = {"alpn": [{"h1": "http/1.1", "h2": "h2", "h3": "h3"}[protocol]], "serverName": "localhost"}
    stream = {"network": "xhttp", "security": "tls", "tlsSettings": tls,
              "xhttpSettings": {"path": PATH, "mode": mode}}
    if role == "server":
        tls["certificates"] = [{"certificateFile": str(root / "cert"), "keyFile": str(root / "key")}]
        inbound = {"listen": HOST, "port": port, "protocol": "vless", "streamSettings": stream,
                   "settings": {"decryption": "none", "clients": [{"id": UUID}]}}
        outbound = {"protocol": "freedom"}
    else:
        inbound = {"listen": HOST, "port": port, "protocol": "socks", "settings": {"auth": "noauth"}}
        outbound = {"protocol": "vless", "streamSettings": stream, "settings": {
            "vnext": [{"address": HOST, "port": edge, "users": [{"id": UUID, "encryption": "none"}]}],
        }}
    if cover:
        stream["security"] = "reality"
        del stream["tlsSettings"]
        stream["realitySettings"] = (
            {"target": f"{HOST}:{cover}", "serverNames": ["localhost"],
             "privateKey": encode(keys[0]), "shortIds": [SHORT]} if role == "server" else
            {"serverName": "localhost", "fingerprint": "chrome", "password": encode(keys[1]), "shortId": SHORT}
        )
    file = root / f"xray-{role}.json"
    file.write_text(json.dumps({"log": {"loglevel": "warning"}, "inbounds": [inbound], "outbounds": [outbound]}))
    return ["env", f"SSL_CERT_FILE={root / 'cert'}", binary, "run", "-config", file]


def exchange(proxy, half_close, tag):
    data = bytes([tag, 7, 0, 255]) * (512 * 1024)
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as worker:
        listener.settimeout(12)
        listener.bind((HOST, 0))
        listener.listen(1)

        def origin():
            with listener.accept()[0] as target:
                target.settimeout(12)
                if exact(target, len(data)) != data:
                    raise AssertionError("uplink data differs")
                if half_close and target.recv(1):
                    raise AssertionError("expected upstream half-close")
                target.sendall(data[::-1])
                target.shutdown(socket.SHUT_WR)

        task = worker.submit(origin)
        client, _ = socks(proxy, 1, listener.getsockname())
        with client:
            client.settimeout(12)
            client.sendall(data)
            if half_close:
                client.shutdown(socket.SHUT_WR)
            if exact(client, len(data)) != data[::-1] or client.recv(1):
                raise AssertionError("downlink data or FIN differs")
        task.result(timeout=15)



def session_descriptors(directory):
    result = []
    for entry in directory.iterdir():
        with suppress(FileNotFoundError):
            kind = str(entry.readlink())
            # epoll initializes its shared timerfd on the first timed operation.
            if kind != "anon_inode:[timerfd]":
                result.append(kind)
    return sorted(result)

def reserve_edge(protocol):
    if protocol != "h3":
        return reserve()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def scenario(binary, xray, root, protocol, mode, nexus_server, cover=None, keys=None):
    edge, local = reserve_edge(protocol), reserve()
    server = (nexus_command if nexus_server else xray_command)(
        binary if nexus_server else xray, root, "server", edge, edge, protocol, mode, cover, keys)
    client = (xray_command if nexus_server else nexus_command)(
        xray if nexus_server else binary, root, "client", local, edge, protocol, mode, cover, keys)
    with ExitStack() as stack:
        server_process = stack.enter_context(running_edge(server, edge, root / "server.log", protocol))
        client_process = stack.enter_context(running(client, local, root / "client.log"))
        files = Path(f"/proc/{(server_process if nexus_server else client_process).pid}/fd")
        time.sleep(.1)
        baseline = session_descriptors(files)
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = [pool.submit(exchange, local, False, tag) for tag in range(3)]
            for job in jobs:
                job.result()
        if nexus_server:
            # Xray retains idle HTTP carriers for reuse while it is running.
            client_process.terminate()
            client_process.wait(timeout=6)
        deadline = time.monotonic() + 6
        while session_descriptors(files) != baseline:
            if time.monotonic() >= deadline:
                raise AssertionError(f"Nexus descriptors differ: {baseline!r} -> {session_descriptors(files)!r}")
            time.sleep(.05)
        print(f"{protocol} {mode}{' REALITY' if cover else ''}, Nexus {'inbound' if nexus_server else 'outbound'}: transfer, FIN, concurrency and FD recovery")



def nexus_half_close(binary, root, protocol, mode):
    edge, local = reserve_edge(protocol), reserve()
    server = nexus_command(binary, root, "server", edge, edge, protocol, mode)
    client = nexus_command(binary, root, "client", local, edge, protocol, mode)
    with running_edge(server, edge, root / "server.log", protocol), running(client, local, root / "client.log"):
        exchange(local, True, 1)
    print(f"{protocol} {mode}, two Nexus peers: independent upload and download FIN")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("nexus", type=Path)
    parser.add_argument("xray", type=Path)
    parser.add_argument("--protocol", choices=("h1", "h2", "h3"), action="append")
    parser.add_argument("--reality-cover", type=Path)
    parser.add_argument("--mixed-edge", type=Path)
    args = parser.parse_args()
    binary, xray = args.nexus.resolve(), args.xray.resolve()
    version = subprocess.check_output([xray, "version"], text=True).splitlines()[0]
    if not version.startswith("Xray 26.3.27 "):
        raise RuntimeError(f"expected Xray 26.3.27, found {version}")
    with tempfile.TemporaryDirectory(prefix="nexus-xhttp-network-") as name:
        root = Path(name)
        keys = credentials(root)
        profiles = [(protocol, mode) for protocol, mode in PROFILES if not args.protocol or protocol in args.protocol]
        for protocol, mode in profiles:
            for nexus_server in (True, False):
                try:
                    scenario(binary, xray, root, protocol, mode, nexus_server)
                except Exception:
                    for log in (root / "server.log", root / "client.log"):
                        if log.exists():
                            print(log.name, log.read_text())
                    raise
        for protocol, mode in profiles:
            if mode != "packet-up":
                nexus_half_close(binary, root, protocol, mode)
        if not args.protocol or "h1" in args.protocol:
            download_settings(binary, root, "h1", "packet-up", sys.modules[__name__])
            pairing_and_abort(binary, root, sys.modules[__name__])
        if not args.protocol or "h2" in args.protocol:
            download_settings(binary, root, "h2", "stream-up", sys.modules[__name__])
            xmux_reuse(binary, root, sys.modules[__name__])
            xmux_reset(binary, root, sys.modules[__name__])
        if not args.protocol or "h3" in args.protocol:
            h3_reclaim(binary, root, sys.modules[__name__])
        if args.mixed_edge:
            for role in (("h1", "h2", "h1", "packet-up"), ("h1", "h2", "h2", "packet-up"),
                         ("h3", "h2", "h3", "stream-up"), ("h2", "h3", "h2", "stream-up")):
                mixed_download(args.mixed_edge.resolve(), binary, root, *role, sys.modules[__name__])
        if args.reality_cover:
            cover = reserve()
            command = [args.reality_cover.resolve(), f"{HOST}:{cover}", root / "cert", root / "key", "hybrid"]
            with running_edge(command, cover, root / "cover.log", "h2", exit_codes=(0, -15)):
                for nexus_server in (True, False):
                    scenario(binary, xray, root, "h2", "auto", nexus_server, cover, keys)


if __name__ == "__main__":
    main()
