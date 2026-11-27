#!/usr/bin/env python3
"""Check SOCKS5 UDP ASSOCIATE through the production named outbound."""
from contextlib import ExitStack
from pathlib import Path
import json
import selectors
import socket
import threading
import subprocess
import sys
import tempfile
import time

from dns_rule_support import Echo, free_port, nexus_process, udp_client
from detour_network import exact, reserve
from httpupgrade_cli_network import address
from network_selection_network import TARGETS, peers, process, stall_primary_connects
from shadowtls_singbox import REVISION, launch_singbox, stop_proc


def run(cli, root, echo):
    secret=root/"password"
    secret.write_text("udp-password\n")
    secret.chmod(0o600)
    front, remote=free_port(),free_port()
    upstream=root/"upstream.json"
    upstream.write_text(json.dumps({
        "log":{"level":"warn"},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":remote,
                     "users":[{"username":"test","password":"udp-password"}]}],
        "outbounds":[{"type":"direct"}],
    }))
    config=root/"nexus.kdl"
    config.write_text(f'''schema-version 1
role "client"
inbound "entry" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "upstream" type="socks5" {{
    server host="127.0.0.1" port={remote}
    authentication username="test" password-file="{secret}"
    udp #true
}}
routing {{ final "upstream"; }}
''')
    peer=launch_singbox(upstream,remote)
    try:
        with nexus_process(cli,config):
            for host in ("127.0.0.1","::1"):
                # The fixed Go direct peer creates a socket for the first
                # target family. Verify each family with its own association.
                with udp_client(front) as (client, relay):
                    for payload in (b"one",b"",b"again"):
                        datagram=b"\0\0\0"+address(host,echo.port)+payload
                        client.sendto(datagram,relay)
                        assert client.recvfrom(65535)[0]==datagram
    finally:
        stop_proc(peer)
    print("Named SOCKS5 UDP carried dual-stack targets and empty datagrams through a fixed independent SOCKS5 server")



def relay_peer(label, port):
    active = {}
    lock = threading.Lock()

    def control(peer, family):
        with peer:
            try:
                assert exact(peer, 3) == b"\x05\x01\x00"
                peer.sendall(b"\x05\x00")
                request = exact(peer, 4)
                assert request == b"\x05\x03\x00\x01"
                assert exact(peer, 6) == bytes(6)
                bound = b"\x04" + bytes(16) if family == socket.AF_INET6 else b"\x01" + bytes(4)
                with lock:
                    active[family] = peer
                peer.sendall(b"\x05\x00\x00" + bound + port.to_bytes(2, "big"))
                assert peer.recv(1) == b""
            except ConnectionError:
                pass
            finally:
                with lock:
                    if active.get(family) is peer:
                        del active[family]

    with ExitStack() as stack:
        poller = stack.enter_context(selectors.DefaultSelector())
        for host in TARGETS:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                endpoint = stack.enter_context(socket.socket(family, kind))
                endpoint.bind((host, port))
                if kind == socket.SOCK_STREAM:
                    endpoint.listen()
                poller.register(endpoint, selectors.EVENT_READ, kind)
        print("ready", flush=True)
        while True:
            for key, _ in poller.select():
                endpoint = key.fileobj
                if key.data == socket.SOCK_STREAM:
                    accepted, _ = endpoint.accept()
                    threading.Thread(target=control, args=(accepted, endpoint.family), daemon=True).start()
                    continue
                message, client = endpoint.recvfrom(2048)
                size = 22 if message[3] == 4 else 10
                payload = message[size:]
                if payload == b"withdraw":
                    with lock:
                        active[endpoint.family].shutdown(socket.SHUT_RDWR)
                    time.sleep(.15)
                endpoint.sendto(message[:size] + label.encode() + b":" + payload, client)


def network_selection(cli):
    with tempfile.TemporaryDirectory(prefix="nexus-socks-upstream-path-") as folder, ExitStack() as stack:
        config = Path(folder) / "nexus.kdl"
        front, remote = reserve(), reserve()
        namespaces = peers(stack, reserve())
        for label, namespace in namespaces.items():
            stack.enter_context(process(["nsenter", "-t", str(namespace), "-n", "--",
                                         sys.executable, __file__, "--relay", label, str(remote)]))
        for host in TARGETS:
            for fast_open in ("#false", "#true"):
                config.write_text(f'''schema-version 1
role "client"
inbound "entry" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{
    tcp-fast-open {fast_open}
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=250 {{
        interface "primary" type="ethernet"
        interface "backup" type="wifi"
    }}
}}
outbound "upstream" type="socks5" {{
    server host="{host}" port={remote}
    detour "direct"
    connect-timeout-ms 1500
    udp #true
}}
routing {{ final "upstream"; }}
''')
                with stall_primary_connects(namespaces["primary"], remote), nexus_process(cli, config):
                    with udp_client(front) as (client, relay):
                        for target in TARGETS:
                            header = b"\0\0\0" + address(target, remote)
                            client.sendto(header + b"selected", relay)
                            reply, _ = client.recvfrom(2048)
                            assert reply == header + b"backup:selected", (host, fast_open, reply)
                        client.sendto(header + b"withdraw", relay)
                        client.settimeout(.4)
                        try:
                            delayed, _ = client.recvfrom(2048)
                        except TimeoutError:
                            pass
                        else:
                            raise AssertionError(f"relay forwarded a reply after control withdrawal: {delayed!r}")
                    with udp_client(front) as (client, relay):
                        client.sendto(header + b"reconnect", relay)
                        assert client.recvfrom(2048)[0] == header + b"backup:reconnect"
    print("SOCKS5 UDP shared the selected TCP backup interface on both families and recovered after control withdrawal")


if __name__ == "__main__":
    if sys.argv[1] == "--relay":
        relay_peer(sys.argv[2], int(sys.argv[3]))
    elif sys.argv[1] == "--namespace":
        network_selection(Path(sys.argv[2]))
    else:
        binary = Path(sys.argv[1]).resolve(strict=True)
        version = subprocess.check_output(["sing-box", "version"], text=True)
        assert f"Revision: {REVISION}" in version
        with tempfile.TemporaryDirectory(prefix="nexus-socks-upstream-udp-") as temp, Echo() as server:
            run(binary, Path(temp), server)
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", str(binary)],
                       check=True, timeout=35)
