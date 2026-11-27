#!/usr/bin/env python3
"""Exercise a named TUIC client's selected physical UDP interface."""

from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from dns_rule_support import nexus_process
from detour_network import reserve
from network_selection_network import LINKS, TARGETS, default_route, peers, socks, stall_primary_connects, verify_tcp, verify_udp, udp
from tailscale_endpoint_network import eventually, process
from tuic_singbox import REVISION
from udp_bind_port_network import certificate


def server(stack, root, namespace, port, host, label, identity):
    config = root / f"{label}-{host}.json"
    config.write_text(json.dumps({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "tuic", "listen": host, "listen_port": port,
            "users": [{"name": "network", "uuid": identity, "password": "network-test"}],
            "tls": {"enabled": True, "server_name": "localhost", "alpn": ["h3"],
                    "certificate_path": str(root / "cert"), "key_path": str(root / "key")},
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }))
    namespace_exec = ["nsenter", "-t", str(namespace), "-n", "--"]
    stack.enter_context(process([*namespace_exec, "sing-box", "run", "-c", config]))
    family = "-6" if ":" in host else "-4"
    eventually(lambda: f":{port} " in subprocess.check_output([*namespace_exec, "ss", family, "-H", "-nlu"], text=True))


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-tuic-networks-") as folder, ExitStack() as stack:
        root = Path(folder)
        certificate(root)
        identity = str(uuid.uuid4())
        uid, password = root / "uuid", root / "password"
        uid.write_text(identity)
        password.write_text("network-test")
        uid.chmod(0o600)
        password.chmod(0o600)
        front, port, echo = reserve(), reserve(), reserve()
        namespaces = peers(stack, echo)
        for name, namespace in namespaces.items():
            for host in TARGETS:
                server(stack, root, namespace, port, host, name, identity)

        config = root / "proxy.kdl"

        def write(host):
            config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{
    network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=350 {{
        interface "primary" type="ethernet"
        interface "backup" type="wifi"
    }}
}}
outbound "remote" type="tuic" {{
    server host="{host}" port={port}
    detour "direct"
    connect-timeout-ms 2200
    authentication {{ uuid-file "{uid}"; password-file "{password}"; }}
    tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
}}
routing {{ final "remote"; }}
''')

        for host in TARGETS:
            write(host)
            for name in ("primary", "backup"):
                with ExitStack() as trial:
                    if name == "backup":
                        trial.enter_context(stall_primary_connects(namespaces["primary"], port, udp=True))
                    trial.enter_context(nexus_process(binary, config))
                    started = time.monotonic()
                    first, code, _ = socks(front, 1, host, echo)
                    trial.enter_context(first)
                    assert code == 0, (name, host, code)
                    if name == "backup":
                        assert .30 <= time.monotonic()-started < 2.2
                    verify_tcp(first, name)
                    session = udp(front, trial)
                    session[0].settimeout(2)
                    verify_udp(session, host, echo, name)
        for link in LINKS:
            default_route(link, False)
        with nexus_process(binary, config):
            client, code, _ = socks(front, 1, TARGETS[-1], echo)
            with client:
                assert code != 0
    print("TUIC TCP and UDP used both selected IPv4/IPv6 interfaces, recovered a silent primary and rejected missing paths")


if __name__ == "__main__":
    if sys.argv[1] == "--namespace":
        verify(sys.argv[2])
    else:
        version = subprocess.check_output(["sing-box", "version"], text=True)
        assert f"Revision: {REVISION}" in version, version
        cli = str(Path(sys.argv[1]).resolve(strict=True))
        subprocess.run(["unshare", "-Urn", sys.executable, __file__, "--namespace", cli], check=True, timeout=55)
