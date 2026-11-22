#!/usr/bin/env python3
"""Verify physical socket bindings in an isolated user/network namespace."""
import argparse
import base64
import contextlib
import hashlib
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading

from anytls_proxy_network import CountedRelay
from anytls_test_peer import address
from detour_network import exact, running
from dns_rule_support import connect, nexus_process, proxy_client, udp_client
from tcp_keepalive_network import reserve

SOURCE4, SOURCE6 = "127.0.0.2", "fd42::2"
FIELDS = f'''bind-interface "lo"; inet4-bind-address "{SOURCE4}"; inet6-bind-address "{SOURCE6}";
routing-mark 16897; reuse-addr #true; bind-address-no-port #true;'''
REVISION = "824dbcfb4dd0a95921840b1737b950cde590241e"
KINDS = ("ss", "vless", "vision", "upgrade", "trojan", "anytls")


class Origins:
    def __init__(self):
        self.port = reserve()
        self.stop, self.errors, self.sources, self.sockets, self.threads = threading.Event(), [], [], [], []
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                peer = socket.socket(family, kind)
                if family == socket.AF_INET6:
                    peer.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                peer.bind((host, self.port))
                peer.settimeout(.1)
                if kind == socket.SOCK_STREAM:
                    peer.listen(16)
                self.sockets.append(peer)
                self.threads.append(threading.Thread(target=self.serve, args=(peer, kind)))

    def serve(self, peer, kind):
        try:
            while not self.stop.is_set():
                try:
                    if kind == socket.SOCK_DGRAM:
                        data, source = peer.recvfrom(65535)
                        self.sources.append(("udp", source[0], len(data)))
                        peer.sendto(data, source)
                    else:
                        connection, source = peer.accept()
                        self.sources.append(("tcp", source[0], 0))
                        with connection:
                            connection.settimeout(3)
                            try:
                                while data := connection.recv(16384):
                                    connection.sendall(data)
                                connection.shutdown(socket.SHUT_WR)
                            except (ConnectionResetError, BrokenPipeError):
                                pass
                except TimeoutError:
                    continue
        except Exception as error:
            self.errors.append(error)

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, kind, *_):
        self.stop.set()
        for thread in self.threads:
            thread.join(4)
        for peer in self.sockets:
            peer.close()
        if kind is None and (self.errors or any(thread.is_alive() for thread in self.threads)):
            raise RuntimeError(f"origin failed to drain: {self.errors}")


class ObservedRelay(CountedRelay):
    def __init__(self, target, ipv6):
        super().__init__(target)
        self.sources = []
        if ipv6:
            self.listener.close()
            self.listener = socket.socket(socket.AF_INET6)
            self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.listener.bind(("::1", 0))
            self.listener.listen(16)
            self.listener.settimeout(.1)
            self.port = self.listener.getsockname()[1]

    def peer(self, incoming):
        self.sources.append(incoming.getpeername()[0])
        super().peer(incoming)


def tcp(front, origin, host, success=True):
    with connect(front) as peer:
        peer.sendall(b"\x05\x01\x00")
        if exact(peer, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS negotiation")
        peer.sendall(b"\x05\x01\x00" + address(host, origin))
        reply = exact(peer, 4)
        if reply[3] not in (1, 4):
            raise RuntimeError(f"SOCKS reply family: {reply!r}")
        exact(peer, 6 if reply[3] == 1 else 18)
        if (reply[1] == 0) != success:
            raise RuntimeError(f"SOCKS success={success}, reply={reply!r}")
        if success:
            data = bytes(range(256)) * 128
            peer.sendall(data)
            if exact(peer, len(data)) != data:
                raise RuntimeError("TCP data mismatch")


def exchange(front, origin, empty=True):
    for host in ("127.0.0.1", "::1"):
        tcp(front, origin.port, host)
    with udp_client(front) as (peer, relay):
        for host in ("127.0.0.1", "::1"):
            header = bytes(3) + address(host, origin.port)
            for payload in ([b"binding", b"", bytes(range(256)) * 32] if empty else [b"binding", bytes(range(256)) * 32]):
                peer.sendto(header + payload, relay)
                if peer.recvfrom(65535)[0] != header + payload:
                    raise RuntimeError("UDP address, empty packet or payload mismatch")


def client_node(root, kind, port, host="127.0.0.1", fields="", detour=""):
    protocol = "shadowsocks" if kind == "ss" else "vless" if kind in ("vless", "vision", "upgrade") else kind
    auth = f'method "2022-blake3-aes-128-gcm"; key-file "{root / "psk"}"; udp-over-tcp "v2";' if kind == "ss" else \
        f'authentication {{ uuid-file "{root / "uuid"}"; }}' if protocol == "vless" else \
        f'authentication {{ password-file "{root / "password"}"; }}'
    tls = "" if kind == "ss" else f'tls {{ server-name "localhost"; ca-file "{root / "cert"}"; verify #true; }}'
    special = 'flow "xtls-rprx-vision";' if kind == "vision" else \
        'transport "httpupgrade" { host "localhost"; path "/binding"; };' if kind == "upgrade" else \
        'pool { max-sessions 4; min-idle 0; idle-timeout-ms 30000; check-interval-ms 30000; };' if kind == "anytls" else ""
    return f'''outbound "edge" type="{protocol}" {{ server host="{host}" port={port}; {auth}
{tls}
{special}
{fields}
{detour} }}
'''


def client_config(root, port, node, workers, direct=""):
    return f'''schema-version 1
role "client"
workers {workers}
inbound "socks" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct" {{ {direct} }}
{node}
routing {{ default-outbound "{'edge' if node else 'direct'}"; }}
'''


def server_config(root, port, kind, workers, fields):
    protocol = "shadowsocks" if kind in ("ss", "ss-native") else "vless" if kind in ("vless", "vision", "upgrade") else kind
    auth = 'authentication "none";' if kind == "socks5" else \
        f'method "2022-blake3-aes-128-gcm"; key-file "{root / "psk"}";' if protocol == "shadowsocks" else \
        f'authentication {{ user "alice" uuid-file="{root / "uuid"}"; }}' if protocol == "vless" else \
        f'authentication {{ user "alice" password-file="{root / "password"}"; }}'
    tls = "" if protocol in ("socks5", "shadowsocks") else f'tls {{ certificate-file "{root / "cert"}"; private-key-file "{root / "key"}"; }}'
    special = 'flow "xtls-rprx-vision";' if kind == "vision" else \
        'transport "httpupgrade" { host "localhost"; path "/binding"; };' if kind == "upgrade" else ""
    return f'''schema-version 1
role "server"
workers {workers}
inbounds {{ {protocol} "edge-in" {{ listen host="127.0.0.1" port={port}; {auth}
{tls}
{special}
}} }}
outbound "direct" type="direct" {{ {fields} }}
routing {{ default-outbound "direct"; }}
'''


@contextlib.contextmanager
def launch(binary, text, port, directory, fault=()):
    directory.mkdir(parents=True, exist_ok=True)
    config, trace = directory / "nexus.kdl", directory / "trace"
    config.write_text(text)
    with running(["strace", "-D", "-f", "-qq", "-e", "trace=setsockopt,bind,connect", *fault,
                  "-o", trace, binary, "run", "--config", config], port, directory / "nexus.log"):
        yield trace


def check_sources(sources, expected):
    if not sources or set(sources) != set(expected):
        raise RuntimeError(f"actual socket sources={sources}, expected={expected}")


def inbound_cases(binary, root, results):
    for workers in (1, 2):
        for kind in ("socks5", "ss-native", "ss", "vless", "vision", "upgrade", "trojan", "anytls"):
            for bound in (False, True):
                label = f"in-{kind}-w{workers}-binding{int(bound)}"
                port, front = reserve(), reserve()
                text = server_config(root, port, kind, workers, FIELDS if bound else "")
                with Origins() as origin, launch(binary, text, port, root / label):
                    if kind == "socks5":
                        exchange(port, origin)
                    elif kind == "ss-native":
                        outbound = {"type": "shadowsocks", "server": "127.0.0.1", "server_port": port,
                                    "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(bytes(range(16))).decode()}
                        with proxy_client(root, outbound) as entry:
                            exchange(entry, origin)
                    else:
                        path = root / "client.kdl"
                        path.write_text(client_config(root, front, client_node(root, kind, port), workers))
                        with nexus_process(binary, path):
                            exchange(front, origin)
                expected = (SOURCE4, SOURCE6) if bound else ("127.0.0.1", "::1")
                for transport in ("tcp", "udp"):
                    check_sources([source for protocol, source, _ in origin.sources if protocol == transport], expected)
                results.append({"case": label, "sources": origin.sources, "exit": 0})
                print(label, "TCP/UDP sources, empty data, recovery and stop passed", flush=True)


def sing_servers(root):
    tls = {"enabled": True, "certificate_path": str(root / "cert"), "key_path": str(root / "key")}
    ports, inbounds = {}, []
    for kind in KINDS:
        port = reserve()
        ports[kind] = port
        protocol = "shadowsocks" if kind == "ss" else "vless" if kind in ("vless", "vision", "upgrade") else kind
        inbound = {"type": protocol, "listen": "127.0.0.1", "listen_port": port}
        if protocol == "shadowsocks":
            inbound.update(method="2022-blake3-aes-128-gcm", password=base64.b64encode(bytes(range(16))).decode())
        else:
            inbound.update(users=[{"uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f", **({"flow": "xtls-rprx-vision"} if kind == "vision" else {})}]
                           if protocol == "vless" else [{"password": "binding-secret"}], tls=tls)
            if kind == "upgrade":
                inbound["transport"] = {"type": "httpupgrade", "host": "localhost", "path": "/binding"}
        inbounds.append(inbound)
    config = root / "sing-server.json"
    config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}))
    return ports, config


def physical_cases(binary, root, results):
    ports, config = sing_servers(root)
    with running(["sing-box", "run", "-c", config], ports["ss"], root / "sing-server.log"):
        for workers in (1, 2):
            for kind in KINDS:
                for ipv6 in (False, True):
                    for mode in ("own", "direct", "layer"):
                        label = f"out-{kind}-v{6 if ipv6 else 4}-w{workers}-{mode}"
                        target = ports["trojan"] if mode == "layer" else ports[kind]
                        with ObservedRelay(target, ipv6) as relay, Origins() as origin:
                            front = reserve()
                            host = "::1" if ipv6 else "127.0.0.1"
                            fields = FIELDS if mode == "own" else ""
                            detour = 'detour "direct";' if mode == "direct" else 'detour "lower";' if mode == "layer" else ""
                            remote = ports[kind] if mode == "layer" else relay.port
                            node = client_node(root, kind, remote, "127.0.0.1" if mode == "layer" else host, fields, detour)
                            if mode == "layer":
                                node += client_node(root, "trojan", relay.port, host, FIELDS).replace('outbound "edge"', 'outbound "lower"')
                            text = client_config(root, front, node, workers, FIELDS if mode == "direct" else "")
                            with launch(binary, text, front, root / label):
                                exchange(front, origin, empty=False)
                        check_sources(relay.sources, (SOURCE6 if ipv6 else SOURCE4,))
                        results.append({"case": label, "physical_sources": relay.sources, "exit": 0})
                        print(label, "lowest physical owner source, TCP/UDP and stop passed", flush=True)


def failure_cases(binary, root, results):
    port = reserve()
    text = client_config(root, port, "", 1, FIELDS)
    with Origins() as origin, launch(binary, text, port, root / "fault-baseline") as trace:
        tcp(port, origin.port, "127.0.0.1")
    lines = trace.read_text().splitlines()
    calls = [line for line in lines if "setsockopt(" in line]
    faults = [("setsockopt", next(i + 1 for i, line in enumerate(calls) if name in line), "EPERM", name)
              for name in ("SO_BINDTODEVICE", "SO_MARK", "SO_REUSEADDR", "IP_BIND_ADDRESS_NO_PORT")]
    calls = [line for line in lines if "bind(" in line]
    faults.append(("bind", next(i + 1 for i, line in enumerate(calls) if SOURCE4 in line), "EADDRNOTAVAIL", "source-bind"))
    for syscall, ordinal, error, label in faults:
        front = reserve()
        text = client_config(root, front, "", 1, FIELDS)
        with Origins() as origin, launch(binary, text, front, root / ("fault-" + label),
                                        (f"--inject={syscall}:error={error}:when={ordinal}",)) as trace:
            tcp(front, origin.port, "127.0.0.1", success=False)
            if origin.sources:
                raise RuntimeError("failed preparation reached origin")
            tcp(front, origin.port, "127.0.0.1")
        check_sources([source for _, source, _ in origin.sources], (SOURCE4,))
        if len(origin.sources)!=1:
            raise RuntimeError("failed preparation created an extra target connection")
        selected=SOURCE4 if label=="source-bind" else label
        if not any(selected in line and error in line and "INJECTED" in line for line in trace.read_text().splitlines()):
            raise RuntimeError(f"fault missed intended operation: {label}")
        results.append({"case": "fault-" + label, "exit": 0})
        print("fault-" + label, "refused connect and next session recovered", flush=True)


def policy_route_cases(binary, root, results):
    # Move only this temporary namespace's local rules behind two precise
    # target-port rules. Frontend/control traffic keeps normal local routing.
    with Origins() as origin:
        for family, target in (("-4", "127.0.0.1"), ("-6", "::1")):
            subprocess.run(["ip", family, "rule", "add", "pref", "1000", "lookup", "local"], check=True)
            subprocess.run(["ip", family, "rule", "del", "pref", "0"], check=True)
            subprocess.run(["ip", family, "rule", "add", "pref", "50", "fwmark", "16897", "lookup", "local"], check=True)
            for protocol, priority in (("tcp", "60"), ("udp", "61")):
                subprocess.run(["ip", family, "rule", "add", "pref", priority, "to", target,
                                "ipproto", protocol, "dport", str(origin.port), "prohibit"], check=True)
        for marked in (False, True):
            front = reserve()
            text = client_config(root, front, "", 1, FIELDS if marked else "")
            with launch(binary, text, front, root / f"policy-mark-{int(marked)}"):
                if marked:
                    exchange(front, origin)
                else:
                    for target in ("127.0.0.1", "::1"):
                        tcp(front, origin.port, target, success=False)
                    with udp_client(front) as (peer, relay):
                        peer.settimeout(.2)
                        for target in ("127.0.0.1", "::1"):
                            peer.sendto(bytes(3) + address(target, origin.port) + b"denied", relay)
                            try:
                                peer.recvfrom(65535)
                            except TimeoutError:
                                pass
                            else:
                                raise RuntimeError("unmarked UDP crossed prohibit rule")
                    if origin.sources:
                        raise RuntimeError("unmarked physical socket reached policy-routed target")
            results.append({"case": f"policy-mark-{int(marked)}", "exit": 0})
            print(f"policy-mark-{int(marked)}", "real TCP/UDP IPv4/IPv6 route selection passed", flush=True)
        for family in ("-4", "-6"):
            subprocess.run(["ip", family, "rule", "add", "pref", "0", "lookup", "local"], check=True)
            for priority in ("50", "60", "61", "1000"):
                subprocess.run(["ip", family, "rule", "del", "pref", priority], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--scope", choices=("all", "inbound", "physical", "failures", "policy"), default="all")
    parser.add_argument("--evidence", type=pathlib.Path)
    parser.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    if not args.binary.is_file():
        parser.error("binary must be a regular executable file")
    if not args.isolated:
        command = ["unshare", "-Urn", sys.executable, str(pathlib.Path(__file__).resolve()), str(args.binary.resolve()),
                   "--isolated", "--scope", args.scope]
        if args.evidence:
            command += ["--evidence", str(args.evidence.resolve())]
        subprocess.run(command, check=True)
        return
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "-6", "addr", "add", SOURCE6 + "/128", "dev", "lo", "nodad"], check=True)
    if f"Revision: {REVISION}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
        raise RuntimeError("unexpected sing-box revision")
    root = pathlib.Path(tempfile.mkdtemp(prefix="nexus-socket-binding-"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", root / "key", "-out", root / "cert", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for name, value in (("uuid", "00010203-0405-0607-0809-0a0b0c0d0e0f"), ("password", "binding-secret"),
                        ("psk", base64.b64encode(bytes(range(16))).decode())):
        (root / name).write_text(value + "\n")
        (root / name).chmod(0o600)
    results, complete = [], False
    try:
        if args.scope in ("all", "inbound"):
            inbound_cases(args.binary.resolve(), root, results)
        if args.scope in ("all", "physical"):
            physical_cases(args.binary.resolve(), root, results)
        if args.scope in ("all", "failures"):
            failure_cases(args.binary.resolve(), root, results)
        if args.scope in ("all", "policy"):
            policy_route_cases(args.binary.resolve(), root, results)
        complete = True
    finally:
        evidence = {"binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                    "driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                    "artifacts": str(root), "complete": complete, "scope": args.scope,
                    "expected_cases": {"all": 111, "inbound": 32, "physical": 72, "failures": 5, "policy": 2}[args.scope],
                    "cases": results}
        if args.evidence:
            args.evidence.parent.mkdir(parents=True, exist_ok=True)
            args.evidence.write_text(json.dumps(evidence, indent=2) + "\n")
        print("Binding artifacts:", root, flush=True)


if __name__ == "__main__":
    main()
