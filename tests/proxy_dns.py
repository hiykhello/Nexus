"""Exercise explicit DNS through the actual proxy CLI and loopback target."""
import pathlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()
guard = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None


def exact(sock, n):
    data = b""
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise RuntimeError("unexpected EOF")
        data += part
    return data


def scenario(workers, mode="success", ipv6=False, named_config=False, strategy=None, bootstrap=None, disable_cache=False):
    dns = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
    host = "::1" if ipv6 else "127.0.0.1"
    dns.bind((host, 0))
    dns.settimeout(0.1)
    dns_tcp = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
    dns_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_tcp.bind((host, dns.getsockname()[1]))
    dns_tcp.listen(8)
    dns_tcp.settimeout(0.1)
    target = socket.socket(socket.AF_INET6 if strategy else socket.AF_INET, socket.SOCK_STREAM)
    if strategy:
        target.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    target.bind(("::" if strategy else "127.0.0.1", 0))
    target.listen(8)
    target.settimeout(0.1)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    quit_event = threading.Event()
    queries = []
    query_names = []
    tcp_queries = []
    queried = threading.Event()
    middle_queried = threading.Event()
    tcp_queried = threading.Event()
    tcp_closed = threading.Event()
    errors = []
    accepted = []

    def nameserver():
        try:
            while not quit_event.is_set():
                try:
                    query, peer = dns.recvfrom(512)
                except TimeoutError:
                    continue
                kind = int.from_bytes(query[-4:-2], "big")
                if query[12:-4] not in (b"\x06target\x04test\x00", b"\x09localhost\x00", b"\x06middle\x04test\x00", b"\x04leaf\x04test\x00") or kind not in (1, 28):
                    raise RuntimeError("unexpected DNS query")
                queries.append(kind)
                query_names.append(query[12:-4])
                queried.set()
                if mode in ("bootstrap-stall-middle", "bootstrap-timeout-middle") and query[12:-4] == b"\x04leaf\x04test\x00":
                    middle_queried.set()
                    continue
                if mode == "bootstrap-timeout-middle" and query[12:-4] == b"\x06middle\x04test\x00" and kind == 1:
                    if quit_event.wait(2):
                        break
                if mode == "stalled":
                    continue
                if mode.startswith("fallback-timeout") and quit_event.wait(2):
                    break
                reply = bytearray(query)
                reply[2:4] = b"\x81\x80"
                if mode.startswith("fallback"):
                    reply[2] |= 2
                elif mode == "failure":
                    reply[3] = 0x82
                elif kind == 1:
                    reply[7] = 1
                    reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                elif strategy:
                    reply[7] = 1
                    reply.extend(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes(15) + b"\x01")
                else:
                    reply[9] = 1
                    reply.extend(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x0c\xc0\x0c" + bytes(20))
                dns.sendto(reply, peer)
        except Exception as exc:
            errors.append(exc)

    def tcp_nameserver():
        try:
            while not quit_event.is_set():
                try:
                    conn, _ = dns_tcp.accept()
                except TimeoutError:
                    continue
                with conn:
                    conn.settimeout(2)
                    size = int.from_bytes(exact(conn, 2), "big")
                    query = exact(conn, size)
                    kind = int.from_bytes(query[-4:-2], "big")
                    if query[12:-4] != b"\x06target\x04test\x00" or kind not in (1, 28):
                        raise RuntimeError("unexpected TCP DNS query")
                    tcp_queries.append(kind)
                    if mode.startswith(("fallback-stop", "fallback-timeout")):
                        if mode == "fallback-stop-prefix":
                            conn.sendall(b"\x00")
                        elif mode == "fallback-timeout-payload":
                            conn.sendall(b"\x00\x20" + query[:4])
                        tcp_queried.set()
                        conn.settimeout(0.1)
                        while not quit_event.is_set():
                            try:
                                if not conn.recv(1):
                                    tcp_closed.set()
                                    break
                                raise RuntimeError("unexpected extra TCP DNS data")
                            except TimeoutError:
                                continue
                        continue
                    reply = bytearray(query)
                    reply[2:4] = b"\x81\x80"
                    if mode == "fallback-bad-id":
                        reply[1] ^= 1
                    elif kind == 1:
                        reply[7] = 1
                        reply.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01")
                    elif strategy:
                        reply[7] = 1
                        reply.extend(b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + bytes(15) + b"\x01")
                    else:
                        reply[9] = 1
                        reply.extend(b"\xc0\x13\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x18\xc0\x13\xc0\x13" + bytes(20))
                    frame = len(reply).to_bytes(2, "big") + reply
                    conn.sendall(frame[:1])
                    conn.sendall(frame[1:])
        except Exception as exc:
            errors.append(exc)

    def upstream():
        try:
            while not quit_event.is_set():
                try:
                    conn, peer = target.accept()
                except TimeoutError:
                    continue
                with conn:
                    accepted.append(peer[0])
                    conn.settimeout(2)
                    conn.sendall(exact(conn, 4).upper())
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=nameserver), threading.Thread(target=tcp_nameserver), threading.Thread(target=upstream)]
    for thread in threads:
        thread.start()
    with tempfile.TemporaryDirectory() as tmp:
        config = pathlib.Path(tmp) / "proxy.kdl"
        if mode == "block":
            (pathlib.Path(tmp) / "blocked.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
        routing = ('outbound "reject" type="block"\nrouting { rule-set "blocked" path="blocked.kdl" format="kdl"; '
                   'rules { - kind="rule-set" value="blocked" outbound="reject"; }; default-outbound "direct"; }') if mode == "block" else 'routing { default-outbound "direct"; }'
        if named_config == "tcp":
            dns_config = f'dns {{ server "tcp" type="tcp" host="{host}" port={dns.getsockname()[1]}; }}'
        elif named_config is True:
            dns_config = (f'dns {{ server "unused" type="udp" host="127.0.0.2"; '
                          f'server "chosen" type="udp" host="{host}" port={dns.getsockname()[1]}; final "chosen"; }}')
        elif named_config == "local":
            dns_config = 'dns { server "unused" type="udp" host="127.0.0.2"; server "system" type="local"; final "system"; }'
        else:
            dns_config = f'dns {{ server "up" type="udp" host="{host}" port={dns.getsockname()[1]}; final "up"; }}'
        if strategy:
            server = ('server "chosen" type="local"' if named_config == "local" else
                      f'server "chosen" type="{"tcp" if named_config == "tcp" else "udp"}" host="{host}" port={dns.getsockname()[1]}')
            dns_config = f'dns {{ {server}; strategy "{strategy}"; }}'
        if bootstrap == "chain":
            leaf_type = "tcp" if named_config == "tcp" else "udp"
            dns_config = (f'dns {{ server "leaf" type="{leaf_type}" host="leaf.test" port={dns.getsockname()[1]} domain-resolver="middle"; '
                          f'server "middle" type="udp" host="middle.test" port={dns.getsockname()[1]} domain-resolver="root"; '
                          f'server "root" type="udp" host="{host}" port={dns.getsockname()[1]}; '
                          + (f'strategy "{strategy}"; ' if strategy else '') + '}')
        elif bootstrap == "local":
            dns_config = (f'dns {{ server "leaf" type="udp" host="localhost" port={dns.getsockname()[1]} domain-resolver="root"; '
                          'server "root" type="local"; }')
        if disable_cache:
            if not dns_config.startswith("dns {"):
                raise RuntimeError("disable-cache requires a DNS block")
            dns_config = dns_config[:-1] + ' disable-cache #true; }'
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
{dns_config}
inbound "local" type="socks5" {{
  listen host="127.0.0.1" port={port}
  authentication "none"
}}
outbound "direct" type="direct"
{routing}
''')
        env = os.environ.copy()
        if guard and named_config != "local" and bootstrap != "local":
            env["LD_PRELOAD"] = str(guard)
        proc = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise RuntimeError(f"proxy exited: {proc.stderr.read()!r}")
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            for index in range(2 if mode == "success" else 1):
                if index:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
                with sock:
                    sock.settimeout(3)
                    sock.sendall(b"\x05\x01\x00")
                    assert exact(sock, 2) == b"\x05\x00"
                    name = b"localhost" if mode == "failure" or named_config == "local" else b"target.test"
                    started = time.monotonic()
                    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target.getsockname()[1].to_bytes(2, "big") + b"ping")
                    if mode in ("stalled", "bootstrap-stall-middle"):
                        if not (middle_queried if mode == "bootstrap-stall-middle" else queried).wait(2):
                            raise RuntimeError("DNS query was not sent")
                        proc.terminate()
                        proc.wait(timeout=2)
                        if proc.returncode:
                            raise RuntimeError(f"stalled DNS stop exit {proc.returncode}")
                        break
                    if mode == "bootstrap-timeout-middle":
                        if not middle_queried.wait(4):
                            raise RuntimeError("intermediate bootstrap query was not sent")
                        sock.settimeout(12)
                        first = sock.recv(1)
                        reply = first + exact(sock, 9) if first else b""
                        if (reply and reply[:4] != b"\x05\x06\x00\x01") or not 9 <= time.monotonic()-started < 12:
                            raise RuntimeError("bootstrap did not respect the shared deadline")
                        continue
                    if mode.startswith(("fallback-stop", "fallback-timeout")):
                        if not tcp_queried.wait(4):
                            raise RuntimeError("TCP fallback query was not sent")
                        if mode.startswith("fallback-stop"):
                            proc.terminate()
                            proc.wait(timeout=2)
                            if proc.returncode:
                                raise RuntimeError(f"TCP fallback stop exit {proc.returncode}")
                        else:
                            sock.settimeout(12)
                            # The session expiry can close the client at the
                            # same deadline as the DNS timeout response.
                            first = sock.recv(1)
                            if first:
                                reply = first + exact(sock, 9)
                                assert reply[:4] == b"\x05\x06\x00\x01"
                            elapsed = time.monotonic() - started
                            if not 9 <= elapsed < 12:
                                raise RuntimeError(f"unexpected total DNS deadline: {elapsed:.2f}s")
                        if not tcp_closed.wait(2):
                            raise RuntimeError("TCP fallback connection was not closed")
                        continue
                    reply = exact(sock, 4)
                    if reply[3] == 1:
                        exact(sock, 6)
                    elif reply[3] == 4:
                        exact(sock, 18)
                    else:
                        raise RuntimeError(f"unexpected SOCKS reply address type: {reply!r}")
                    if mode in ("block", "failure", "fallback-bad-id"):
                        assert reply == (b"\x05\x02\x00\x01" if mode == "block" else b"\x05\x04\x00\x01")
                        continue
                    assert reply[:3] == b"\x05\x00\x00"
                    assert exact(sock, 4) == b"PING"
            if mode == "success" and workers == 1 and not strategy and not bootstrap and named_config not in ("local", "tcp") and queries != ([1, 28, 1, 28] if disable_cache else [1, 28, 28]):
                raise RuntimeError(f"expected cached second resolution, saw {queries}")
            if bootstrap == "chain" and mode == "success" and workers == 1 and not strategy and named_config != "tcp":
                middle, leaf, target_name = b"\x06middle\x04test\x00", b"\x04leaf\x04test\x00", b"\x06target\x04test\x00"
                expected = [(middle, 1), (middle, 28), (leaf, 1), (leaf, 28), (target_name, 1), (target_name, 28),
                            (middle, 28), (leaf, 28), (target_name, 28)]
                if disable_cache:
                    expected = expected[:6] * 2
                if list(zip(query_names, queries)) != expected:
                    raise RuntimeError(f"unexpected bootstrap queries: {list(zip(query_names, queries))}")
            if strategy and workers == 1 and named_config != "local":
                expected = {"prefer_ipv4": [1, 28], "prefer_ipv6": [28, 1], "ipv4_only": [1], "ipv6_only": [28]}[strategy]
                if disable_cache:
                    expected *= 2
                actual = tcp_queries if named_config == "tcp" else queries
                if actual != expected:
                    raise RuntimeError(f"unexpected {strategy} DNS queries: {actual}")
            if strategy:
                expected_ipv6 = strategy in ("prefer_ipv6", "ipv6_only")
                if len(accepted) != 2 or any((peer == "::1") != expected_ipv6 for peer in accepted):
                    raise RuntimeError(f"unexpected system resolver address family: {accepted}")
            if named_config == "tcp":
                expected_tcp = ({"prefer_ipv4": [1, 28], "prefer_ipv6": [28, 1], "ipv4_only": [1], "ipv6_only": [28]}[strategy]
                                if strategy else ([1, 28, 1, 28] if disable_cache else [1, 28, 28]) if mode == "success" else [1])
                if strategy and disable_cache:
                    expected_tcp *= 2
                allowed = [expected_tcp] if workers == 1 or mode != "success" else [expected_tcp, [1, 28, 1, 28]]
                if (queries and not bootstrap) or tcp_queries not in allowed:
                    raise RuntimeError(f"unexpected TCP-only DNS queries: udp={queries}, tcp={tcp_queries}")
            if (mode in ("block", "failure", "fallback-bad-id", "stalled", "bootstrap-stall-middle", "bootstrap-timeout-middle") or mode.startswith(("fallback-stop", "fallback-timeout"))) and accepted:
                raise RuntimeError("blocked or failed resolution connected to target")
            if mode.startswith("fallback") and tcp_queries != ([1, 28] if mode == "fallback" else [1]):
                raise RuntimeError(f"unexpected TCP fallback queries {tcp_queries}")
            if (named_config not in ("local", "tcp") and not queries) or errors:
                raise RuntimeError(f"queries={queries}, errors={errors}")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            quit_event.set()
            for thread in threads:
                thread.join(timeout=2)
            dns.close()
            dns_tcp.close()
            target.close()
            stderr = proc.stderr.read()
            if proc.returncode or b"unexpected-system-resolver" in stderr:
                raise RuntimeError(f"proxy exit {proc.returncode}: {stderr!r}")


for count in (1, 2):
    for ipv6 in (False, True):
        scenario(count, ipv6=ipv6)
        for mode in ("stalled", "block", "failure", "fallback", "fallback-bad-id", "fallback-stop", "fallback-timeout", "fallback-stop-prefix", "fallback-timeout-payload"):
            scenario(count, mode, ipv6)
scenario(1, named_config=True)
scenario(1, named_config="local")
scenario(1, bootstrap="chain")
scenario(1, bootstrap="local")
scenario(1, bootstrap="chain", disable_cache=True)
scenario(1, named_config=True, disable_cache=True)
scenario(1, named_config="tcp", disable_cache=True)
scenario(1, ipv6=True, named_config="tcp", strategy="ipv6_only", bootstrap="chain")
for count in (1, 2):
    for mode in ("failure", "stalled", "bootstrap-stall-middle"):
        scenario(count, mode=mode, bootstrap="chain")
scenario(1, mode="bootstrap-timeout-middle", bootstrap="chain")
for strategy in ("prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"):
    scenario(1, strategy=strategy)
    scenario(1, named_config="local", strategy=strategy)
    scenario(1, named_config="tcp", strategy=strategy)
for count in (1, 2):
    for ipv6 in (False, True):
        scenario(count, ipv6=ipv6, named_config="tcp")
        scenario(count, mode="fallback-bad-id", ipv6=ipv6, named_config="tcp")
        scenario(count, mode="fallback-stop-prefix", ipv6=ipv6, named_config="tcp")
        scenario(count, mode="fallback-timeout-payload", ipv6=ipv6, named_config="tcp")
print("explicit DNS proxy resolution and cache passed")
