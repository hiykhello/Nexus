#!/usr/bin/env python3
"""Check named HTTPS interface selection before the TLS handshake."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import os
import select
import subprocess
import sys
import tempfile
import time

from detour_network import reserve
from network_selection_network import LINKS, TARGETS, default_route, peers, process, stall_primary_connects


TLS_PEER = r"""
import selectors, socket, ssl, sys, threading
label, port, cert, key, *addresses = sys.argv[1:]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(["http/1.1"])
ctx.load_cert_chain(cert, key)
rules = f'schema-version 2\nkind "predicate"\nrule type="domain" value="{label}.test"\n'.encode()
def serve(raw):
    try:
        with raw:
            raw.settimeout(2)
            with ctx.wrap_socket(raw, server_side=True) as peer:
                request = bytearray()
                while not request.endswith(b"\r\n\r\n") and len(request)<8192:
                    chunk = peer.recv(4096)
                    if not chunk: return
                    request.extend(chunk)
                assert request.startswith(b"GET /rules HTTP/1.1\r\n")
                peer.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(rules)}\r\nConnection: close\r\n\r\n".encode()+rules)
                peer.unwrap()
    except (OSError, ValueError):
        pass
with selectors.DefaultSelector() as active:
    for address in addresses:
        listener = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET)
        listener.bind((address, int(port)))
        listener.listen()
        active.register(listener, selectors.EVENT_READ)
    print("ready", flush=True)
    while True:
        for info, _ in active.select():
            conn, _ = info.fileobj.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()
"""


@contextmanager
def run_quic(command, binding, source):
    env = dict(os.environ, NEXUS_TEST_BIND_UDP_ADDRESS=binding,
               NEXUS_TEST_SOURCE_HOST=source, NEXUS_TEST_SERVER_NAME="")
    with subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as peer:
        try:
            if not select.select([peer.stdout], [], [], 4)[0] or not peer.stdout.readline().strip():
                raise RuntimeError(f"HTTP/3 peer startup failed: {command}")
            yield
        finally:
            if peer.poll() is None:
                peer.terminate()
            _, errors = peer.communicate(timeout=3)
            if b"unexpected source" in errors or b"received UDP payload" in errors:
                raise RuntimeError(errors.decode(errors="replace"))


def authority(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def check(binary, quic_fixture=None):
    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix="nexus-https-networks-") as directory:
        root = Path(directory)
        namespaces = peers(stack, reserve())
        origin, front = reserve(), reserve()
        cert, key, config, output = (root / name for name in ("cert", "key", "nexus.kdl", "published.kdl"))
        names = ",".join(f"IP:{address}" for address in TARGETS)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=network-selection.test", "-addext", f"subjectAltName={names}",
                        "-keyout", key, "-out", cert], check=True, capture_output=True)
        for name, pid in namespaces.items():
            stack.enter_context(process(["nsenter", "-t", str(pid), "-n", "--", sys.executable, "-u",
                                         "-c", TLS_PEER, name, str(origin), cert, key, *TARGETS]))
        if quic_fixture:
            for link in LINKS:
                label, source4, _, source6, _, _ = link
                rules = root / f"{label}.kdl"
                rules.write_text(f'schema-version 2\nkind "predicate"\nrule type="domain" value="{label}.test"\n')
                command = ["nsenter", "-t", str(namespaces[label]), "-n", "--", quic_fixture, cert, key, rules]
                for target, source in zip(TARGETS, (source4, source6), strict=True):
                    stack.enter_context(run_quic(command, authority(target, origin), source))
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{
  network strategy="prefer" type="ethernet" fallback="wifi" fallback-delay-ms=125 {{
    interface "primary" type="ethernet"
    interface "backup" type="wifi"
  }}
}}
dns {{ server "bootstrap" type="local"; final "bootstrap"; }}
http-clients {{
  updates {{ outbound "direct"; domain-resolver "bootstrap"; ca-file "{cert}"; timeout-ms 950; }}
}}
routing {{ default-outbound "direct"; }}
''')

        def fetch(address, expect):
            result = subprocess.run([binary, "rule", "fetch", config, "updates",
                                     f"https://{authority(address, origin)}/rules", "kdl", output],
                                    capture_output=True, text=True, timeout=3)
            if expect:
                assert not result.returncode and f'"{expect}.test"' in output.read_text(), result.stderr
            else:
                assert result.returncode and ("connection" in result.stderr or "eligible" in result.stderr), result.stderr

        def verify(udp):
            for target in TARGETS:
                fetch(target, "primary")
            with stall_primary_connects(namespaces["primary"], origin, udp=udp):
                for target in TARGETS:
                    start = time.monotonic()
                    fetch(target, "backup")
                    assert .10 <= time.monotonic() - start < .9, target
            for link in LINKS:
                default_route(link, False)
            try:
                for target in TARGETS:
                    fetch(target, None)
            finally:
                for link in LINKS:
                    default_route(link, True)

        verify(False)
        print("Named HTTPS used both selected interfaces before TLS over IPv4 and IPv6")
        if quic_fixture:
            options='protocol "h3"; max-udp-payload-size 1200; timeout-ms 950;'
            config.write_text(config.read_text().replace('timeout-ms 950;', options))
            verify(True)
            print("Named HTTP/3 used both selected interfaces before QUIC over IPv4 and IPv6")


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    namespace = os.stat("/proc/self/ns/net").st_ino
    if "--parent-netns" not in sys.argv:
        fixture = [str(Path(sys.argv[2]).resolve(strict=True))] if len(sys.argv)==3 else []
        subprocess.run(["unshare", "-Urn", "--", sys.executable, __file__, binary, *fixture,
                        "--parent-netns", str(namespace)], check=True)
    else:
        assert int(sys.argv[-1]) != namespace
        check(binary, sys.argv[2] if len(sys.argv)==5 else None)
