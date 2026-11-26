#!/usr/bin/env python3
"""Exercise the production state CLI, FakeIP crash recovery and DNS shards."""
import contextlib
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from dns_message_persistence_network import Peer, checkpoint_listener_port
from dns_rule_support import dns_request, exact
from dns_tls_network import DotServer


@contextlib.contextmanager
def running(binary, config, crash=False, env=None):
    with tempfile.TemporaryFile() as diagnostics:
        process = subprocess.Popen(["stdbuf", "-oL", binary, "run", "--config", config],
                                   stdout=subprocess.PIPE, stderr=diagnostics, env=env)
        try:
            assert select.select([process.stdout], [], [], 10)[0], "listener startup deadline"
            assert b"listening" in process.stdout.readline()
            yield process
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            process.wait(timeout=10)
            process.stdout.close()
            if process.returncode != (-signal.SIGKILL if crash else 0):
                diagnostics.seek(0)
                raise RuntimeError(f"process exit {process.returncode}: {diagnostics.read().decode()}")


def program(dns_port, dns, state="", proxy_port=None):
    proxy_port = proxy_port or checkpoint_listener_port()
    return f'''schema-version 1
role "client"
inbounds {{
    inbound "main" type="socks5" {{
        listen host="127.0.0.1" port={proxy_port}
        authentication "none"
    }}
}}
outbounds {{ outbound "direct" type="direct"; }}
routing {{ default-outbound "direct"; }}
{state}
dns {{
    listen host="127.0.0.1" port={dns_port}
    {dns}
}}
'''


def command(binary, config, verb, *options, expect=0):
    result = subprocess.run([binary, "state", verb, "--config", config, *options],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == expect, (result.stdout, result.stderr)
    return result


def per_mapping_fault(binary, config, port, shim):
    import concurrent.futures

    env = dict(os.environ, LD_PRELOAD=str(shim), NEXUS_STATE_FAULT="fakeip-partial-wal")
    with running(binary, config, crash=True, env=env) as process,             concurrent.futures.ThreadPoolExecutor() as pool:
        observed = pool.submit(dns_request, port, "torn.private.test")
        try:
            assert select.select([process.stdout], [], [], 4)[0]
            assert process.stdout.readline() == b"READY\n"
            assert not observed.done(), "per-mapping answer preceded WAL sync"
        finally:
            process.kill()
            try:
                observed.result(timeout=4)
            except TimeoutError:
                pass
            else:
                raise AssertionError("a partial WAL record produced an answer")


def fakeip(binary, root, peer, shim, durable):
    state, cache = root / "authority", root / "cache"
    config = root / "proxy.kdl"
    port = checkpoint_listener_port()
    mode = "per-mapping" if durable else "range-reserve"
    proxy = checkpoint_listener_port()
    config.write_text(program(port, f'''
servers {{ server "dns" type="udp" host="{peer.host}" port={peer.port}; }}
final "dns"
fake-ip server="dns" ipv4-pool="198.18.0.0/22" ipv6-pool="fd15:4231::/96"
''', f'''state {{
    directory "{state}"
    cache-directory "{cache}"
    fakeip-crash-mode "{mode}"
}}''', proxy))
    empty = command(binary, config, "inspect").stdout
    assert "health=missing" in empty and not state.exists() and not cache.exists()
    with running(binary, config, crash=True):
        assert dns_request(port, "known.private.test") == (0, "198.18.0.1")
        # One complete record is needed before the separate torn-tail fault.
        if not durable:
            deadline = time.monotonic() + 3
            complete=64+14+len("known.private.test")
            while (state / "fakeip/fakeip.wal").stat().st_size < complete and time.monotonic() < deadline:
                time.sleep(.02)
            assert (state / "fakeip/fakeip.wal").stat().st_size == complete
    with running(binary, config, crash=True):
        assert dns_request(port, "known.private.test") == (0, "198.18.0.1")
    # A fresh restart in range mode skips to the next reservation before the
    # torn record. A durable store still advances exactly one complete slot.
    if durable:
        per_mapping_fault(binary, config, port, shim)
    else:
        env = dict(os.environ, LD_PRELOAD=str(shim), NEXUS_STATE_FAULT="fakeip-partial-wal")
        with running(binary, config, crash=True, env=env) as process:
            assert dns_request(port, "torn.private.test") == (0, "198.18.1.1")
            assert select.select([process.stdout], [], [], 4)[0]
            assert process.stdout.readline() == b"READY\n"
    wal = state / "fakeip/fakeip.wal"
    torn_size = wal.stat().st_size
    with running(binary, config, crash=True):
        assert wal.stat().st_size < torn_size, "torn suffix was not truncated at restart"
        assert dns_request(port, "known.private.test") == (0, "198.18.0.1")
        if not durable:
            with socket.create_connection(("127.0.0.1", proxy), timeout=3) as client:
                client.sendall(b"\5\1\0")
                assert exact(client,2)==b"\5\0"
                client.sendall(b"\5\1\0\1" + socket.inet_aton("198.18.1.1") + b"\0\120")
                status=client.recv(2)
                assert status==b"" or status[1]!=0, "lost range lease resolved to a new domain"
        expected = "198.18.0.2" if durable else "198.18.2.1"
        assert dns_request(port, "new.private.test") == (0, expected)
        refused = command(binary, config, "reset", "--target", "fakeip", "--confirm", expect=1)
        assert "lock instance" in refused.stderr
    info = command(binary, config, "inspect").stdout
    assert "private.test" not in info and str(state) not in info
    assert "component=fakeip version=NXFP01 entries=" in info
    # Explicit selector legacy snapshot proves byte-for-byte authority isolation.
    selector = state / "selectors.state"
    selector.write_bytes(b"NXSEL1\0")
    selector.chmod(0o600)
    names = [selector, state / "fakeip/fakeip.meta", wal]
    before = [path.read_bytes() for path in names]
    command(binary, config, "clear-cache")
    assert [path.read_bytes() for path in names] == before
    refusal = command(binary, config, "reset", "--target", "fakeip", expect=2)
    assert "--confirm" in refusal.stderr
    assert [path.read_bytes() for path in names] == before
    selector_backup = command(binary, config, "reset", "--target", "selectors", "--confirm")
    assert not selector.exists() and (state / selector_backup.stdout.strip().split("=",1)[1]).read_bytes() == before[0]
    fake_backup = command(binary, config, "reset", "--target", "fakeip", "--confirm")
    backup_dir = state / fake_backup.stdout.strip().split("=",1)[1]
    assert not (state / "fakeip").exists()
    assert (backup_dir / "fakeip.meta").read_bytes() == before[1]
    with running(binary, config):
        assert dns_request(port, "after-reset.private.test") == (0, "198.18.0.1")
    print(f"PASS {mode} SIGKILL, torn WAL, restore/reallocation, redacted inspect, protected clear, backed-up reset")


def encrypted_views(binary, root, plain):
    with DotServer(root, "127.0.0.1", socket.AF_INET) as tls:
        config, cache = root / "proxy.kdl", root / "cache"
        rules = root / "view.kdl"
        port = checkpoint_listener_port()
        dns = f'''
servers {{
    server "plain" type="udp" host="{plain.host}" port={plain.port}
    server "secure" type="tls" host="{tls.host}" port={tls.port} server-name="dot.test" ca-file="{tls.cert}"
}}
rule-set "policy" path="{rules}" format="kdl"
rules {{ - rule-set="policy" server="secure"; }}
final "plain"
'''
        config.write_text(program(port, dns, f'state {{ cache-directory "{cache}"; }}'))
        fingerprint = lambda domain: f'schema-version 2\nkind "predicate"\nrule type="domain" value="{domain}"\n'
        rules.write_text(fingerprint("secure.private.test"))
        initial_plain = len(plain.seen)
        for iteration in range(2):
            with running(binary, config):
                for name in ("secure.private.test", "plain.private.test"):
                    assert dns_request(port, name) == (0, "127.0.0.1")
                assert len(tls.queries) == 1 and len(plain.seen) == initial_plain+1, iteration
        rules.write_text(fingerprint("plain.private.test"))
        with running(binary, config):
            for name in ("secure.private.test", "plain.private.test"):
                assert dns_request(port, name) == (0, "127.0.0.1")
            assert len(tls.queries) == 2 and len(plain.seen) == initial_plain+2
        paths = list((cache / "dns").glob("*.state"))
        assert len(paths) == 2
        shards = {path:path.read_bytes() for path in paths}
        command(binary, config, "clear-cache", "--rulesets")
        assert all(path.read_bytes()==wire for path,wire in shards.items())
        rules_index = cache / "rulesets/index.state"
        cached_index = rules_index.read_bytes()
        with running(binary, config):
            assert dns_request(port, "plain.private.test") == (0, "127.0.0.1")
            command(binary, config, "clear-cache", "--dns")
        assert rules_index.read_bytes() == cached_index
        assert sorted(path.name for path in (cache / "dns").glob("*.state")) == ["epoch.state"]
        with running(binary, config):
            assert dns_request(port, "plain.private.test") == (0, "127.0.0.1")
            assert len(tls.queries) == 3
        assert "private.test" not in command(binary, config, "inspect").stdout
    print("PASS encrypted/external rules, cold policy isolation, live DNS clear epoch rejects old checkpoint")


if __name__ == "__main__":
    cli, library = (Path(path).resolve(strict=True) for path in sys.argv[1:3])
    with tempfile.TemporaryDirectory(prefix="nexus-state-cli-") as directory, Peer() as peer:
        root = Path(directory)
        for label in ("range", "mapping", "encrypted"):
            (root / label).mkdir()
        fakeip(cli, root / "range", peer, library, False)
        fakeip(cli, root / "mapping", peer, library, True)
        encrypted_views(cli, root / "encrypted", peer)
