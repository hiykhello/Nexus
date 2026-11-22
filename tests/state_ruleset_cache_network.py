#!/usr/bin/env python3
"""Exercise persistent rule cache through real HTTPS and a private directory."""

import argparse
from contextlib import contextmanager
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, free_port
from named_http_rule_fetch import RULES
from udp_bind_port_network import certificate


class Origin(ThreadingHTTPServer):
    def __init__(self, root):
        super().__init__(("127.0.0.1", 0), Handler)
        self.body = RULES
        self.tag = 'W/"shared"'
        self.seen = []
        self.arrived = threading.Event()
        self.release = threading.Event()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.load_cert_chain(root / "cert", root / "key")
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        received = self.headers.get("If-None-Match")
        code = 304 if received == self.server.tag else 200
        self.server.seen.append((self.path, received, code))
        if self.path == "/held":
            self.server.arrived.set()
            if not self.server.release.wait(4):
                return
        self.send_response(code)
        self.send_header("Connection", "close")
        self.send_header("ETag", self.server.tag)
        self.send_header("Last-Modified", "Sat, 07 Mar 2026 00:00:00 GMT")
        if code == 200:
            self.send_header("Content-Length", str(len(self.server.body)))
        self.end_headers()
        if code == 200:
            self.wfile.write(self.server.body)


@contextmanager
def running(root):
    with Origin(root) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02})
        thread.start()
        try:
            yield server
        finally:
            server.release.set()
            server.shutdown()
            thread.join()


def until(action):
    end = time.monotonic() + 5
    while not action():
        assert time.monotonic() < end
        time.sleep(.02)


def configuration(root, dns):
    path = root / "client.kdl"
    path.write_text(f'''schema-version 1
role "client"
inbound "front" type="socks5" {{ listen host="127.0.0.1" port={free_port()}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
    server "numeric" type="udp" host="127.0.0.1" port={dns.port}
    final "numeric"
    strategy "ipv4_only"
}}
http-clients {{
    fetch {{
        outbound "direct"; domain-resolver "numeric"; ca-file "{root / 'cert'}"
        protocol "http/1.1"; timeout-ms 1600; max-response-bytes 8192
    }}
}}
''')
    return path


def arguments(config, url, format, output, cache, *options):
    return [config, "fetch", url, format, output, "--cache-dir", cache, *options]


def execute(binary, command, *args, accept=True):
    proc = subprocess.run([binary, "rule", command, *args], capture_output=True, text=True, timeout=6)
    assert (proc.returncode == 0) == accept, proc
    return proc


def formats(binary, compiler, root):
    plain = root / "payload.kdl"
    structured = root / "payload.beve"
    packed = root / "payload.srs"
    source = root / "payload.json"
    plain.write_bytes(RULES)
    execute(binary, "convert", "kdl", "beve", plain, structured)
    source.write_text(json.dumps({"version": 2, "rules": [{"domain": "fresh.test"}]}))
    subprocess.run([compiler, "rule-set", "compile", source, "-o", packed], check=True, capture_output=True)
    return [("kdl", RULES), ("beve", structured.read_bytes()), ("srs", packed.read_bytes())]


def check(binary, compiler, root, dns):
    certificate(root)
    config = configuration(root, dns)
    cache = root / "cache"
    cache.mkdir(mode=0o700)
    child = cache / "rulesets"
    output = root / "out"
    payloads = formats(binary, compiler, root)

    with running(root) as origin:
        url = f"https://localhost:{origin.server_port}/rules"
        for format, data in payloads:
            origin.body = data
            args = arguments(config, url, format, output, cache)
            execute(binary, "fetch", *args)
            assert origin.seen[-1] == ("/rules", None, 200), origin.seen
            assert output.read_bytes() == data
            output.unlink()
            execute(binary, "fetch", *args)
            assert origin.seen[-1] == ("/rules", origin.tag, 304), origin.seen
            assert output.read_bytes() == data
        print("PASS #4136 same URL and ETag: KDL, BEVE and SRS each start with unconditional 200, then 304")
        assert (child / "index.state").read_bytes().startswith(b"NXRS01")
        assert len(list(child.glob("*.blob"))) == 3

        origin.body = RULES
        kdl = next(path for path in child.glob("*.blob") if path.read_bytes() == RULES)
        kdl.write_bytes(b"!" + RULES[1:])
        args = arguments(config, url, "kdl", output, cache)
        child.chmod(0o500)
        count = len(origin.seen)
        try:
            failed = execute(binary, "fetch", *args, accept=False)
            assert "remove cache blob" in failed.stderr and f"errno={errno.EACCES}" in failed.stderr, failed
            assert len(origin.seen) == count and kdl.read_bytes().startswith(b"!")
        finally:
            child.chmod(0o700)
        execute(binary, "fetch", *args)
        assert origin.seen[-1] == ("/rules", None, 200)
        assert kdl.read_bytes() == RULES
        print("PASS #4727 real EACCES unlink on mode 0500, preserves original file and reports deletion error")

        index = child / "index.state"
        index.write_bytes(b"bad index")
        child.chmod(0o500)
        try:
            failure = execute(binary, "fetch", *args, accept=False)
            assert "remove cache index" in failure.stderr and f"errno={errno.EACCES}" in failure.stderr, failure
        finally:
            child.chmod(0o700)
        execute(binary, "fetch", *args)
        assert origin.seen[-1] == ("/rules", None, 200) and len(list(child.glob("*.blob"))) == 1
        print("PASS damaged index cold start and orphan blob recovery")

        output.unlink()
        watch_args = [binary, "rule", "watch", "150", *args]
        with subprocess.Popen(watch_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as watcher:
            try:
                until(lambda: output.exists() and output.read_bytes() == RULES)
                assert origin.seen[-1][2] == 304
                count = len(origin.seen)
                until(lambda: len(origin.seen) > count)
                assert origin.seen[-1][2] == 304
            finally:
                watcher.terminate()
                _, stderr = watcher.communicate(timeout=4)
                assert watcher.returncode == 0, stderr
        print("PASS rule watch cold process reuses cache and restores absent publication")

        orphan = child / ("e" * 64 + ".blob")
        orphan.write_bytes(b"orphan")
        smaller = ("--ruleset-cache-max-bytes", str(len(RULES) + 4))
        origin.body = RULES.replace(b"fresh", b"other")
        execute(binary, "fetch", *arguments(config, url + "?other", "kdl", output, cache, *smaller))
        assert not orphan.exists() and not kdl.exists()
        assert sum(blob.stat().st_size for blob in child.glob("*.blob")) <= len(RULES) + 4
        origin.body = RULES
        execute(binary, "fetch", *args)
        assert origin.seen[-1] == ("/rules", None, 200)
        authority = cache / "selectors.state"
        authority.write_bytes(b"unrelated authority")
        held = arguments(config, f"https://localhost:{origin.server_port}/held", "kdl", output, cache)
        with subprocess.Popen([binary, "rule", "fetch", *held], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as request:
            try:
                assert origin.arrived.wait(4)
                execute(binary, "fetch", "--clear-cache", cache)
            finally:
                origin.release.set()
            _, error = request.communicate(timeout=4)
            assert request.returncode == 1 and "stale clear epoch" in error, error
        assert not list(child.glob("*.blob")) and authority.read_bytes() == b"unrelated authority"
        execute(binary, "fetch", *args)
        print("PASS physical byte cap, orphan sweep and clear during in-flight HTTPS")

    pin = hashlib.sha256(RULES).hexdigest()
    offline = (*args, "--sha256", pin, "--offline-cache")
    output.unlink()
    execute(binary, "fetch", *offline)
    assert output.read_bytes() == RULES
    fail = execute(binary, "fetch", *args, accept=False)
    assert "connection" in fail.stderr
    wrong = execute(binary, "fetch", *args, "--sha256", "00" * 32, "--offline-cache", accept=False)
    assert output.read_bytes() == RULES and wrong.returncode == 1
    print("PASS pinned, unexpired offline fallback with origin stopped; no fallback by default or on pin mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=lambda v: Path(v).resolve(strict=True))
    parser.add_argument("sing_box", type=lambda v: Path(v).resolve(strict=True))
    options = parser.parse_args()
    assert os.geteuid() != 0, "real EACCES fixture requires an unprivileged process"
    with tempfile.TemporaryDirectory(prefix="nexus-ruleset-net-") as temp, DnsPeer() as dns:
        check(options.binary, options.sing_box, Path(temp), dns)
