#!/usr/bin/env python3
"""Exercise local control identity and reload using mapped Linux users."""

from contextlib import ExitStack
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

from dns_rule_support import free_port, nexus_process


def run(binary, control, *arguments, uid=0, expected=0):
    if uid:
        with binary.open("rb") as executable:
            command = ["setpriv", "--reuid", str(uid), "--regid", str(uid), "--clear-groups",
                       f"/proc/self/fd/{executable.fileno()}", "control", str(control), *arguments]
            result = subprocess.run(command, pass_fds=(executable.fileno(),),
                                    capture_output=True, text=True, timeout=5)
    else:
        result = subprocess.run([binary, "control", control, *arguments],
                                capture_output=True, text=True, timeout=5)
    assert result.returncode == expected, result
    return result.stdout if expected == 0 else result.stderr


def status_generation(status):
    return int(re.search(r"^control-generation=(\d+)$", status, re.MULTILINE)[1])


def operation(binary, control, state, generation):
    queued = run(binary, control, "reload")
    op_id = re.fullmatch(r"id=(\d+) state=pending\n", queued)[1]
    deadline = time.monotonic() + 5
    while True:
        result = run(binary, control, "--server-uid", "0", "operation", op_id, uid=1)
        if "state=pending" not in result:
            break
        assert time.monotonic() < deadline
        time.sleep(.02)
    expected = f"id={op_id} action=reload state={state} control-generation={generation}\n"
    if state == "failed":
        expected += "reason=reload-failed\n"
    assert result == expected, result
    return op_id


def check_events(binary, control, instance, oldest):
    reader = ("--server-uid", "0")
    result = run(binary, control, *reader, "events", uid=1)
    assert f"instance={instance} next=6 latest=6 gap=0" in result, result
    assert f"id=2 event=reload-queued control-generation=2 operation={oldest}" in result
    assert f"id=3 event=reload-failed control-generation=2 operation={oldest}" in result
    assert "private-" not in result
    assert run(binary, control, *reader, "events", "6", "prior-instance",
               uid=1, expected=1) == "stale-event-cursor\n"
    assert run(binary, control, *reader, "events", "6", instance, uid=1).count("\n") == 1
    for _ in range(64):
        run(binary, control, "reload")
    result = run(binary, control, *reader, "events", "1", instance, uid=1)
    assert re.match(r"instance=\w+ next=\d+ latest=134 gap=1\n", result), result
    assert result.count("\n") == 33
    assert run(binary, control, *reader, "operation", oldest,
               uid=1, expected=1) == "unknown-operation\n"

    with ExitStack() as stack:
        for _ in range(30):
            idle = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
            idle.connect(str(control))
        assert "state=running" in run(binary, control, *reader, "status", uid=1)
        time.sleep(2.15)
        counts = run(binary, control, *reader, "diagnostics", uid=1)
        assert int(re.search(r"expired=(\d+)", counts)[1]) >= 30, counts
        assert int(re.search(r"unauthorized=(\d+)", counts)[1]) >= 1, counts


def check(binary, folder):
    folder.chmod(0o711)
    config = folder / "private.kdl"
    config.touch(mode=0o600)
    control = folder / "cli.sock"
    port = free_port()
    source = f'''schema-version 1
role "client"
control socket="{control}" read-uid=1
inbound "input" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "blocked" type="block"
outbound "private-selector" type="selector" {{ member "direct"; member "blocked"; }}
routing {{ default-outbound "direct"; }}
'''
    config.write_text(source)
    with nexus_process(binary, config):
        assert control.stat().st_mode & 0o777 == 0o666
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as old:
            old.settimeout(3)
            old.connect(str(control))
            old.sendall(b"NEXUS/1 status")
            reply = old.recv(65536)
            assert reply.startswith(b"NEXUS/1 OK\n") and b"group=private-selector" in reply, reply
        assert "unexpected control server UID" in run(binary, control, "status", uid=1, expected=1)
        read = run(binary, control, "--server-uid", "0", "status", uid=1)
        assert "private-selector" not in read
        assert status_generation(read) == 1
        instance = re.search(r"^instance=([0-9a-f]{32})$", read, re.MULTILINE)[1]
        unauthorized = run(binary, control, "--server-uid", "0", "status", uid=2, expected=1)
        assert "permission-denied" not in unauthorized
        for command in [("reload",), ("select", "private-selector", "blocked"),
                        ("close", "0", "1"), ("connections", "0"), ("user-usage", "0"),
                        ("group-health", "private-selector")]:
            denied = run(binary, control, "--server-uid", "0", *command, uid=1, expected=1)
            assert denied == "permission-denied\n", denied
        run(binary, control, "select", "private-selector", "blocked", "1")
        status = run(binary, control, "status")
        assert "group=private-selector selected=blocked" in status
        assert status_generation(status) == 2
        assert run(binary, control, "select", "private-selector", "direct", "1",
                   expected=1) == "stale-generation\n"
        config.write_text(source + 'unknown-option "private-reload-value"\n')
        oldest = operation(binary, control, "failed", 2)
        config.write_text(source)
        operation(binary, control, "succeeded", 3)
        run(binary, control, "select", "private-selector", "direct")
        assert status_generation(run(binary, control, "status")) == 4
        check_events(binary, control, instance, oldest)
        current = str(status_generation(run(binary, control, "status")))
        assert run(binary, control, "close", "0", "1", current, "prior-instance",
                   expected=1) == "stale-generation\n"
        assert run(binary, control, "close", "0", "1", current, instance,
                   expected=1) == "unknown-connection\n"
    assert not control.exists()


if __name__ == "__main__":
    assert os.geteuid() == 0, "run in unshare --user --map-root-user --map-auto"
    with tempfile.TemporaryDirectory(prefix="nexus-local-control-") as temporary:
        check(Path(sys.argv[1]).resolve(strict=True), Path(temporary))
    print("Local control peer UID, redaction, legacy NEXUS/1, reload, audit loss and idle expiry passed")
