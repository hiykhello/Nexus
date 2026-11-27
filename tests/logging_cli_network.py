#!/usr/bin/env python3
"""Exercise run logging, reload, and the local control socket on real listeners."""

from contextlib import contextmanager
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

from dns_rule_support import free_port
from local_control_network import run as control


def source(port, extra="", control_path=None, reader=False):
    control_node = ""
    if control_path:
        control_node = f'control socket="{control_path}"'
        if reader:
            control_node += " read-uid=1"
    return f'''schema-version 1
role "client"
{control_node}
inbound "private-input" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
{extra}
'''


def until(action, seconds=5):
    deadline = time.monotonic() + seconds
    while True:
        result = action()
        if result:
            return result
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {action}")
        time.sleep(.02)


def connected(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=.2):
            return True
    except OSError:
        return False


@contextmanager
def launch(binary, config, port, stderr):
    with stderr.open("wb") as error:
        process = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=error)
        try:
            until(lambda: process.poll() is not None or connected(port))
            assert process.poll() is None, stderr.read_text()
            yield process
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    assert process.wait(timeout=5) == 0, stderr.read_text()
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    raise


def invalid(binary, folder, expect_journald):
    config = folder / "invalid.kdl"
    link = folder / "link"
    secret = folder / "protected"
    secret.touch(mode=0o600)
    link.symlink_to(secret)
    cases = [
        ('log { level "all"; }', "invalid log level"),
        ('log { format "xml"; }', "log format"),
        ('log { timestamp "local"; }', "invalid log timestamp"),
        ('log { privacy "public"; }', "invalid log privacy"),
        ('log { domain-levels { invalid "info"; }; }', "invalid log domain"),
        ('log { domain-levels { dns "warn"; dns "error"; }; }', "duplicate log domain"),
        ('log {}\nlog {}', "duplicate log block"),
        ('log { sink "off"; sink "stderr"; }', "only sink"),
        ('log { sink "file" path="relative"; }', "absolute file path"),
        (f'log {{ sink "file" path="{secret}" max-files=2; }}', "log file rotation"),
        (f'log {{ sink "file" path="{secret}"; sink "file" path="{secret}"; }}', "duplicate log sink"),
        (f'log {{ sink "file" path="{secret}" max-size-mib=1 max-files=2; sink "file" path="{secret}.1"; }}',
         "rotation path conflicts"),
        (f'log {{ sink "file" path="{config}"; }}', "conflicts"),
        (f'log {{ sink "file" path="{link}"; }}', "cannot open log file sink"),
        (f'log {{ sink "file" path="{folder / "missing" / "log"}"; }}', "cannot open log file sink"),
        (f'log {{ sink "file" path="{secret}"; }}\ncontrol socket="{secret}"', "conflicts"),
    ]
    if not expect_journald:
        cases.append(('log { sink "journald"; }', "journald is unavailable in this build"))
    for options, expected in cases:
        port = free_port()
        config.write_text(source(port, options))
        result = subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=5)
        assert result.returncode != 0 and expected in result.stderr, (options, result)
        assert "listening on" not in result.stdout and not connected(port), options
    print(f"PASS {len(cases)} invalid log configurations rejected before listening")


def basic_outputs(binary, folder):
    config = folder / "basic.kdl"
    stderr = folder / "stderr"
    port = free_port()
    config.write_text(source(port))
    with launch(binary, config, port, stderr):
        until(lambda: "proxy started" in stderr.read_text())
    output = stderr.read_text()
    assert "info core" in output and "proxy draining" in output and "proxy stopped" in output
    assert "private-input" not in output

    port = free_port()
    config.write_text(source(port, 'log { sink "off"; }'))
    with launch(binary, config, port, stderr):
        pass
    assert not stderr.read_bytes()

    port = free_port()
    config.write_text(source(port, 'log { format "jsonl"; timestamp "monotonic"; sink "stderr"; }'))
    with launch(binary, config, port, stderr):
        pass
    records = [json.loads(line) for line in stderr.read_text().splitlines()]
    assert [entry["event_code"] for entry in records] == [100, 104, 105]
    assert all(entry["timestamp"] == entry["monotonic_ns"] for entry in records)
    print("PASS default text stderr, JSONL stderr, off and clean shutdown")


def file_and_reload(binary, folder):
    config, stderr = folder / "reload.kdl", folder / "stderr"
    log, control_path = folder / "events", folder / "control.sock"
    saved = folder / "saved"
    archived = log.with_suffix(".1")
    log.touch(mode=0o600)
    log.write_bytes(b"x" * (1024 * 1024))
    port = free_port()

    def write(level="info", extra=""):
        config.write_text(source(port, f'''log {{
    level "{level}"
    format "jsonl"
    timestamp "none"
    domain-levels {{ dns "error"; }}
    sink "stderr"
    sink "file" path="{log}" max-size-mib=1 max-files=2
}}
{extra}''', control_path))

    def has(path, message):
        return path.exists() and message in path.read_text()

    write()
    with launch(binary, config, port, stderr) as process:
        until(lambda: has(log, "proxy started"))
        assert has(stderr, "proxy started") and archived.stat().st_size == 1024 * 1024
        startup = json.loads(log.read_text().splitlines()[0])
        assert "timestamp" not in startup and "private-input" not in log.read_text()
        initial = control(binary, control_path, "log-level")
        assert "core=info\n" in initial and "dns=error\n" in initial
        assert "dns=off\n" in control(binary, control_path, "log-level", "dns", "off")
        all_warn = control(binary, control_path, "log-level", "global", "warn")
        assert "core=warn\n" in all_warn and "dns=warn\n" in all_warn
        assert "invalid-domain" in control(binary, control_path, "log-level", "bogus", "info", expected=1)

        log.rename(saved)
        log.symlink_to(saved)
        process.send_signal(signal.SIGHUP)
        until(lambda: has(saved, "log reopen failed"))
        assert "sink-errors=1" in control(binary, control_path, "log-level")
        log.unlink()
        write("debug")
        process.send_signal(signal.SIGHUP)
        until(lambda: has(log, "reloaded"))
        levels = control(binary, control_path, "log-level")
        assert "core=debug\n" in levels and "dns=error\n" in levels, levels
        assert not has(saved, "reloaded")

        write("trace", 'private-host-example.test "private-user-marker"\n')
        process.send_signal(signal.SIGHUP)
        until(lambda: has(log, "traffic rule reload failed"))
        current = log.read_text()
        assert "<redacted>" in current
        assert all(secret not in current and secret not in stderr.read_text()
                   for secret in ("private-host-example.test", "private-user-marker"))
        assert "core=debug\n" in control(binary, control_path, "log-level")
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert records[-1]["message"] == "proxy stopped"
    assert log.stat().st_mode & 0o777 == 0o600
    print("PASS file rotation, sink fan-out, failed and successful reopen, default redaction and admin log-level")


def dns_diagnostics(binary, folder):
    cache = folder / "cache"
    cache.mkdir(mode=0o700)
    destination = folder / "dns-diagnostics.jsonl"
    stderr, config = folder / "stderr", folder / "dns.kdl"
    # A directory at the snapshot pathname makes both restore and atomic publish fail.
    (cache / "messages.cache").mkdir()
    port, dns_port, upstream_port = free_port(), free_port(), free_port()
    config.write_text(source(port, f'''log {{ format "jsonl"; sink "file" path="{destination}"; }}
dns {{
    listen host="127.0.0.1" port={dns_port}
    server "numeric" type="udp" host="127.0.0.1" port={upstream_port}
    final "numeric"
    message-cache-directory "{cache}"
}}'''))
    with launch(binary, config, port, stderr):
        pass
    events = [json.loads(line) for line in destination.read_text().splitlines()]
    dns_events = [line for line in events if line["domain"] == "dns"]
    assert [entry["event_code"] for entry in dns_events] == [120, 121]
    assert not stderr.read_bytes() and all("<redacted>" in entry["message"] for entry in dns_events)
    print("PASS DNS cache restore and checkpoint failures use the configured logger")


def reader_uid(binary, folder):
    assert os.geteuid() == 0, "use unshare --map-root-user --map-auto"
    folder.chmod(0o711)
    path, config = folder / "control.sock", folder / "reader.kdl"
    port = free_port()
    config.write_text(source(port, control_path=path, reader=True))
    with launch(binary, config, port, folder / "stderr"):
        reader = ("--server-uid", "0", "log-level")
        read = control(binary, path, *reader, uid=1)
        assert "core=info\n" in read and "sink-errors=" in read and "private-input" not in read
        assert control(binary, path, *reader, "global", "off", uid=1, expected=1) == "permission-denied\n"
        assert control(binary, path, *reader, "dns", "debug", uid=1, expected=1) == "permission-denied\n"
        assert control(binary, path, *reader, uid=1) == read
    print("PASS SO_PEERCRED read UID can query logs and cannot mutate either threshold")


def native_journal(binary, folder):
    config = folder / "journal.kdl"
    port = free_port()
    config.write_text(source(port, 'log { sink "journald"; }'))
    start = time.time()
    with launch(binary, config, port, folder / "stderr") as process:
        pid = process.pid
        def journal():
            result = subprocess.run(["journalctl", "--no-pager", "-o", "json",
                                     "--since", f"@{int(start) - 1}", f"_PID={pid}", "NEXUS_EVENT=100"],
                                    text=True, capture_output=True, timeout=3, check=True)
            return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        records = until(journal)
        event = records[-1]
        assert event["PRIORITY"] == "6" and event["NEXUS_DOMAIN"] == "core" and event["NEXUS_GEN"] == "1"
        assert "proxy started" in event["MESSAGE"] and "private-input" not in event["MESSAGE"]
    assert not (folder / "stderr").read_bytes()
    print("PASS native sd_journal_sendv structured fields")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("--journald", action="store_true")
    parser.add_argument("--reader-only", action="store_true")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-log-cli-") as path:
        folder = Path(path)
        if options.reader_only:
            reader_uid(options.binary, folder)
            return
        invalid(options.binary, folder, options.journald)
        basic_outputs(options.binary, folder)
        file_and_reload(options.binary, folder)
        dns_diagnostics(options.binary, folder)
        if options.journald:
            native_journal(options.binary, folder)


if __name__ == "__main__":
    main()
