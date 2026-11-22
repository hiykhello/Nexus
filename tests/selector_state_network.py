#!/usr/bin/env python3
"""Verify persisted manual selector choices through real routed TCP."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch

from anytls_network import Origin
from dns_rule_support import free_port, nexus_process, stream_request
from local_control_network import run, status_generation
from proxy_listener_reload_network import reload


def failed_start(binary, config, diagnostic):
    process = subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=5)
    assert process.returncode == 1 and diagnostic in process.stderr, process


def check(binary, root, origin, shim=None):
    front = free_port()
    config = root / "proxy.kdl"
    control = root / "control"
    directory = root / "state"
    directory.mkdir(mode=0o700)
    snapshot = directory / "selectors.state"
    stage = directory / ".selectors.next"
    (root / "target.kdl").write_text(
        f'schema-version 2\nkind "predicate"\nrule type="port" value="{origin.port}"\n')
    source = f'''schema-version 1
role "client"
log {{ privacy "verbose"; }}
control socket="{control}" selector-state-directory="{directory}"
inbound "input" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "blocked" type="block"
outbound "manual" type="selector" {{ member "direct"; member "blocked"; selected "direct"; }}
routing {{
    rule-set "target" path="target.kdl" format="kdl"
    rule kind="rule-set" value="target" outbound="manual"
    default-outbound "direct"
}}
'''
    config.write_text(source)
    legacy = b"NXSEL1\x01\x06manual\x06direct"
    snapshot.write_bytes(legacy)
    snapshot.chmod(0o600)
    with nexus_process(binary, config) as running:
        failed_start(binary, config, "selector state directory cannot be locked")
        stream_request(front, origin.port, "127.0.0.1")
        run(binary, control, "select", "manual", "blocked")
        stream_request(front, origin.port, "127.0.0.1", success=False)
        assert snapshot.stat().st_mode & 0o777 == 0o600
        saved = snapshot.read_bytes()
        assert saved.startswith(b"NXST01") and int.from_bytes(saved[16:24], "little") == 1
        assert saved[64:].startswith(b"NXSEL1")
        assert (directory / "instance.lock").stat().st_mode & 0o777 == 0o600
        reload(running)
        stream_request(front, origin.port, "127.0.0.1", success=False)
        generation = status_generation(run(binary, control, "status"))

        stage.mkdir()
        assert "cannot clear staging file" in run(binary, control, "select", "manual", "direct", expected=1)
        assert status_generation(run(binary, control, "status")) == generation
        assert snapshot.read_bytes() == saved
        stream_request(front, origin.port, "127.0.0.1", success=False)
        stage.rmdir()

    with nexus_process(binary, config):
        assert "group=manual selected=blocked" in run(binary, control, "status")
        stream_request(front, origin.port, "127.0.0.1", success=False)
        run(binary, control, "select", "manual", "direct")
        stream_request(front, origin.port, "127.0.0.1")

    config.write_text(source.replace('member "blocked"; ', ""))
    snapshot.write_bytes(saved)
    failed_start(binary, config, "selector state does not match a configured manual group and member")
    assert snapshot.read_bytes() == saved
    config.write_text(source)
    unsupported = saved[:6] + b"\x02\x00" + saved[8:]
    snapshot.write_bytes(unsupported)
    failed_start(binary, config, "selector state has an unsupported or damaged format")
    assert snapshot.read_bytes() == unsupported
    snapshot.write_bytes(saved[:-1])
    failed_start(binary, config, "selector state has an unsupported or damaged format")
    assert snapshot.read_bytes() == saved[:-1]
    snapshot.write_bytes(legacy[:-1])
    failed_start(binary, config, "selector state contains invalid or duplicate choices")
    assert snapshot.read_bytes() == legacy[:-1]
    snapshot.write_bytes(saved)
    with nexus_process(binary, config):
        stream_request(front, origin.port, "127.0.0.1", success=False)

    if shim:
        fault = {"LD_PRELOAD": str(shim), "NEXUS_STATE_FAULT": "dir-sync-error",
                 "NEXUS_STATE_DIRECTORY": str(directory)}
        with patch.dict(os.environ, fault), nexus_process(binary, config):
            before = status_generation(run(binary, control, "status"))
            uncertain = run(binary, control, "select", "manual", "direct", expected=1)
            assert uncertain == "selector-active-persistence-uncertain\n", uncertain
            assert status_generation(run(binary, control, "status")) == before + 1
            stream_request(front, origin.port, "127.0.0.1")
        with nexus_process(binary, config):
            stream_request(front, origin.port, "127.0.0.1")
        print("Selector uncertain fsync reports the existing wire error after publishing the visible choice")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="nexus-selector-state-") as folder, Origin(idle_timeout=10) as peer:
        shim = Path(sys.argv[2]).resolve(strict=True) if len(sys.argv) > 2 else None
        check(Path(sys.argv[1]).resolve(strict=True), Path(folder), peer, shim)
    print("Selector state routing, restart, reload, ownership, write failure and damaged-state recovery passed")
