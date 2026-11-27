#!/usr/bin/env python3
"""Verify Wave 22 core config-boundary CLI primitives:
- nexus check [--config|--config-dir] [--host-override] [--print-merged]
- nexus run [--host-override] --config (both flag orders) + SIGHUP hot-reload persistence
- nexus convert-config --emit-nodes-json (URI, base64, JSON escaping, 0600 secrets)
- AST round-trip across real docs/configuration/examples/*.kdl configs
"""
import base64
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"port {port} did not become reachable")


def run_cli(nexus: str, *args: str, stdin_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [nexus, *args],
        input=stdin_text,
        text=True,
        capture_output=True,
        timeout=15,
    )


def test_check_and_host_override(nexus: str, root: Path, repo: Path) -> None:
    base = root / "custom.kdl"
    base.write_text(
        'schema-version 1\n'
        'role "client"\n'
        'workers 1\n'
        'inbounds {\n'
        '    socks5 "local-in" { listen "127.0.0.1:1080"; authentication "none"; }\n'
        '    tun "base-tun" { inet4-address "198.18.0.1/30"; mtu 1400; }\n'
        '}\n'
        'outbounds {\n'
        '    direct\n'
        '    block\n'
        '}\n'
        'routing { final "direct"; }\n'
    )
    ov = root / "host-override.kdl"
    ov.write_text(
        'host-override {\n'
        '    strip-tun #true\n'
        '}\n'
        'workers 2\n'
        'inbound "local-in" type="mixed" { listen host="127.0.0.1" port=17890; authentication "none"; }\n'
    )

    # 1. check without --print-merged prints configuration valid
    r = run_cli(nexus, "check", "--config", str(base), "--host-override", str(ov))
    assert r.returncode == 0 and r.stdout.strip() == "configuration valid", (r.returncode, r.stdout, r.stderr)

    # 2. check --print-merged outputs ONLY valid merged KDL to stdout (re-checkable!)
    r2 = run_cli(nexus, "check", "--host-override", str(ov), "-c", str(base), "--print-merged")
    assert r2.returncode == 0, (r2.returncode, r2.stderr)
    assert "configuration valid" not in r2.stdout, r2.stdout
    assert "host-override" not in r2.stdout, r2.stdout
    assert "base-tun" not in r2.stdout, r2.stdout
    assert "17890" in r2.stdout, r2.stdout
    merged_file = root / "00-effective.kdl"
    merged_file.write_text(r2.stdout)
    r3 = run_cli(nexus, "check", str(merged_file))
    assert r3.returncode == 0, (r3.returncode, r3.stderr)

    # 3. Round-trip real docs/configuration/examples/*.kdl + full TUN/DNS/routing/selector/proxy-provider config
    empty_ov = root / "noop-override.kdl"
    empty_ov.write_text("workers 2\n")
    ex_dir = repo / "docs/configuration/examples"
    for name in ("ergonomic-client.kdl", "low-memory-client.kdl", "mixed.kdl", "socks5.kdl"):
        ex = ex_dir / name
        if not ex.exists():
            continue
        rr = run_cli(nexus, "-D", str(ex_dir), "check", "--config", str(ex), "--host-override", str(empty_ov), "--print-merged")
        assert rr.returncode == 0, f"round-trip failed for {name}: {rr.stderr}"
        rt = root / f"rt-{name}"
        rt.write_text(rr.stdout)
        rr2 = run_cli(nexus, "-D", str(ex_dir), "check", str(rt))
        assert rr2.returncode == 0, f"re-check failed for {name}: {rr2.stderr}"

    sub_file = root / "prov-sub.txt"
    sub_file.write_text("trojan://pw123@198.51.100.55:443?sni=p.test#Prov-Node\n")
    rich = root / "rich.kdl"
    rich.write_text(
        'schema-version 1\n'
        'role "client"\n'
        'certificate { store "system"; }\n'
        'proxy-providers {\n'
        f'    provider "p1" {{ type "file"; path "{sub_file}"; cache-dir "{root / "pcache"}"; update-interval-ms 60000; }}\n'
        '}\n'
        'inbounds {\n'
        '    mixed "local" { listen "127.0.0.1:7890"; authentication "none"; }\n'
        '    tun "sys-tun" { inet4-address "198.18.0.1/30"; mtu 1420; }\n'
        '}\n'
        'outbounds {\n'
        '    direct\n'
        '    block\n'
        '    selector "proxy" { use "p1"; members "direct"; }\n'
        '}\n'
        'dns {\n'
        '    servers { local "sys"; udp "cf" host="1.1.1.1" port=53; }\n'
        '    rules { - domain-suffix "lan" to="sys"; }\n'
        '    final "cf"\n'
        '}\n'
        'routing {\n'
        '    rules { - ip-is-private #true to="direct"; - final "proxy"; }\n'
        '}\n'
    )
    rich_ov = root / "rich-ov.kdl"
    rich_ov.write_text(
        'inbound "host-tun" type="tun" { device-fd 7; mtu 1500; }\n'
        'state { directory "' + str(root / "state") + '"; }\n'
    )
    rr_rich = run_cli(nexus, "check", "--config", str(rich), "--host-override", str(rich_ov), "--print-merged")
    assert rr_rich.returncode == 0, f"rich round-trip failed: {rr_rich.stderr}"
    assert "sys-tun" not in rr_rich.stdout and "host-tun" in rr_rich.stdout and "Prov-Node" in rr_rich.stdout, rr_rich.stdout
    rich_eff = root / "rich-eff.kdl"
    rich_eff.write_text(rr_rich.stdout)
    rr_rich2 = run_cli(nexus, "check", str(rich_eff))
    assert rr_rich2.returncode == 0, f"rich re-check failed: {rr_rich2.stderr}"

    # 4. Empty or duplicate --host-override rejected with exit 2 on check & run
    for cmd in (
        ("check", "--config", str(base), "--host-override", ""),
        ("check", "--config", str(base), "--host-override", "", "--host-override", str(ov)),
        ("run", "--config", str(base), "--host-override", ""),
        ("run", "--config", str(base), "--host-override", "", "--host-override", str(ov)),
    ):
        rc = run_cli(nexus, *cmd)
        assert rc.returncode == 2, f"expected exit 2 for {cmd}, got {rc.returncode}: {rc.stderr}"

    # 5. Override TUN placed BEFORE host-override { strip-tun #false; } still strips base TUN
    ov_order = root / "ov-order.kdl"
    ov_order.write_text(
        'inbound "new-tun" type="tun" { device-fd 5; mtu 1500; }\n'
        'host-override { strip-tun #false; }\n'
    )
    r_ord = run_cli(nexus, "check", "--config", str(base), "--host-override", str(ov_order), "--print-merged")
    assert r_ord.returncode == 0, r_ord.stderr
    assert "base-tun" not in r_ord.stdout and "new-tun" in r_ord.stdout, r_ord.stdout


def test_convert_nodes_json(nexus: str, root: Path) -> None:
    sec_dir = root / "secrets"
    pbk_hex = "0123456789abcdef" * 4
    uris = "\n".join([
        'vless://11111111-2222-3333-4444-555555555555@198.51.100.10:443?security=tls&sni=edge.test&type=ws&path=%2Fws#HK%20%22Quote%22%5CSlash',
        'trojan://s3cr3t-pass@198.51.100.20:8443?sni=tr.test#JP-Node',
        'hysteria2://hy2pass@198.51.100.30:443?sni=hy2.test&obfs=salamander&obfs-password=salpass#US-Hy2',
        'tuic://11111111-2222-3333-4444-555555555555:tuicpass@198.51.100.40:443?sni=tuic.test&udp_relay_mode=quic#TUIC-Quic',
        'tuic://11111111-2222-3333-4444-555555555555:tuicpass@198.51.100.41:443?sni=tuic.test&udp_relay_mode=native#TUIC-Native',
        f'vless://11111111-2222-3333-4444-555555555555@198.51.100.50:443?security=reality&sni=x.test&pbk={pbk_hex}&sid=01020304&type=xhttp&path=%2Fx&mode=auto#VLESS-XHTTP-Reality',
        'vless://11111111-2222-3333-4444-555555555555@198.51.100.60:443?security=reality&sni=bad.test&pbk=INVALID_KEY#BadReality',
    ]) + "\n"
    b64 = base64.b64encode(uris.encode()).decode()

    r = run_cli(
        nexus, "convert-config", "--emit-nodes-json", "--from", "base64",
        "--secrets-dir", str(sec_dir), "--tag-prefix", "sub1-", "-",
        stdin_text=b64,
    )
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert "BadReality" in r.stderr, r.stderr
    # Failed node must leave ZERO orphaned secret files in --secrets-dir
    assert not list(sec_dir.glob("*BadReality*")), list(sec_dir.iterdir())
    payload = json.loads(r.stdout)
    assert isinstance(payload, dict) and "nodes" in payload and len(payload["nodes"]) == 6, payload
    protos = [n["protocol"] for n in payload["nodes"]]
    assert protos == ["vless", "trojan", "hysteria2", "tuic", "tuic", "vless"], protos
    by_tag = {n["tag"]: n for n in payload["nodes"]}
    # Multi-secret protocols expose all written 0600 files in secret_files
    assert len(by_tag["sub1-US-Hy2"]["secret_files"]) == 2, by_tag["sub1-US-Hy2"]
    assert len(by_tag["sub1-TUIC-Quic"]["secret_files"]) == 2, by_tag["sub1-TUIC-Quic"]
    assert by_tag["sub1-TUIC-Quic"]["secret_file"] == by_tag["sub1-TUIC-Quic"]["secret_files"][0]
    # TUIC udp-over-stream mapping: quic -> #true, native -> #false
    assert "udp-over-stream #true" in by_tag["sub1-TUIC-Quic"]["kdl"], by_tag["sub1-TUIC-Quic"]["kdl"]
    assert "udp-over-stream #false" in by_tag["sub1-TUIC-Native"]["kdl"], by_tag["sub1-TUIC-Native"]["kdl"]
    # VLESS XHTTP + Reality emits both reality and xhttp transport
    xhttp_kdl = by_tag["sub1-VLESS-XHTTP-Reality"]["kdl"]
    assert "reality {" in xhttp_kdl and 'transport "xhttp"' in xhttp_kdl, xhttp_kdl

    for node in payload["nodes"]:
        assert node["tag"].startswith("sub1-"), node
        assert node["host"].startswith("198.51.100."), node
        assert node["port"] in (443, 8443), node
        assert isinstance(node["secret_files"], list) and len(node["secret_files"]) >= 1, node
        assert node["secret_file"] == node["secret_files"][0], node
        for sfp in node["secret_files"]:
            sf = Path(sfp)
            assert sf.is_file(), node
            mode = stat.S_IMODE(sf.stat().st_mode)
            assert mode == 0o600, f"expected 0600, got {oct(mode)} for {sf}"
        assert node["kdl"].startswith('outbound "'), node["kdl"]
        # Verify each standalone node KDL embeds cleanly in a full config
        probe = root / f"probe-{node['tag']}.kdl"
        probe.write_text(
            'schema-version 1\nrole "client"\ncertificate { store "system"; }\n'
            'inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }\n'
            'outbounds {\noutbound "direct" type="direct"\n'
            + node["kdl"]
            + '}\n'
            + f'routing {{ final "{node["tag"]}"; }}\n'
        )
        chk = run_cli(nexus, "check", str(probe))
        assert chk.returncode == 0, f"standalone node KDL failed check: {chk.stderr}\n{node['kdl']}"

    # Malformed UTF-8 percent-encoded bytes must still produce strict RFC 8259 UTF-8 JSON
    bad_utf8_uri = "vless://11111111-2222-3333-4444-555555555555@198.51.100.70:443?security=tls&sni=u.test&type=ws&path=%2Fws%FF%FE#BadUTF8\n"
    r_utf8 = subprocess.run(
        [nexus, "convert-config", "--emit-nodes-json", "--from", "uri", "--inline-placeholders", "-"],
        input=bad_utf8_uri.encode("ascii"),
        capture_output=True,
        timeout=15,
    )
    assert r_utf8.returncode == 0, (r_utf8.returncode, r_utf8.stderr)
    parsed_utf8 = json.loads(r_utf8.stdout.decode("utf-8"))
    assert "\ufffd" in parsed_utf8["nodes"][0]["kdl"], parsed_utf8

    # convert-config KDL mode must also clean up orphaned secrets on failed node emission
    kdl_sec = root / "kdl-secrets"
    mixed_uris = (
        "trojan://okpass@198.51.100.80:443?sni=ok.test#GoodNode\n"
        "vless://11111111-2222-3333-4444-555555555555@198.51.100.81:443?security=reality&sni=bad.test&pbk=INVALID_KEY#BadKdlReality\n"
    )
    r_kdl = run_cli(nexus, "convert-config", "--from", "uri", "--secrets-dir", str(kdl_sec), "-", stdin_text=mixed_uris)
    assert r_kdl.returncode == 0, (r_kdl.returncode, r_kdl.stderr)
    assert not list(kdl_sec.glob("*BadKdlReality*")), list(kdl_sec.iterdir())

    # Stdin exceeding rulefile::max_file_bytes (32 MiB) is rejected cleanly
    r_big = subprocess.run(
        [nexus, "convert-config", "--emit-nodes-json", "--from", "uri", "-"],
        input=b"#" + b"a" * (32 * 1024 * 1024 + 64),
        capture_output=True,
        timeout=15,
    )
    assert r_big.returncode == 1 and b"exceeds maximum size" in r_big.stderr, (r_big.returncode, r_big.stderr)


def test_run_host_override_and_hot_reload(nexus: str, root: Path) -> None:
    p1 = pick_free_port()
    p2 = pick_free_port()
    base = root / "run-base.kdl"
    base.write_text(
        'schema-version 1\n'
        'role "client"\n'
        'inbounds { inbound "in" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }; }\n'
        'outbounds { outbound "direct" type="direct"; outbound "block" type="block"; }\n'
        'routing { final "direct"; }\n'
    )
    ov = root / "run-ov.kdl"
    ov.write_text(
        f'inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port={p1}; authentication "none"; }}; }}\n'
    )

    # Start with --host-override BEFORE --config
    proc = subprocess.Popen(
        [nexus, "run", "--host-override", str(ov), "--config", str(base)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        wait_port(p1)
        # Update host-override to a new port and send SIGHUP: hot reload must keep applying host-override!
        ov.write_text(
            f'inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port={p2}; authentication "none"; }}; }}\n'
        )
        proc.send_signal(signal.SIGHUP)
        wait_port(p2)
        # Reload attempting to direct a file log sink at host-override.kdl must fail without overwriting it
        bad_reload_ov = (
            f'log {{ sink "file" path="{ov}"; }}\n'
            f'inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port={p2}; authentication "none"; }}; }}\n'
        )
        ov.write_text(bad_reload_ov)
        os.chmod(ov, 0o600)
        proc.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        assert ov.read_text() == bad_reload_ov, "reload log sink corrupted host-override.kdl"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # Startup with a log file sink pointing at host-override.kdl (including relative path via -D) must be rejected
    prot_ov = root / "protected-ov.kdl"
    prot_text = (
        f'log {{ sink "file" path="{prot_ov}"; }}\n'
        f'inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port={p1}; authentication "none"; }}; }}\n'
    )
    prot_ov.write_text(prot_text)
    os.chmod(prot_ov, 0o600)
    r_prot = run_cli(nexus, "-D", str(root), "run", "-c", str(base), "--host-override", "protected-ov.kdl")
    assert r_prot.returncode != 0, (r_prot.returncode, r_prot.stdout, r_prot.stderr)
    assert "conflicts" in r_prot.stderr, r_prot.stderr
    assert prot_ov.read_text() == prot_text, "startup log sink corrupted host-override.kdl"


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-nexus-bin>", file=sys.stderr)
        return 2
    nexus = sys.argv[1]
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="nexus-wave22-cli-") as td:
        root = Path(td)
        test_check_and_host_override(nexus, root, repo)
        test_convert_nodes_json(nexus, root)
        test_run_host_override_and_hot_reload(nexus, root)
    print("WAVE 22 CONFIG BOUNDARY CLI TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
