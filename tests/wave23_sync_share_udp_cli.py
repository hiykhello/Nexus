#!/usr/bin/env python3
"""Verify Wave 23 Core deliverables:
1. `nexus workspace export-share` & `import-share` (nexus://share/v1/<base64url>):
   - Transitive proxy_chain & policy_group export, dynamic_sub_id -> "self" -> --subscription-id
   - Rejects full_custom_kdl on export and import, rejects proxy_chain cycles, bad base64url, >256 KiB
   - Atomic 0600 --out-workspace write
2. `nexus workspace seal-sync` & `open-sync` (nexus-sync-v1: scrypt + XChaCha20-Poly1305):
   - Exact envelope schema & AAD tamper detection (revision/ciphertext/plaintext_sha256)
   - Passphrase via --passphrase-file and --passphrase-env; forbids raw --passphrase argv (exit 2)
   - Strips stray host/telemetry/cred keys on seal & open
   - Atomic 0600 --out / --out-workspace writes
3. `nexus tools udp-probe` (NTP / DNS / STUN):
   - Direct UDP against live local mock NTP, DNS, STUN servers
   - RFC 1928 SOCKS5 UDP ASSOCIATE through a live `nexus run` SOCKS5 inbound
"""
import base64
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def make_node(pid: str, remarks: str, server: str = "198.51.100.1", sub: str = "") -> dict:
    return {
        "id": pid, "remarks": remarks, "subscription_id": sub, "is_from_sub": bool(sub),
        "kind": "node",
        "node": {
            "protocol": "vless", "server": server, "port": 443,
            "password": "11111111-2222-3333-4444-555555555555",
            "tls": {"enabled": True, "sni": server},
        },
    }


def test_share_bundle(nexus: str, root: Path) -> None:
    ws = {
        "schema_version": 1, "revision": 7, "updated_at_ms": 1700000000000,
        "profiles": [
            make_node("n1", "Entry", "198.51.100.10", sub="sub-a"),
            make_node("n2", "Exit", "198.51.100.11", sub="sub-a"),
            {"id": "ch1", "remarks": "Chain", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["n1", "n2"]}},
            {"id": "pg1", "remarks": "Auto", "kind": "policy_group",
             "policy_group": {"strategy": "url-test", "member_ids": ["n1"], "dynamic_sub_id": "sub-a"}},
            {"id": "fc1", "remarks": "Full", "kind": "full_custom_kdl", "full_custom_kdl": 'schema-version 1\nrole "client"\n'},
        ],
    }
    ws_p = root / "share-ws.json"
    ws_p.write_text(json.dumps(ws), encoding="utf-8")

    # Export proxy_chain + policy_group transitively
    p = subprocess.run([nexus, "workspace", "export-share", "--workspace", str(ws_p),
                        "--id", "ch1", "--id", "pg1", "--json-result"],
                       capture_output=True, text=True, timeout=15)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    exp = json.loads(p.stdout)
    assert exp["ok"] and exp["exported_count"] == 4 and exp["uri"].startswith("nexus://share/v1/"), exp
    raw_b64 = exp["uri"][len("nexus://share/v1/"):]
    assert "=" not in raw_b64 and "+" not in raw_b64 and "/" not in raw_b64, raw_b64
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    bundle = json.loads(base64.urlsafe_b64decode(padded))
    assert bundle["schema_version"] == 1 and bundle["kind"] == "bundle" and len(bundle["profiles"]) == 4, bundle
    for bp in bundle["profiles"]:
        assert bp["id"].startswith("p") and bp["subscription_id"] == "" and not bp["is_from_sub"], bp
        if bp["kind"] == "policy_group":
            assert bp["policy_group"]["dynamic_sub_id"] == "self", bp

    # Reject full_custom_kdl on export
    pf = subprocess.run([nexus, "workspace", "export-share", "--workspace", str(ws_p),
                         "--id", "fc1", "--json-result"], capture_output=True, text=True, timeout=15)
    assert pf.returncode == 1 and not json.loads(pf.stdout)["ok"], pf.stdout

    # Import into fresh workspace with --subscription-id and 0600 --out-workspace
    dst_ws = root / "dst-ws.json"
    dst_ws.write_text(json.dumps({"schema_version": 1, "profiles": [make_node("p1", "Existing")]}), encoding="utf-8")
    out_ws = root / "merged-ws.json"
    pi = subprocess.run([nexus, "workspace", "import-share", "--workspace", str(dst_ws),
                         "--uri", exp["uri"], "--subscription-id", "sub-target",
                         "--out-workspace", str(out_ws), "--json-result"],
                        capture_output=True, text=True, timeout=15)
    assert pi.returncode == 0, (pi.returncode, pi.stdout, pi.stderr)
    imp = json.loads(pi.stdout)
    assert imp["ok"] and len(imp["imported_ids"]) == 4, imp
    assert stat.S_IMODE(out_ws.stat().st_mode) == 0o600
    merged = json.loads(out_ws.read_text(encoding="utf-8"))
    assert len(merged["profiles"]) == 5, merged
    pgs = [x for x in merged["profiles"] if x["kind"] == "policy_group"]
    assert len(pgs) == 1 and pgs[0]["policy_group"]["dynamic_sub_id"] == "sub-target", pgs
    chains = [x for x in merged["profiles"] if x["kind"] == "proxy_chain"]
    merged_ids = {x["id"] for x in merged["profiles"]}
    assert all(h in merged_ids and h != "p1" for h in chains[0]["proxy_chain"]["hop_ids"]), chains

    # Reject hostile bundles on import (full_custom_kdl, cyclic proxy_chain, duplicate hop_ids, >256 KiB, invalid UTF-8)
    for label, bad_obj in [
        ("full-custom", {"schema_version": 1, "kind": "bundle", "profiles": [{"id": "p1", "kind": "full_custom_kdl", "full_custom_kdl": "x"}]}),
        ("cycle", {"schema_version": 1, "kind": "bundle", "profiles": [{"id": "p1", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["p1"]}}]}),
        ("dup-hop", {"schema_version": 1, "kind": "bundle", "profiles": [
            make_node("p1", "H1"),
            {"id": "p2", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["p1", "p1"]}},
        ]}),
    ]:
        enc = base64.urlsafe_b64encode(json.dumps(bad_obj).encode()).decode().rstrip("=")
        r = subprocess.run([nexus, "workspace", "import-share", "--workspace", str(dst_ws),
                            "--uri", "nexus://share/v1/" + enc, "--json-result"],
                           capture_output=True, text=True, timeout=15)
        assert r.returncode == 1 and not json.loads(r.stdout)["ok"], (label, r.stdout)

    # Also reject duplicate hop_ids on export-share
    ws_dup = {"schema_version": 1, "profiles": [
        make_node("n1", "H1"), {"id": "ch-dup", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["n1", "n1"]}}
    ]}
    ws_dup_p = root / "dup-hop-ws.json"
    ws_dup_p.write_text(json.dumps(ws_dup), encoding="utf-8")
    r_dup = subprocess.run([nexus, "workspace", "export-share", "--workspace", str(ws_dup_p),
                            "--id", "ch-dup", "--json-result"], capture_output=True, text=True, timeout=15)
    assert r_dup.returncode == 1 and not json.loads(r_dup.stdout)["ok"], r_dup.stdout

    big_uri_file = root / "big-share.uri"
    big_uri_file.write_text("nexus://share/v1/" + ("A" * 360000), encoding="utf-8")
    rb = subprocess.run([nexus, "workspace", "import-share", "--workspace", str(dst_ws),
                         "--uri-file", str(big_uri_file), "--json-result"], capture_output=True, text=True, timeout=15)
    assert rb.returncode == 1 and not json.loads(rb.stdout)["ok"], rb.stdout
    bad_utf8 = base64.urlsafe_b64encode(b"\xff\xfe\xfd").decode().rstrip("=")
    ru = subprocess.run([nexus, "workspace", "import-share", "--workspace", str(dst_ws),
                         "--uri", "nexus://share/v1/" + bad_utf8, "--json-result"], capture_output=True, text=True, timeout=15)
    assert ru.returncode == 1 and not json.loads(ru.stdout)["ok"], ru.stdout


def test_e2ee_sync(nexus: str, root: Path) -> None:
    ws_dirty = {
        "schema_version": 1, "revision": 42, "updated_at_ms": 1730000001234,
        "profiles": [make_node("n1", "Tokyo", "198.51.100.20")],
        "webdav_password": "MUST-BE-STRIPPED-SECRET",
        "sync_passphrase": "MUST-NOT-LEAK",
        "mixed_listen": "127.0.0.1:7890",
    }
    ws_p = root / "sync-ws.json"
    ws_p.write_text(json.dumps(ws_dirty), encoding="utf-8")
    pass_p = root / "sync.pass"
    pass_p.write_text("S3cur3-Wave23-Passphrase!\n", encoding="utf-8")
    os.chmod(pass_p, 0o600)

    # Raw --passphrase (both separate & =value forms) MUST be rejected with exit 2 and never echo the secret
    bad_cli = subprocess.run([nexus, "workspace", "seal-sync", "--workspace", str(ws_p),
                              "--passphrase", "leak-in-ps"], capture_output=True, text=True, timeout=15)
    assert bad_cli.returncode == 2 and "leak-in-ps" not in bad_cli.stderr, (bad_cli.returncode, bad_cli.stderr)
    bad_cli_eq = subprocess.run([nexus, "workspace", "seal-sync", "--workspace", str(ws_p),
                                 "--passphrase=SUPERSECRET_EQ"], capture_output=True, text=True, timeout=15)
    assert bad_cli_eq.returncode == 2 and "SUPERSECRET_EQ" not in bad_cli_eq.stderr, (bad_cli_eq.returncode, bad_cli_eq.stderr)

    # Multi-byte UTF-8 device label >128 bytes must truncate cleanly at codepoint boundary (valid UTF-8 envelope!)
    cjk_label = "测试设备" * 12  # 48 CJK chars = 144 UTF-8 bytes
    cjk_env_p = root / "cjk-label.enc"
    p_cjk = subprocess.run([nexus, "workspace", "seal-sync", "--workspace", str(ws_p),
                            "--passphrase-file", str(pass_p), "--device-label", cjk_label,
                            "--out", str(cjk_env_p), "--json-result"], capture_output=True, text=True, timeout=20)
    assert p_cjk.returncode == 0 and json.loads(p_cjk.stdout)["ok"], p_cjk.stdout
    cjk_env = json.loads(cjk_env_p.read_text(encoding="utf-8"))
    assert len(cjk_env["device_label"].encode("utf-8")) <= 128 and cjk_env["device_label"].startswith("测试设备"), cjk_env

    # Seal via --passphrase-file + write 0600 envelope
    env_p = root / "nexus-workspace-v1.enc"
    ps = subprocess.run([nexus, "workspace", "seal-sync", "--workspace", str(ws_p),
                         "--passphrase-file", str(pass_p), "--device-label", "linux-workstation",
                         "--out", str(env_p), "--json-result"],
                        capture_output=True, text=True, timeout=20)
    assert ps.returncode == 0, (ps.returncode, ps.stdout, ps.stderr)
    sealed = json.loads(ps.stdout)
    assert sealed["ok"] and sealed["revision"] == 42 and sealed["updated_at_ms"] == 1730000001234, sealed
    assert len(sealed["envelope_sha256"]) == 64 and stat.S_IMODE(env_p.stat().st_mode) == 0o600
    env = json.loads(env_p.read_text(encoding="utf-8"))
    assert env["format"] == "nexus-sync-v1" and env["kdf"] == "scrypt" and env["kdf_n"] == 32768
    assert env["kdf_r"] == 8 and env["kdf_p"] == 1 and env["aead"] == "xchacha20-poly1305"
    assert env["device_label"] == "linux-workstation" and len(env["plaintext_sha256"]) == 64

    # Open via --passphrase-env + verify host/cred keys were stripped
    out_ws = root / "opened-ws.json"
    child_env = dict(os.environ, NEXUS_SYNC_PASS="S3cur3-Wave23-Passphrase!")
    po = subprocess.run([nexus, "workspace", "open-sync", "--envelope", str(env_p),
                         "--passphrase-env", "NEXUS_SYNC_PASS", "--out-workspace", str(out_ws),
                         "--json-result"], env=child_env, capture_output=True, text=True, timeout=20)
    assert po.returncode == 0, (po.returncode, po.stdout, po.stderr)
    opened = json.loads(po.stdout)
    assert opened["ok"] and opened["revision"] == 42 and opened["device_label"] == "linux-workstation", opened
    assert stat.S_IMODE(out_ws.stat().st_mode) == 0o600
    ws_text = out_ws.read_text(encoding="utf-8")
    assert "MUST-BE-STRIPPED-SECRET" not in ws_text and "MUST-NOT-LEAK" not in ws_text and "mixed_listen" not in ws_text
    assert json.loads(ws_text)["profiles"][0]["remarks"] == "Tokyo"

    # Wrong passphrase fails
    wrong_env = dict(os.environ, NEXUS_SYNC_PASS="wrong-passphrase")
    pw = subprocess.run([nexus, "workspace", "open-sync", "--envelope", str(env_p),
                         "--passphrase-env", "NEXUS_SYNC_PASS", "--json-result"],
                        env=wrong_env, capture_output=True, text=True, timeout=20)
    assert pw.returncode == 1 and not json.loads(pw.stdout)["ok"], pw.stdout

    # Tampering with AAD-bound revision or plaintext_sha256 fails
    for field, val in [("revision", 43), ("plaintext_sha256", "0" * 64)]:
        tampered = dict(env)
        tampered[field] = val
        tp = root / f"tamper-{field}.enc"
        tp.write_text(json.dumps(tampered), encoding="utf-8")
        pt = subprocess.run([nexus, "workspace", "open-sync", "--envelope", str(tp),
                             "--passphrase-file", str(pass_p), "--json-result"],
                            capture_output=True, text=True, timeout=20)
        assert pt.returncode == 1 and not json.loads(pt.stdout)["ok"], (field, pt.stdout)


class MockUdpServers:
    def __init__(self) -> None:
        self.stop_evt = threading.Event()
        self.socks: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.ports: dict[str, int] = {}

    def start(self) -> None:
        for kind, handler in [("ntp", self._ntp), ("dns", self._dns), ("stun", self._stun)]:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            s.settimeout(0.1)
            self.ports[kind] = s.getsockname()[1]
            self.socks.append(s)
            t = threading.Thread(target=self._loop, args=(s, handler), daemon=True)
            t.start()
            self.threads.append(t)

    def _loop(self, sock: socket.socket, handler) -> None:
        while not self.stop_evt.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            rep = handler(data, addr)
            if rep:
                sock.sendto(rep, addr)

    @staticmethod
    def _ntp(data: bytes, _addr) -> bytes | None:
        if len(data) < 48 or (data[0] & 7) != 3:
            return None
        rep = bytearray(48)
        rep[0] = 0x24  # LI=0, VN=4, Mode=4
        rep[1] = 2     # stratum 2
        rep[24:32] = data[40:48]
        rep[40:48] = b"\xe5\x00\x00\x01\x00\x00\x00\x01"
        return bytes(rep)

    @staticmethod
    def _dns(data: bytes, _addr) -> bytes | None:
        if len(data) < 12:
            return None
        txid = data[0:2]
        # Minimal valid A response: QR=1, RD=1, RA=1, RCODE=0, QD=1, AN=1
        hdr = txid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        q = data[12:]
        ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"
        return hdr + q + ans

    @staticmethod
    def _stun(data: bytes, addr) -> bytes | None:
        if len(data) < 20 or data[0:2] != b"\x00\x01" or data[4:8] != b"\x21\x12\xa4\x42":
            return None
        ip_b = socket.inet_aton(addr[0])
        xport = addr[1] ^ 0x2112
        xip = bytes(a ^ b for a, b in zip(ip_b, b"\x21\x12\xa4\x42"))
        attr = struct.pack("!HHBBH", 0x0020, 8, 0, 1, xport) + xip
        return struct.pack("!HHI", 0x0101, len(attr), 0x2112a442) + data[8:20] + attr

    def close(self) -> None:
        self.stop_evt.set()
        for s in self.socks:
            s.close()
        for t in self.threads:
            t.join(timeout=1.0)


def pick_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_udp_probe_direct_and_socks5(nexus: str, root: Path) -> None:
    mocks = MockUdpServers()
    mocks.start()
    socks_port = pick_free_tcp_port()
    cfg = root / "socks5-udp.kdl"
    cfg.write_text(
        'schema-version 1\nrole "client"\n'
        f'inbound "s5" type="socks5" {{ listen host="127.0.0.1" port={socks_port}; authentication "none"; }}\n'
        'outbound "direct" type="direct"\n'
        'routing { default-outbound "direct"; }\n',
        encoding="utf-8",
    )
    proc = subprocess.Popen([nexus, "run", "--config", str(cfg)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        # Wait for SOCKS5 listener ready
        ready = False
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        assert ready, "nexus SOCKS5 listener failed to start"

        for kind, expected_detail in [("ntp", "stratum=2"), ("dns", "answers=1"), ("stun", "mapped=127.0.0.1:")]:
            target = f"127.0.0.1:{mocks.ports[kind]}"
            # Direct UDP
            pd = subprocess.run([nexus, "tools", "udp-probe", "--kind", kind, "--target", target,
                                 "--timeout-ms", "1500", "--attempts", "2", "--json"],
                                capture_output=True, text=True, timeout=10)
            assert pd.returncode == 0, (kind, "direct", pd.stdout, pd.stderr)
            jd = json.loads(pd.stdout)
            assert jd["ok"] and jd["kind"] == kind and not jd["via_socks5"] and expected_detail in jd["detail"], jd

            # Via SOCKS5 UDP ASSOCIATE
            ps = subprocess.run([nexus, "tools", "udp-probe", "--kind", kind, "--target", target,
                                 "--socks5", f"127.0.0.1:{socks_port}",
                                 "--timeout-ms", "1500", "--attempts", "2", "--json"],
                                capture_output=True, text=True, timeout=10)
            assert ps.returncode == 0, (kind, "socks5", ps.stdout, ps.stderr)
            js = json.loads(ps.stdout)
            assert js["ok"] and js["kind"] == kind and js["via_socks5"] and expected_detail in js["detail"], js
        # Invalid non-UTF-8 --kind must still output valid UTF-8 JSON (replaced with U+FFFD)
        p_bad_utf8 = subprocess.run([nexus.encode(), b"tools", b"udp-probe", b"--kind", b"bad\xff\xfe", b"--json"],
                                    capture_output=True, timeout=10)
        assert p_bad_utf8.returncode == 1
        j_bad = json.loads(p_bad_utf8.stdout.decode("utf-8"))
        assert not j_bad["ok"] and "\ufffd" in j_bad["kind"], j_bad
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        mocks.close()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-nexus-bin>", file=sys.stderr)
        return 2
    nexus = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="nexus-wave23-") as td:
        root = Path(td)
        test_share_bundle(nexus, root)
        test_e2ee_sync(nexus, root)
        test_udp_probe_direct_and_socks5(nexus, root)
    print("WAVE 23 SYNC / SHARE / UDP-PROBE CLI TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
