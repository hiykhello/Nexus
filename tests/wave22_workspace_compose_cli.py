#!/usr/bin/env python3
"""Verify Wave 22 Track 2 Unified Core Workspace Compiler & URI upgrades:
- 5-kind profiles (node, custom_outbound, policy_group, proxy_chain, full_custom_kdl)
- Fail-Closed proxy_chain (missing hop, cycle, vless+xhttp, url-test target) + secret rollback
- Subscription prev_profile_id / next_profile_id virtual chain wrapping
- Sibling selector generation & max_selector_members
- desktop_process vs android_packages platform isolation
- Android protect-path + detour="direct" encrypted DNS + TUN without auto-route + proxy_only
- Desktop Linux strict-route mixed suppression with warning
- SimpleDNS FakeIP /15 -> /16 coercion, block_aaaa/block_svcb_https, ProtectDomainList, underscore strategy
- full_template overlay
- Hy2 mport/upmbps/downmbps & WireGuard reserved (base64 & CSV) URI parsing
"""
import json
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def compose(nexus: str, root: Path, name: str, ws: dict, host: dict,
            active: str | None = None, emit_kdl: bool = False) -> tuple[int, dict, Path, Path]:
    ws_p = root / f"{name}-ws.json"
    host_p = root / f"{name}-host.json"
    sec_d = root / f"{name}-secrets"
    out_kdl = root / f"{name}-out.kdl"
    ws_p.write_text(json.dumps(ws), encoding="utf-8")
    host_p.write_text(json.dumps(host), encoding="utf-8")
    cmd = [nexus, "workspace", "compose", "--workspace", str(ws_p), "--host", str(host_p),
           "--secrets-dir", str(sec_d), "--json-result"]
    if active:
        cmd += ["--active", active]
    if emit_kdl:
        cmd += ["--emit-kdl", str(out_kdl)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    res = json.loads(p.stdout)
    if res["ok"] and emit_kdl:
        assert out_kdl.is_file(), f"{out_kdl} not written"
        assert stat.S_IMODE(out_kdl.stat().st_mode) == 0o600
        chk = subprocess.run([nexus, "check", str(out_kdl)], capture_output=True, text=True, timeout=15)
        assert chk.returncode == 0, f"nexus check failed for {name}: {chk.stderr}\n{res['kdl']}"
    return p.returncode, res, sec_d, out_kdl


def make_node(pid: str, remarks: str, proto: str = "vless", server: str = "edge.example.test",
              port: int = 443, sub: str = "", **extra) -> dict:
    node = {
        "protocol": proto, "server": server, "port": port,
        "password": "11111111-2222-3333-4444-555555555555",
        "tls": {"enabled": True, "sni": server},
    }
    node.update(extra)
    return {"id": pid, "remarks": remarks, "subscription_id": sub, "kind": "node", "node": node}


def test_five_kinds_and_siblings(nexus: str, root: Path) -> None:
    ws = {
        "schema_version": 1,
        "profiles": [
            make_node("n1", "HK-1", server="hk1.example.test", sub="sub1"),
            make_node("n2", "JP-2", proto="trojan", server="jp2.example.test", sub="sub1", password="tr-pw"),
            make_node("n3", "US-3", proto="shadowsocks", server="us3.example.test", port=8388, sub="sub2",
                      method="2022-blake3-aes-128-gcm", password="AAAAAAAAAAAAAAAAAAAAAA==", packet_encoding="uot"),
            {
                "id": "co1", "remarks": "Custom-Trojan", "kind": "custom_outbound",
                "custom_outbound_kdl": (
                    'outbound "{{tag}}" type="trojan" {\n'
                    '  server host="custom.example.test" port=443\n'
                    '  authentication { password-file "/etc/hosts"; }\n'
                    '  tls { server-name "custom.example.test"; verify #true; }\n'
                    '  detour "{{detour}}"\n}\n'
                ),
            },
            {
                "id": "pg-auto", "remarks": "Auto-Sub1", "kind": "policy_group",
                "policy_group": {
                    "strategy": "url-test", "dynamic_sub_id": "sub1",
                    "include_regex": "HK|JP", "probe_url": "https://www.gstatic.com/generate_204",
                    "probe_interval_ms": 60000, "tolerance_ms": 50,
                },
            },
            {
                "id": "pg-sel", "remarks": "Manual-Sel", "kind": "policy_group",
                "policy_group": {"strategy": "selector", "member_ids": ["n1", "n2"]},
            },
            {
                "id": "ch1", "remarks": "Relay-Chain", "kind": "proxy_chain",
                "proxy_chain": {"hop_ids": ["n1", "n2", "co1"]},
            },
        ],
        "routing_profiles": [{
            "id": "rp1", "name": "Default", "is_active": True,
            "domain_strategy": "ip-if-non-match", "default_outbound": "proxy",
            "rules": [
                {"id": "r-priv", "enabled": True, "scope": "routing_only", "target_type": "direct", "ips": ["private"]},
                {"id": "r-cn", "enabled": True, "scope": "both", "target_type": "direct", "domains": ["domain:cn.example.test"]},
                {"id": "r-proc", "enabled": True, "scope": "routing_only", "target_type": "profile_id",
                 "target_profile_id": "n3", "desktop_process": ["curl", "/usr/bin/git"],
                 "android_packages": ["com.example.app"], "tls_fragment": True},
                {"id": "r-bad-tgt", "enabled": True, "scope": "routing_only", "target_type": "profile_id",
                 "target_profile_id": "deleted-profile", "domains": ["full:fallback.example.test"]},
            ],
        }],
        "dns": {
            "mode": "simple",
            "simple": {
                "bootstrap_dns": "223.5.5.5",
                "direct_dns": ["https://dns.alidns.com/dns-query"],
                "remote_dns": ["https://1.1.1.1/dns-query"],
                "fake_ip_enabled": True,
                "fake_ip_v4_pool": "198.18.0.0/15",
                "fake_ip_v6_pool": "fc00::/18",
                "block_aaaa": True,
                "block_svcb_https": True,
                "serve_stale_seconds": 60,
                "strategy": "prefer-ipv4",
            },
        },
    }
    host_desk = {
        "schema_version": 1, "platform": "desktop-linux", "workers": 2,
        "state_dir": str(root / "desk-state"), "log_level": "info",
        "control_http_listen": "127.0.0.1:9090",
        "include_sibling_nodes_in_selector": True, "max_selector_members": 10,
        "desktop": {
            "enable_mixed": True, "mixed_listen": "127.0.0.1:7890",
            "lan_listen": "127.0.0.1:7891", "lan_username": "u", "lan_password": "p",
            "bind_interface": "eth0",
            "theme": "dark", "language": "en",  # UI-only unknown keys must be ignored!
        },
    }

    # 1. Node active + sibling selector + FakeIP /15->/16 coercion + desktop_process (no android_packages)
    rc, res, sec_d, _ = compose(nexus, root, "desk-node", ws, host_desk, active="n1", emit_kdl=True)
    assert rc == 0 and res["ok"], res
    assert res["selector_tag"] == "proxy" and res["active_tag"] == "HK-1", res
    assert set(res["selector_members"]) == {"HK-1", "JP-2", "US-3"}, res
    assert any("/15" in w and "/16" in w for w in res["warnings"]), res["warnings"]
    assert any("deleted-profile" in w for w in res["warnings"]), res["warnings"]
    kdl = res["kdl"]
    assert 'ipv4-pool="198.18.0.0/16"' in kdl and 'strategy "prefer_ipv4"' in kdl, kdl
    assert 'query-type="AAAA" action="reject" reject-rcode="NOERROR"' in kdl, kdl
    assert 'query-type="SVCB" action="reject" reject-rcode="NOERROR"' in kdl, kdl
    assert 'domain="hk1.example.test" to="direct-dns-0"' in kdl, kdl
    assert 'process-name "curl"' in kdl and 'process-path "/usr/bin/git"' in kdl, kdl
    assert "package-name" not in kdl and "com.example.app" not in kdl, kdl
    assert 'tls-record-fragment=#true' in kdl, kdl
    assert 'control http-listen="127.0.0.1:9090" metrics=#true' in kdl, kdl
    for sf in res["secret_files"]:
        assert stat.S_IMODE(Path(sf).stat().st_mode) == 0o600

    # 2. Policy group (url-test with dynamic_sub_id)
    rc, res_pg, _, _ = compose(nexus, root, "desk-pg", ws, host_desk, active="pg-auto", emit_kdl=True)
    assert rc == 0 and res_pg["ok"] and 'type="url-test"' in res_pg["kdl"], res_pg

    # 3. 3-hop ProxyChain (n1 physical -> n2 detour -> co1 detour)
    rc, res_ch, _, _ = compose(nexus, root, "desk-ch", ws, host_desk, active="ch1", emit_kdl=True)
    assert rc == 0 and res_ch["ok"], res_ch
    assert 'detour "HK-1"' in res_ch["kdl"], res_ch["kdl"]
    assert 'custom.example.test' in res_ch["kdl"], res_ch["kdl"]

    # 4. Android host: protect-path, detour="direct" on direct encrypted DNS, android_packages (no desktop_process), TUN without auto-route
    host_and = {
        "schema_version": 1, "platform": "android", "state_dir": str(root / "and-state"),
        "android": {
            "run_mode": "vpn", "enable_local_proxy": True, "local_listen": "127.0.0.1:10808",
            "tun_mtu": 1400, "protect_socket_path": "/tmp/nexus-protect.sock",
            "dns_listen": "127.0.0.1:1053",
            "per_app_mode": "exclude", "exclude_self_from_vpn": False, "oom_soft_limit_mb": 50,
        },
    }
    rc, res_and, _, _ = compose(nexus, root, "and-vpn", ws, host_and, active="n1", emit_kdl=True)
    assert rc == 0 and res_and["ok"], res_and
    akdl = res_and["kdl"]
    assert 'protect-path "/tmp/nexus-protect.sock"' in akdl, akdl
    assert 'server "direct-dns-0" type="https"' in akdl and 'detour="direct"' in akdl, akdl
    assert 'inbound "tun-in" type="tun"' in akdl and "endpoint-independent-nat #false" in akdl, akdl
    assert "auto-route" not in akdl and "strict-route" not in akdl and "inet4-address" not in akdl, akdl
    assert 'package-name "com.example.app"' in akdl and "process-name" not in akdl, akdl

    # 5. Android proxy_only mode emits mixed only (no TUN)
    host_po = json.loads(json.dumps(host_and))
    host_po["android"]["run_mode"] = "proxy_only"
    rc, res_po, _, _ = compose(nexus, root, "and-po", ws, host_po, active="n1", emit_kdl=True)
    assert rc == 0 and res_po["ok"] and 'type="tun"' not in res_po["kdl"] and 'type="mixed"' in res_po["kdl"], res_po

    # 6. Cross-track interop: transport.type=="tcp" preserves VLESS Reality+Vision, hosts accepts string OR array & wildcards
    ws_interop = {
        "schema_version": 1,
        "profiles": [
            make_node("v-real", "VLESS-Real", server="198.51.100.30", flow="xtls-rprx-vision",
                      transport={"type": "tcp"},
                      tls={"enabled": True, "sni": "real.example.test",
                           "reality_public_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                           "reality_short_id": "abcd"}),
        ],
        "dns": {
            "mode": "simple",
            "simple": {
                "direct_dns": ["223.5.5.5", "https://[2606:4700:4700::1111]/dns-query"],
                "remote_dns": ["https://1.1.1.1/dns-query"],
                "hosts": {
                    "desk.lan": "10.0.0.3",
                    "*.app.lan": ["10.0.0.1", "10.0.0.2"],
                },
            },
        },
    }
    rc, res_io, _, _ = compose(nexus, root, "interop", ws_interop, host_and, active="v-real", emit_kdl=True)
    assert rc == 0 and res_io["ok"], res_io
    ikdl = res_io["kdl"]
    assert 'flow "xtls-rprx-vision"' in ikdl and "reality {" in ikdl, ikdl
    assert 'entry host="desk.lan" ip="10.0.0.3"' in ikdl, ikdl
    assert 'entry host="*.app.lan" ip="10.0.0.1,10.0.0.2"' in ikdl, ikdl
    assert 'domain-wildcard="*.app.lan" to="static-hosts"' in ikdl, ikdl
    assert any("2606:4700:4700::1111" in w for w in res_io["warnings"]), res_io["warnings"]

    # 7. Duplicate CLI flag must exit 2
    dup = subprocess.run([nexus, "workspace", "compose", "--workspace", "a", "--workspace", "b",
                          "--host", "h", "--secrets-dir", "s"], capture_output=True, text=True, timeout=10)
    assert dup.returncode == 2, (dup.returncode, dup.stderr)

    # 8. secret_files includes .pem and .ech alongside .secret (for orphan GC tracking)
    ws_sec = {
        "schema_version": 1,
        "profiles": [
            make_node("hy-sec", "Hy2-Sec", proto="hysteria2", server="hy2.example.test", password="hy-pw",
                      tls={"enabled": True, "sni": "hy2.example.test",
                           "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                           "ech_mode": "config", "ech_config": "AAAA"}),
        ],
    }
    rc, res_sec, _, _ = compose(nexus, root, "sec-ext", ws_sec, host_desk, active="hy-sec", emit_kdl=True)
    assert rc == 0 and res_sec["ok"], res_sec
    exts = {Path(p).suffix for p in res_sec["secret_files"]}
    assert {".secret", ".pem", ".ech"}.issubset(exts), (exts, res_sec["secret_files"])
    for sf in res_sec["secret_files"]:
        assert Path(sf).is_file() and stat.S_IMODE(Path(sf).stat().st_mode) == 0o600


def test_fail_closed_chains_and_sub_chaining(nexus: str, root: Path) -> None:
    host = {"schema_version": 1, "platform": "desktop-linux", "desktop": {"enable_mixed": True, "mixed_listen": "127.0.0.1:7890"}}
    base_profiles = [
        make_node("a", "Node-A", server="198.51.100.1"),
        make_node("b", "Node-B", server="198.51.100.2", sub="s-chain"),
        make_node("c", "Node-C", server="198.51.100.3"),
        make_node("xhttp-node", "XH", server="198.51.100.4", transport={"type": "xhttp", "path": "/x"}),
        {"id": "ut", "remarks": "UT", "kind": "policy_group", "policy_group": {"strategy": "url-test", "member_ids": ["a"]}},
        {"id": "fc", "remarks": "FC", "kind": "full_custom_kdl", "full_custom_kdl": 'schema-version 1\nrole "client"\ninbound "i" type="mixed" { listen "127.0.0.1:1080"; authentication "none"; }\noutbound "direct" type="direct"\nrouting { default "direct"; }\n'},
    ]
    bad_cases = [
        ("missing-hop", [{"id": "bad", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["a", "ghost"]}}], "not found"),
        ("direct-cycle", [{"id": "bad", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["a", "bad"]}}], "cycle"),
        ("xhttp-hop", [{"id": "bad", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["a", "xhttp-node"]}}], "xhttp"),
        ("urltest-hop", [{"id": "bad", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["ut", "a"]}}], "non-selector"),
        ("fullcustom-hop", [{"id": "bad", "kind": "proxy_chain", "proxy_chain": {"hop_ids": ["a", "fc"]}}], "full_custom_kdl"),
    ]
    for label, extra_p, expect_err in bad_cases:
        ws = {"schema_version": 1, "profiles": base_profiles + extra_p}
        rc, res, sec_d, _ = compose(nexus, root, f"fail-{label}", ws, host, active="bad")
        assert rc == 1 and not res["ok"], (label, rc, res)
        assert any(expect_err in e for e in res["errors"]), (label, res["errors"])
        assert not sec_d.exists() or not any(sec_d.iterdir()), f"leaked secrets on {label}: {list(sec_d.iterdir())}"

    # Subscription prev_profile_id / next_profile_id wraps active profile into [a -> b -> c]
    ws_sub = {
        "schema_version": 1,
        "profiles": base_profiles[:3],
        "subscriptions": [{"id": "s-chain", "remarks": "S", "prev_profile_id": "a", "next_profile_id": "c"}],
    }
    rc, res_sc, _, _ = compose(nexus, root, "sub-chain", ws_sub, host, active="b", emit_kdl=True)
    assert rc == 0 and res_sc["ok"], res_sc
    assert 'detour "Node-A"' in res_sc["kdl"] and "subchain-h1-Node-B" in res_sc["kdl"] and "subchain-h2-Node-C" in res_sc["kdl"], res_sc["kdl"]


def test_linux_strict_route_full_custom_and_template(nexus: str, root: Path) -> None:
    # 1. desktop-linux strict-route allows loopback mixed coexistence and omits non-loopback lan_listen with warning
    ws_ip = {"schema_version": 1, "profiles": [make_node("ip1", "IP-Node", server="198.51.100.9")]}
    host_strict = {
        "schema_version": 1, "platform": "desktop-linux",
        "desktop": {
            "enable_mixed": True, "mixed_listen": "127.0.0.1:7890",
            "lan_listen": "0.0.0.0:7891",
            "enable_tun": True, "tun_interface_name": "nx0", "tun_inet4": "198.18.0.1/30",
            "tun_auto_route": True, "tun_strict_route": True, "tun_route_exclude": ["10.0.0.0/8"],
        },
    }
    rc, res_st, _, _ = compose(nexus, root, "linux-strict", ws_ip, host_strict, active="ip1", emit_kdl=True)
    assert rc == 0 and res_st["ok"], res_st
    assert 'inbound "mixed-in" type="mixed"' in res_st["kdl"] and "strict-route #true" in res_st["kdl"], res_st["kdl"]
    assert 'lan-in' not in res_st["kdl"], res_st["kdl"]
    assert any("strict-route" in w and "lan_listen" in w for w in res_st["warnings"]), res_st["warnings"]

    # 2. full_custom_kdl + Android host override strips base TUN and injects Android TUN + control/state
    ws_fc = {
        "schema_version": 1,
        "profiles": [{
            "id": "fc1", "remarks": "CustomFull", "kind": "full_custom_kdl",
            "full_custom_kdl": (
                'schema-version 1\nrole "client"\n'
                'inbounds { mixed "m" { listen "127.0.0.1:1080"; authentication "none"; }\n'
                '           tun "old-tun" { inet4-address "198.18.0.1/30"; mtu 1400; } }\n'
                'outbounds { direct; block; }\nrouting { default "direct"; }\n'
            ),
        }],
    }
    host_and = {
        "schema_version": 1, "platform": "android", "control_socket": "/tmp/nx-fc-ctl.sock",
        "android": {"run_mode": "vpn", "tun_mtu": 1480},
    }
    rc, res_fc, _, _ = compose(nexus, root, "and-fc", ws_fc, host_and, active="fc1", emit_kdl=True)
    assert rc == 0 and res_fc["ok"], res_fc
    assert "old-tun" not in res_fc["kdl"] and "tun-in" in res_fc["kdl"] and "/tmp/nx-fc-ctl.sock" in res_fc["kdl"], res_fc["kdl"]

    # 2b. full_custom_kdl with TUN-only inbound under Android proxy_only injects local-mixed fallback
    ws_fc_tun_only = {
        "schema_version": 1,
        "profiles": [{
            "id": "fc2", "remarks": "TunOnly", "kind": "full_custom_kdl",
            "full_custom_kdl": (
                'schema-version 1\nrole "client"\n'
                'inbounds { tun "old-tun" { inet4-address "198.18.0.1/30"; mtu 1400; } }\n'
                'outbounds { direct; block; }\nrouting { default "direct"; }\n'
            ),
        }],
    }
    host_and_po = {"schema_version": 1, "platform": "android", "android": {"run_mode": "proxy_only", "local_listen": "127.0.0.1:10809"}}
    rc, res_fc_po, _, _ = compose(nexus, root, "and-fc-po", ws_fc_tun_only, host_and_po, active="fc2", emit_kdl=True)
    assert rc == 0 and res_fc_po["ok"], res_fc_po
    assert "old-tun" not in res_fc_po["kdl"] and "local-mixed" in res_fc_po["kdl"] and "10809" in res_fc_po["kdl"], res_fc_po["kdl"]

    # 3. full_template overlay replaces routing/dns from template
    ws_tmpl = {
        "schema_version": 1,
        "profiles": [make_node("t1", "Tmpl-Node", server="198.51.100.11")],
        "full_template": {
            "enabled": True,
            "template_kdl": 'routing {\n  rules { - domain-suffix "tmpl.test" to="direct"; }\n  default "proxy"\n}\n',
        },
    }
    host_d = {"schema_version": 1, "platform": "desktop-linux", "desktop": {"enable_mixed": True, "mixed_listen": "127.0.0.1:7890"}}
    rc, res_tm, _, _ = compose(nexus, root, "tmpl", ws_tmpl, host_d, active="t1", emit_kdl=True)
    assert rc == 0 and res_tm["ok"] and "tmpl.test" in res_tm["kdl"], res_tm


def test_uri_parser_hy2_mport_and_wg_reserved(nexus: str, root: Path) -> None:
    sec_d = root / "uri-secrets"
    uris = "\n".join([
        "hy2://mypw@198.51.100.20:443?sni=hy2.test&mport=20000-20100,30000&hop-interval=15&upmbps=100&downmbps=200#Hy2-Hop",
        "hy2://mypw@198.51.100.23:443?sni=hy2b.test&mport=20000-20100&hop-interval=600#Hy2-Sec600",
        "hy2://mypw@198.51.100.24:443?sni=hy2c.test&mport=20000-20100&hop-interval-ms=750#Hy2-Ms750",
        "wg://cHJpdmF0ZWtleXNlY3JldA==@198.51.100.21:51820?publickey=cHVibGlja2V5c2VjcmV0&address=172.16.0.2/32&reserved=1,2,3#WG-CSV",
        "wg://cHJpdmF0ZWtleXNlY3JldA==@198.51.100.22:51820?publickey=cHVibGlja2V5c2VjcmV0&address=172.16.0.3/32&reserved=AQID#WG-B64",
        "wg://cHJpdmF0ZWtleXNlY3JldA==@198.51.100.25:51820?publickey=cHVibGlja2V5c2VjcmV0&address=172.16.0.4/32&reserved=1,2,3,4#WG-BadCSV",
    ]) + "\n"
    p = subprocess.run(
        [nexus, "convert-config", "--emit-nodes-json", "--from", "uri", "--secrets-dir", str(sec_d), "-"],
        input=uris, text=True, capture_output=True, timeout=15,
    )
    assert p.returncode == 0, (p.returncode, p.stderr)
    nodes = {n["tag"]: n for n in json.loads(p.stdout)["nodes"]}
    hy2_kdl = nodes["Hy2-Hop"]["kdl"]
    assert 'ports "20000-20100,30000"' in hy2_kdl and "hop-interval-ms 15000" in hy2_kdl, hy2_kdl
    assert "send-bps 12500000" in hy2_kdl and "receive-bps 25000000" in hy2_kdl, hy2_kdl
    assert "hop-interval-ms 600000" in nodes["Hy2-Sec600"]["kdl"], nodes["Hy2-Sec600"]["kdl"]
    assert "hop-interval-ms 750" in nodes["Hy2-Ms750"]["kdl"], nodes["Hy2-Ms750"]["kdl"]
    assert "reserved 1 2 3" in nodes["WG-CSV"]["kdl"], nodes["WG-CSV"]["kdl"]
    assert "reserved 1 2 3" in nodes["WG-B64"]["kdl"], nodes["WG-B64"]["kdl"]
    assert "reserved " not in nodes["WG-BadCSV"]["kdl"], nodes["WG-BadCSV"]["kdl"]
    for tag, n in nodes.items():
        probe = root / f"uri-{tag}.kdl"
        probe.write_text(
            'schema-version 1\nrole "client"\ncertificate { store "system"; }\n'
            'inbound "i" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none"; }\n'
            'outbound "direct" type="direct"\n' + n["kdl"] + f'routing {{ default-outbound "{tag}"; }}\n'
        )
        chk = subprocess.run([nexus, "check", str(probe)], capture_output=True, text=True, timeout=15)
        assert chk.returncode == 0, f"URI probe failed for {tag}: {chk.stderr}\n{n['kdl']}"


def test_review_kernel_regressions(nexus: str, root: Path) -> None:
    host = {"schema_version": 1, "platform": "desktop-linux", "desktop": {"enable_mixed": True, "mixed_listen": "127.0.0.1:7890"}}

    # P1 #1: failed fault-isolated sibling rolls back secrets from disk and res.secret_files
    ws_sib = {
        "schema_version": 1,
        "profiles": [
            make_node("ok1", "OK1", server="198.51.100.41"),
            make_node("bad1", "BAD1", server="198.51.100.42", password="22222222-3333-4444-5555-666666666666",
                      tls={"enabled": True, "sni": "bad.test", "reality_public_key": "not-valid-key"}),
        ],
    }
    rc, res, sec_d, _ = compose(nexus, root, "p1-sib-rb", ws_sib, host, active="ok1", emit_kdl=True)
    assert rc == 0 and res["ok"] and len(res["secret_files"]) == 1, res
    assert len(list(sec_d.iterdir())) == 1, list(sec_d.iterdir())

    # P1 #2 [T1/T2/T3]: full_template ergonomic direct/block, top-level outbound, and proxy_detour w/ template outbound & vless+xhttp skip
    t1_ws = {
        "schema_version": 1, "profiles": [make_node("p1", "P1", server="198.51.100.43")],
        "full_template": {"enabled": True, "append_proxies_only": True, "template_kdl": (
            'schema-version 1\nrole "client"\ninbounds { mixed "m" { listen "127.0.0.1:1080"; authentication "none"; } }\n'
            'outbounds { direct; block; }\nrouting { default "proxy"; }\n')},
    }
    rc, r_t1, _, _ = compose(nexus, root, "p1-t1", t1_ws, host, active="p1", emit_kdl=True)
    assert rc == 0 and r_t1["ok"], r_t1
    t2_ws = {
        "schema_version": 1, "profiles": [make_node("p1", "P1", server="198.51.100.44")],
        "full_template": {"enabled": True, "append_proxies_only": True, "template_kdl": (
            'schema-version 1\nrole "client"\ninbound "m" type="mixed" { listen "127.0.0.1:1080"; authentication "none"; }\n'
            'outbound "direct" type="direct"\nrouting { default "proxy"; }\n')},
    }
    rc, r_t2, _, _ = compose(nexus, root, "p1-t2", t2_ws, host, active="p1", emit_kdl=True)
    assert rc == 0 and r_t2["ok"], r_t2
    t3_ws = {
        "schema_version": 1,
        "profiles": [
            make_node("p1", "P1", server="198.51.100.45"),
            make_node("xh", "XH", server="198.51.100.46", transport={"type": "xhttp", "path": "/x"}),
        ],
        "full_template": {"enabled": True, "proxy_detour": "relay-out", "template_kdl": (
            'outbound "relay-out" type="socks5" { server host="127.0.0.1" port=1081; }\n'
            'routing { default "proxy"; }\n')},
    }
    rc, r_t3, _, _ = compose(nexus, root, "p1-t3", t3_ws, host, active="p1", emit_kdl=True)
    assert rc == 0 and r_t3["ok"] and 'detour "relay-out"' in r_t3["kdl"], r_t3

    # P1 #3 + P2 #2 + P2 #3: invalid rule-sets skipped, raw_kdl DNS server extracted for remote rule-set, lazy ip-if-non-match, SimpleDNS warnings
    ws_rs = {
        "schema_version": 1, "profiles": [make_node("p1", "P1", server="198.51.100.47")],
        "rule_set_assets": [
            {"tag": "bad-http", "source_type": "remote", "url": "http://insecure.test/a.nxmm", "format": "nxmm"},
            {"tag": "bad-sha", "source_type": "remote", "url": "https://ok.test/a.nxmm", "sha256": "z" * 64, "format": "nxmm"},
            {"tag": "bad-loc", "source_type": "local", "path": "", "format": "nxmm"},
            {"tag": "good-rem", "source_type": "remote", "url": "https://ok.test/good.nxmm", "format": "nxmm"},
        ],
        "dns": {"mode": "raw_kdl", "raw_kdl": 'dns {\n  servers { server "my-dns" type="udp" host="223.5.5.5" port=53; }\n  final "my-dns"\n}\n'},
        "routing_profiles": [{
            "id": "rp", "is_active": True, "domain_strategy": "ip-if-non-match", "default_outbound": "proxy",
            "rules": [
                {"id": "r1", "enabled": True, "scope": "both", "target_type": "direct", "domains": ["domain:pure.test"]},
                {"id": "r2", "enabled": True, "scope": "both", "target_type": "direct",
                 "rule_sets": ["bad-http", "bad-sha", "bad-loc", "good-rem"], "ips": ["private"]},
            ],
        }],
    }
    rc, r_rs, _, _ = compose(nexus, root, "p1-rs", ws_rs, host, active="p1", emit_kdl=True)
    assert rc == 0 and r_rs["ok"], r_rs
    kdl = r_rs["kdl"]
    assert 'domain-resolver "my-dns"' in kdl and "bad-http" not in kdl and "bad-sha" not in kdl and "bad-loc" not in kdl, kdl
    assert kdl.index('domain-suffix "pure.test"') < kdl.index('- "resolve" route-only=#true') < kdl.index("ip-is-private #true"), kdl

    # P2 #1 & P2 #3: WG 4-byte reserved rejected in compose; unused SimpleDNS fields warn
    ws_wg_bad = {"schema_version": 1, "profiles": [make_node("w1", "WG", proto="wireguard", server="198.51.100.48", port=51820,
                 extra={"wg_peer_public_key": "cHVibGlja2V5c2VjcmV0", "wg_local_addresses": ["172.16.0.2/32"], "wg_reserved": "1,2,3,4"})]}
    rc, r_wg, _, _ = compose(nexus, root, "p2-wg", ws_wg_bad, host, active="w1")
    assert rc == 1 and not r_wg["ok"] and any("reserved" in e for e in r_wg["errors"]), r_wg
    ws_sd_warn = {
        "schema_version": 1, "profiles": [make_node("p1", "P1", server="198.51.100.49")],
        "dns": {"mode": "simple", "simple": {"parallel_query": True, "direct_expected_rule_sets": ["cn"], "fake_ip_global": True}},
    }
    rc, r_sw, _, _ = compose(nexus, root, "p2-sdw", ws_sd_warn, host, active="p1", emit_kdl=True)
    assert rc == 0 and r_sw["ok"], r_sw
    wtext = "\n".join(r_sw["warnings"])
    assert "parallel_query" in wtext and "direct_expected_rule_sets" in wtext and "fake_ip_global" in wtext, r_sw["warnings"]
    # Wave 27: workers_spec + workers_max (incl. full_custom_kdl), uncapped workers=20, fail-closed invalid workers_spec
    ws_w = {"schema_version": 1, "profiles": [make_node("w1", "W1", server="198.51.100.50")]}
    h_spec = dict(host, workers_spec="max-2", workers_max=12)
    rc, r_ws, _, _ = compose(nexus, root, "w27-spec", ws_w, h_spec, active="w1", emit_kdl=True)
    assert rc == 0 and r_ws["ok"] and 'workers "max-2" max=12\n' in r_ws["kdl"], r_ws
    rc, r_whi, _, _ = compose(nexus, root, "w27-hi", ws_w, dict(host, workers=20), active="w1", emit_kdl=True)
    assert rc == 0 and r_whi["ok"] and "workers 20\n" in r_whi["kdl"], r_whi
    ws_fcw = {"schema_version": 1, "profiles": [{"id": "fcw", "kind": "full_custom_kdl", "full_custom_kdl": 'schema-version 1\nrole "client"\nworkers 2\ninbound "i" type="mixed" { listen "127.0.0.1:1080"; authentication "none"; }\noutbound "direct" type="direct"\nrouting { default "direct"; }\n'}]}
    rc, r_fcw, _, _ = compose(nexus, root, "w27-fc", ws_fcw, h_spec, active="fcw", emit_kdl=True)
    assert rc == 0 and r_fcw["ok"] and 'workers "max-2" max=12' in r_fcw["kdl"], r_fcw
    for bad in ("max-abc", "max--1", "foo"):
        rc, r_wb, sec_b, _ = compose(nexus, root, f"w27-bad-{bad}", ws_w, dict(host, workers_spec=bad), active="w1")
        assert rc == 1 and not r_wb["ok"] and any("workers_spec" in e for e in r_wb["errors"]) and not (sec_b.exists() and any(sec_b.iterdir()))


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-nexus-bin>", file=sys.stderr)
        return 2
    nexus = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="nexus-wave22-ws-") as td:
        root = Path(td)
        test_five_kinds_and_siblings(nexus, root)
        test_fail_closed_chains_and_sub_chaining(nexus, root)
        test_linux_strict_route_full_custom_and_template(nexus, root)
        test_uri_parser_hy2_mport_and_wg_reserved(nexus, root)
        test_review_kernel_regressions(nexus, root)
    print("WAVE 22 WORKSPACE COMPOSE CLI TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
