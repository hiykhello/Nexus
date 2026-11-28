#!/usr/bin/env python3
"""Audit Nexus uTLS ClientHello wire output against upstream uTLS specs or live browser captures.

Separates differences into:
  - DATA DRIFT: capabilities Nexus already implements (fixable in src/tls/browser_profiles.cppm).
  - CAPABILITY GAP: extensions/ciphers/groups Nexus intentionally omits until implemented in src/tls/.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import urllib.request

from utls_wire import EXT_ID_TO_NAME, fmt_hex_list, parse_client_hello, parse_utls_go

REPO_ROOT = Path(__file__).resolve().parent.parent

NEXUS_ALL_CIPHERS = {0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8}
NEXUS_GROUPS = {0x11EC, 0x001D, 0x0017, 0x0018, 0x0019}
NEXUS_TLS13_SIGS = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0904, 0x0905, 0x0906}
NEXUS_ALL_SIGS = NEXUS_TLS13_SIGS | {0x0401, 0x0501, 0x0601}
NEXUS_EXTENSIONS = {
    0, 5, 10, 11, 13, 16, 18, 21, 23, 27, 28, 34, 35, 43, 45, 51,
    0x0039, 0x4469, 0x44CD, 0xCA34, 0xFE0D, 0xFF01,
}
NEXUS_MAX_INITIAL_KEY_SHARES = 3


def compare_profile(family: str, nexus: dict, ref: dict, cert_comp_enabled: bool) -> dict:
    data_drift: list[str] = []
    cap_gaps: list[str] = []

    ref_cs = [c for c in ref["ciphers"] if c in NEXUS_ALL_CIPHERS]
    unsup_cs = [c for c in ref["ciphers"] if c not in NEXUS_ALL_CIPHERS]
    if unsup_cs:
        cap_gaps.append(f"unsupported legacy ciphers omitted ({len(unsup_cs)}): {fmt_hex_list(unsup_cs)}")
    if ref_cs and nexus["ciphers"] != ref_cs:
        data_drift.append(f"cipher order/set mismatch: nexus={fmt_hex_list(nexus['ciphers'])} ref={fmt_hex_list(ref_cs)}")

    for key in ("grease_cipher", "grease_sigalgs", "record_size_limit", "alps_code", "has_ech"):
        if nexus[key] != ref[key]:
            data_drift.append(f"{key} mismatch: nexus={nexus[key]} ref={ref[key]}")

    ref_groups = [g for g in ref["groups"] if g in NEXUS_GROUPS]
    unsup_groups = [g for g in ref["groups"] if g not in NEXUS_GROUPS]
    if unsup_groups:
        cap_gaps.append(f"unsupported groups omitted: {fmt_hex_list(unsup_groups)}")
    if ref_groups and nexus["groups"] != ref_groups:
        data_drift.append(f"supported_groups mismatch: nexus={fmt_hex_list(nexus['groups'])} ref={fmt_hex_list(ref_groups)}")

    ref_ks = [g for g in ref["key_shares"] if g in NEXUS_GROUPS]
    if len(ref_ks) > NEXUS_MAX_INITIAL_KEY_SHARES:
        cap_gaps.append(f"initial key_shares > {NEXUS_MAX_INITIAL_KEY_SHARES}: ref={fmt_hex_list(ref_ks)}")
    ref_ks_capped = ref_ks[:NEXUS_MAX_INITIAL_KEY_SHARES]
    if ref_ks_capped and nexus["key_shares"] != ref_ks_capped:
        data_drift.append(f"key_share mismatch: nexus={fmt_hex_list(nexus['key_shares'])} ref={fmt_hex_list(ref_ks_capped)}")

    unsup_sigs = [s for s in ref["sigalgs"] if s not in NEXUS_ALL_SIGS]
    if unsup_sigs:
        cap_gaps.append(f"unsupported signature_algorithms omitted: {fmt_hex_list(unsup_sigs)}")
    nx_t13_sigs = [s for s in nexus["sigalgs"] if s in NEXUS_TLS13_SIGS]
    ref_t13_sigs: list[int] = []
    for s in ref["sigalgs"]:
        if s in NEXUS_TLS13_SIGS and s not in ref_t13_sigs:
            ref_t13_sigs.append(s)
    if ref_t13_sigs and nx_t13_sigs != ref_t13_sigs:
        data_drift.append(f"tls13 sigalgs mismatch: nexus={fmt_hex_list(nx_t13_sigs)} ref={fmt_hex_list(ref_t13_sigs)}")

    if cert_comp_enabled:
        if nexus["cert_comp"] != ref["cert_comp"]:
            data_drift.append(f"cert_compression mismatch: nexus={nexus['cert_comp']} ref={ref['cert_comp']}")
    elif ref["cert_comp"]:
        cap_gaps.append(f"cert_compression disabled in this build (ref={ref['cert_comp']})")

    ignore_exts = {21} if cert_comp_enabled else {21, 27}
    ref_exts = [e for e in ref["extensions"] if e in NEXUS_EXTENSIONS and e not in ignore_exts]
    unsup_exts = [e for e in ref["extensions"] if e not in NEXUS_EXTENSIONS]
    if unsup_exts:
        names = [f"{EXT_ID_TO_NAME.get(e, 'unknown')}(0x{e:04x})" for e in unsup_exts]
        cap_gaps.append(f"unsupported extensions omitted: {names}")

    nx_exts = [e for e in nexus["extensions"] if e not in ignore_exts]
    missing = [e for e in ref_exts if e not in set(nx_exts)]
    if missing:
        data_drift.append(f"missing supported extensions: {fmt_hex_list(missing)}")
    common_ref = [e for e in ref_exts if e in set(nx_exts)]
    common_nx = [e for e in nx_exts if e in set(ref_exts)]
    if not ref.get("shuffled", False) and common_nx != common_ref:
        data_drift.append(f"extension order mismatch: nexus={common_nx} ref={common_ref}")

    return {
        "family": family, "nexus_baseline": nexus.get("baseline", ""),
        "upstream_id": ref.get("upstream_id", "live-capture"),
        "nexus_ja4": nexus["ja4"], "data_drift": data_drift, "capability_gaps": cap_gaps,
    }


def find_dumper(explicit: Path | None) -> Path:
    if explicit:
        return explicit.resolve(strict=True)
    candidates = sorted(REPO_ROOT.glob("target/**/bin/utls-dump"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise SystemExit("utls-dump not found under target/; run: mcpp run --features profile-linux-uring,test-bins utls-dump")
    return candidates[0]


def load_upstream_utls(utls_dir: Path | None, fetch: bool) -> tuple[str, str, str]:
    if fetch:
        base = "https://raw.githubusercontent.com/refraction-networking/utls/master"
        with urllib.request.urlopen(f"{base}/u_common.go", timeout=15) as r:
            u_common = r.read().decode("utf-8")
        with urllib.request.urlopen(f"{base}/u_parrots.go", timeout=15) as r:
            u_parrots = r.read().decode("utf-8")
        return f"{base} (live master)", u_common, u_parrots

    dirs: list[Path] = [utls_dir] if utls_dir else []
    if not dirs:
        gopath = Path(os.environ.get("GOPATH", Path.home() / "go"))
        for pat in ("pkg/mod/github.com/refraction-networking/utls@*", "pkg/mod/github.com/metacubex/utls@*"):
            dirs.extend(Path(p) for p in glob.glob(str(gopath / pat)))
    dirs = [d for d in dirs if (d / "u_common.go").exists() and (d / "u_parrots.go").exists()]
    if not dirs:
        raise SystemExit("No local uTLS Go module found; pass --utls-dir PATH or --fetch-upstream")
    chosen = max(dirs, key=lambda p: p.stat().st_mtime)
    return str(chosen), (chosen / "u_common.go").read_text("utf-8"), (chosen / "u_parrots.go").read_text("utf-8")


def capture_live_client_hello(cmd_template: str | None, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(4)
        srv.settimeout(timeout)

        proc = None
        if cmd_template:
            proc = subprocess.Popen(shlex.split(cmd_template.replace("{port}", str(port))),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print(f"Listening on https://127.0.0.1:{port} — connect within {timeout:.0f}s...", file=sys.stderr)
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(5.0)
                hdr = b""
                while len(hdr) < 5:
                    chunk = conn.recv(5 - len(hdr))
                    if not chunk:
                        raise RuntimeError("peer closed before TLS record header")
                    hdr += chunk
                rec_len = int.from_bytes(hdr[3:5], "big")
                body = b""
                while len(body) < rec_len:
                    chunk = conn.recv(rec_len - len(body))
                    if not chunk:
                        break
                    body += chunk
                return hdr + body
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dumper", type=Path, help="Path to built utls-dump binary")
    parser.add_argument("--utls-dir", type=Path, help="Path to local refraction-networking/utls source directory")
    parser.add_argument("--fetch-upstream", action="store_true", help="Fetch latest u_common.go/u_parrots.go from GitHub master")
    parser.add_argument("--profiles", default="chrome,firefox,safari", help="Comma-separated browser families to audit")
    parser.add_argument("--capture-profile", help="Capture a live ClientHello and compare against this Nexus profile")
    parser.add_argument("--capture-cmd", help="Command template to trigger live capture (use {port} placeholder)")
    parser.add_argument("--capture-timeout", type=float, default=20.0, help="Seconds to wait for live capture")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--fail-on-data-drift", action="store_true", help="Exit 1 if any DATA DRIFT is detected")
    args = parser.parse_args()

    dumper = find_dumper(args.dumper)
    raw_dump = json.loads(subprocess.check_output([str(dumper), "--transport", "tcp", "--group", "hybrid"], text=True))
    cert_comp_enabled = bool(raw_dump["cert_compression_enabled"])
    nexus_by_name = {}
    for entry in raw_dump["profiles"]:
        parsed = parse_client_hello(bytes.fromhex(entry["hello_hex"]))
        parsed["baseline"] = entry["baseline"]
        nexus_by_name[entry["name"]] = parsed

    reports: list[dict] = []
    if args.capture_profile:
        source_label = f"live-capture ({args.capture_cmd or 'manual'})"
        live_ref = parse_client_hello(capture_live_client_hello(args.capture_cmd, args.capture_timeout))
        live_ref["upstream_id"] = "live-capture"
        live_ref["shuffled"] = args.capture_profile in ("chrome", "edge")
        reports.append(compare_profile(args.capture_profile, nexus_by_name[args.capture_profile], live_ref, cert_comp_enabled))
    else:
        source_label, u_common, u_parrots = load_upstream_utls(args.utls_dir, args.fetch_upstream)
        upstream = parse_utls_go(u_common, u_parrots)
        for family in [p.strip() for p in args.profiles.split(",") if p.strip()]:
            if family in nexus_by_name and family in upstream:
                reports.append(compare_profile(family, nexus_by_name[family], upstream[family], cert_comp_enabled))

    if args.json:
        print(json.dumps({"source": source_label, "cert_compression_enabled": cert_comp_enabled, "reports": reports}, indent=2))
    else:
        print(f"uTLS Audit Source: {source_label}\nNexus cert_compression_enabled: {cert_comp_enabled}\n")
        for r in reports:
            status = "OK" if not r["data_drift"] else f"DATA DRIFT ({len(r['data_drift'])})"
            print(f"[{r['family']}] nexus={r['nexus_baseline']} vs ref={r['upstream_id']}  JA4={r['nexus_ja4']}  => {status}")
            for item in r["data_drift"]:
                print(f"  [DATA DRIFT]     {item}")
            for item in r["capability_gaps"]:
                print(f"  [CAPABILITY GAP] {item}")
            if not r["data_drift"] and not r["capability_gaps"]:
                print("  (exact match)")
            print()

    return 1 if (args.fail_on_data_drift and any(r["data_drift"] for r in reports)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
