"""Batch 95C end-to-end tests: HTTP /v1 control plane, Bearer auth, OpenMetrics /metrics, slow-consumer DoS & toggle-off."""
import argparse
import http.client
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from detour_network import reserve, running


def http_req(port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def test_disabled_binary(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-95c-off-") as tmp:
        root = Path(tmp)
        front, ctrl_port = reserve(), reserve()
        cfg = root / "off.kdl"
        cfg.write_text(f'''schema-version 1
role "client"
control http-listen="127.0.0.1:{ctrl_port}" metrics=#true
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        res = subprocess.run([binary, "run", "--config", str(cfg)], capture_output=True, text=True, timeout=5)
        assert res.returncode != 0 and "http control startup failed" in res.stderr, res.stderr
    print("95C toggle-off check passed (control-http disabled binary cleanly rejects http-listen)")


def test_config_security_rejection(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-95c-sec-") as tmp:
        root = Path(tmp)
        cfg = root / "nonloopback.kdl"
        cfg.write_text('''schema-version 1
role "client"
control http-listen="0.0.0.0:19090"
inbound "in" type="socks5" { listen host="127.0.0.1" port=18080; authentication "none"; }
outbound "direct" type="direct"
routing { final "direct"; }
''')
        res = subprocess.run([binary, "run", "--config", str(cfg)], capture_output=True, text=True, timeout=5)
        assert res.returncode != 0 and "bearer-token-file" in res.stderr, res.stderr
    print("95C non-loopback without bearer-token-file rejected at config check")


def test_http_control_and_metrics(binary):
    with tempfile.TemporaryDirectory(prefix="nexus-95c-on-") as tmp:
        root = Path(tmp)
        token_val = "nexus-batch95c-secret-token-0123456789abcdef"
        token_file = root / "control.token"
        token_file.write_text(token_val + "\n")
        os.chmod(token_file, 0o600)

        front, ctrl_port = reserve(), reserve()
        cfg = root / "on.kdl"
        cfg.write_text(f'''schema-version 1
role "client"
control http-listen="127.0.0.1:{ctrl_port}" bearer-token-file="{token_file}" metrics=#true
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "blocked" type="block"
outbound "alt" type="socks5" {{ server host="127.0.0.1" port=18081; }}
outbound "choice" type="selector" {{
    member "direct"
    member "alt"
    member "blocked"
    selected "direct"
}}
outbound "auto_probe" type="url-test" {{
    member "direct"
    member "alt"
    probe-url "http://127.0.0.1:1/generate_204"
    probe-interval-ms 60000
    probe-timeout-ms 500
}}
routing {{ final "choice"; }}
''')
        auth = {"Authorization": f"Bearer {token_val}"}
        with running([binary, "run", "--config", cfg], front, root / "proxy.log"):
            # 1. Auth hard boundaries: missing, wrong, and query-param token all rejected 401
            for hdrs, path in (
                ({}, "/v1/status"),
                ({"Authorization": "Bearer wrong-token-0000000000000000"}, "/v1/status"),
                ({}, f"/v1/status?token={token_val}"),
                (auth, f"/v1/status?token={token_val}"),
            ):
                code, _, body = http_req(ctrl_port, "GET", path, headers=hdrs)
                assert code == 401, f"expected 401 for {path} {hdrs}, got {code}: {body}"

            # 2. Core read endpoints
            code, _, body = http_req(ctrl_port, "GET", "/v1/health", headers=auth)
            assert code == 200 and json.loads(body)["status"] == "ok", body

            code, _, body = http_req(ctrl_port, "GET", "/v1/status", headers=auth)
            st = json.loads(body)
            assert code == 200 and st["state"] == "running" and st["listeners"] == 1, st
            assert isinstance(st["upload_bytes_total"], str) and isinstance(st["control_generation"], str), st

            code, _, body = http_req(ctrl_port, "GET", "/v1/outbounds", headers=auth)
            ob = json.loads(body)
            assert code == 200 and ob["groups"][0]["name"] == "choice" and ob["groups"][0]["selected"] == "direct", ob

            code, _, body = http_req(ctrl_port, "GET", "/v1/connections", headers=auth)
            assert code == 200 and "connections" in json.loads(body), body

            # 3. Mutations: PUT /v1/groups/{tag} (valid 200 + illegal block default 409), POST /v1/log-level, POST /v1/reload
            code, _, body = http_req(ctrl_port, "PUT", "/v1/groups/choice",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"member":"blocked"}')
            assert code == 409 and "default-outbound cannot select block" in body, (code, body)
            code, _, body = http_req(ctrl_port, "PUT", "/v1/groups/choice",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"member":"alt"}')
            assert code == 200 and json.loads(body)["selected"] == "alt", (code, body)
            code, _, body = http_req(ctrl_port, "PUT", "/v1/groups/choice",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"member":"direct"}')
            assert code == 200 and json.loads(body)["selected"] == "direct", (code, body)

            code, _, body = http_req(ctrl_port, "POST", "/v1/log-level",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"level":"debug"}')
            assert code == 200 and json.loads(body)["level"] == "debug", (code, body)

            code, _, body = http_req(ctrl_port, "POST", "/v1/reload", headers=auth, body="{}")
            assert code == 202 and json.loads(body)["state"] == "pending", (code, body)

            # 3b. Cache clear endpoint (default all, targeted dns, and invalid target rejection)
            code, _, body = http_req(ctrl_port, "POST", "/v1/state/clear-cache", headers=auth, body="{}")
            assert code == 200 and json.loads(body)["cleared"] is True and json.loads(body)["target"] == "all", (code, body)
            code, _, body = http_req(ctrl_port, "POST", "/v1/state/clear-cache",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"target":"dns"}')
            assert code == 200 and json.loads(body)["target"] == "dns", (code, body)
            code, _, body = http_req(ctrl_port, "POST", "/v1/state/clear-cache",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"target":"bogus"}')
            assert code == 400 and "invalid-target" in body, (code, body)

            # 3c. Network-change event & connection termination (Batch 111)
            code, _, body = http_req(ctrl_port, "POST", "/v1/network-change",
                                     headers={**auth, "Content-Type": "application/json"},
                                     body='{"generation":"42"}')
            assert code == 200 and json.loads(body)["accepted"] is True, (code, body)

            code, _, body = http_req(ctrl_port, "DELETE", "/v1/connections/999999", headers=auth)
            assert code == 404 and "unknown-connection" in body, (code, body)
            code, _, body = http_req(ctrl_port, "DELETE", "/v1/connections/not-a-num", headers=auth)
            assert code == 400 and "invalid-id" in body, (code, body)

            # Live active connection termination via DELETE /v1/connections/{id}
            sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sink.bind(("127.0.0.1", 0))
            sink.listen(4)
            sink_port = sink.getsockname()[1]
            client = socket.create_connection(("127.0.0.1", front), timeout=2)
            client.sendall(b"\x05\x01\x00")
            assert client.recv(2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + sink_port.to_bytes(2, "big"))
            assert client.recv(10)[:2] == b"\x05\x00"
            peer, _ = sink.accept()
            try:
                conn_id = None
                for _ in range(30):
                    code, _, body = http_req(ctrl_port, "GET", "/v1/connections", headers=auth)
                    conns = json.loads(body).get("connections", [])
                    if conns:
                        conn_id = conns[0]["id"]
                        break
                    time.sleep(0.05)
                assert conn_id is not None, "expected active SOCKS5 connection in /v1/connections"
                code, _, body = http_req(ctrl_port, "DELETE", f"/v1/connections/{conn_id}", headers=auth)
                assert code == 200 and json.loads(body)["closed"] is True, (code, body)
                client.settimeout(2.0)
                assert client.recv(16) == b"", "expected EOF after DELETE /v1/connections/{id}"
            finally:
                peer.close()
                client.close()
                sink.close()

            # 3d. Batch 117: DELETE /v1/connections (close-all), POST /v1/groups/{name}/probe, GET /v1/diagnostics & /v1/events
            code, _, body = http_req(ctrl_port, "POST", "/v1/groups/auto_probe/probe", headers=auth, body="{}")
            assert code == 202 and json.loads(body)["probe"] == "triggered", (code, body)
            code, _, body = http_req(ctrl_port, "POST", "/v1/groups/choice/probe", headers=auth, body="{}")
            assert code == 409 and "not-probe-group" in body, (code, body)
            code, _, body = http_req(ctrl_port, "POST", "/v1/groups/missing/probe", headers=auth, body="{}")
            assert code == 404 and "unknown-group" in body, (code, body)

            sink2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sink2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sink2.bind(("127.0.0.1", 0))
            sink2.listen(4)
            sink2_port = sink2.getsockname()[1]
            clients, peers = [], []
            try:
                for _ in range(2):
                    c = socket.create_connection(("127.0.0.1", front), timeout=2)
                    c.sendall(b"\x05\x01\x00")
                    assert c.recv(2) == b"\x05\x00"
                    c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + sink2_port.to_bytes(2, "big"))
                    assert c.recv(10)[:2] == b"\x05\x00"
                    p, _ = sink2.accept()
                    clients.append(c)
                    peers.append(p)
                for _ in range(30):
                    code, _, body = http_req(ctrl_port, "GET", "/v1/connections", headers=auth)
                    if len(json.loads(body).get("connections", [])) >= 2:
                        break
                    time.sleep(0.05)
                code, _, body = http_req(ctrl_port, "DELETE", "/v1/connections", headers=auth)
                assert code == 200 and json.loads(body)["closed"] >= 2, (code, body)
                for c in clients:
                    c.settimeout(2.0)
                    assert c.recv(16) == b"", "expected EOF after DELETE /v1/connections"
            finally:
                for p in peers:
                    p.close()
                for c in clients:
                    c.close()
                sink2.close()

            code, _, body = http_req(ctrl_port, "GET", "/v1/diagnostics", headers=auth)
            diag = json.loads(body)
            assert code == 200 and diag["authorized_requests"] >= 10 and diag["listeners"] == 1, (code, diag)

            code, _, body = http_req(ctrl_port, "GET", "/v1/events", headers=auth)
            ev = json.loads(body)
            ev_names = {item["event"] for item in ev.get("events", [])}
            assert code == 200 and "network-changed" in ev_names and "probe-triggered" in ev_names, (code, ev)

            # 4. OpenMetrics /metrics strict format & low-cardinality verification
            code, hdrs, metrics_text = http_req(ctrl_port, "GET", "/metrics", headers=auth)
            assert code == 200, (code, metrics_text)
            ctype = next((v for k, v in hdrs.items() if k.lower() == "content-type"), "")
            assert "application/openmetrics-text" in ctype, ctype
            assert metrics_text.endswith("# EOF\n"), metrics_text[-40:]
            for metric_name in (
                "nexus_control_generation",
                "nexus_active_sessions{listener=\"0\"}",
                "nexus_traffic_upload_bytes_total{listener=\"0\"}",
                "nexus_traffic_download_bytes_total{listener=\"0\"}",
                "nexus_control_requests_total{outcome=\"authorized\"}",
                "nexus_control_requests_total{outcome=\"unauthorized\"}",
            ):
                assert metric_name in metrics_text, f"missing {metric_name} in:\n{metrics_text}"
            # Ensure zero high-cardinality labels or token leakage
            assert token_val not in metrics_text
            for forbidden in ("client_ip=", "domain=", "url=", "port="):
                assert forbidden not in metrics_text, f"forbidden high-cardinality label {forbidden}"

            # 5. Slow-consumer resilience: saturate 16 stalled control sockets -> wait 2.3s -> recovers cleanly!
            stalled = []
            for _ in range(16):
                s = socket.create_connection(("127.0.0.1", ctrl_port), timeout=2)
                s.sendall(b"GET /v1/health HTTP/1.1\r\n")  # intentionally incomplete headers
                stalled.append(s)
            time.sleep(2.3)
            for s in stalled:
                s.close()
            code, _, body = http_req(ctrl_port, "GET", "/v1/health", headers=auth)
            assert code == 200 and json.loads(body)["status"] == "ok", (code, body)
            code, _, metrics_text2 = http_req(ctrl_port, "GET", "/metrics", headers=auth)
            assert "nexus_control_requests_total{outcome=\"expired\"} " in metrics_text2
            exp_line = [ln for ln in metrics_text2.splitlines() if 'outcome="expired"' in ln][0]
            assert int(exp_line.split()[-1]) >= 16, exp_line

    print("95C HTTP /v1 control, Bearer constant-time auth, OpenMetrics /metrics & slow-consumer eviction passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--disabled-binary", default="")
    args = parser.parse_args()
    if args.disabled_binary:
        test_disabled_binary(args.disabled_binary)
    test_config_security_rejection(args.binary)
    test_http_control_and_metrics(args.binary)


if __name__ == "__main__":
    main()
