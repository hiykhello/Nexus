"""Fixed sing-box VLESS interoperability fixtures."""
import json
import socket
import subprocess
import threading
import time

from interop_common import PROXY_WORKERS, NEXUS, VLESS_CLIENT
from vless_fixture_interop import vless_identity_failure
from vless_proxy_interop import vless_proxy
from vless_multi_outbound import multi_outbound

def vless_singbox(directory):
    version = subprocess.run(["sing-box", "version"], check=True, text=True, capture_output=True).stdout
    revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
    if f"Revision: {revision}" not in version:
        raise RuntimeError("sing-box revision differs from the verified test fixture")
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    target.listen(1)
    target.settimeout(10)
    target_port = target.getsockname()[1]
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    config = {
        "log": {"level": "warn"},
        "inbounds": [{"type": "vless", "tag": "test", "listen": "127.0.0.1", "listen_port": port,
                      "users": [{"uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f"}],
                      "tls": {"enabled": True, "certificate_path": str(directory / "server.pem"),
                              "key_path": str(directory / "server.key")}}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }
    path = directory / "sing-box.json"
    path.write_text(json.dumps(config))
    subprocess.run(["sing-box", "check", "-c", path], check=True, capture_output=True)
    server = subprocess.Popen(["sing-box", "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    errors = []
    def origin():
        try:
            with target.accept()[0] as conn:
                conn.settimeout(10)
                data = bytearray()
                while len(data) < 5:
                    block = conn.recv(5-len(data))
                    if not block:
                        raise RuntimeError("truncated origin request")
                    data += block
                if data != b"hello":
                    raise RuntimeError(f"unexpected origin data: {data!r}")
                conn.sendall(b"world")
        except Exception as exc:
            errors.append(exc)
        finally:
            target.close()
    thread = threading.Thread(target=origin)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except ConnectionRefusedError:
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("sing-box failed to start")
                time.sleep(0.05)
        result = subprocess.run([VLESS_CLIENT, str(port), directory / "root.pem", directory / "user.uuid", "relay", str(target_port)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if result.returncode:
            raise RuntimeError(f"sing-box VLESS client exit {result.returncode}: {result.stderr.decode(errors='replace')}")
        thread.join(timeout=12)
        if thread.is_alive() or errors:
            raise RuntimeError(f"sing-box origin failed: {errors}")
        with socket.socket() as rejected_origin:
            rejected_origin.bind(("127.0.0.1", 0))
            rejected_origin.listen(1)
            rejected_origin.settimeout(1)
            rejected_port = rejected_origin.getsockname()[1]
            result = subprocess.run([VLESS_CLIENT, str(port), directory / "root.pem", directory / "user.uuid", "bad-user", str(rejected_port)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            if result.returncode:
                raise RuntimeError(f"sing-box invalid UUID test exit {result.returncode}: {result.stderr.decode(errors='replace')}")
            try:
                conn, _ = rejected_origin.accept()
            except TimeoutError:
                pass
            else:
                conn.close()
                raise RuntimeError("sing-box connected to origin for an invalid UUID")
        vless_proxy(directory, port)
        vless_proxy(directory, port, "edge")
        # A closed upstream proves the matching direct rule bypasses VLESS.
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            closed_port = unused.getsockname()[1]
        vless_proxy(directory, closed_port, "direct")
        multi_outbound(directory, port)
        vless_block(directory, port)
        vless_identity_failure(directory, port)
        vless_identity_failure(directory, port, selected=True)
        vless_backpressure(directory, port)
        print(f"VLESS TLS sing-box {revision} end-to-end passed")
    finally:
        server.terminate()
        try:
            server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.communicate()
        target.close()
        thread.join(timeout=11)


def vless_backpressure(directory, upstream_port):
    with socket.socket() as origin, socket.socket() as reservation:
        origin.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin.settimeout(8)
        reservation.bind(("127.0.0.1", 0))
        port=reservation.getsockname()[1]
        reservation.close()
        config=directory / "backpressure.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={upstream_port}
  authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
  tls {{ server-name "server.example"; ca-file "{directory / 'root.pem'}"; verify #true; }}
}}
routing {{ default-outbound "edge"; }}
''')
        process=subprocess.Popen([NEXUS,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
                try:
                    client=socket.create_connection(("127.0.0.1",port),timeout=1)
                    break
                except ConnectionRefusedError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(0.05)
            with client:
                client.settimeout(8)
                client.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
                def exact(size):
                    data=bytearray()
                    while len(data)<size:
                        chunk=client.recv(size-len(data))
                        if not chunk: raise RuntimeError("backpressure client closed early")
                        data+=chunk
                    return bytes(data)
                client.sendall(b"\x05\x01\x00")
                if exact(2)!=b"\x05\x00": raise RuntimeError("backpressure greeting failed")
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+origin.getsockname()[1].to_bytes(2,"big")+b"x")
                if exact(10)[:2]!=b"\x05\x00": raise RuntimeError("backpressure connect failed")
                with origin.accept()[0] as held:
                    held.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
                    held.settimeout(8)
                    if held.recv(1)!=b"x": raise RuntimeError("backpressure origin did not connect")
                    client.settimeout(1)
                    total=0
                    block=bytes(65536)
                    try:
                        while total<64*1024*1024:
                            sent=client.send(block)
                            if not sent: raise RuntimeError("backpressure client closed while sending")
                            total+=sent
                    except TimeoutError:
                        pass
                    else:
                        raise RuntimeError("failed to induce backpressure")
                    if total<65536: raise RuntimeError("backpressure occurred before meaningful traffic")
                    with socket.socket() as other_origin:
                        other_origin.bind(("127.0.0.1",0))
                        other_origin.listen(1)
                        other_origin.settimeout(8)
                        with socket.create_connection(("127.0.0.1",port),timeout=8) as other:
                            other.settimeout(8)
                            other.sendall(b"\x05\x01\x00")
                            if other.recv(2)!=b"\x05\x00": raise RuntimeError("parallel greeting failed")
                            other.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+other_origin.getsockname()[1].to_bytes(2,"big")+b"hello")
                            response=bytearray()
                            while len(response)<10:
                                part=other.recv(10-len(response))
                                if not part: raise RuntimeError("parallel response truncated")
                                response+=part
                            if response[:2]!=b"\x05\x00": raise RuntimeError("parallel connect failed")
                            with other_origin.accept()[0] as remote:
                                remote.settimeout(8)
                                received=bytearray()
                                while len(received)<5:
                                    part=remote.recv(5-len(received))
                                    if not part: raise RuntimeError("parallel upload truncated")
                                    received+=part
                                if received!=b"hello": raise RuntimeError("parallel upload mismatch")
                                remote.sendall(b"world")
                                received.clear()
                                while len(received)<5:
                                    part=other.recv(5-len(received))
                                    if not part: raise RuntimeError("parallel reply truncated")
                                    received+=part
                                if received!=b"world": raise RuntimeError("parallel reply mismatch")
                    process.terminate()
                    process.wait(timeout=5)
                    if process.returncode!=0: raise RuntimeError(f"backpressure stop exit {process.returncode}")
                    client.settimeout(5)
                    try:
                        while client.recv(4096): pass
                    except ConnectionResetError:
                        pass
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stderr.close()


def vless_block(directory, upstream_port):
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    (directory / "deny.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
    config = directory / "blocked-vless.kdl"
    config.write_text(f'''schema-version 1
role "client"
workers {PROXY_WORKERS}
inbound "local" type="mixed" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={upstream_port}
  authentication {{ uuid-file "{directory / 'user.uuid'}"; }}
  tls {{ server-name "server.example"; ca-file "{directory / 'root.pem'}"; verify #true; }}
}}
routing {{ rule-set "deny" path="deny.kdl" format="kdl"; rules {{ - kind="rule-set" value="deny" outbound="reject"; }}; default-outbound "edge"; }}
''')
    process = subprocess.Popen([NEXUS, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline: raise
                time.sleep(0.05)
        with client:
            client.settimeout(5)
            client.sendall(b"\x05\x01\x00")
            if client.recv(2) != b"\x05\x00": raise RuntimeError("blocked greeting failed")
            client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
            response = bytearray()
            while len(response) < 10:
                data = client.recv(10-len(response))
                if not data: raise RuntimeError("truncated blocked response")
                response += data
            if response[:2] != b"\x05\x02": raise RuntimeError(f"VLESS policy bypass: {response!r}")
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stderr.close()
    if process.returncode != 0: raise RuntimeError("blocked VLESS proxy did not stop cleanly")
