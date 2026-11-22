"""Exercise DNS CLI with a controlled UDP upstream and both client transports."""
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary = Path(sys.argv[1]).resolve()
binding = ' bind-interface="lo"' if sys.argv[2:] == ["bind"] else ''
upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upstream.bind(("127.0.0.1", 0))
upstream.settimeout(5)
upstream_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
upstream_tcp.bind(upstream.getsockname())
upstream_tcp.listen(1)
upstream_tcp.settimeout(5)

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

listen, proxy = free_port(), free_port()
while proxy == listen:
    proxy = free_port()
config = f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={listen}; disable-cache #true; server "a" type="udp" host="127.0.0.1" port={upstream.getsockname()[1]}{binding}; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
query = bytes.fromhex("123401000001000000000000076578616d706c6504746573740000010001")
seen = []
errors = []
def server():
    try:
        for index in range(2):
            request, peer = upstream.recvfrom(65535)
            seen.append(request)
            if index == 1:
                truncated = bytearray(request); truncated[2:4] = b"\x83\x80"
                upstream.sendto(truncated, peer)
                connection, _ = upstream_tcp.accept()
                with connection:
                    connection.settimeout(5)
                    def read_exact(count):
                        data = b""
                        while len(data) < count:
                            part = connection.recv(count - len(data))
                            if not part: raise RuntimeError("short TCP upstream request")
                            data += part
                        return data
                    size = int.from_bytes(read_exact(2), "big")
                    tcp_request = read_exact(size)
                    assert tcp_request == request
                    response = bytearray(tcp_request); response[2:4] = b"\x81\x80"; response[7] = 1
                    response.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
                    connection.sendall(len(response).to_bytes(2, "big") + response)
                continue
            response = bytearray(request)
            response[2:4] = b"\x81\x80"
            response[7] = 1
            response.extend(bytes.fromhex("c00c000100010000003c0004c0000201"))
            wrong_id = bytearray(response); wrong_id[1] ^= 1
            upstream.sendto(wrong_id, peer)
            upstream.sendto(response, peer)
    except Exception as error:
        errors.append(error)

upstream_port = upstream.getsockname()[1]
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "config.kdl"
    path.write_text(config)
    process = subprocess.Popen([str(binary), "run", "--config", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    worker = threading.Thread(target=server)
    worker.start()
    try:
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                sock = socket.create_connection(("127.0.0.1", listen), timeout=.1)
                sock.close()
                break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("DNS listener failed to start")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            client.sendto(query, ("127.0.0.1", listen))
            response, _ = client.recvfrom(4096)
            assert response[:2] == query[:2] and response[-4:] == bytes([192, 0, 2, 1])
        with socket.create_connection(("127.0.0.1", listen), timeout=4) as client:
            client.sendall(len(query).to_bytes(2, "big") + query)
            header = client.recv(2)
            assert len(header) == 2
            length = int.from_bytes(header, "big")
            response = b""
            while len(response) < length:
                chunk = client.recv(length - len(response))
                assert chunk
                response += chunk
            assert response[:2] == query[:2] and response[-4:] == bytes([192, 0, 2, 1])
    finally:
        process.terminate()
        out, err = process.communicate(timeout=8)
        worker.join(timeout=6)
        upstream.close()
        upstream_tcp.close()
        if process.returncode:
            raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
    assert not worker.is_alive() and not errors and len(seen) == 2, errors
    assert all(request[2:] == query[2:] for request in seen)
# Keep an upstream request unanswered and stop while the query is active.
with tempfile.TemporaryDirectory() as directory:
    blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blackhole.bind(("127.0.0.1", 0))
    blackhole.settimeout(4)
    active_listen, active_proxy = free_port(), free_port()
    while active_proxy == active_listen:
        active_proxy = free_port()
    active_config = config.replace(f"port={listen}", f"port={active_listen}", 1).replace(
        f"port={upstream_port}", f"port={blackhole.getsockname()[1]}", 1).replace(
        f"port={proxy}", f"port={active_proxy}", 1)
    path = Path(directory) / "config.kdl"
    path.write_text(active_config)
    process = subprocess.Popen([str(binary), "run", "--config", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                client = socket.create_connection(("127.0.0.1", active_listen), timeout=.1)
                break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("DNS listener failed to start")
        with client:
            client.sendall(len(query).to_bytes(2, "big") + query)
            blackhole.recvfrom(65535)
            started = time.monotonic()
            process.terminate()
            out, err = process.communicate(timeout=4)
            assert process.returncode == 0, err.decode()
            assert time.monotonic() - started < 4
            client.settimeout(1)
            assert client.recv(1) == b""
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        blackhole.close()
# Resolve a domain-named upstream through a separate bootstrap server.
with tempfile.TemporaryDirectory() as directory:
    bootstrap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bootstrap.bind(("127.0.0.1", 0)); target.bind(("127.0.0.1", 0))
    bootstrap.settimeout(5); target.settimeout(5)
    domain_listen, domain_proxy = free_port(), free_port()
    while domain_proxy == domain_listen:
        domain_proxy = free_port()
    domain_config = f'''schema-version 1
role "client"
dns {{ listen host="127.0.0.1" port={domain_listen}; server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.getsockname()[1]}{binding}; server "remote" type="udp" host="resolver.test" port={target.getsockname()[1]} domain-resolver="bootstrap"{binding}; final "remote"; }}
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={domain_proxy}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
    path = Path(directory) / "config.kdl";path.write_text(domain_config)
    process = subprocess.Popen([str(binary), "run", "--config", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    failures = []
    def answer_domain():
        try:
            for _ in range(2):
                request, peer = bootstrap.recvfrom(65535)
                answer = bytearray(request);answer[2:4] = b"\x81\x80"
                answer[7] = 1
                if request[-4:-2] == b"\x00\x01":
                    answer.extend(bytes.fromhex("c00c000100010000003c00047f000001"))
                else:
                    answer.extend(bytes.fromhex("c00c001c00010000003c001000000000000000000000000000000001"))
                bootstrap.sendto(answer, peer)
            request, peer = target.recvfrom(65535)
            answer = bytearray(request);answer[2:4] = b"\x81\x80";answer[7] = 1
            answer.extend(bytes.fromhex("c00c000100010000003c0004c0000201"));target.sendto(answer, peer)
        except Exception as error:
            failures.append(error)
    worker = threading.Thread(target=answer_domain);worker.start()
    try:
        for _ in range(80):
            if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
            try:
                probe=socket.create_connection(("127.0.0.1", domain_listen), timeout=.1);probe.close();break
            except OSError:time.sleep(.05)
        else:raise RuntimeError("domain listener failed to start")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5);client.sendto(query,("127.0.0.1",domain_listen));answer,_=client.recvfrom(4096)
            assert answer[:2]==query[:2] and answer[-4:]==bytes([192,0,2,1]),answer.hex()
    finally:
        process.terminate();out,err=process.communicate(timeout=5);worker.join(timeout=6);bootstrap.close();target.close()
        if process.returncode:raise RuntimeError(f"exit {process.returncode}: {err.decode()}")
    assert not worker.is_alive() and not failures, failures
if binding:
    from detour_network import running

    with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(.15)
        path = Path(directory) / "config.kdl"
        missing = config.replace('bind-interface="lo"', 'bind-interface="nxdns-missing"')
        path.write_text(missing.replace(f"port={upstream_port}", f"port={peer.getsockname()[1]}", 1))
        with running([str(binary), "run", "--config", str(path)], listen, path.with_suffix(".log")):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(4)
                client.sendto(query, ("127.0.0.1", listen))
                answer = client.recv(4096)
                assert answer[:2] == query[:2] and answer[3] & 15 == 2, answer.hex()
            try:
                peer.recv(4096)
            except TimeoutError:
                pass
            else:
                raise AssertionError("invalid binding leaked the query to an unbound socket")
print(f"DNS CLI UDP/TCP upstream, bootstrap and active shutdown passed ({'bound' if binding else 'default'})")
