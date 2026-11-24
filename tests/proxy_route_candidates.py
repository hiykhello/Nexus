#!/usr/bin/env python3
"""Exercise address-by-address routing and retry using a local DNS fixture."""
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise AssertionError("unexpected EOF")
        data += part
    return data


def scenario(root, workers, rules, expected, queries, direct_first=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as target, socket.socket() as reserved:
        dns.bind(("127.0.0.1", 0))
        dns.settimeout(.2)
        target.bind(("127.0.0.1", 0))
        target.listen(2)
        target.settimeout(.5)
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        reserved.close()
        stop = threading.Event()
        received = []
        def answer():
            while not stop.is_set():
                try:
                    packet, peer = dns.recvfrom(4096)
                except TimeoutError:
                    continue
                received.append(packet)
                response = packet[:2] + b"\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" + packet[12:]
                for last in (2, 1):
                    response += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00" + bytes([last])
                dns.sendto(response, peer)
        worker = threading.Thread(target=answer)
        worker.start()
        (root / "rules.kdl").write_text('schema-version 2\nkind "predicate"\n' + rules)
        (root / "direct.kdl").write_text(f'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.{direct_first or 1}/32"\n')
        direct_set = 'rule-set "allow" path="direct.kdl" format="kdl"; ' if direct_first else ''
        direct_rule = '- kind="rule-set" value="allow" outbound="direct"; ' if direct_first else ''
        config = root / "config.kdl"
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }} }}
outbounds {{ direct "direct"; block "reject"; }}
dns {{ servers {{ udp "local" host="127.0.0.1" port={dns.getsockname()[1]}; }}; strategy "ipv4_only"; disable-cache #true; }}
routing {{ {direct_set} rule-set "blocked" path="rules.kdl" format="kdl"; rules {{ {direct_rule} - kind="rule-set" value="blocked" outbound="reject"; }}; default-outbound "direct"; }}
''')
        proc = subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while True:
                if proc.poll() is not None: raise AssertionError(proc.stderr.read().decode())
                try:
                    client=socket.create_connection(("127.0.0.1",port),timeout=.2)
                    break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(5)
                client.sendall(b"\x05\x01\x00")
                assert exact(client,2)==b"\x05\x00"
                name=b"candidate.test"
                client.sendall(b"\x05\x01\x00\x03"+bytes([len(name)])+name+target.getsockname()[1].to_bytes(2,"big"))
                response=exact(client,10)
                assert response[1]==expected, response
                if expected==0:
                    with target.accept()[0] as peer:
                        client.sendall(b"ping")
                        assert exact(peer,4)==b"ping"
                        peer.sendall(b"pong")
                        assert exact(client,4)==b"pong"
                else:
                    try: target.accept()[0].close()
                    except TimeoutError: pass
                    else: raise AssertionError("blocked target was dialed")
            assert len(received)==queries, len(received)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            stop.set()
            worker.join(timeout=2)
            if proc.returncode and sys.exc_info()[0] is None:
                raise AssertionError(proc.stderr.read().decode())
            proc.stderr.close()


with tempfile.TemporaryDirectory(prefix="nexus-route-candidates-") as tmp:
    root=pathlib.Path(tmp)
    for workers in (1,2):
        scenario(root,workers,'rule type="ip-cidr" value="192.0.2.0/24"\n',0,1)
        scenario(root,workers,'rule type="ip-cidr" value="127.0.0.2/32"\n',0,1)
        scenario(root,workers,'rule type="ip-cidr" value="127.0.0.0/8"\n',2,1)
        scenario(root,workers,'rule type="domain-suffix" value="candidate.test"\n',2,0)
        scenario(root,workers,'rule type="domain-suffix" value="candidate.test"\n',0,1,direct_first=1)
        scenario(root,workers,'rule type="domain-suffix" value="candidate.test"\n',5,1,direct_first=2)
print("DNS candidate retry, filtering and pre-resolution blocking passed")
