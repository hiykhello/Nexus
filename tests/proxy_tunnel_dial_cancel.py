#!/usr/bin/env python3
"""Verify cancellation and ordinary retry of VLESS and SS-2022 candidates."""
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part:
            raise AssertionError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def pending(pid, port):
    owned=set()
    for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir():
        try: name=str(fd.readlink())
        except FileNotFoundError: continue
        if name.startswith('socket:['): owned.add(name[8:-1])
    destination=f'0200007F:{port:04X}'
    return sum(parts[2]==destination and parts[3]=='02' and parts[9] in owned
               for parts in (line.split() for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]))


def scenario(root, workers, shadowsocks, retry=False):
    with socket.socket() as first, socket.socket() as second, socket.socket() as reservation, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        first.bind(('127.0.0.2', 0)); first.listen(1 if shadowsocks else 2); first.settimeout(4)
        fillers=[socket.create_connection(first.getsockname(),timeout=2) for _ in range(2)] if shadowsocks and not retry else []
        second.bind(('127.0.0.1', first.getsockname()[1])); second.listen(2); second.settimeout(.7)
        reservation.bind(('127.0.0.1', 0)); port=reservation.getsockname()[1]; reservation.close()
        dns.bind(('127.0.0.1', 0)); dns.settimeout(.1)
        done=threading.Event(); queries=[]
        def answer():
            while not done.is_set():
                try: packet, peer=dns.recvfrom(4096)
                except TimeoutError: continue
                queries.append(packet)
                prefix=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00'
                dns.sendto(packet[:2]+b'\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00'+packet[12:]+prefix+b'\x02'+prefix+b'\x01',peer)
        thread=threading.Thread(target=answer); thread.start()
        config=root/'proxy.kdl'
        outbound=(f'outbound "edge" type="shadowsocks" {{ bootstrap-resolver "boot"; server host="edge.test" port={first.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root / "ss.key"}"; }}' if shadowsocks else
                  f'outbound "edge" type="vless" {{ bootstrap-resolver "boot"; server host="edge.test" port={first.getsockname()[1]}; authentication {{ uuid-file "{root / "user.uuid"}"; }}; tls {{ server-name "localhost"; ca-file "{root / "cert.pem"}"; verify #true; }}; }}')
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
{outbound}
routing {{ default-outbound "edge"; }}
''')
        process=subprocess.Popen([binary,'run','--config',config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while True:
                if process.poll() is not None: raise AssertionError(process.stderr.read().decode())
                try: client=socket.create_connection(('127.0.0.1',port),timeout=.2); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            with client:
                client.settimeout(4); client.sendall(b'\x05\x01\x00'); assert exact(client,2)==b'\x05\x00'
                if retry and shadowsocks: first.close()
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2')
                if retry:
                    if not shadowsocks:
                        with first.accept()[0] as rejected:
                            rejected.settimeout(3)
                            header=exact(rejected,5)
                            assert header[0]==22 and exact(rejected,int.from_bytes(header[3:5],'big'))[0]==1
                    second.settimeout(4)
                    with second.accept()[0] as upstream:
                        upstream.settimeout(4)
                        if shadowsocks:
                            assert exact(client,10)[:2]==b'\x05\x00'
                            assert upstream.recv(1024), 'SS request was not sent to the second candidate'
                        else:
                            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            context.minimum_version=ssl.TLSVersion.TLSv1_3
                            context.load_cert_chain(root/'cert.pem',root/'key.pem')
                            with context.wrap_socket(upstream,server_side=True) as tls:
                                header=exact(tls,26)
                                assert header==b'\x00'+bytes(range(16))+b'\x00\x01\x04\xd2\x01\x7f\x00\x00\x01'
                                tls.sendall(b'\x00\x00')
                                assert exact(client,10)[:2]==b'\x05\x00'
                                client.sendall(b'ping'); assert exact(tls,4)==b'ping'
                                tls.sendall(b'pong'); assert exact(client,4)==b'pong'
                elif shadowsocks:
                    deadline=time.monotonic()+3
                    while not pending(process.pid,first.getsockname()[1]):
                        if time.monotonic()>=deadline: raise AssertionError('first SS candidate did not become pending')
                        time.sleep(.01)
                    client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); client.close()
                    deadline=time.monotonic()+3
                    while pending(process.pid,first.getsockname()[1]):
                        if time.monotonic()>=deadline: raise AssertionError('SS connect was not canceled')
                        time.sleep(.01)
                    with first.accept()[0], first.accept()[0]:
                        first.settimeout(.5)
                        try: first.accept()[0].close()
                        except TimeoutError: pass
                        else: raise AssertionError('canceled SS candidate remained queued')
                else:
                    with first.accept()[0] as upstream:
                        upstream.settimeout(3)
                        header=exact(upstream,5)
                        assert header[0]==22 and exact(upstream,int.from_bytes(header[3:5],'big'))[0]==1
                        client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); client.close()
                        assert upstream.recv(1)==b'', 'upstream handshake was not canceled'
                if not retry:
                    try: second.accept()[0].close()
                    except TimeoutError: pass
                    else: raise AssertionError('later tunnel candidate was dialed after client reset')
                assert len(queries)==1 and process.poll() is None
        finally:
            if process.poll() is None: process.terminate(); process.wait(timeout=5)
            done.set(); thread.join(timeout=2)
            for filler in fillers: filler.close()
            if process.returncode and sys.exc_info()[0] is None: raise AssertionError(process.stderr.read().decode())
            process.stderr.close()
            assert not thread.is_alive()


def overlapping_handshakes(root, workers, shadowsocks, established=False):
    with socket.socket() as first, socket.socket() as second, socket.socket() as reservation, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        pending_ss=shadowsocks and not established
        first.bind(('127.0.0.2', 0)); first.listen(1 if pending_ss else 4); first.settimeout(4)
        fillers=[socket.create_connection(first.getsockname(),timeout=2) for _ in range(2)] if pending_ss else []
        second.bind(('127.0.0.1', first.getsockname()[1])); second.listen(4); second.settimeout(.5)
        reservation.bind(('127.0.0.1', 0)); port=reservation.getsockname()[1]; reservation.close()
        dns.bind(('127.0.0.1', 0)); dns.settimeout(.1)
        done=threading.Event(); queries=[]
        def answer():
            while not done.is_set():
                try: packet, peer=dns.recvfrom(4096)
                except TimeoutError: continue
                queries.append(packet)
                record=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00'
                dns.sendto(packet[:2]+b'\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00'+packet[12:]+record+b'\x02'+record+b'\x01',peer)
        thread=threading.Thread(target=answer); thread.start()
        config=root/'overlap.kdl'
        outbound=(f'outbound "edge" type="shadowsocks" {{ bootstrap-resolver "boot"; server host="edge.test" port={first.getsockname()[1]}; method "2022-blake3-aes-128-gcm"; key-file "{root / "ss.key"}"; }}' if shadowsocks else
                  f'outbound "edge" type="vless" {{ bootstrap-resolver "boot"; server host="edge.test" port={first.getsockname()[1]}; authentication {{ uuid-file "{root / "user.uuid"}"; }}; tls {{ server-name "localhost"; ca-file "{root / "cert.pem"}"; verify #true; }}; }}')
        config.write_text(f'''schema-version 1
role "client"
workers {workers}
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.getsockname()[1]}; strategy "ipv4_only"; disable-cache #true; }}
{outbound}
routing {{ default-outbound "edge"; }}
''')
        process=subprocess.Popen([binary,'run','--config',config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        clients=[]; upstreams=[]
        try:
            for _ in range(3):
                deadline=time.monotonic()+5
                while True:
                    if process.poll() is not None: raise AssertionError(process.stderr.read().decode())
                    try: client=socket.create_connection(('127.0.0.1',port),timeout=.2); break
                    except OSError:
                        if time.monotonic()>=deadline: raise
                        time.sleep(.02)
                clients.append(client); client.settimeout(3)
                client.sendall(b'\x05\x01\x00'); assert exact(client,2)==b'\x05\x00'
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2')
                if not pending_ss:
                    upstream=first.accept()[0]; upstream.settimeout(3); upstreams.append(upstream)
                    if shadowsocks:
                        assert upstream.recv(1024), 'SS request was not sent'
                        assert exact(client,10)[:2]==b'\x05\x00'
                    else:
                        header=exact(upstream,5)
                        assert header[0]==22 and exact(upstream,int.from_bytes(header[3:5],'big'))[0]==1
            if pending_ss:
                deadline=time.monotonic()+3
                while pending(process.pid,first.getsockname()[1])!=3:
                    if process.poll() is not None or time.monotonic()>=deadline: raise AssertionError('SS connections did not all become pending')
                    time.sleep(.01)
            assert len(queries)==3
            clients[0].setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); clients[0].close()
            if pending_ss:
                deadline=time.monotonic()+3
                while pending(process.pid,first.getsockname()[1])!=2:
                    if process.poll() is not None or time.monotonic()>=deadline: raise AssertionError('reset did not cancel only its SS connection')
                    time.sleep(.01)
            else:
                if shadowsocks:
                    while upstreams[0].recv(1024): pass
                else:
                    assert upstreams[0].recv(1)==b'', 'reset did not cancel its handshake'
            for upstream in upstreams[1:]:
                upstream.settimeout(.1)
                try:
                    while upstream.recv(1024): pass
                except TimeoutError: pass
                else: raise AssertionError('another tunnel stopped early')
            process.terminate(); process.wait(timeout=5)
            for upstream in upstreams[1:]:
                upstream.settimeout(2)
                while upstream.recv(1024): pass
            for client in clients[1:]:
                client.settimeout(2); assert client.recv(1)==b'', 'stop did not close inbound client'
            if pending_ss:
                with first.accept()[0], first.accept()[0]:
                    first.settimeout(.5)
                    try: first.accept()[0].close()
                    except TimeoutError: pass
                    else: raise AssertionError('canceled SS connection remained queued')
            try: second.accept()[0].close()
            except TimeoutError: pass
            else: raise AssertionError('later tunnel candidate was dialed after stop')
            assert process.returncode==0
        finally:
            if process.poll() is None: process.terminate(); process.wait(timeout=5)
            done.set(); thread.join(timeout=2)
            for sock in clients+upstreams+fillers: sock.close()
            if process.returncode and sys.exc_info()[0] is None: raise AssertionError(process.stderr.read().decode())
            process.stderr.close(); assert not thread.is_alive()


with tempfile.TemporaryDirectory(prefix='nexus-vless-dial-cancel-') as directory:
    root=pathlib.Path(directory)
    (root/'user.uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (root/'user.uuid').chmod(0o600)
    (root/'ss.key').write_text('AAAAAAAAAAAAAAAAAAAAAA==\n'); (root/'ss.key').chmod(0o600)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    shadowsocks=len(sys.argv)>2 and sys.argv[2]=='ss'
    for workers in (1,2):
        for retry in (False,True): scenario(root,workers,shadowsocks,retry)
        overlapping_handshakes(root,workers,shadowsocks)
        if shadowsocks: overlapping_handshakes(root,workers,True,established=True)
print('tunnel candidates: reset, retry and overlapping stop passed')
