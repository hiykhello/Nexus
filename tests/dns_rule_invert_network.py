#!/usr/bin/env python3
"""Exercise whole-condition DNS inversion at real TCP and UDP ingress."""
import contextlib
import base64
import pathlib
import socket
import struct
import sys
import tempfile
from dns_rule_support import DnsPeer, Echo, datagram_request, exact, free_port, nexus_process, ss_client

binary=pathlib.Path(sys.argv[1]).resolve()
use_ss='--ss' in sys.argv[2:]

@contextlib.contextmanager
def client(port,user=None):
    with socket.create_connection(('127.0.0.1',port),timeout=3) as sock:
        sock.settimeout(3)
        method=2 if user else 0
        sock.sendall(bytes([5,1,method]))
        if exact(sock,2)!=bytes([5,method]): raise RuntimeError('SOCKS method')
        if user:
            raw=user.encode(); sock.sendall(bytes([1,len(raw)])+raw+b'\x06secret')
            if exact(sock,2)!=b'\x01\x00': raise RuntimeError('SOCKS auth')
        yield sock

def stream(port,origin,name,accepted,user=None):
    with client(port,user) as sock:
        raw=name.encode();sock.sendall(b'\x05\x01\x00\x03'+bytes([len(raw)])+raw+struct.pack('!H',origin))
        reply=exact(sock,4)
        if reply[1]!=(0 if accepted else 2): raise RuntimeError(f'{name} unexpected status {reply!r}')
        exact(sock,6 if reply[3]==1 else 18)
        if accepted:
            sock.sendall(b'invert');
            if exact(sock,6)!=b'invert': raise RuntimeError('echo')

@contextlib.contextmanager
def association(port,user=None):
    with client(port,user) as sock:
        sock.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x00')
        reply=exact(sock,10)
        if reply[:4]!=b'\x05\x00\x00\x01': raise RuntimeError('association')
        yield socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big')

for workers in (1,2):
    with tempfile.TemporaryDirectory(prefix='nexus-invert-') as tmp,DnsPeer() as dns,Echo() as origin:
        root=pathlib.Path(tmp); password=root/'password';password.write_text('secret\n');password.chmod(0o600)
        ports=[free_port() for _ in range(4)]; config=root/'config.kdl'
        key=bytes(range(16));keyfile=root/'key';keyfile.write_text(base64.b64encode(key).decode()+'\n');keyfile.chmod(0o600)
        ss=f' shadowsocks "ss" {{ listen host="127.0.0.1" port={ports[3]}; method "2022-blake3-aes-128-gcm"; key-file "{keyfile}"; }}' if use_ss else ''
        config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{
 mixed "anonymous" {{ listen host="127.0.0.1" port={ports[0]}; authentication "none"; }}
 socks5 "alice" {{ listen host="127.0.0.1" port={ports[1]}; authentication "password" username="alice" password-file="{password}"; }}
 socks5 "bob" {{ listen host="127.0.0.1" port={ports[2]}; authentication "password" username="bob" password-file="{password}"; }}
 {ss}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{
 server "first" type="udp" host="127.0.0.1" port={dns.port}
 rule domain="protected.test" auth-user="alice" invert=#true action="reject"
 rule action="route-options" disable-cache=#true
 rule action="route" server="first"
 strategy "ipv4_only"
}}
''')
        with nexus_process(binary,config,4 if use_ss else 3):
            for port,user,accepted in ((ports[0],None,True),(ports[1],'alice',True),(ports[2],'bob',False)):
                stream(port,origin.port,'protected.test',accepted,user)
                with association(port,user) as relay, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    datagram_request(udp,relay,origin.port,'protected.test',accepted)
            before=dns.count('outside.test',1)
            stream(ports[0],origin.port,'outside.test',False)
            if dns.count('outside.test',1)!=before: raise RuntimeError('inverted domain reached DNS')
            if use_ss:
                with ss_client(root,ports[3],key) as (udp,relay):
                    datagram_request(udp,relay,origin.port,'protected.test',True)
                    datagram_request(udp,relay,origin.port,'outside.test',False)
        print(f'DNS invert TCP/UDP identity and domain passed workers={workers} ss={use_ss}')
