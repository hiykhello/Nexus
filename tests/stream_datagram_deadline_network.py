"""Trojan UDP queued frames keep their original budget across a blocked DNS query."""
import argparse
import hashlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Works both from tests/ after integration and the isolated candidate directory.
for parent in Path(__file__).resolve().parents:
    if (parent/'tests/dns_rule_support.py').is_file():
        sys.path.insert(0,str(parent/'tests'))
        break
from dns_rule_support import DnsPeer, exact, free_port, nexus_process


def frame(name, port, payload):
    if name is None:
        address=b'\x01'+socket.inet_aton('127.0.0.1')
    else:
        encoded=name.encode();address=b'\x03'+bytes([len(encoded)])+encoded
    return address+struct.pack('!HH',port,len(payload))+b'\r\n'+payload


def exercise(binary, ordered):
    with tempfile.TemporaryDirectory(prefix='nexus-stream-deadline-') as temporary, DnsPeer() as dns, \
            socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as origin:
        root=Path(temporary);front=free_port();origin.bind(('127.0.0.1',0));origin.settimeout(.1)
        dns.drop.update({('held.example',1),('queued.example',1)})
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),
                        '-out',str(root/'cert'),'-days','1','-subj','/CN=localhost'],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (root/'key').chmod(0o600);(root/'password').write_text('secret');(root/'password').chmod(0o600)
        program='tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true { rule action="resolve"; rule action="route" outbound="direct"; };' if ordered else ''
        config=root/'config.kdl'
        config.write_text(f'''schema-version 1
role "server"
inbound "trojan" type="trojan" {{ listen host="127.0.0.1" port={front}; authentication {{ user "bob" password-file="{root/'password'}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; }}
outbound "direct" type="direct"
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{ {program} final "direct"; }}
''')
        with nexus_process(binary,str(config)):
            context=ssl.create_default_context(cafile=str(root/'cert'))
            with context.wrap_socket(socket.create_connection(('127.0.0.1',front),timeout=5),server_hostname='localhost') as client:
                client.settimeout(3)
                auth=hashlib.sha224(b'secret').hexdigest().encode()+b'\r\n\x03\x01'+bytes(6)+b'\r\n'
                # One TLS write makes both complete frames available to the same
                # decoder turn before the first domain resolution suspends.
                started=time.monotonic()
                client.sendall(auth+frame('held.example',origin.getsockname()[1],b'held')+
                               frame('queued.example',origin.getsockname()[1],b'expired'))
                limit=time.monotonic()+3
                while not dns.count('held.example',1):
                    if time.monotonic()>=limit:raise RuntimeError('first DNS query never started')
                    time.sleep(.01)
                while time.monotonic()-started<10.8:
                    try:
                        packet,_=origin.recvfrom(1024)
                        raise RuntimeError(f'expired frame reached target: {packet!r}')
                    except TimeoutError:pass
                # Adjacent accepted frames can differ by microseconds. A query
                # begun in that tiny remaining interval is legal; it must not
                # keep the fresh packet queued behind a new ten-second wait.
                queued_queries=dns.count('queued.example',1)
                client.sendall(frame(None,origin.getsockname()[1],b'fresh'))
                origin.settimeout(3);packet,peer=origin.recvfrom(1024)
                if packet!=b'fresh':raise RuntimeError(f'fresh frame did not recover association: {packet!r}')
                origin.sendto(packet,peer)
                if exact(client,1)!=b'\x01' or exact(client,4)!=socket.inet_aton('127.0.0.1'):
                    raise RuntimeError('reply address')
                if int.from_bytes(exact(client,2),'big')!=origin.getsockname()[1]:raise RuntimeError('reply port')
                length=int.from_bytes(exact(client,2),'big')
                if exact(client,2)!=b'\r\n' or exact(client,length)!=b'fresh':raise RuntimeError('reply payload')
                if dns.count('queued.example',1)!=queued_queries:raise RuntimeError('expired queued frame queried after recovery')
        print(f'Trojan UDP ordered={ordered}: queued original deadline, no renewed wait/late send, fresh frame recovery and clean stop passed')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary',type=Path)
    parser.add_argument('--ordered',action='store_true')
    args=parser.parse_args();exercise(str(args.binary.resolve()),args.ordered)
