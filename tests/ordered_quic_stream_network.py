"""Fragmented QUIC Initial over Trojan UDP framing."""
import hashlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from dns_rule_support import exact, free_port, nexus_process


def main(binary, fixture, protocol=False):
    data = subprocess.run([fixture, '--fragments'], check=True, capture_output=True).stdout
    length = int.from_bytes(data[:2], 'big'); first = data[2:2+length]; data = data[2+length:]
    length = int.from_bytes(data[:2], 'big'); second = data[2:2+length]
    if len(second) != length or len(data) != length+2: raise RuntimeError('invalid fixture')
    with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        root=Path(directory); port=free_port()
        origin.bind(('127.0.0.1',0)); other.bind(('127.0.0.1',0)); origin.settimeout(.4); other.settimeout(3)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),
                        '-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (root/'key').chmod(0o600);(root/'password').write_text('secret');(root/'password').chmod(0o600)
        predicate = 'type="protocol" value="quic"' if protocol else 'type="domain" value="example.com"'
        (root/'rule.kdl').write_text(f'schema-version 2\nkind "predicate"\nrule {predicate}\n')
        (root/'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "trojan" type="trojan" {{ listen host="127.0.0.1" port={port}; authentication {{ user "bob" password-file="{root/'password'}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; }}
outbound "direct" type="direct"
routing {{ rule-set "blocked" path="rule.kdl" format="kdl"; tcp-program sniff-timeout-ms=300 unknown="skip" udp=#true {{ rule action="sniff"; rule action="reject" rule-set="blocked" domain-source="sniffed"; rule action="route" outbound="direct"; }}; default-outbound "direct"; }}
''')
        def frame(sock,payload):
            return b'\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!HH',sock.getsockname()[1],len(payload))+b'\r\n'+payload
        with nexus_process(binary,str(root/'config.kdl')):
            context=ssl.create_default_context(cafile=str(root/'cert'))
            with context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as client:
                client.settimeout(4)
                auth=hashlib.sha224(b'secret').hexdigest().encode()
                client.sendall(auth+b'\r\n\x03\x01\x00\x00\x00\x00\x00\x00\r\n'+frame(origin,first)+frame(other,b'interleaved')+frame(origin,second))
                packet, peer=other.recvfrom(4096)
                if packet!=b'interleaved':raise RuntimeError('interleaved packet lost')
                other.sendto(packet,peer)
                reply=exact(client,1+4+2+2+2+len(packet))
                if reply!=frame(other,packet):raise RuntimeError('interleaved reply mismatch')
                try:
                    packet,_=origin.recvfrom(4096);raise RuntimeError(f'rejected fragment forwarded: {len(packet)}')
                except TimeoutError:pass
                client.sendall(frame(origin,first));origin.settimeout(3)
                packet,peer=origin.recvfrom(4096)
                if packet!=first:raise RuntimeError('timeout replay changed packet')
                origin.sendto(packet,peer)
                if exact(client,1+4+2+2+2+len(packet))!=frame(origin,packet):raise RuntimeError('timeout reply mismatch')
        config=root/'config.kdl'
        config.write_text(config.read_text().replace('rule action="reject" rule-set="blocked" domain-source="sniffed"',
                                                     'rule action="route" rule-set="blocked" domain-source="sniffed" outbound="direct"'))
        with nexus_process(binary,str(config)):
            context=ssl.create_default_context(cafile=str(root/'cert'))
            with context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as client:
                auth=hashlib.sha224(b'secret').hexdigest().encode()
                client.sendall(auth+b'\r\n\x03\x01\x00\x00\x00\x00\x00\x00\r\n'+frame(origin,first)+frame(origin,second))
                received=[origin.recvfrom(4096)[0],origin.recvfrom(4096)[0]]
                if received!=[first,second]:raise RuntimeError('accepted fragments lost or reordered')
    print('Trojan UDP fragmented QUIC reject, interleaved packet and timeout replay passed')


if __name__=='__main__':main(sys.argv[1],sys.argv[2],"--protocol" in sys.argv[3:])
