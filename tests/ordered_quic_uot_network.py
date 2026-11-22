"""Fragmented QUIC Initial over authenticated SS UoT v2."""
import base64
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from dns_rule_support import free_port, nexus_process, proxy_client, udp_client


def main(binary, fixture):
    data=subprocess.run([fixture,'--fragments'],check=True,capture_output=True).stdout
    size=int.from_bytes(data[:2],'big'); first=data[2:2+size]; data=data[2+size:]
    size=int.from_bytes(data[:2],'big'); second=data[2:2+size]
    if len(second)!=size or len(data)!=size+2:raise RuntimeError('invalid fixture')
    with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as origin, \
            socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as other:
        root=Path(directory);front=free_port();key=bytes(range(16));password=base64.b64encode(key).decode()
        (root/'key').write_text(password);(root/'key').chmod(0o600)
        (root/'rule.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="example.com"\n')
        (root/'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct"
routing {{ rule-set "blocked" path="rule.kdl" format="kdl"; tcp-program sniff-timeout-ms=300 unknown="skip" udp=#true {{ rule action="sniff"; rule action="reject" rule-set="blocked" domain-source="sniffed"; rule action="route" outbound="direct"; }}; default-outbound "direct"; }}
''')
        origin.bind(('127.0.0.1',0));other.bind(('127.0.0.1',0));origin.settimeout(.4);other.settimeout(3)
        def header(sock):return b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',sock.getsockname()[1])
        outbound={'type':'shadowsocks','server':'127.0.0.1','server_port':front,'method':'2022-blake3-aes-128-gcm',
                  'password':password,'udp_over_tcp':{'enabled':True,'version':2}}
        with nexus_process(binary,str(root/'config.kdl')), proxy_client(root,outbound) as proxy, udp_client(proxy) as (client,relay):
            client.sendto(header(origin)+first,relay);client.sendto(header(other)+b'interleaved',relay);client.sendto(header(origin)+second,relay)
            packet,peer=other.recvfrom(4096)
            if packet!=b'interleaved':raise RuntimeError('interleaved packet lost')
            other.sendto(packet,peer);client.settimeout(3)
            reply,_=client.recvfrom(4096)
            if reply!=header(other)+packet:raise RuntimeError('interleaved reply mismatch')
            try:
                packet,_=origin.recvfrom(4096);raise RuntimeError(f'rejected fragment forwarded: {len(packet)}')
            except TimeoutError:pass
            client.sendto(header(origin)+first,relay);origin.settimeout(3)
            packet,peer=origin.recvfrom(4096)
            if packet!=first:raise RuntimeError('timeout replay changed packet')
            origin.sendto(packet,peer);reply,_=client.recvfrom(4096)
            if reply!=header(origin)+packet:raise RuntimeError('timeout reply mismatch')
    print('SS UoT v2 fragmented QUIC reject, interleaved packet and timeout replay passed')


if __name__=='__main__':main(sys.argv[1],sys.argv[2])
