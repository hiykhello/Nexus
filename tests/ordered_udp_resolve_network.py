import sys
import socket
import struct
import time
import tempfile
from pathlib import Path
from dns_rule_support import DnsPeer, Echo, connect, datagram_request, exact, free_port, nexus_process, udp_client


def main(binary):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as echo:
        root=Path(directory)
        front=free_port()
        (root/'loopback.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.0/8"\n')
        config=root/'config.kdl'
        config.write_text(f'''schema-version 1
role "client"
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{
    rulesets {{ "loopback" path="loopback.kdl" format="kdl"; }}
    tcp-program sniff-timeout-ms=100 unknown="pause" udp=#true {{
        rule action="resolve"
        rule action="route" rule-set="loopback" outbound="direct"
        rule action="reject"
    }}
    final "direct"
}}
''')
        dns.drop.add(('pending.example',1))
        with nexus_process(binary,str(config)):
            with udp_client(front) as (client,relay):
                datagram_request(client,relay,echo.port,'allowed.example')
                assert dns.count('allowed.example',1)==1, dns.seen
                assert echo.received.count(b'question-datagram')==1, echo.received
            with connect(front) as control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.bind(('127.0.0.1',0));control.sendall(b'\x05\x01\x00');assert exact(control,2)==b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',client.getsockname()[1]))
                reply=exact(control,10);assert reply[:2]==b'\x05\x00'
                relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
                raw=b'pending.example';client.sendto(b'\x00\x00\x00\x03'+bytes([len(raw)])+raw+struct.pack('!H',echo.port)+b'pending',relay)
                deadline=time.monotonic()+3
                while not dns.count('pending.example',1) and time.monotonic()<deadline: time.sleep(.01)
                assert dns.count('pending.example',1)==1,dns.seen
            with udp_client(front) as (client,relay):
                datagram_request(client,relay,echo.port,'after.example')
            assert dns.count('after.example',1)==1,dns.seen
        print('ordered UDP resolve candidate, single lookup and pending cancellation passed')


if __name__=='__main__': main(sys.argv[1])
