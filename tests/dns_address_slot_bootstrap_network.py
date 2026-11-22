#!/usr/bin/env python3
"""TCP and SS UDP evaluate via named bootstrap, including active shutdown."""
import base64
import pathlib
import struct
import sys
import tempfile
import time
from dns_rule_support import DnsPeer, Echo, connect, datagram_request, exact, free_port, nexus_process, ss_client, stream_request

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-address-slot-') as directory, DnsPeer() as bootstrap, DnsPeer() as upstream, Echo() as origin:
    root = pathlib.Path(directory)
    front, ss_port = free_port(), free_port()
    while ss_port == front:
        ss_port = free_port()
    key = bytes(range(16)); key_path = root / 'key'
    key_path.write_text(base64.b64encode(key).decode()); key_path.chmod(0o600)
    bootstrap.drop.add(('stall.bootstrap.test', 1))
    config = root / 'config.kdl'
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_path}"; }} }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{ server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.port};
 server "named" type="udp" host="dns.bootstrap.test" port={upstream.port} domain-resolver="bootstrap";
 server "stalled" type="udp" host="stall.bootstrap.test" port={upstream.port} domain-resolver="bootstrap";
 rule domain-suffix="stop.test" action="evaluate" server="stalled" tag="wait" timeout-ms=8000;
 rule domain-suffix="ok.test" action="evaluate" server="named" tag="selected";
 rule match-response="selected" action="respond";
 rule action="route" server="bootstrap";
 strategy "ipv4_only"; disable-cache #true;
}}
''')
    with nexus_process(str(binary), str(config), 2), ss_client(root, ss_port, key) as ss_udp:
        stream_request(front, origin.port, 'tcp.ok.test')
        datagram_request(*ss_udp, origin.port, 'udp.ok.test')
        if bootstrap.count('dns.bootstrap.test', 1) < 2 or not upstream.count('tcp.ok.test', 1) or not upstream.count('udp.ok.test', 1):
            raise RuntimeError('named evaluate did not use the expected bootstrap and upstream')
    for kind in ('tcp', 'ss-udp'):
        with nexus_process(str(binary), str(config), 2) as process, ss_client(root, ss_port, key) as ss_udp:
            before = bootstrap.count('stall.bootstrap.test', 1)
            if kind == 'tcp':
                client = connect(front)
                client.sendall(b'\x05\x01\x00')
                if exact(client, 2) != b'\x05\x00':
                    raise RuntimeError('SOCKS greeting failed')
                name = b'tcp.stop.test'
                client.sendall(b'\x05\x01\x00\x03' + bytes([len(name)]) + name + struct.pack('!H', origin.port))
            else:
                client, relay = ss_udp
                name = b'udp.stop.test'
                client.sendto(b'\0\0\0\x03' + bytes([len(name)]) + name + struct.pack('!H', origin.port) + b'pending', relay)
            until = time.monotonic() + 3
            while bootstrap.count('stall.bootstrap.test', 1) == before:
                if time.monotonic() >= until:
                    raise RuntimeError(f'{kind}: bootstrap did not start')
                time.sleep(.01)
            start = time.monotonic(); process.terminate(); process.wait(timeout=3)
            if time.monotonic() - start > 2:
                raise RuntimeError(f'{kind}: pending bootstrap did not drain')
            if kind == 'tcp':
                client.close()
print('TCP/SS UDP independent response lookup: named bootstrap, response and active shutdown passed')
