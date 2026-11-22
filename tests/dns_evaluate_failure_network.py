#!/usr/bin/env python3
"""An unsuccessful evaluate leaves its slot unknown and later rules run."""
import base64
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
from dns_rule_support import DnsPeer, Echo, connect, datagram_request, exact, free_port, nexus_process, question, ss_client, stream_request, wire_name

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-evaluate-failure-') as directory, DnsPeer() as good, DnsPeer() as bad, Echo() as origin:
    root = pathlib.Path(directory)
    original = bad.reply
    def bad_reply(packet, transport):
        name, kind, _ = question(packet)
        if name.startswith('malformed.'):
            bad.seen.append((name, kind, transport))
            return packet[:2] + b'\x81\x80'
        if name.startswith('timeout.'):
            bad.seen.append((name, kind, transport))
            return None
        return original(packet, transport)
    bad.reply = bad_reply
    front, dns_port, ss_port = free_port(), free_port(), free_port()
    while dns_port == front:
        dns_port = free_port()
    while ss_port in (front, dns_port):
        ss_port = free_port()
    key = bytes(range(16));key_path = root / 'key'
    key_path.write_text(base64.b64encode(key).decode());key_path.chmod(0o600)
    config = root / 'config.kdl'
    config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
 shadowsocks "ss" {{ listen host="127.0.0.1" port={ss_port}; method "2022-blake3-aes-128-gcm"; key-file "{key_path}"; }} }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
dns {{ listen host="127.0.0.1" port={dns_port};
 server "good" type="udp" host="127.0.0.1" port={good.port};
 server "bad" type="udp" host="127.0.0.1" port={bad.port};
 server "named-bad" type="udp" host="malformed.bootstrap.test" port=53 domain-resolver="bad";
 rule domain="timeout.stop.test" action="evaluate" server="bad" timeout-ms=8000;
 rule domain="bootstrap.test" action="evaluate" server="named-bad" tag="bootstrap" timeout-ms=120;
 rule match-response="bootstrap" invert=#true action="reject";
 rule domain-suffix="tag.test" action="evaluate" server="good" tag="saved";
 rule domain-suffix="tag.test" action="evaluate" server="bad" tag="failed" timeout-ms=120;
 rule match-response="failed" invert=#true action="reject";
 rule domain-suffix="tag.test" match-response="saved" action="respond";
 rule domain-suffix="anonymous.test" action="evaluate" server="good";
 rule domain-suffix="anonymous.test" action="evaluate" server="bad" timeout-ms=120;
 rule match-response=#true invert=#true action="reject";
 rule action="route" server="good";
 strategy "ipv4_only"; disable-cache #true;
}}
''')
    def ask(name, tcp):
        packet = struct.pack('!HHHHHH', 23, 0x100, 1, 0, 0, 0) + wire_name(name) + b'\0\1\0\1'
        if tcp:
            with socket.create_connection(('127.0.0.1', dns_port), timeout=3) as client:
                client.sendall(struct.pack('!H', len(packet)) + packet)
                response = exact(client, int.from_bytes(exact(client, 2), 'big'))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3);client.sendto(packet, ('127.0.0.1', dns_port));response, _ = client.recvfrom(4096)
        if response[3] & 15 or response[-4:] != socket.inet_aton('127.0.0.1'):
            raise RuntimeError(f'{name}: wrong reply {response.hex()}')
    with nexus_process(str(binary), str(config), 2), ss_client(root, ss_port, key) as ss_udp:
        for tcp in (False, True):
            before = good.count('bootstrap.test', 1)
            ask('bootstrap.test', tcp)
            if good.count('bootstrap.test', 1) != before + 1 or not bad.count('malformed.bootstrap.test', 1):
                raise RuntimeError('failed evaluate bootstrap did not continue to fallback')
            for mode in ('malformed', 'timeout'):
                for kind in ('tag', 'anonymous'):
                    name = f'{mode}.{kind}.test'
                    before = good.count(name, 1)
                    ask(name, tcp)
                    expected = 1 if kind == 'tag' else 2
                    if good.count(name, 1) - before != expected:
                        raise RuntimeError(f'{name}: saved or fallback response was not selected')
        for mode in ('malformed', 'timeout'):
            stream_request(front, origin.port, f'{mode}.tag.test')
            datagram_request(*ss_udp, origin.port, f'{mode}.anonymous.test')
        stream_request(front, origin.port, 'healthy.test')
    with nexus_process(str(binary), str(config), 2) as process, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        packet = struct.pack('!HHHHHH', 24, 0x100, 1, 0, 0, 0) + wire_name('timeout.stop.test') + b'\0\1\0\1'
        client.sendto(packet, ('127.0.0.1', dns_port))
        until = time.monotonic() + 3
        while not bad.count('timeout.stop.test', 1):
            if time.monotonic() >= until:
                raise RuntimeError('pending evaluate did not start')
            time.sleep(.01)
        start=time.monotonic();process.terminate();process.wait(timeout=3)
        if time.monotonic()-start>2:
            raise RuntimeError('shutdown did not cancel pending evaluate promptly')
    with nexus_process(str(binary), str(config), 2) as process, connect(front) as client:
        client.sendall(b'\x05\x01\x00')
        if exact(client, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS handshake failed')
        name=b'timeout.stop.test';before=bad.count(name.decode(), 1)
        client.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H', origin.port))
        until = time.monotonic() + 3
        while bad.count(name.decode(), 1)==before:
            if time.monotonic() >= until:
                raise RuntimeError('pending proxy evaluate did not start')
            time.sleep(.01)
        start=time.monotonic();process.terminate();process.wait(timeout=3)
        if time.monotonic()-start>2:
            raise RuntimeError('shutdown did not cancel pending proxy evaluate promptly')
print('failed evaluate preserves earlier tags, clears anonymous result, continues and recovers over DNS/TCP/SS UDP')
