"""Fragmented QUIC Initial routing, interleaved UDP, and replay."""
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from dns_rule_support import free_port, nexus_process, udp_client


def main(binary, fixture):
    data = subprocess.run([fixture, '--fragments'], check=True, capture_output=True).stdout
    size = int.from_bytes(data[:2], 'big'); first = data[2:2+size]; data = data[2+size:]
    size = int.from_bytes(data[:2], 'big'); second = data[2:2+size]
    if len(second) != size or len(data) != size + 2: raise RuntimeError('invalid fragment fixture')
    with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        root = Path(directory); front = free_port()
        origin.bind(('127.0.0.1', 0)); other.bind(('127.0.0.1', 0))
        origin.settimeout(.35); other.settimeout(3)
        (root/'block.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="example.com"\n')
        config=root/'config.kdl'
        config.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
routing {{ rule-set "block" path="block.kdl" format="kdl"; tcp-program sniff-timeout-ms=300 unknown="skip" udp=#true {{ rule action="sniff"; rule action="reject" rule-set="block" domain-source="sniffed"; rule action="route" outbound="direct"; }}; default-outbound "direct"; }}
''')
        def header(sock): return b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', sock.getsockname()[1])
        with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
            client.sendto(header(origin)+first, relay)
            client.sendto(header(other)+b'interleaved', relay)
            client.sendto(header(origin)+second, relay)
            data, peer = other.recvfrom(4096)
            if data != b'interleaved': raise RuntimeError('interleaved datagram lost')
            other.sendto(data, peer)
            client.settimeout(3); response, _ = client.recvfrom(4096)
            if response != header(other)+data: raise RuntimeError('interleaved reply mismatch')
            try:
                data, _ = origin.recvfrom(4096)
                raise RuntimeError(f'rejected fragment forwarded: {len(data)} bytes')
            except TimeoutError: pass
            # A new incomplete flow times out and replays the original packet.
            client.sendto(header(origin)+first, relay)
            origin.settimeout(3); data, peer = origin.recvfrom(4096)
            if data != first: raise RuntimeError('timeout replay changed packet')
            origin.sendto(data, peer); response, _ = client.recvfrom(4096)
            if response != header(origin)+first: raise RuntimeError('timeout replay reply mismatch')
        config.write_text(config.read_text().replace('rule action="reject" rule-set="block" domain-source="sniffed"',
                                                     'rule action="route" rule-set="block" domain-source="sniffed" outbound="direct"'))
        with nexus_process(binary, str(config)), udp_client(front) as (client, relay):
            client.sendto(header(origin)+first, relay); client.sendto(header(origin)+second, relay)
            received = [origin.recvfrom(4096)[0], origin.recvfrom(4096)[0]]
            if received != [first, second]: raise RuntimeError('accepted fragments were not replayed in order')
    print('SOCKS UDP QUIC fragmented rejection, interleaved packet and timeout replay passed')


if __name__ == '__main__': main(sys.argv[1], sys.argv[2])
