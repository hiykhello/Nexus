"""Exercise the owned TUN driver across two disposable network namespaces."""
import os
import json
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time


def checksum(data):
    if len(data) & 1: data += b'\0'
    total = sum(struct.unpack(f'!{len(data)//2}H', data))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def unknown_tcp_resets(family, source, destination):
    source_ip = socket.inet_pton(family, source)
    dest_ip = socket.inet_pton(family, destination)
    with socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_TCP) as raw:
        raw.bind((source, 0)); raw.settimeout(3)
        for port, flags, seq, ack, payload, expected in (
            (43101, 0x10, 123, 0x12345678, b'abc', (4, 0x12345678, 0)),
            (43102, 0x01, 0xfffffffe, 0, b'abc', (0x14, 0, 2)),
        ):
            header = struct.pack('!HHIIBBHHH', port, 43210, seq, ack, 0x50, flags, 8192, 0, 0)
            tcp = header + payload
            if family == socket.AF_INET:
                pseudo = source_ip + dest_ip + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp))
            else:
                pseudo = source_ip + dest_ip + struct.pack('!I3xB', len(tcp), socket.IPPROTO_TCP)
            tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
            raw.sendto(tcp, (destination, 0))
            deadline = time.monotonic() + 3
            while True:
                raw.settimeout(max(0.001, deadline - time.monotonic()))
                packet = raw.recv(65535)
                if family == socket.AF_INET:
                    packet = packet[(packet[0] & 15) * 4:]
                if len(packet) < 20: continue
                sport, dport, received_seq, received_ack, offset, received_flags, window, _, _ = struct.unpack('!HHIIBBHHH', packet[:20])
                if (sport, dport) != (43210, port): continue
                if (received_flags, received_seq, received_ack) != expected or window or len(packet) != 20 or offset != 0x50:
                    raise RuntimeError(f'invalid unknown-flow reset: {packet.hex()}')
                if family == socket.AF_INET:
                    response_pseudo = dest_ip + source_ip + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(packet))
                else:
                    response_pseudo = dest_ip + source_ip + struct.pack('!I3xB', len(packet), socket.IPPROTO_TCP)
                if checksum(response_pseudo + packet): raise RuntimeError('invalid reset checksum')
                break
        port = 43103
        tcp = struct.pack('!HHIIBBHHH', port, 43210, 123, 0, 0x50, 4, 0, 0, 0)
        if family == socket.AF_INET:
            pseudo = source_ip + dest_ip + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(tcp))
        else:
            pseudo = source_ip + dest_ip + struct.pack('!I3xB', len(tcp), socket.IPPROTO_TCP)
        tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
        raw.sendto(tcp, (destination, 0))
        deadline = time.monotonic() + 0.15
        while time.monotonic() < deadline:
            raw.settimeout(deadline - time.monotonic())
            try: packet = raw.recv(65535)
            except TimeoutError: break
            if family == socket.AF_INET: packet = packet[(packet[0] & 15) * 4:]
            if len(packet) >= 4 and struct.unpack('!HH', packet[:4]) == (43210, port):
                raise RuntimeError('received a response to a reset')

binary = str(pathlib.Path(sys.argv[1]).resolve())
if len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[2] in ('--fin-loss', '--source')):
    fin_loss = sys.argv[2:] == ['--fin-loss']
    source_test = sys.argv[2:] == ['--source']
    for link_mtu in (1280, 1500):
        subprocess.run(['unshare', '-Urn', sys.executable, __file__, binary, 'outer',
                        str(os.stat('/proc/self/ns/net').st_ino), str(link_mtu), str(int(fin_loss)), str(int(source_test))], check=True, timeout=40)
elif sys.argv[2] == 'outer':
    if os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('outer namespace was not isolated')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'addr', 'add', '10.77.0.2/32', 'dev', 'lo'], check=True)
    subprocess.run(['ip', '-6', 'addr', 'add', 'fd77::2/128', 'dev', 'lo', 'nodad'], check=True)
    for command in (
        ['ip', 'addr', 'add', '10.77.0.3/32', 'dev', 'lo'],
        ['ip', '-6', 'addr', 'add', 'fd77::3/128', 'dev', 'lo', 'nodad'],
        ['ip', 'route', 'add', 'local', '10.77.0.2/32', 'dev', 'lo', 'src', '10.77.0.3', 'table', '100'],
        ['ip', '-6', 'route', 'add', 'local', 'fd77::2/128', 'dev', 'lo', 'src', 'fd77::3', 'table', '100'],
        ['ip', 'rule', 'del', 'priority', '0'],
        ['ip', 'rule', 'add', 'priority', '1', 'fwmark', '42', 'lookup', '100'],
        ['ip', 'rule', 'add', 'priority', '2', 'to', '10.77.0.2/32', 'prohibit'],
        ['ip', 'rule', 'add', 'priority', '3', 'lookup', 'local'],
        ['ip', '-6', 'rule', 'del', 'priority', '0'],
        ['ip', '-6', 'rule', 'add', 'priority', '1', 'fwmark', '42', 'lookup', '100'],
        ['ip', '-6', 'rule', 'add', 'priority', '2', 'to', 'fd77::2/128', 'prohibit'],
        ['ip', '-6', 'rule', 'add', 'priority', '3', 'lookup', 'local'],
    ):
        subprocess.run(command, check=True)
    for family, destination in (([], '10.77.0.2'), (['-6'], 'fd77::2')):
        denied = subprocess.run(['ip', *family, 'route', 'get', destination], capture_output=True)
        allowed = subprocess.run(['ip', *family, 'route', 'get', destination, 'mark', '42'], capture_output=True)
        if denied.returncode == 0 or allowed.returncode != 0:
            raise RuntimeError(f'policy routes do not require mark 42 for {destination}')
    origin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    origin.bind(('10.77.0.2', 0)); origin.listen(1); origin.settimeout(12)
    origin6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    origin6.bind(('fd77::2', 0)); origin6.listen(1); origin6.settimeout(12)
    udp_origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_origin.bind(('10.77.0.2', 0)); udp_origin.settimeout(12)
    udp6_origin = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp6_origin.bind(('fd77::2', 0)); udp6_origin.settimeout(12)
    errors = []
    def upstream():
        try:
            with origin.accept()[0] as peer:
                peer.settimeout(10); data = bytearray()
                while True:
                    part = peer.recv(64)
                    if not part: break
                    data.extend(part)
                if data != b'hello': raise RuntimeError(f'unexpected TCP request {data!r}')
                peer.sendall(b'world'); peer.shutdown(socket.SHUT_WR)
        except Exception as exc: errors.append(exc)
    def upstream6():
        try:
            with origin6.accept()[0] as peer:
                peer.settimeout(10); data = bytearray()
                while True:
                    part = peer.recv(64)
                    if not part: break
                    data.extend(part)
                if data != b'hello6' * 1024: raise RuntimeError(f'unexpected IPv6 TCP request {data!r}')
                peer.sendall(b'world6' * 1024); peer.shutdown(socket.SHUT_WR)
        except Exception as exc: errors.append(exc)
    def udp_upstream():
        try:
            data, peer = udp_origin.recvfrom(64)
            if data != b'udp': raise RuntimeError(f'unexpected UDP request {data!r}')
            udp_origin.sendto(b'UDP', peer)
        except Exception as exc: errors.append(exc)
    def udp6_upstream():
        try:
            for request in (b'udp6', b'options', b'both', b'unknown'):
                data, peer = udp6_origin.recvfrom(64)
                if data != request: raise RuntimeError(f'unexpected IPv6 UDP request {data!r}')
                udp6_origin.sendto(b'UDP6', peer)
        except Exception as exc: errors.append(exc)
    threads = [threading.Thread(target=upstream, daemon=True), threading.Thread(target=upstream6, daemon=True), threading.Thread(target=udp_upstream, daemon=True),
               threading.Thread(target=udp6_upstream, daemon=True)]
    ns_fd = os.open('/proc/self/ns/net', os.O_RDONLY)
    try:
        for thread in threads: thread.start()
        subprocess.run(['unshare', '-n', sys.executable, __file__, binary, 'inner',
                        str(os.stat('/proc/self/ns/net').st_ino), str(ns_fd),
                        str(origin.getsockname()[1]), str(udp_origin.getsockname()[1]), str(udp6_origin.getsockname()[1]),
                        str(origin6.getsockname()[1]), sys.argv[4], sys.argv[5], sys.argv[6]],
                       pass_fds=(ns_fd,), check=True, timeout=25)
        for thread in threads: thread.join(timeout=12)
        if any(thread.is_alive() for thread in threads) or errors: raise RuntimeError(f'upstream errors: {errors}')
    finally:
        os.close(ns_fd); origin.close(); origin6.close(); udp_origin.close(); udp6_origin.close()
else:
    if sys.argv[2] != 'inner' or os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('inner namespace was not isolated')
    ns_fd = int(sys.argv[4])
    subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_ecn=1'], check=True, stdout=subprocess.DEVNULL)
    source_test = sys.argv[11] == '1'
    proc = subprocess.Popen([binary, str(ns_fd), '42', '1280'] + (['source'] if source_test else []), pass_fds=(ns_fd,), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if proc.stdout.readline().strip() != 'ready':
            raise RuntimeError(f'driver did not create its TUN: {proc.stderr.read()}')
        for command in (
            ['ip', 'addr', 'add', '10.77.0.1/24', 'dev', 'nx-owned'],
            ['ip', '-6', 'addr', 'add', 'fd77::1/64', 'dev', 'nx-owned', 'nodad'],
            ['ip', 'link', 'set', 'nx-owned', 'mtu', sys.argv[9], 'up'],
        ):
            subprocess.run(command, check=True)
        if source_test:
            subprocess.run(['ip', 'addr', 'add', '10.77.0.4/24', 'dev', 'nx-owned'], check=True)
            subprocess.run(['ip', '-6', 'addr', 'add', 'fd77::4/64', 'dev', 'nx-owned', 'nodad'], check=True)
        proc.stdin.write('G'); proc.stdin.flush()
        unknown_tcp_resets(socket.AF_INET, '10.77.0.1', '10.77.0.2')
        unknown_tcp_resets(socket.AF_INET6, 'fd77::1', 'fd77::2')
        if source_test:
            for family, permitted, denied, destination, tcp_port, udp_port in (
                (socket.AF_INET, '10.77.0.1', '10.77.0.4', '10.77.0.2', int(sys.argv[5]), int(sys.argv[6])),
                (socket.AF_INET6, 'fd77::1', 'fd77::4', 'fd77::2', int(sys.argv[8]), int(sys.argv[7])),
            ):
                for address, port in ((denied, 0), (permitted, 43110)):
                    with socket.socket(family, socket.SOCK_DGRAM) as blocked:
                        blocked.bind((address, port)); blocked.settimeout(0.25)
                        blocked.sendto(b'blocked', (destination, udp_port))
                        try: blocked.recvfrom(64)
                        except TimeoutError: pass
                        else: raise RuntimeError('blocked UDP received a response')
                    with socket.socket(family, socket.SOCK_STREAM) as blocked:
                        blocked.bind((address, port)); blocked.settimeout(0.25)
                        try: blocked.connect((destination, tcp_port))
                        except (TimeoutError, ConnectionRefusedError, ConnectionResetError): pass
                        else: raise RuntimeError('blocked TCP connected')
        if sys.argv[10] == '1':
            rules = '''table inet nexus_fin_loss {
                counter client4 {}
                counter server4 {}
                counter client6 {}
                counter server6 {}
                chain output {
                    type filter hook output priority 0; policy accept;
                    oifname "nx-owned" meta nfproto ipv4 tcp flags & fin == fin limit rate 1/hour burst 1 packets counter name client4 drop
                    oifname "nx-owned" meta nfproto ipv6 tcp flags & fin == fin limit rate 1/hour burst 1 packets counter name client6 drop
                }
                chain input {
                    type filter hook input priority 0; policy accept;
                    iifname "nx-owned" meta nfproto ipv4 tcp flags & fin == fin limit rate 1/hour burst 1 packets counter name server4 drop
                    iifname "nx-owned" meta nfproto ipv6 tcp flags & fin == fin limit rate 1/hour burst 1 packets counter name server6 drop
                }
            }'''
            subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as tcp_capture, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            tcp_capture.bind(('nx-owned', 0)); tcp_capture.settimeout(10)
            client.settimeout(10)
            if source_test: client.bind(('10.77.0.1', 0))
            client.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes([1, 1, 0, 0]))
            client.connect(('10.77.0.2', int(sys.argv[5])))
            while True:
                packet = tcp_capture.recv(65535)
                if len(packet) >= 44 and packet[0] >> 4 == 4 and packet[9] == 6 and packet[37] & 2:
                    if packet[37] & 0xc0 != 0xc0: raise RuntimeError('IPv4 SYN did not request ECN')
                    if packet[0] != 0x46 or packet[20:24] != bytes([1, 1, 0, 0]):
                        raise RuntimeError(f'IPv4 options missing from TCP SYN: {packet[:24].hex()}')
                    break
            with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as capture, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                capture.bind(('nx-owned', 0)); capture.settimeout(10)
                udp.settimeout(10)
                if source_test: udp.bind(('10.77.0.1', 0))
                udp.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes([1, 1, 0, 0]))
                udp.sendto(b'udp', ('10.77.0.2', int(sys.argv[6])))
                if udp.recvfrom(64)[0] != b'UDP': raise RuntimeError('invalid UDP response')
                while True:
                    packet = capture.recv(65535)
                    if len(packet) >= 35 and packet[0] >> 4 == 4 and packet[9] == 17 and packet.endswith(b'udp'):
                        if packet[0] != 0x46 or packet[20:24] != bytes([1, 1, 0, 0]):
                            raise RuntimeError(f'IPv4 options missing from TUN packet: {packet[:24].hex()}')
                        break
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp6:
                udp6.settimeout(10)
                if source_test: udp6.bind(('fd77::1', 0))
                for request in (b'udp6', b'options', b'both', b'unknown'):
                    if request == b'options':
                        udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, bytes([0, 0, 1, 4, 0, 0, 0, 0]))
                    if request == b'both':
                        udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPOPTS, bytes([0, 0, 1, 4, 0, 0, 0, 0]))
                    if request == b'unknown':
                        udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, bytes([0, 0, 0x1e, 2, 0xaa, 0xbb, 1, 0]))
                    udp6.sendto(request, ('fd77::2', int(sys.argv[7])))
                    data, peer = udp6.recvfrom(64)
                    if data != b'UDP6' or peer[:2] != ('fd77::2', int(sys.argv[7])):
                        raise RuntimeError(f'invalid IPv6 UDP response {data!r} from {peer!r}')
            client.sendall(b'hello'); client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                part = client.recv(64)
                if not part: break
                response.extend(part)
            if response != b'world': raise RuntimeError(f'unexpected TCP response {response!r}')
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as capture6, \
                socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client6:
            capture6.bind(('nx-owned', 0)); capture6.settimeout(10)
            client6.settimeout(10)
            if source_test: client6.bind(('fd77::1', 0))
            client6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPOPTS, bytes([0, 0, 1, 4, 0, 0, 0, 0]))
            client6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, bytes([0, 0, 0x1e, 2, 0xaa, 0xbb, 1, 0]))
            client6.connect(('fd77::2', int(sys.argv[8])))
            negotiated_mss = client6.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            if not 0 < negotiated_mss <= 1220:
                raise RuntimeError(f'IPv6 TCP MSS exceeds advertised limit: {negotiated_mss}')
            while True:
                packet = capture6.recv(65535)
                if len(packet) >= 76 and packet[0] >> 4 == 6 and packet[6] == 0 and packet[40] == 60 and packet[48] == 6 and packet[69] & 2:
                    if packet[69] & 0xc0 != 0xc0: raise RuntimeError('IPv6 SYN did not request ECN')
                    if packet[42:48] != bytes([1, 4, 0, 0, 0, 0]) or packet[50:56] != bytes([0x1e, 2, 0xaa, 0xbb, 1, 0]):
                        raise RuntimeError('IPv6 TCP extension options missing from SYN')
                    break
            client6.sendall(b'hello6' * 1024); client6.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                part = client6.recv(64)
                if not part: break
                response.extend(part)
            if response != b'world6' * 1024: raise RuntimeError(f'unexpected IPv6 TCP response of {len(response)} bytes')
            capture6.setblocking(False)
            segments = 0
            while True:
                try: packet = capture6.recv(65535)
                except BlockingIOError: break
                if len(packet) >= 76 and packet[0] >> 4 == 6 and packet[6] == 0 and packet[40] == 60 and packet[48] == 6:
                    tcp_header = (packet[68] >> 4) * 4
                    if len(packet) > 56 + tcp_header:
                        if len(packet) > 1280: raise RuntimeError(f'oversize IPv6 TCP packet: {len(packet)}')
                        if packet[1] & 0x30: raise RuntimeError('IPv6 TCP data unexpectedly used ECN')
                        segments += 1
            if segments < 2: raise RuntimeError(f'expected segmented IPv6 request, saw {segments} packets')
        if sys.argv[10] == '1':
            result = subprocess.run(['nft', '-j', 'list', 'counters', 'table', 'inet', 'nexus_fin_loss'],
                                    check=True, capture_output=True, text=True)
            counters = {item['counter']['name']: item['counter']['packets']
                        for item in json.loads(result.stdout)['nftables'] if 'counter' in item}
            if counters != {name: 1 for name in ('client4', 'server4', 'client6', 'server6')}:
                raise RuntimeError(f'FIN drop counters do not match: {counters}')
        proc.stdin.write('X'); proc.stdin.flush()
        out, err = proc.communicate(timeout=5)
        if proc.returncode: raise RuntimeError(f'driver failed: {proc.returncode} {out} {err}')
        print(out.strip())
        if pathlib.Path('/sys/class/net/nx-owned').exists(): raise RuntimeError('TUN was not removed')
    finally:
        if proc.poll() is None:
            proc.kill(); proc.communicate()
