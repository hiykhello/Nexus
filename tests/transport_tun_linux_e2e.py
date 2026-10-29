"""Exercise the owned TUN driver across two disposable network namespaces."""
import os
import pathlib
import socket
import subprocess
import sys
import threading

binary = str(pathlib.Path(sys.argv[1]).resolve())
if len(sys.argv) == 2:
    subprocess.run(['unshare', '-Urn', sys.executable, __file__, binary, 'outer',
                    str(os.stat('/proc/self/ns/net').st_ino)], check=True, timeout=40)
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
                if data != b'hello6': raise RuntimeError(f'unexpected IPv6 TCP request {data!r}')
                peer.sendall(b'world6'); peer.shutdown(socket.SHUT_WR)
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
                        str(origin6.getsockname()[1])],
                       pass_fds=(ns_fd,), check=True, timeout=25)
        for thread in threads: thread.join(timeout=12)
        if any(thread.is_alive() for thread in threads) or errors: raise RuntimeError(f'upstream errors: {errors}')
    finally:
        os.close(ns_fd); origin.close(); origin6.close(); udp_origin.close(); udp6_origin.close()
else:
    if sys.argv[2] != 'inner' or os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('inner namespace was not isolated')
    ns_fd = int(sys.argv[4])
    proc = subprocess.Popen([binary, str(ns_fd), '42'], pass_fds=(ns_fd,), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if proc.stdout.readline().strip() != 'ready':
            raise RuntimeError(f'driver did not create its TUN: {proc.stderr.read()}')
        for command in (
            ['ip', 'addr', 'add', '10.77.0.1/24', 'dev', 'nx-owned'],
            ['ip', '-6', 'addr', 'add', 'fd77::1/64', 'dev', 'nx-owned', 'nodad'],
            ['ip', 'link', 'set', 'nx-owned', 'up'],
        ):
            subprocess.run(command, check=True)
        proc.stdin.write('G'); proc.stdin.flush()
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as tcp_capture, \
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            tcp_capture.bind(('nx-owned', 0)); tcp_capture.settimeout(10)
            client.settimeout(10)
            client.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes([1, 1, 0, 0]))
            client.connect(('10.77.0.2', int(sys.argv[5])))
            while True:
                packet = tcp_capture.recv(65535)
                if len(packet) >= 44 and packet[0] >> 4 == 4 and packet[9] == 6 and packet[37] & 2:
                    if packet[0] != 0x46 or packet[20:24] != bytes([1, 1, 0, 0]):
                        raise RuntimeError(f'IPv4 options missing from TCP SYN: {packet[:24].hex()}')
                    break
            with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3)) as capture, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                capture.bind(('nx-owned', 0)); capture.settimeout(10)
                udp.settimeout(10)
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
            client6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPOPTS, bytes([0, 0, 1, 4, 0, 0, 0, 0]))
            client6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, bytes([0, 0, 0x1e, 2, 0xaa, 0xbb, 1, 0]))
            client6.connect(('fd77::2', int(sys.argv[8])))
            while True:
                packet = capture6.recv(65535)
                if len(packet) >= 76 and packet[0] >> 4 == 6 and packet[6] == 0 and packet[40] == 60 and packet[48] == 6 and packet[69] & 2:
                    if packet[42:48] != bytes([1, 4, 0, 0, 0, 0]) or packet[50:56] != bytes([0x1e, 2, 0xaa, 0xbb, 1, 0]):
                        raise RuntimeError('IPv6 TCP extension options missing from SYN')
                    break
            client6.sendall(b'hello6'); client6.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                part = client6.recv(64)
                if not part: break
                response.extend(part)
            if response != b'world6': raise RuntimeError(f'unexpected IPv6 TCP response {response!r}')
        proc.stdin.write('X'); proc.stdin.flush()
        out, err = proc.communicate(timeout=5)
        if proc.returncode: raise RuntimeError(f'driver failed: {proc.returncode} {out} {err}')
        print(out.strip())
        if pathlib.Path('/sys/class/net/nx-owned').exists(): raise RuntimeError('TUN was not removed')
    finally:
        if proc.poll() is None:
            proc.kill(); proc.communicate()
