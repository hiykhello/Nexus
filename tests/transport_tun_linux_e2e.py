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
    origin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    origin.bind(('10.77.0.2', 0)); origin.listen(1); origin.settimeout(12)
    udp_origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_origin.bind(('10.77.0.2', 0)); udp_origin.settimeout(12)
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
    def udp_upstream():
        try:
            data, peer = udp_origin.recvfrom(64)
            if data != b'udp': raise RuntimeError(f'unexpected UDP request {data!r}')
            udp_origin.sendto(b'UDP', peer)
        except Exception as exc: errors.append(exc)
    threads = [threading.Thread(target=upstream, daemon=True), threading.Thread(target=udp_upstream, daemon=True)]
    ns_fd = os.open('/proc/self/ns/net', os.O_RDONLY)
    try:
        for thread in threads: thread.start()
        subprocess.run(['unshare', '-n', sys.executable, __file__, binary, 'inner',
                        str(os.stat('/proc/self/ns/net').st_ino), str(ns_fd),
                        str(origin.getsockname()[1]), str(udp_origin.getsockname()[1])],
                       pass_fds=(ns_fd,), check=True, timeout=25)
        for thread in threads: thread.join(timeout=12)
        if any(thread.is_alive() for thread in threads) or errors: raise RuntimeError(f'upstream errors: {errors}')
    finally:
        os.close(ns_fd); origin.close(); udp_origin.close()
else:
    if sys.argv[2] != 'inner' or os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('inner namespace was not isolated')
    ns_fd = int(sys.argv[4])
    proc = subprocess.Popen([binary, str(ns_fd)], pass_fds=(ns_fd,), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if proc.stdout.readline().strip() != 'ready':
            raise RuntimeError(f'driver did not create its TUN: {proc.stderr.read()}')
        for command in (
            ['ip', 'addr', 'add', '10.77.0.1/24', 'dev', 'nx-owned'],
            ['ip', 'link', 'set', 'nx-owned', 'up'],
        ):
            subprocess.run(command, check=True)
        proc.stdin.write('G'); proc.stdin.flush()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(('10.77.0.2', int(sys.argv[5])))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(10)
                udp.sendto(b'udp', ('10.77.0.2', int(sys.argv[6])))
                if udp.recvfrom(64)[0] != b'UDP': raise RuntimeError('invalid UDP response')
            client.sendall(b'hello'); client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                part = client.recv(64)
                if not part: break
                response.extend(part)
            if response != b'world': raise RuntimeError(f'unexpected TCP response {response!r}')
        proc.stdin.write('X'); proc.stdin.flush()
        out, err = proc.communicate(timeout=5)
        if proc.returncode: raise RuntimeError(f'driver failed: {proc.returncode} {out} {err}')
        print(out.strip())
        if pathlib.Path('/sys/class/net/nx-owned').exists(): raise RuntimeError('TUN was not removed')
    finally:
        if proc.poll() is None:
            proc.kill(); proc.communicate()
