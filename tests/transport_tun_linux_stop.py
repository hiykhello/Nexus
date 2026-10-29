"""Stop an owned TUN with several live TCP and UDP direct flows."""
import os
import pathlib
import socket
import subprocess
import sys
import threading

binary = str(pathlib.Path(sys.argv[1]).resolve())
if len(sys.argv) == 2:
    subprocess.run(['unshare', '-Urn', sys.executable, __file__, binary, 'outer',
                    str(os.stat('/proc/self/ns/net').st_ino)], check=True, timeout=45)
elif sys.argv[2] == 'outer':
    if os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('outer namespace was not isolated')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'addr', 'add', '10.77.0.2/32', 'dev', 'lo'], check=True)
    tcp = socket.socket(); tcp.bind(('10.77.0.2', 0)); tcp.listen(4); tcp.settimeout(12)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(('10.77.0.2', 0)); udp.settimeout(12)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(12)
    ns_fd = os.open('/proc/self/ns/net', os.O_RDONLY)
    peers = []; udp_sources = []; errors = []
    def tcp_server():
        try:
            for _ in range(3):
                peer, _ = tcp.accept(); peer.settimeout(12); peers.append(peer)
                if peer.recv(1) != b't': raise RuntimeError('invalid TCP request')
                peer.sendall(b'T')
            for peer in peers:
                if peer.recv(1) != b'': raise RuntimeError('TCP upstream remained open or sent extra data')
        except Exception as exc: errors.append(exc)
    def udp_server():
        try:
            for _ in range(2):
                data, source = udp.recvfrom(64)
                if data != b'u': raise RuntimeError('invalid UDP request')
                udp_sources.append(source); udp.sendto(b'U', source)
        except Exception as exc: errors.append(exc)
    threads = [threading.Thread(target=tcp_server, daemon=True), threading.Thread(target=udp_server, daemon=True)]
    process = None
    try:
        for thread in threads: thread.start()
        process = subprocess.Popen(['unshare', '-n', sys.executable, __file__, binary, 'inner',
                                    str(os.stat('/proc/self/ns/net').st_ino), str(ns_fd), str(child.fileno()),
                                    str(tcp.getsockname()[1]), str(udp.getsockname()[1])],
                                   pass_fds=(ns_fd, child.fileno()))
        child.close()
        if parent.recv(1) != b'S': raise RuntimeError('driver did not stop')
        for thread in threads: thread.join(timeout=12)
        if any(thread.is_alive() for thread in threads) or errors: raise RuntimeError(f'upstream errors: {errors}')
        if len(set(udp_sources)) != 2: raise RuntimeError('UDP flows did not use distinct sockets')
        # Rebinding each source while the driver process is still alive proves its UDP sockets were closed.
        for source in udp_sources:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(source)
        parent.sendall(b'Q')
        if process.wait(timeout=5): raise RuntimeError('inner fixture failed')
    finally:
        if process is not None and process.poll() is None: process.kill(); process.wait()
        for peer in peers: peer.close()
        parent.close(); child.close(); tcp.close(); udp.close(); os.close(ns_fd)
else:
    if sys.argv[2] != 'inner' or os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('inner namespace was not isolated')
    ns_fd = int(sys.argv[4]); control = socket.socket(fileno=int(sys.argv[5])); control.settimeout(12)
    proc = subprocess.Popen([binary, str(ns_fd)], pass_fds=(ns_fd,), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    clients = []; datagrams = []
    try:
        if proc.stdout.readline().strip() != 'ready': raise RuntimeError('driver failed to start')
        subprocess.run(['ip', 'addr', 'add', '10.77.0.1/24', 'dev', 'nx-owned'], check=True)
        subprocess.run(['ip', 'link', 'set', 'nx-owned', 'up'], check=True)
        proc.stdin.write('G'); proc.stdin.flush()
        for _ in range(3):
            client = socket.socket(); clients.append(client); client.settimeout(10)
            client.connect(('10.77.0.2', int(sys.argv[6]))); client.sendall(b't')
            if client.recv(1) != b'T': raise RuntimeError('invalid TCP response')
        for _ in range(2):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); datagrams.append(client); client.settimeout(10)
            client.sendto(b'u', ('10.77.0.2', int(sys.argv[7])))
            if client.recvfrom(64)[0] != b'U': raise RuntimeError('invalid UDP response')
        proc.stdin.write('S'); proc.stdin.flush()
        if proc.stdout.readline().strip() != 'stopped': raise RuntimeError('driver did not stop')
        if pathlib.Path('/sys/class/net/nx-owned').exists(): raise RuntimeError('TUN was not removed')
        control.sendall(b'S')
        if control.recv(1) != b'Q': raise RuntimeError('upstream validation failed')
        proc.stdin.write('Q'); proc.stdin.flush()
        out, err = proc.communicate(timeout=5)
        if proc.returncode: raise RuntimeError(f'driver failed: {proc.returncode} {out} {err}')
        print('stopped three active TCP and two UDP flows before driver destruction')
    finally:
        for client in clients + datagrams: client.close()
        control.close()
        if proc.poll() is None: proc.kill(); proc.communicate()
