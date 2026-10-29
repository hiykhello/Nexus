"""Exercise IPv6 UDP through TUN between two temporary network namespaces."""
import array
import fcntl
import os
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())
if len(sys.argv) == 2:
    parent_ns = str(os.stat('/proc/self/ns/net').st_ino)
    subprocess.run(['unshare', '-Urn', sys.executable, __file__, binary, 'outer', parent_ns], check=True, timeout=35)
elif sys.argv[2] == 'outer':
    if os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('outer namespace was not isolated')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', '-6', 'addr', 'add', 'fd77::2/128', 'dev', 'lo', 'nodad'], check=True)
    origin = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    origin.bind(('fd77::2', 0))
    origin.settimeout(12)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(12)
    stop_read, stop_write = os.pipe()
    namespace = engine = None
    errors = []
    def serve():
        try:
            for request in (b'ipv6-request', b'ipv6-options', b'ipv6-both', b'ipv6-unknown'):
                data, peer = origin.recvfrom(128)
                if data != request:
                    raise RuntimeError(f'unexpected request {data!r}')
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as rogue:
                    rogue.bind(('fd77::2', 0))
                    rogue.sendto(b'unexpected', peer)
                    time.sleep(0.05)
                origin.sendto(b'ipv6-response', peer)
        except Exception as exc:
            errors.append(exc)
    thread = threading.Thread(target=serve, daemon=True)
    try:
        namespace = subprocess.Popen(['unshare', '-n', sys.executable, __file__, binary, 'inner',
                                      str(os.stat('/proc/self/ns/net').st_ino), str(child.fileno()),
                                      str(origin.getsockname()[1])], pass_fds=(child.fileno(),))
        child.close()
        msg, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
        descriptors = array.array('i')
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(data[:descriptors.itemsize])
        if msg != b'T' or len(descriptors) != 1:
            raise RuntimeError('inner namespace did not provide the TUN descriptor')
        fd = descriptors[0]
        try:
            engine = subprocess.Popen([binary, str(fd), str(stop_read), 'udp6'], pass_fds=(fd, stop_read))
        finally:
            os.close(fd)
        thread.start()
        parent.sendall(b'G')
        if namespace.wait(timeout=15):
            raise RuntimeError('IPv6 UDP client failed')
        thread.join(timeout=12)
        if thread.is_alive() or errors:
            raise RuntimeError(f'IPv6 UDP upstream failed: {errors}')
        os.write(stop_write, b'X')
        if engine.wait(timeout=5):
            raise RuntimeError('transport fixture failed')
    finally:
        for proc in (namespace, engine):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
        parent.close()
        child.close()
        origin.close()
        os.close(stop_read)
        os.close(stop_write)
else:
    if sys.argv[2] != 'inner' or os.stat('/proc/self/ns/net').st_ino == int(sys.argv[3]):
        raise RuntimeError('inner namespace was not isolated')
    control = socket.socket(fileno=int(sys.argv[4]))
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', b'nx-test', 0x0001 | 0x1000))
        subprocess.run(['ip', '-6', 'addr', 'add', 'fd77::1/64', 'dev', 'nx-test', 'nodad'], check=True)
        subprocess.run(['ip', 'link', 'set', 'nx-test', 'up'], check=True)
        control.sendmsg([b'T'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        if control.recv(1) != b'G':
            raise RuntimeError('transport fixture did not start')
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
            client.settimeout(10)
            port = int(sys.argv[5])
            for request in (b'ipv6-request', b'ipv6-options', b'ipv6-both', b'ipv6-unknown'):
                if request == b'ipv6-options':
                    # Linux fills the next-header byte when emitting the packet.
                    client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, bytes([0,0,1,4,0,0,0,0]))
                if request == b'ipv6-both':
                    client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_HOPOPTS, bytes([0,0,1,4,0,0,0,0]))
                if request == b'ipv6-unknown':
                    client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, bytes([0,0,0x1e,2,0xaa,0xbb,1,0]))
                client.settimeout(10)
                client.sendto(request, ('fd77::2', port))
                data, peer = client.recvfrom(128)
                if data != b'ipv6-response' or peer[:2] != ('fd77::2', port):
                    raise RuntimeError(f'unexpected response {data!r} from {peer!r}')
                client.settimeout(0.1)
                try:
                    extra = client.recvfrom(128)
                except TimeoutError:
                    pass
                else:
                    raise RuntimeError(f'unexpected extra response {extra!r}')
    finally:
        os.close(fd)
        control.close()
