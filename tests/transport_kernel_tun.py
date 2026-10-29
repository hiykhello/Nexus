"""Drive TCP and UDP direct paths using a client in a disposable network namespace."""
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
    origin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    origin.bind(("127.0.0.2", 0))
    origin.listen(1)
    origin.settimeout(12)
    udp_origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_origin.bind(("127.0.0.2", 0))
    udp_origin.settimeout(12)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(12)
    stop_read, stop_write = os.pipe()
    namespace = engine = None
    errors = []
    def serve():
        try:
            with origin.accept()[0] as peer:
                peer.settimeout(10)
                request = bytearray()
                while True:
                    data = peer.recv(64)
                    if not data:
                        break
                    request.extend(data)
                if request != b"hello":
                    raise RuntimeError(f"unexpected upstream request {request!r}")
                peer.sendall(b"world")
                peer.shutdown(socket.SHUT_WR)
        except Exception as exc:
            errors.append(exc)
    thread = threading.Thread(target=serve, daemon=True)
    def serve_udp():
        try:
            data, peer = udp_origin.recvfrom(64)
            if data != b"udp-request":
                raise RuntimeError(f"unexpected UDP request {data!r}")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue:
                rogue.bind(("127.0.0.2", 0))
                rogue.sendto(b"unexpected", peer)
                time.sleep(0.05)
            udp_origin.sendto(b"udp-response", peer)
        except Exception as exc:
            errors.append(exc)
    udp_thread = threading.Thread(target=serve_udp, daemon=True)
    try:
        namespace = subprocess.Popen(["unshare", "-Urn", sys.executable, __file__, binary,
                                      str(os.stat('/proc/self/ns/net').st_ino), str(child.fileno()),
                                      str(origin.getsockname()[1]), str(udp_origin.getsockname()[1])], pass_fds=(child.fileno(),))
        child.close()
        msg, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
        descriptors = array.array('i')
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(data[:descriptors.itemsize])
        if msg != b'T' or len(descriptors) != 1:
            raise RuntimeError("namespace did not provide the TUN descriptor")
        fd = descriptors[0]
        try:
            engine = subprocess.Popen([binary, str(fd), str(stop_read)], pass_fds=(fd, stop_read))
        finally:
            os.close(fd)
        thread.start()
        udp_thread.start()
        parent.sendall(b'G')
        if namespace.wait(timeout=15):
            raise RuntimeError("isolated TCP client failed")
        thread.join(timeout=12)
        udp_thread.join(timeout=12)
        if thread.is_alive() or udp_thread.is_alive() or errors:
            raise RuntimeError(f"upstream failed: {errors}")
        os.write(stop_write, b'X')
        if engine.wait(timeout=5):
            raise RuntimeError("transport fixture failed")
    finally:
        for proc in (namespace, engine):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
        parent.close()
        child.close()
        origin.close()
        udp_origin.close()
        os.close(stop_read)
        os.close(stop_write)
else:
    if os.stat('/proc/self/ns/net').st_ino == int(sys.argv[2]):
        raise RuntimeError("fixture must run in a separate network namespace")
    control = socket.socket(fileno=int(sys.argv[3]))
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", b"nx-test", 0x0001 | 0x1000))
        subprocess.run(["ip", "addr", "add", "10.77.0.1/24", "dev", "nx-test"], check=True)
        subprocess.run(["ip", "link", "set", "nx-test", "up"], check=True)
        pathlib.Path('/proc/sys/net/ipv4/conf/nx-test/route_localnet').write_text('1\n')
        subprocess.run(["ip", "route", "add", "127.0.0.2/32", "dev", "nx-test"], check=True)
        control.sendmsg([b'T'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        if control.recv(1) != b'G':
            raise RuntimeError("transport fixture did not start")
        with socket.create_connection(("127.0.0.2", int(sys.argv[4])), timeout=10) as client:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(10)
                udp.sendto(b"udp-request", ("127.0.0.2", int(sys.argv[5])))
                data, sender = udp.recvfrom(64)
                if data != b"udp-response" or sender != ("127.0.0.2", int(sys.argv[5])):
                    raise RuntimeError(f"unexpected UDP response {data!r} from {sender!r}")
                udp.settimeout(0.1)
                try:
                    extra = udp.recvfrom(64)
                except TimeoutError:
                    pass
                else:
                    raise RuntimeError(f"unexpected extra UDP response {extra!r}")
            client.sendall(b"hello")
            client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while True:
                data = client.recv(64)
                if not data:
                    break
                response.extend(data)
            if response != b"world":
                raise RuntimeError(f"unexpected response {response!r}")
    finally:
        os.close(fd)
        control.close()
