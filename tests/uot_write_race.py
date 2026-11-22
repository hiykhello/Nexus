#!/usr/bin/env python3
"""Hold UoT authorization open while a real encrypted peer replies."""
import os
import pathlib
import select
import socket
import subprocess
import sys

fixture = pathlib.Path(sys.argv[1]).resolve()
peer_binary = fixture.with_name("nexus-uot-fault-server")

def exact(sock, size):
    result = b""
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data:
            raise RuntimeError("unexpected EOF")
        result += data
    return result

for mode in ("success", "failure", "cancel"):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        peer_read, peer_write = os.pipe()
        gate_read, gate_write = os.pipe()
        peer = proxy = None
        try:
            peer = subprocess.Popen([peer_binary, str(listener.fileno()), "valid", str(peer_read)],
                                    pass_fds=(listener.fileno(), peer_read))
            env = dict(os.environ, NEXUS_TEST_UOT_WRITE_RACE=str(gate_read))
            proxy = subprocess.Popen([fixture, str(listener.getsockname()[1])], env=env,
                                     pass_fds=(gate_read,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(peer_read); peer_read = -1
            os.close(gate_read); gate_read = -1
            if not select.select([proxy.stdout], [], [], 5)[0]:
                raise RuntimeError("fixture did not start")
            port = int(proxy.stdout.readline())
            with socket.create_connection(("127.0.0.1", port), timeout=5) as control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                control.settimeout(5); client.bind(("127.0.0.1", 0)); client.settimeout(0.2)
                control.sendall(b"\x05\x01\x00")
                if exact(control, 2) != b"\x05\x00": raise RuntimeError("authentication failed")
                control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                response = exact(control, 10)
                if response[:4] != b"\x05\x00\x00\x01": raise RuntimeError("association failed")
                relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:10], "big"))
                header = b"\x00\x00\x00\x01\x7f\x00\x00\x01\x00\x35"
                client.sendto(header + b"probe", relay)
                if not select.select([proxy.stderr], [], [], 5)[0] or b"uot reply pending" not in proxy.stderr.readline():
                    raise RuntimeError("reply did not reach pending authorization")
                try:
                    raise RuntimeError(f"reply delivered before write completion: {client.recvfrom(65535)!r}")
                except socket.timeout:
                    pass
                if mode == "cancel":
                    control.close()
                    try:
                        raise RuntimeError(f"reply delivered after cancellation: {client.recvfrom(65535)!r}")
                    except socket.timeout:
                        pass
                else:
                    os.write(gate_write, b"s" if mode == "success" else b"f")
                    if mode == "success":
                        client.settimeout(5)
                        if client.recvfrom(65535)[0] != header + b"good": raise RuntimeError("valid reply lost")
                    else:
                        if control.recv(1): raise RuntimeError("failed write did not close association")
                        try:
                            raise RuntimeError(f"reply delivered after failed write: {client.recvfrom(65535)!r}")
                        except socket.timeout:
                            pass
                os.write(peer_write, b"x")
                if peer.wait(timeout=5): raise RuntimeError(f"peer exit {peer.returncode}")
        finally:
            for fd in (peer_read, peer_write, gate_read, gate_write):
                if fd >= 0: os.close(fd)
            for process in (peer, proxy):
                if process and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
print("UoT pending reply waits for successful write and is dropped on failure or cancellation")
