#!/usr/bin/env python3
"""Exercise the UDP server session core via a pinned sing-box SOCKS client."""
import base64
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length-len(data))
        if not part:
            raise RuntimeError("SOCKS connection closed")
        data += part
    return data

with tempfile.TemporaryDirectory(prefix="nexus-ss2022-udp-inbound-") as directory:
    for size in (16, 32):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener, socket.socket() as reserved, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
            listener.bind(("127.0.0.1", 0))
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))
            target.bind(("127.0.0.1", 0))
            target.settimeout(5)
            def target_worker():
                for i in range(2):
                    data, sender=target.recvfrom(65535)
                    if data!=b"hello"+bytes([48+i]):
                        return
                    target.sendto(b"world"+bytes([48+i]),sender)
            worker=threading.Thread(target=target_worker,daemon=True)
            worker.start()
            reserved.bind(("127.0.0.1", 0))
            port=reserved.getsockname()[1]
            reserved.close()
            config={"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":port}],
                    "outbounds":[{"type":"shadowsocks","tag":"edge","server":"127.0.0.1", "server_port":listener.getsockname()[1],
                                  "method":f"2022-blake3-aes-{size*8}-gcm","password":base64.b64encode(bytes(range(size))).decode()}],
                    "route":{"final":"edge"}}
            path=pathlib.Path(directory)/"client.json"
            path.write_text(json.dumps(config))
            subprocess.run(["sing-box","check","-c",path],check=True,capture_output=True)
            peer=subprocess.Popen([fixture,str(listener.fileno()),str(size),str(target.getsockname()[1])],pass_fds=(listener.fileno(),))
            box=subprocess.Popen(["sing-box","run","-c",path],stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+5
                while True:
                    if box.poll() is not None:
                        raise RuntimeError(box.stderr.read().decode())
                    try:
                        client=socket.create_connection(("127.0.0.1",port),timeout=.2)
                        break
                    except OSError:
                        if time.monotonic()>=deadline:
                            raise
                        time.sleep(.02)
                with client, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    client.settimeout(5)
                    udp.bind(("127.0.0.1",0))
                    udp.settimeout(5)
                    client.sendall(b"\x05\x01\x00")
                    if exact(client,2)!=b"\x05\x00":
                        raise RuntimeError("SOCKS greeting failed")
                    client.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01"+struct.pack("!H",udp.getsockname()[1]))
                    head=exact(client,4)
                    if head!=b"\x05\x00\x00\x01":
                        raise RuntimeError(f"SOCKS UDP association failed: {head!r}")
                    relay=exact(client,6)
                    host=socket.inet_ntoa(relay[:4])
                    if host=="0.0.0.0": host="127.0.0.1"
                    endpoint=(host,struct.unpack("!H",relay[4:])[0])
                    header=b"\x00\x00\x00\x01\x7f\x00\x00\x01"+struct.pack("!H",target.getsockname()[1])
                    for i in range(2):
                        udp.sendto(header+b"hello"+bytes([48+i]),endpoint)
                        response,_=udp.recvfrom(65535)
                        if response!=header+b"world"+bytes([48+i]):
                            raise RuntimeError(f"response mismatch: {response!r}")
                if peer.wait(timeout=5)!=0:
                    raise RuntimeError(f"fixture failed: {peer.returncode}")
            finally:
                if peer.poll() is None:
                    peer.kill()
                    peer.wait()
                box.terminate()
                try:
                    box.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    box.kill()
                    box.communicate()
print(f"SS-2022 UDP server relay with sing-box {revision} passed")
