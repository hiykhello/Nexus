#!/usr/bin/env python3
"""Exercise VLESS TLS over an actual SS tunnel."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

binary = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], check=True, capture_output=True, text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
reservations = [socket.socket() for _ in range(3)]
for sock in reservations: sock.bind(("127.0.0.1", 0))
ports = [sock.getsockname()[1] for sock in reservations]
for sock in reservations: sock.close()
with tempfile.TemporaryDirectory(prefix="nexus-chain-vless-") as directory:
    root = pathlib.Path(directory); key, cert, uuid = (root / name for name in ("key", "cert", "uuid"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-subj", "/CN=cover.example", "-addext", "subjectAltName=DNS:cover.example", "-days", "1"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    user = "00010203-0405-0607-0809-0a0b0c0d0e0f"; uuid.write_text(user); uuid.chmod(0o600)
    inbounds = [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ports[0],
                 "method": "2022-blake3-aes-128-gcm", "password": base64.b64encode(bytes(range(16))).decode()}]
    for port, vision in zip(ports[1:], (False, True)):
        inbounds.append({"type": "vless", "listen": "127.0.0.1", "listen_port": port,
                         "users": [{"uuid": user, **({"flow": "xtls-rprx-vision"} if vision else {})}],
                         "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}})
    config = root / "box.json"; config.write_text(json.dumps({"log": {"level": "warn"}, "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}))
    subprocess.run(["sing-box", "check", "-c", config], check=True, capture_output=True)
    process = subprocess.Popen(["sing-box", "run", "-c", config], stderr=subprocess.PIPE)
    try:
        deadline=time.monotonic()+5
        while True:
            if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(("127.0.0.1",ports[0]),timeout=.2): break
            except OSError:
                if time.monotonic()>=deadline: raise
                time.sleep(.02)
        for backend in ("epoll", "uring"):
            for mode, port in zip(("normal", "vision"), ports[1:]):
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1",0)); listener.listen(1); listener.settimeout(10); errors=[]
                    def peer():
                        try:
                            with listener.accept()[0] as conn:
                                conn.settimeout(8); expected=bytes(range(256))*1024; data=bytearray()
                                while len(data)<len(expected):
                                    part=conn.recv(min(65536,len(expected)-len(data)))
                                    if not part: raise RuntimeError("truncated upload")
                                    data.extend(part)
                                if data!=expected or conn.recv(1): raise RuntimeError("upload or FIN mismatch")
                                conn.sendall(expected); conn.shutdown(socket.SHUT_WR)
                        except Exception as error: errors.append(error)
                    thread=threading.Thread(target=peer); thread.start()
                    result=subprocess.run([binary,str(ports[0]),str(port),str(listener.getsockname()[1]),uuid,cert,mode,backend,"data"],timeout=12)
                    thread.join(10)
                    if result.returncode or thread.is_alive() or errors: raise RuntimeError(f"{backend} {mode}: exit={result.returncode}, peer={errors}")
                    print(f"VLESS {mode} over SS {backend}: data and delayed half-close passed")
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as listener:
                    listener.bind(("127.0.0.1",0)); listener.settimeout(8); errors=[]
                    def echo():
                        try:
                            seen=set()
                            for _ in range(2):
                                data,address=listener.recvfrom(65535)
                                if data not in (b"probe",b"\x01\x02\x03") or data in seen: raise RuntimeError("unexpected datagram")
                                seen.add(data); listener.sendto(data,address)
                        except Exception as error: errors.append(error)
                    thread=threading.Thread(target=echo); thread.start()
                    result=subprocess.run([binary,str(ports[0]),str(port),str(listener.getsockname()[1]),uuid,cert,mode,backend,"xudp"],timeout=12)
                    thread.join(8)
                    if result.returncode or thread.is_alive() or errors: raise RuntimeError(f"{backend} {mode} xudp: exit={result.returncode}, peer={errors}")
                    print(f"VLESS {mode} over SS {backend}: XUDP passed")
            for mode in ("timeout", "cancel"):
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1",0)); listener.listen(1); listener.settimeout(8); errors=[]
                    def stalled():
                        try:
                            with listener.accept()[0] as conn:
                                conn.settimeout(5)
                                if not conn.recv(4096): raise RuntimeError("missing ClientHello")
                                time.sleep(.7)
                        except Exception as error: errors.append(error)
                    thread=threading.Thread(target=stalled); thread.start()
                    result=subprocess.run([binary,str(ports[0]),str(listener.getsockname()[1]),"80",uuid,cert,"normal",backend,mode],timeout=12)
                    thread.join(8)
                    if result.returncode or thread.is_alive() or errors: raise RuntimeError(f"{backend} {mode}: exit={result.returncode}, peer={errors}")
                    print(f"VLESS over SS {backend}: handshake {mode} passed")
    finally:
        process.terminate()
        try: process.communicate(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.communicate()
