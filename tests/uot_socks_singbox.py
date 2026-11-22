#!/usr/bin/env python3
"""SOCKS UDP through Nexus UoT v2 and a pinned sing-box SS-2022 inbound."""
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

fixture = pathlib.Path(sys.argv[1]).resolve()
revision = "824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box", "version"], capture_output=True, text=True, check=True).stdout:
    raise RuntimeError("unexpected sing-box revision")
def exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise RuntimeError("unexpected EOF")
        data += chunk
    return data
with tempfile.TemporaryDirectory(prefix="nexus-uot-socks-") as directory, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as origin:
    origin.bind(("127.0.0.1", 0)); origin.settimeout(10)
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0)); port=reserved.getsockname()[1]
    config={"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":port,
            "method":"2022-blake3-aes-128-gcm","password":base64.b64encode(bytes(range(16))).decode()}],
            "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
    path=pathlib.Path(directory)/"config.json"; path.write_text(json.dumps(config))
    subprocess.run(["sing-box","check","-c",path],capture_output=True,check=True)
    box=subprocess.Popen(["sing-box","run","-c",path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    proxy=None; received=[]
    def echo():
        try:
            for _ in range(3):
                data, peer=origin.recvfrom(65535); received.append(data); origin.sendto(data,peer)
        except Exception as exc: received.append(exc)
    thread=threading.Thread(target=echo,daemon=True); thread.start()
    try:
        time.sleep(.5)
        if box.poll() is not None: raise RuntimeError(box.stderr.read())
        proxy=subprocess.Popen([fixture,str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        proxy_port=int(proxy.stdout.readline())
        with socket.create_connection(("127.0.0.1",proxy_port),timeout=10) as control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            control.settimeout(10); client.settimeout(10); client.bind(("127.0.0.1",0))
            control.sendall(b"\x05\x01\x00"); assert exact(control,2)==b"\x05\x00"
            control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            reply=exact(control,10)
            if reply[:4]!=b"\x05\x00\x00\x01": raise RuntimeError(f"association rejected: {reply!r}")
            relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],"big"))
            header=b"\x00\x00\x00\x01\x7f\x00\x00\x01"+origin.getsockname()[1].to_bytes(2,"big")
            for payload in (b"one",b"",b"third"):
                client.sendto(header+payload,relay)
                data,_=client.recvfrom(65535)
                if data!=header+payload: raise RuntimeError(f"incorrect reply: {data!r}")
        thread.join(timeout=10)
        if received!=[b"one",b"",b"third"]: raise RuntimeError(f"origin: {received!r}")
        print("SOCKS UDP -> SS-2022 UoT v2 -> sing-box: data and empty packet passed")
    finally:
        if proxy:
            proxy.terminate(); proxy.communicate(timeout=5)
        box.terminate(); box.communicate(timeout=5)
