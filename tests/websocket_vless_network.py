#!/usr/bin/env python3
"""Exercise VLESS over authenticated WebSocket on a real TLS connection."""
import base64
import concurrent.futures
import hashlib
from pathlib import Path
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

from dns_rule_support import DnsPeer, Echo, exact, free_port, nexus_process, proxy_client, udp_client
from httpupgrade_cli_network import ALICE, HOST, PATH, TARGET, address, begin, client_config, go_outbound, server_config, vless
from httpupgrade_tls_network import UUID, certificates, client_context, header
from shadowtls_singbox import REVISION, launch_singbox, stop_proc


def enable(config):
    config.write_text(config.read_text().replace('transport "httpupgrade"', 'transport "websocket"'))
    return config


def traffic(front, origin):
    for target in ("127.0.0.1", "::1"):
        for payload in (b"hello", b"websocket" * 200):
            with begin(front, origin.port, host=target) as stream:
                stream.sendall(payload)
                assert exact(stream, len(payload)) == payload
        with udp_client(front) as (client, relay):
            prefix=b"\0\0\0" + address(target,origin.port)
            client.sendto(prefix+b"packet",relay)
            assert client.recvfrom(1024)[0] == prefix+b"packet"


def masked_frame(opcode, payload, final=True):
    assert len(payload)<126
    mask=os.urandom(4)
    return bytes((opcode | (0x80 if final else 0),0x80 | len(payload))) + mask + bytes(
        byte ^ mask[index % 4] for index, byte in enumerate(payload))


def server_frame(sock):
    opcode, length=exact(sock,2)
    assert opcode & 0x80 and length < 128
    if length==126:
        length=struct.unpack("!H",exact(sock,2))[0]
    elif length==127:
        length=struct.unpack("!Q",exact(sock,8))[0]
    return opcode & 0x0f, exact(sock,length) if length else b""


def open_raw(root, port, request_path=TARGET):
    raw=socket.create_connection(("127.0.0.1",port),timeout=3)
    conn=client_context(root,["http/1.1"]).wrap_socket(raw,server_hostname="localhost")
    key=base64.b64encode(os.urandom(16))
    wire=f"GET {request_path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n".encode()
    wire+=b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+b"\r\n\r\n"
    conn.sendall(wire)
    return conn, key


def echo_until_close(listener):
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(3)
        while data := peer.recv(1024):
            peer.sendall(data)


def raw_frames(root, remote, origin_port):
    with open_raw(root,remote)[0] as bad:
        assert header(bad).startswith(b"HTTP/1.1 101 ")
        bad.sendall(b"\x82\x04fake")
        try:
            assert bad.recv(1)==b""
        except (ConnectionResetError,ssl.SSLError):
            pass

    connection,key=open_raw(root,remote)
    with connection as peer:
        response=header(peer)
        accept=base64.b64encode(hashlib.sha1(key+b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        assert response.startswith(b"HTTP/1.1 101 ") and b"Sec-WebSocket-Accept: "+accept+b"\r\n" in response
        request=vless("127.0.0.1",origin_port)
        peer.sendall(masked_frame(2,request[:9],False)+masked_frame(9,b"ping")+
                     masked_frame(0,request[9:]+b"fragment"))
        got=bytearray()
        pong=False
        while len(got)<10 or not pong:
            opcode,payload=server_frame(peer)
            if opcode==10:
                assert payload==b"ping"
                pong=True
            else:
                assert opcode==2
                got.extend(payload)
        assert got==b"\0\0fragment"
        peer.sendall(masked_frame(8,b"\x03\xe8"))
        assert server_frame(peer)==(8,b"\x03\xe8")
    print("WebSocket verified RFC 6455 accept proof, mask, continuation, ping/pong and Close")


def run(binary, root, dns):
    remote=free_port()
    config=enable(server_config(root,remote,1,dns))
    with nexus_process(binary,config), Echo() as origin:
        with socket.create_server(("127.0.0.1", 0)) as listener:
            listener.settimeout(4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                echoed = executor.submit(echo_until_close, listener)
                raw_frames(root, remote, listener.getsockname()[1])
                echoed.result(timeout=4)
        upstream=go_outbound(root,remote)
        transport = upstream["transport"]
        transport["type"] = "ws"
        transport["headers"]["Host"] = transport.pop("host")
        with proxy_client(root,upstream) as front:
            traffic(front,origin)
        with nexus_process(binary,enable(client_config(root,front:=free_port(),remote,1,dns))):
            traffic(front,origin)

    front,remote=free_port(),free_port()
    config=root/"go-websocket.json"
    config.write_text(json.dumps({
        "log": {"level":"warn"},
        "inbounds":[{
            "type":"vless","listen":"127.0.0.1","listen_port":remote,"users":[{"uuid":UUID}],
            "tls":{"enabled":True,"certificate_path":str(root/"cert"),"key_path":str(root/"key"),"alpn":["http/1.1"]},
            "transport":{"type":"ws","path":PATH}
        }],
        "outbounds":[{"type":"direct"}]
    }))
    peer=launch_singbox(config,remote)
    try:
        with nexus_process(binary,enable(client_config(root,front,remote,1,dns,path=PATH))), Echo() as origin:
            traffic(front,origin)
    finally:
        stop_proc(peer)
    print("VLESS WebSocket carried TCP and XUDP to Nexus and fixed sing-box in both directions")


if __name__=="__main__":
    binary=Path(sys.argv[1]).resolve(strict=True)
    assert f"Revision: {REVISION}" in subprocess.check_output(["sing-box","version"],text=True)
    with tempfile.TemporaryDirectory(prefix="nexus-websocket-vless-") as directory, DnsPeer() as dns:
        root=Path(directory)
        certificates(root)
        for name,value in (("uuid",UUID),("alice",ALICE)):
            (root/name).write_text(value+"\n")
            (root/name).chmod(0o600)
        run(binary,root,dns)
