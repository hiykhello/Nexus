#!/usr/bin/env python3
"""REALITY wire selection and cover shutdown through the production CLI."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, suppress
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time

from detour_network import exact, reserve, running, socks
from tailscale_endpoint_network import eventually, process
from tls_fingerprint_cli import Observer, grease
from tuic_singbox import start_tcp_echo

HYBRID, X25519 = 0x11EC, 0x001D
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"
SHORT = "0123456789abcdef"
SING_BOX = "/usr/bin/sing-box"
def uint(data):
    return int.from_bytes(data, "big")

def tls_record(sock):
    header = exact(sock, 5)
    return header + exact(sock, uint(header[3:5]))

def share_extension(record, server):
    assert record[0] == 22 and record[5] == (2 if server else 1), record[:10].hex()
    end = 9 + 2 + 32
    end += 1 + record[end]
    if server:
        end += 3
    else:
        end += 2 + uint(record[end:end + 2])
        end += 1 + record[end]
    assert end + 2 + uint(record[end:end + 2]) == len(record)
    end += 2
    while end < len(record):
        kind, size = struct.unpack_from("!HH", record, end)
        end += 4
        if kind == 51:
            return record[end:end + size]
        end += size
    raise AssertionError("missing TLS key_share")


class WireObserver(Observer):
    def peer(self, source):
        try:
            with source, socket.create_connection(("127.0.0.1", self.target), timeout=5) as destination:
                source.settimeout(5)
                hello = tls_record(source)
                destination.sendall(hello)
                response = tls_record(destination)
                source.sendall(response)
                shares = share_extension(hello, False)
                groups = []
                cursor = 2
                while cursor < len(shares):
                    group, size = struct.unpack_from("!HH", shares, cursor)
                    cursor += 4 + size
                    if not grease(group):
                        groups.append(group)
                self.messages.append((groups, uint(share_extension(response, True)[:2])))
                def copy(sender, receiver):
                    while chunk := sender.recv(65536):
                        receiver.sendall(chunk)
                    with suppress(OSError): receiver.shutdown(socket.SHUT_WR)

                with ThreadPoolExecutor(2) as pool:
                    up = pool.submit(copy, source, destination)
                    copy(destination, source)
                    up.result()
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            self.errors.append(repr(error))

def encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def credentials(root):
    seed = bytes.fromhex("25" + "00" * 31)
    (root / "secret").write_text(seed.hex())
    (root / "uuid").write_text(UUID)
    (root / "secret").chmod(0o600)
    (root / "uuid").chmod(0o600)
    key_der = bytes.fromhex("302e020100300506032b656e04220420") + seed
    public = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                            input=key_der, check=True, capture_output=True).stdout[-32:]
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", root / "key", "-out", root / "cert", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    return seed, public

def server_config(binary, kind, root, port, cover, seed, xray):
    if kind == "nexus":
        file = root / "server.kdl"
        file.write_text(f'''schema-version 1
role "server"
inbound "edge" type="vless" {{
  listen host="127.0.0.1" port={port}
  authentication {{ user "test" uuid-file="{root / 'uuid'}"; }}
  tls {{ reality {{
    private-key-file "{root / 'secret'}"; server-name "localhost"; short-id "{SHORT}";
    max-time-difference 15; fallback host="127.0.0.1" port={cover};
  }}; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        return [binary, "run", "--config", file]
    file = root / "server.json"
    if kind == "xray":
        file.write_text(json.dumps({"log":{"loglevel":"error"},"inbounds":[{
            "listen":"127.0.0.1","port":port,"protocol":"vless",
            "settings":{"decryption":"none","clients":[{"id":UUID}]},
            "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
                "target":f"127.0.0.1:{cover}","serverNames":["localhost"],
                "privateKey":encode(seed),"shortIds":[SHORT]}}}],"outbounds":[{"protocol":"freedom"}]}))
        return [xray, "run", "-config", file]
    file.write_text(json.dumps({"log":{"level":"error"},"inbounds":[{
        "listen":"127.0.0.1","listen_port":port,"type":"vless","users":[{"uuid":UUID}],
        "tls":{"enabled":True,"server_name":"localhost","reality":{"enabled":True,
              "handshake":{"server":"127.0.0.1","server_port":cover},"private_key":encode(seed),"short_id":[SHORT]}}
    }],"outbounds":[{"type":"direct"}]}))
    return [SING_BOX, "run", "-c", file]

def client_config(binary, kind, root, port, server, public, mode, xray):
    if kind == "nexus":
        group = "x25519" if mode == "classical" else "x25519-mlkem768-only" if mode == "hybrid-only" else "x25519-mlkem768"
        shape = 'fingerprint "chrome";' if mode == "chrome" else ""
        file = root / "client.kdl"
        file.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="vless" {{
  server host="127.0.0.1" port={server}
  authentication {{ uuid-file "{root / 'uuid'}"; }}
  tls {{ server-name "localhost"; key-exchange "{group}"; {shape}
         reality {{ public-key "{public.hex()}"; short-id "{SHORT}"; }}; }}
}}
routing {{ default-outbound "edge"; }}
''')
        return [binary, "run", "--config", file]
    file = root / "client.json"
    if kind == "xray":
        file.write_text(json.dumps({"log":{"loglevel":"error"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"auth":"noauth"}}],
            "outbounds":[{"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":server,"users":[{"id":UUID,"encryption":"none"}]}]},
                "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
                    "serverName":"localhost","fingerprint":"chrome" if mode=="hybrid" else "hellosafari_16_0",
                    "password":encode(public),"shortId":SHORT}}}]}))
        return [xray, "run", "-config", file]
    file.write_text(json.dumps({"log":{"level":"error"},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":port}],
        "outbounds":[{"type":"vless","server":"127.0.0.1","server_port":server,"uuid":UUID,
            "tls":{"enabled":True,"server_name":"localhost","utls":{"enabled":True,"fingerprint":"chrome"},
                   "reality":{"enabled":True,"public_key":encode(public),"short_id":SHORT}}}]}))
    return [SING_BOX, "run", "-c", file]
def relay_matrix(binary, root, seed, public, xray, tls_cover):
    # The TLS cover advertises h2 and TLS 1.3 to the independent implementations.
    origin, port, stop = start_tcp_echo()
    covers = {HYBRID: reserve(), X25519: reserve()}
    cases = [("nexus", "nexus", mode, HYBRID if mode!="classical" else X25519)
             for mode in ("classical", "hybrid", "hybrid-only", "chrome")]
    cases += [("nexus", "sing-box", "hybrid", None), ("nexus", "sing-box", "classical", X25519),
              ("sing-box", "nexus", "classical", X25519)]
    if xray:
        cases += [("nexus", "xray", mode, group) for mode,group in (
            ("hybrid",HYBRID),("hybrid",X25519),("classical",X25519))]
        cases += [("xray", "nexus", mode, group) for mode,group in (("hybrid",HYBRID),("classical",X25519))]
    try:
        with ExitStack() as stack:
            for group, cover in covers.items():
                stack.enter_context(process([tls_cover,f"127.0.0.1:{cover}",root/"cert",root/"key",
                    "hybrid" if group==HYBRID else "classical"]))
            for client, server, mode, selected in cases:
                remote, front = reserve(), reserve()
                cover = covers[selected] if server=="xray" and selected else covers[HYBRID]
                server_cmd = server_config(binary,server,root,remote,cover,seed,xray)
                with running(server_cmd,remote,root/"server.log"), WireObserver(remote) as wire:
                    client_cmd = client_config(binary,client,root,front,wire.port,public,mode,xray)
                    with running(client_cmd,front,root/"client.log"):
                        with socks(front,1,("127.0.0.1",port))[0] as stream:
                            payload=bytes(range(256))*32
                            stream.sendall(payload)
                            assert exact(stream,len(payload))==payload
                            stream.shutdown(socket.SHUT_WR)
                            assert stream.recv(1)==b""
                assert len(wire.messages)==1,wire.messages
                offered, negotiated=wire.messages[0]
                if client=="nexus":
                    expected=[X25519] if mode=="classical" else [HYBRID] if mode=="hybrid-only" else [HYBRID,X25519]
                    assert offered==expected,(offered,expected)
                assert selected is None or negotiated==selected,(offered,negotiated,selected)
                print(f"{client} -> {server} {mode}: shares={[hex(group) for group in offered]}, selected={negotiated:#06x}, VLESS echo/FIN")
    finally:
        stop.set()
        origin.close()

def fallback(binary, root, seed, public, fixture):
    port = reserve()
    with socket.socket() as cover, ThreadPoolExecutor(2) as pool:
        cover.bind(("127.0.0.1",0))
        cover.listen(8)
        cover.settimeout(5)
        cmd = server_config(binary,"nexus",root,port,cover.getsockname()[1],seed,None)
        with running(cmd,port,root/"fallback.log") as server:
            cover.accept()[0].close()
            files = Path(f"/proc/{server.pid}/fd")
            time.sleep(.05)
            baseline=len(list(files.iterdir()))
            for address in (cover.getsockname()[1],port):
                for termination in ("client-fin","cover-fin","cover-rst"):
                    def origin():
                        with cover.accept()[0] as peer:
                            peer.settimeout(4)
                            assert exact(peer,1)==b"?"
                            if termination=="cover-rst":
                                peer.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
                                return
                            if termination=="client-fin":
                                assert peer.recv(1)==b""
                            peer.sendall(b"reply")
                            peer.shutdown(socket.SHUT_WR)
                            if termination=="cover-fin":
                                assert exact(peer,1)==b"!"
                                assert peer.recv(1)==b""

                    future=pool.submit(origin)
                    with socket.create_connection(("127.0.0.1",address),timeout=4) as client:
                        client.sendall(b"?")
                        if termination=="client-fin":
                            client.shutdown(socket.SHUT_WR)
                        if termination=="cover-rst":
                            try:
                                client.recv(1)
                            except ConnectionResetError:
                                pass
                            else:
                                raise AssertionError(f"expected RST on port {address}")
                        else:
                            assert exact(client,5)==b"reply" and client.recv(1)==b""
                            if termination=="cover-fin":
                                client.sendall(b"!")
                                client.shutdown(socket.SHUT_WR)
                    future.result()
            server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(root/"cert",root/"key")
            client_context=ssl.create_default_context(cafile=str(root/"cert"))
            def origin_tls():
                with cover.accept()[0] as peer, server_context.wrap_socket(peer,server_side=True) as stream:
                    assert exact(stream,3)==b"get"
                    stream.sendall(b"ok")

            future=pool.submit(origin_tls)
            with client_context.wrap_socket(socket.create_connection(("127.0.0.1",port)),server_hostname="localhost") as client:
                client.sendall(b"get")
                assert exact(client,2)==b"ok"
            future.result()
            for short,age in (("ff",0),(SHORT,30)):
                wire=subprocess.check_output([fixture,str(port),public.hex(),"localhost","1",short,"--hello-age",str(age)])
                for address in (cover.getsockname()[1],port):
                    with socket.create_connection(("127.0.0.1",address),timeout=4) as client:
                        client.sendall(wire)
                        with cover.accept()[0] as peer:
                            peer.settimeout(4)
                            assert exact(peer,len(wire))==wire
                            peer.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack("ii",1,0))
                        try:
                            client.recv(1)
                        except ConnectionResetError:
                            pass
                        else:
                            raise AssertionError("bad REALITY identity failed to mirror cover reset")
            eventually(lambda:len(list(files.iterdir()))==baseline)
        print("REALITY fallback matched direct FIN/RST, normal TLS, invalid and expired identities, and released all FDs")


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("binary",type=Path)
    parser.add_argument("fixture",type=Path)
    parser.add_argument("--xray",type=Path)
    parser.add_argument("--cover",type=Path,required=True)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-94a-reality-") as directory:
        root=Path(directory)
        seed, public=credentials(root)
        relay_matrix(args.binary.resolve(),root,seed,public,args.xray,args.cover.resolve())
        fallback(args.binary.resolve(),root,seed,public,args.fixture.resolve())
