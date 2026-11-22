#!/usr/bin/env python3
"""Production ordered routing with independent TLS, Trojan and VLESS peers."""
import hashlib
from pathlib import Path
import re
import select
import socket
import ssl
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

from anytls_network import Origin
from ordered_tcp_network import headers
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request
from proxy_listener_reload_network import reload
from traffic_rule_reload import reload_rules, replace


def certificates(root):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,DNS:outer.example",
                    "-keyout", root/"key", "-out", root/"cert"], check=True, capture_output=True)


def config(front, program, extra="", sets=""):
    return f'''schema-version 1
role "client"
log {{ privacy "verbose"; }}
inbound "front" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
{extra}
routing {{
  {sets}
  tcp-program sniff-timeout-ms=1000 unknown="skip" {{
    {program}
  }}
  default-outbound "direct"
}}
'''


def listen():
    server = socket.socket()
    server.bind(("127.0.0.1",0))
    server.listen()
    server.settimeout(4)
    return server


def capture_proxy(listener, root, protocol):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/"cert",root/"key")
    raw,_ = listener.accept()
    with raw, context.wrap_socket(raw,server_side=True) as stream:
        if protocol == "trojan":
            assert exact(stream,59) == hashlib.sha224(b"credential").hexdigest().encode()+b"\r\n\1"
            kind = exact(stream,1)[0]
            name = exact(stream,exact(stream,1)[0]).decode() if kind==3 else socket.inet_ntoa(exact(stream,4))
            port = int.from_bytes(exact(stream,2),"big")
            assert exact(stream,2)==b"\r\n"
        else:
            assert exact(stream,19)==b"\0"+bytes(range(16))+b"\0\1"
            port = int.from_bytes(exact(stream,2),"big")
            kind = exact(stream,1)[0]
            name = exact(stream,exact(stream,1)[0]).decode() if kind==2 else socket.inet_ntoa(exact(stream,4))
            stream.sendall(b"\0\0")
        stream.sendall(exact(stream,15))
    return kind,name,port


def route_only(binary, root):
    front = free_port()
    conf = root/"route.kdl"
    (root/"pass").write_text("credential")
    (root/"uuid").write_text("00010203-0405-0607-0809-0a0b0c0d0e0f")
    for name in ("pass","uuid"):
        (root/name).chmod(0o600)
    with DnsPeer() as dns, listen() as edge, Echo() as origin, ThreadPoolExecutor(1) as work:
        for protocol in ("trojan","vless"):
            endpoint = edge.getsockname()[1]
            field, file = ("password-file","pass") if protocol=="trojan" else ("uuid-file","uuid")
            extra = f'''outbound "edge" type="{protocol}" {{
 server host="127.0.0.1" port={endpoint}
 authentication {{ {field} "{root/file}"; }}
 tls {{ server-name "localhost"; ca-file "{root/'cert'}"; verify #true; }}
}}
dns {{
 server "resolver" type="udp" host="127.0.0.1" port={dns.port}
 strategy "ipv4_only"
 final "resolver"
}}
'''
            for only in (True,False):
                name = f"original-{protocol}-{int(only)}.test"
                action = 'rule { action "resolve" route-only=#true; }' if only else 'rule action="resolve" route-only=#false'
                conf.write_text(config(front,f'''{action}
rule action="route" outbound="edge" {{ ip-cidr "127.0.0.0/8"; }}
rule action="reject"''',extra))
                with nexus_process(binary,conf):
                    captured = work.submit(capture_proxy,edge,root,protocol)
                    stream_request(front,origin.port,name)
                    kind, remote, port = captured.result(timeout=5)
                    expected_kind = (3 if protocol=="trojan" else 2) if only else 1
                    assert (kind,remote,port)==(expected_kind,name if only else "127.0.0.1",origin.port), (kind,remote,port)
                    assert dns.count(name,1)==1
                explain=subprocess.check_output([binary,"rule","explain",conf,"front","tcp",
                    f"{name}:{origin.port}","resolved-ip=127.0.0.1"],text=True)
                assert ("resolve(route-only)" in explain)==only and "outbound=edge" in explain,explain
                print(f"PASS {protocol} route-only={only}: local CIDR matched, peer received kind={kind} target={remote}")
        conf.write_text(config(front,'''rule action="resolve" route-only=#true
rule action="route" outbound="direct" { ip-cidr "127.0.0.0/8"; }
rule action="reject"''',extra[extra.index("\ndns {"):]))
        with nexus_process(binary,conf):
            stream_request(front,origin.port,"direct-reuse.test")
            assert dns.count("direct-reuse.test",1)==1
        print("PASS direct reused route-only DNS candidates")


def logical(binary, root):
    front = free_port()
    conf = root/"logical.kdl"
    rules = root/"corp.kdl"
    alias = root/"alias.kdl"
    prologue = 'schema-version 2\nkind "predicate"\n'
    replace(alias, (prologue+'rule-set "corp"\n').encode())
    good = (prologue+'ip-cidr "127.0.0.0/8"\n').encode()
    replace(rules, good)
    conf.write_text(config(front,'''rule action="route" outbound="direct" {
    all { rule-set "alias"; not { port 443; }; }
}
rule action="reject"''',sets='''rule-set "corp" path="corp.kdl" format="kdl"
rule-set "alias" path="alias.kdl" format="kdl"'''))
    with Origin(idle_timeout=15) as origin, nexus_process(binary,conf) as process:
        with socket.create_connection(("127.0.0.1",front),timeout=4) as active:
            active.sendall(b"\5\1\0")
            assert exact(active,2)==b"\5\0"
            active.sendall(b"\5\1\0\1\x7f\0\0\1"+origin.port.to_bytes(2,"big"))
            assert exact(active,10)[:2]==b"\5\0"
            replace(rules,(prologue+'rule-set "alias"\n').encode())
            reload_rules(process,False,b"cyclic rule-set")
            stream_request(front,origin.port,"127.0.0.1",http=True)
            replace(rules,(prologue+'rule-set "absent"\n').encode())
            reload_rules(process,False,b"unknown or empty rule-set")
            stream_request(front,origin.port,"127.0.0.1",http=True)
            replace(rules,(prologue+'ip-cidr "192.0.2.0/24"\n').encode())
            reload(process)
            stream_request(front,origin.port,"127.0.0.1",http=True,success=False)
            active.sendall(b"retained")
            assert exact(active,8)==b"retained"
            replace(rules,good)
            reload(process)
            stream_request(front,origin.port,"127.0.0.1",http=True)
        explain=subprocess.check_output([binary,"rule","explain",conf,"front","tcp","127.0.0.1:443"],text=True)
        assert "reject" in explain and "rule=2" in explain,explain
    print("PASS recursive rule-set, all/not, hot reload, rejected cycle/unknown, and retained TCP session")


def join_tls(listener, front, port, socks=False):
    remote,_ = listener.accept()
    with remote, socket.create_connection(("127.0.0.1",front),timeout=4) as proxy:
        remote.settimeout(4)
        hello = exact(remote,5)
        data = hello+exact(remote,int.from_bytes(hello[3:5],"big"))
        if socks:
            proxy.sendall(b"\5\1\0")
            assert exact(proxy,2)==b"\5\0"
            proxy.sendall(b"\5\1\0\1\x7f\0\0\1"+port.to_bytes(2,"big")+data)
            reply=exact(proxy,4)
            exact(proxy,6 if reply[3]==1 else 18)
            if reply[1]==2:
                return False
            assert reply[1]==0,reply
        else:
            authority=f"127.0.0.1:{port}"
            request=f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
            proxy.sendall(request+data)
            reply=headers(proxy)
            if reply.startswith(b"HTTP/1.1 403 "):
                return False
            assert reply.startswith(b"HTTP/1.1 200 "),reply
        while True:
            ready,_,_ = select.select([remote,proxy],[],[],4)
            assert ready,"TLS relay stalled"
            for source in ready:
                try:
                    chunk=source.recv(65536)
                    if not chunk:
                        return True
                    (remote if source is proxy else proxy).sendall(chunk)
                except (BrokenPipeError,ConnectionResetError):
                    return True


def tls_routes(binary, root):
    conf = root/"tls.kdl"
    key = root/"ech.pem"
    subprocess.run(["openssl","ech","-public_name","outer.example","-out",key],check=True,capture_output=True)
    block = re.search(r"-----BEGIN ECHCONFIG-----\n(.*?)-----END ECHCONFIG-----",key.read_text(),re.S)
    modes = [
        ("plain",[],b"ECH not attempted"),
        ("real",["-ech_config_list","".join(block.group(1).split())],b"ECH success: outer sni: outer.example, inner sni: localhost"),
        ("grease",["-ech_grease","-ech_grease_type","65037"],b"ECH attempt we interpret as GREASE"),
    ]
    port, front = free_port(),free_port()
    with (root/"tls-origin.log").open("wb") as output:
        peer = subprocess.Popen(["openssl","s_server","-accept",f"127.0.0.1:{port}",
            "-cert",root/"cert","-key",root/"key","-tls1_3","-ech_key",key,"-www"],stdout=output,stderr=output)
        try:
            with connect(port):
                pass
            for predicate, allowed in [('protocol "tls"',{"plain","real","grease"}),
                                       ('protocol "tls-ech"',{"real","grease"}),
                                       ('tls-ech #true',{"real","grease"}),('tls-ech #false',{"plain"})]:
                conf.write_text(config(front,f'''rule action="sniff"
rule action="route" outbound="direct" {{ {predicate}; }}
rule action="reject"'''))
                with nexus_process(binary,conf), ThreadPoolExecutor(1) as worker:
                    for socks in (False,True):
                        for name, args, evidence in modes:
                            with listen() as middle:
                                relay=worker.submit(join_tls,middle,front,port,socks)
                                result=subprocess.run(["openssl","s_client","-connect",f"127.0.0.1:{middle.getsockname()[1]}",
                                    "-tls1_3","-servername","localhost","-CAfile",root/"cert","-verify_hostname","localhost",
                                    "-verify_return_error","-brief","-ign_eof",*args],input=b"GET / HTTP/1.0\r\n\r\n",
                                    capture_output=True,timeout=6)
                                assert relay.result(timeout=4)==(name in allowed),(predicate,name,result.stderr)
                                if name in allowed:
                                    assert result.returncode==0 and evidence in result.stdout,(predicate,name,result.stderr,result.stdout)
                                    assert b"Protocol version: TLSv1.3" in result.stderr
                for metadata,mode in ((["protocol=tls","tls-ech=false"],"plain"),(["protocol=tls-ech"],"real")):
                    detail=subprocess.check_output([binary,"rule","explain",conf,"front","tcp",
                        f"127.0.0.1:{port}",*metadata],text=True)
                    assert ("outbound=direct" in detail)==(mode in allowed),detail
                print(f"PASS {predicate} over HTTP CONNECT and SOCKS5: {', '.join(sorted(allowed))}")
            conf.write_text(config(front,'''rule action="sniff"
rule action="route" outbound="direct" { not { tls-ech #true; }; }
rule action="reject"'''))
            with nexus_process(binary,conf), Echo() as origin:
                with socket.create_connection(("127.0.0.1",front),timeout=4) as active:
                    active.sendall(b"\5\1\0")
                    assert exact(active,2)==b"\5\0"
                    active.sendall(b"\5\1\0\1\x7f\0\0\1"+origin.port.to_bytes(2,"big")+b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    assert exact(active,2)==b"\5\2"
            print("PASS non-TLS ECH remains unknown through NOT")
        finally:
            peer.terminate()
            peer.wait(timeout=5)


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-93a-network-") as folder:
        root = Path(folder)
        certificates(root)
        route_only(cli,root)
        logical(cli,root)
        tls_routes(cli,root)
