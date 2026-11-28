#!/usr/bin/env python3
"""Reload DNS rules and traffic rules as a single production generation."""
import contextlib
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time

from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request, wire_name
from traffic_rule_reload import greet, pending_request, reload_rules, replace


def rules(name):
    return f'schema-version 2\nkind "predicate"\nrule type="domain" value="{name}"\n'.encode()


def send_tcp_query(client, name, identifier):
    query = struct.pack("!HHHHHH",identifier,0x100,1,0,0,0) + wire_name(name) + b"\0\1\0\1"
    client.sendall(struct.pack("!H",len(query)) + query)


def recv_tcp(client, identifier, expected):
    wire = exact(client,int.from_bytes(exact(client,2),"big"))
    txid,flags,_,answers = struct.unpack_from("!4H",wire)
    assert (txid,flags&15) == (identifier,expected),wire
    assert bool(answers) == (not expected),wire


def ask_udp(port, name, expected):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        query = struct.pack("!HHHHHH",1,0x100,1,0,0,0) + wire_name(name) + b"\0\1\0\1"
        client.sendto(query,("127.0.0.1",port))
        response=client.recv(1024)
        assert response[:2]==query[:2] and response[3]&15==expected,response


binary=str(Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as origin:
    root = Path(directory)
    front, dns_port = free_port(), free_port()
    route = root / "route.kdl"
    policy = root / "dns.kdl"
    route.write_bytes(rules("unused-route.test"))
    policy.write_bytes(rules("unused-dns.test"))
    cfg = root / "nexus.kdl"
    cfg.write_text(f"""schema-version 1
role "client"
workers 2
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}; }}
outbounds {{ direct "direct"; block "drop"; }}
dns {{
  listen host="127.0.0.1" port={dns_port}
  server "business" type="udp" host="127.0.0.1" port={dns.port}
  disable-cache #true
  strategy "ipv4_only"
  final "business"
  rulesets {{ "dns" path="dns.kdl" format="kdl"; }}
  rule rule-set="dns" action="reject"
}}
routing {{
  rulesets {{ "traffic" path="route.kdl" format="kdl"; }}
  rules {{ - rule-set="traffic" to="drop"; }}
  final "direct"
}}
""")
    with nexus_process(binary,str(cfg)) as process, contextlib.ExitStack() as active:
        previous=active.enter_context(connect(front))
        greet(previous)
        tcp=active.enter_context(socket.create_connection(("127.0.0.1",dns_port),timeout=3))
        gate=threading.Event()
        dns.gates["fresh.test",1]=gate
        send_tcp_query(tcp,"fresh.test",100)
        deadline=time.monotonic()+2
        while not dns.count("fresh.test",1) and time.monotonic()<deadline:
            time.sleep(.01)
        assert dns.count("fresh.test",1)
        replace(route,rules("blocked.test"))
        replace(policy,b"malformed rules")
        reload_rules(process,False,b"DNS rule-set")
        gate.set()
        recv_tcp(tcp,100,0)
        stream_request(front,origin.port,"blocked.test",success=True)
        gate.clear()
        send_tcp_query(tcp,"fresh.test",101)
        deadline=time.monotonic()+2
        while dns.count("fresh.test",1)<2 and time.monotonic()<deadline:
            time.sleep(.01)
        assert dns.count("fresh.test",1)==2
        replace(policy,rules("fresh.test"))
        try:
            reload_rules(process,True)
        finally:
            gate.set()
        recv_tcp(tcp,101,0)
        pending_request(previous,origin.port,allowed=True)
        send_tcp_query(tcp,"fresh.test",102)
        recv_tcp(tcp,102,5)
        ask_udp(dns_port,"fresh.test",5)
        stream_request(front,origin.port,"fresh.test",success=False,code=2)
        stream_request(front,origin.port,"blocked.test",success=False,code=2)
        stream_request(front,origin.port,"allowed.test")
        replace(policy,rules("unused-dns.test"))
        reload_rules(process,True)
        send_tcp_query(tcp,"fresh.test",103)
        recv_tcp(tcp,103,0)
        stream_request(front,origin.port,"fresh.test")
print("DNS TCP/UDP and internal DNS changed together with traffic rules, with failed-candidate rollback and old-query/session retention")
