#!/usr/bin/env python3
"""Exercise FakeIP through the Linux TUN business data plane in a test netns."""
import os
import select
from proxy_listener_reload_network import reload as reload_listeners
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

from dns_rule_support import DnsPeer, Echo, exact, free_port, wire_name


def address(port, query_type, name="target.test"):
    request=struct.pack("!HHHHHH",query_type,0x0100,1,0,0,0)+wire_name(name)+struct.pack("!HH",query_type,1)
    deadline=time.monotonic()+14
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        while time.monotonic()<deadline:
            sock.sendto(request,("127.0.0.1",port))
            response=sock.recv(1024)
            _,flags,_,answers=struct.unpack_from("!4H",response)
            if answers==1 and not flags&15:
                family,length=(socket.AF_INET,4) if query_type==1 else (socket.AF_INET6,16)
                return socket.inet_ntop(family,response[-length:])
            assert flags&15==2 and answers==0,response
            time.sleep(.2)
    raise RuntimeError("FakeIP quarantine did not end")


def ip(*args):
    subprocess.run(["ip",*args],check=True,capture_output=True)


binary=str(Path(sys.argv[1]).resolve(strict=True))
namespace=os.stat("/proc/self/ns/net").st_ino
if len(sys.argv)==2 or sys.argv[2]=="--policy-view":
    subprocess.run(["unshare","-Urn","--",sys.executable,"-u",__file__,binary,str(namespace),*sys.argv[2:]],check=True)
    sys.exit(0)
if int(sys.argv[2])==namespace:
    raise RuntimeError("FakeIP TUN test requires an isolated network namespace")
ip("link","set","lo","up")
with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns, Echo() as echo:
    root=Path(directory)
    state=root/"state"
    state.mkdir(mode=0o700)
    for name,size in (("instance.id",16),("history.key",32)):
        credential=state/name
        credential.touch(mode=0o600)
        credential.write_bytes(os.urandom(size))
    listener=free_port()
    config=root/"proxy.kdl"
    dns_rules=""
    policy_view="--policy-view" in sys.argv
    if policy_view:
        rule_file=root/"dns.kdl"
        rule_file.write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="unrelated.test"\n')
        dns_rules='rulesets { reload path="dns.kdl" format="kdl"; }\n  rule rule-set="reload" action="reject"'
    config.write_text(f"""schema-version 1
role "client"
inbounds {{
  tun "os" {{
    interface-name "nx-fake"
    inet4-address "10.99.0.1/30"
    inet6-address "fd81::1/64"
    endpoint-independent-nat #false
  }}
}}
outbounds {{ direct "direct"; }}
dns {{
  listen host="127.0.0.1" port={listener}
  server "business" type="udp" host="127.0.0.1" port={dns.port}
  final "business"
  strategy "ipv4_only"
  {dns_rules}
  fake-ip server="business" ipv4-pool="198.18.12.0/29" ipv6-pool="fd15:42::/96" ttl-seconds=2 state-directory="{state}" initialize=#true
}}
routing {{ final "direct"; }}
""")
    command=["stdbuf","-oL",binary,"run","--config",str(config)]
    with subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as cli:
        try:
            assert select.select([cli.stdout],[],[],5)[0]
            assert b"TUN listening on nx-fake" in cli.stdout.readline()
            ip("route","add","198.18.12.0/29","dev","nx-fake","src","10.99.0.1")
            ip("-6","route","add","fd15:42::/96","dev","nx-fake","src","fd81::1")
            ipv4=address(listener,1)
            ipv6=address(listener,28)
            for family, target in ((socket.AF_INET,ipv4),(socket.AF_INET6,ipv6)):
                with socket.create_connection((target,echo.port),timeout=5) as tcp:
                    tcp.sendall(b"tun tcp")
                    assert exact(tcp,7)==b"tun tcp"
                with socket.socket(family,socket.SOCK_DGRAM) as udp:
                    udp.settimeout(4)
                    udp.sendto(b"tun udp",(target,echo.port))
                    reply,remote=udp.recvfrom(256)
                    assert reply==b"tun udp" and remote[:2]==(target,echo.port),(reply,remote)
            assert dns.count("target.test",1)
            if policy_view:
                def exchange(peer,target,data):
                    peer.sendto(data,(target,echo.port))
                    response,source=peer.recvfrom(256)
                    assert (response,source[:2])==(data,(target,echo.port))

                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as old:
                    old.settimeout(3)
                    exchange(old,ipv4,b"old view")
                    rule_file.write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.test"\n')
                    assert reload_listeners(cli) is None
                    updated=address(listener,1)
                    assert updated!=ipv4,(updated,ipv4)
                    exchange(old,ipv4,b"retained view")
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as current:
                        current.settimeout(3)
                        current.sendto(b"stale alias",(ipv4,echo.port))
                        assert not select.select([current],[],[],.25)[0]
                        exchange(current,updated,b"new view")
                print("TUN UDP retained the old policy view and required the new alias on new flows")
            held=address(listener,1,"held.test")
            dns.drop.add(("held.test",1))
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                udp.sendto(b"held at DNS",(held,echo.port))
            deadline=time.monotonic()+3
            while not dns.count("held.test",1) and time.monotonic()<deadline:
                time.sleep(.02)
            assert dns.count("held.test",1),dns.seen
        finally:
            if cli.poll() is None:
                cli.terminate()
            try:
                stdout,stderr=cli.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                cli.kill()
                cli.communicate(timeout=3)
                raise
            assert cli.returncode==0,(stdout,stderr)
    vanished=subprocess.run(["ip","link","show","nx-fake"],capture_output=True)
    assert vanished.returncode
print("Native TUN IPv4/IPv6 FakeIP TCP and UDP, alias reply sources, active DNS cancellation and device cleanup passed")
