import contextlib
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from connect_traffic_stats import snapshot, trojan_server
from dns_rule_support import DnsPeer, dns_request
from tproxy_udp_dns_support import verify_dns_hijack

def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def ns(pid,*args):
    return command("nsenter","-t",str(pid),"-n",*args)

def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

def network_namespace(stack):
    proc=subprocess.Popen(["unshare","-n","sh","-c","echo ready; exec sleep 90"],stdout=subprocess.PIPE)
    stack.callback(stop,proc)
    assert proc.stdout.readline()==b"ready\n"
    ns(proc.pid,"ip","link","set","lo","up")
    return proc.pid

def veth(peer, local, foreign):
    command("ip","link","add",local,"type","veth","peer","name",foreign)
    command("ip","link","set",foreign,"netns",str(peer))
    command("ip","link","set",local,"up")
    ns(peer,"ip","link","set",foreign,"up")

def ready(process,stdout=False):
    pipe=process.stdout if stdout else process.stderr
    if select.select([pipe],[],[],5)[0]:
        return pipe.readline()
    raise AssertionError("child output did not arrive")

def launch_namespace(stack, pid, script, *args):
    proc=subprocess.Popen(["nsenter","-t",str(pid),"-n",sys.executable,"-c",script,*map(str,args)],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    stack.callback(stop,proc)
    return proc

def endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

class TargetDns(DnsPeer):
    def __init__(self, real_address):
        super().__init__()
        family = socket.AF_INET6 if ":" in real_address else socket.AF_INET
        self.kind = 28 if family == socket.AF_INET6 else 1
        self.real = socket.inet_pton(family, real_address)

    def reply(self, packet, transport):
        wire = super().reply(packet, transport)
        return wire[:-len(self.real)] + self.real

def fake_dns(case, root, transport_address):
    peer=case.enter_context(TargetDns(transport_address))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1",0))
        port=reservation.getsockname()[1]
    state=root/"state"
    state.mkdir(mode=0o700)
    for name,size in (("instance.id",16),("history.key",32)):
        path=state/name
        path.touch(mode=0o600)
        path.write_bytes(os.urandom(size))
    strategy="ipv6_only" if peer.kind==28 else "ipv4_only"
    dns=f'''dns {{
        listen host="127.0.0.1" port={port}
        server "protected" type="udp" host="127.0.0.1" port={peer.port}
        final "protected"
        strategy "{strategy}"
        fake-ip server="protected" ipv4-pool="198.18.0.0/29" ipv6-pool="fd15:4231::/96" ttl-seconds=2 state-directory="{state}" initialize=#true
    }}'''
    return port, peer.kind, dns

def verify(binary, client_ns, origin_ns, family, listener_address, client_address, target_address,
           firewall, tunneled, check_route, fakeip=False, check_interface=False):
    with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as case:
        root=Path(directory)
        edge=case.enter_context(trojan_server(binary,root)) if tunneled else ""
        origin=launch_namespace(case,origin_ns,'''import socket,sys
with socket.socket(int(sys.argv[1]),socket.SOCK_DGRAM) as peer:
    peer.bind((sys.argv[2],0)); peer.settimeout(25)
    print(peer.getsockname()[1],flush=True)
    for payload in (b'',b'payload'):
        got,remote=peer.recvfrom(128)
        assert got==payload, got
        peer.sendto(got[::-1],remote)
''',family,target_address)
        target_port=int(ready(origin,True))
        with socket.socket(family) as spare:
            spare.bind((listener_address,0))
            listener_port=spare.getsockname()[1]
        config=root/"tproxy.kdl"
        control=root/"control.sock"
        original_address=target_address
        dns_config=""
        if fakeip:
            dns_port,qtype,dns_config=fake_dns(case,root,target_address)
            original_address="fd15:4231::c612:1" if qtype==28 else "198.18.0.1"
        (root/"uid.kdl").write_text(
            'schema-version 2\nkind "predicate"\nrule type="source-uid" value="0"\n')
        (root/"process.kdl").write_text(
            'schema-version 2\nkind "predicate"\nrule type="not" { rule type="process-name" value="unrelated"; }\n')
        outbound="edge" if tunneled else "direct"
        if tunneled:
            route='''tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {
                rule action="reject" rule-set="uid"
                rule action="reject" rule-set="process"
                rule action="sniff"
                rule action="route" outbound="edge"
            }'''
        else:
            route='''rule kind="rule-set" value="uid" outbound="deny"
                rule kind="rule-set" value="process" outbound="deny"'''
        alias_rule=""
        if fakeip:
            (root/"alias.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="origin.test"\n')
            alias_rule='rule-set "alias" path="alias.kdl" format="kdl"'
            if tunneled:
                route=route.replace('rule action="route" outbound="edge"',
                    'rule action="route" rule-set="alias" domain-source="fakeip" outbound="edge"\n                rule action="reject"')
            else:
                route+='\n    rule kind="rule-set" value="alias" outbound="direct"'
        ingress_rule=""
        if check_interface:
            ingress='rule type="source-interface" value="nxclienthost"'
            predicate=ingress if not fakeip else (
                'rule type="and" { '+ingress+'; rule type="domain" value="origin.test"; }')
            (root/"ingress.kdl").write_text('schema-version 2\nkind "predicate"\n'+predicate+'\n')
            ingress_rule='rule-set "ingress" path="ingress.kdl" format="kdl"'
            if fakeip:
                alias_rule=""
            if tunneled:
                route=route.replace('rule-set="alias"', 'rule-set="ingress"') if fakeip else route.replace(
                    'rule action="route" outbound="edge"',
                    'rule action="route" rule-set="ingress" outbound="edge"\n                rule action="reject"')
            else:
                if fakeip:
                    route=route.replace('value="alias" outbound="direct"', 'value="ingress" outbound="direct"')
                else:
                    route+='\n    rule kind="rule-set" value="ingress" outbound="direct"'
                ingress_rule+='\n    rule-set "all" path="all.kdl" format="kdl"'
                (root/"all.kdl").write_text(
                    'schema-version 2\nkind "predicate"\nrule type="network" value="udp"\n')
                route+='\n    rule kind="rule-set" value="all" outbound="deny"'
        config.write_text(f'''schema-version 1
role "client"
workers 2
control socket="{control}"
inbounds {{ tproxy "local" {{ udp #true; listen host="{listener_address}" port={listener_port}; }}; }}
outbounds {{ direct "direct" {{ routing-mark 20804; }}; block "deny"; {edge} }}
{dns_config}
routing {{
    rule-set "uid" path="uid.kdl" format="kdl"
    rule-set "process" path="process.kdl" format="kdl"
    {alias_rule}
    {ingress_rule}
    {route}
    default-outbound "{outbound}"
}}
''')
        rule=("-i","nxclienthost","-p","udp","-d",original_address,"--dport",str(target_port),"-j","TPROXY",
              "--on-ip",listener_address,"--on-port",str(listener_port),"--tproxy-mark","42")
        command(firewall,"-t","mangle","-A","PREROUTING",*rule)
        try:
            proxy=subprocess.Popen([binary,"run","--traffic-stats","--config",str(config)],
                                   stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,bufsize=0)
            try:
                for _ in range(100):
                    assert proxy.poll() is None,proxy.stderr.read()
                    try:
                        with socket.create_connection((listener_address,listener_port),timeout=.1):
                            break
                    except OSError:
                        time.sleep(.03)
                else:
                    raise AssertionError("TPROXY listener did not start")
                if fakeip:
                    deadline=time.monotonic()+16
                    while True:
                        status,published=dns_request(dns_port,"origin.test",kind=qtype)
                        if status==0:
                            assert published==original_address, published
                            break
                        assert status==2 and time.monotonic()<deadline, status
                        time.sleep(.2)
                client=launch_namespace(case,client_ns,'''import select, socket, sys
family = int(sys.argv[1]); endpoint = (sys.argv[2], int(sys.argv[3]))
with socket.socket(family,socket.SOCK_DGRAM) as first, socket.socket(family,socket.SOCK_DGRAM) as second:
    for peer in (first, second):
        peer.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
    first.bind((sys.argv[4],0))
    second.bind(first.getsockname())
    for sender,payload in ((first,b''),(second,b'payload')):
        sender.sendto(payload,endpoint)
        readable,_,_=select.select((first,second),(),(),5)
        assert readable, 'reply did not arrive'
        reply,source=readable[0].recvfrom(128)
        assert reply==payload[::-1] and source[:2]==endpoint, (reply,source)
    print(first.getsockname()[1],flush=True)
''',family,original_address,target_port,client_address)
                output=ready(client,True)
                assert output,client.stderr.read()
                source_port=int(output)
                client.wait(timeout=5)
                origin.wait(timeout=5)
                assert client.returncode==0,client.stderr.read()
                assert origin.returncode==0,origin.stderr.read()
                totals,rows=snapshot(proxy,1)
                assert totals==(7,7) and int(rows["tproxy-udp"]["source-port"])==source_port, (totals,rows)
                assert int(rows["tproxy-udp"]["destination-port"])==target_port, rows
                listing=command(binary,"control",str(control),"connections","0")
                udp_rows=[line for line in listing.splitlines() if "protocol=tproxy-udp " in line]
                assert len(udp_rows)==1, listing
                fields=dict(field.split("=",1) for field in udp_rows[0].split())
                assert fields["transport-source"]==endpoint(client_address,source_port), fields
                assert fields["original-destination"]==endpoint(original_address,target_port), fields
                assert int(fields["ingress-ifindex"])==socket.if_nametoindex("nxclienthost"), fields
                assert {"source-uid","process-path"}.isdisjoint(fields), fields
                if check_route:
                    assert fields["route-generation"]=="1" and fields["outbound"]==outbound, fields
                    assert fields["route-target"]==endpoint(target_address,target_port), fields
                    assert fields["route-mode"]==("ordered" if tunneled else "indexed"), fields
                    assert fields["route-rule"]==("4" if tunneled else "3" if fakeip or check_interface else "default"), fields
                evidence=command(firewall,"-t","mangle","-L","PREROUTING","-v","-x","-n")
                assert any(int(line.split()[0])>0 for line in evidence.splitlines() if "TPROXY" in line), evidence
                print(f"{family.name} {outbound}: {udp_rows[0]}",flush=True)
            finally:
                stop(proxy)
            assert proxy.returncode==0,proxy.stderr.read()
        finally:
            command(firewall,"-t","mangle","-D","PREROUTING",*rule)

if "--isolated" not in sys.argv:
    raise SystemExit(subprocess.call(["unshare","-Urn",sys.executable,__file__,*sys.argv[1:],"--isolated"]))

with contextlib.ExitStack() as stack:
    command("ip","link","set","lo","up")
    client_ns=network_namespace(stack)
    origin_ns=network_namespace(stack)
    veth(client_ns,"nxclienthost","nxclient")
    veth(origin_ns,"nxoriginhost","nxorigin")
    for family, flag, firewall, link in (
        (socket.AF_INET,"-4","iptables",("192.0.2.1","192.0.2.2","198.51.100.1","198.51.100.2",24)),
        (socket.AF_INET6,"-6","ip6tables",("2001:db8:1::1","2001:db8:1::2","2001:db8:2::1","2001:db8:2::2",64)),
    ):
        listen, client, egress, target, prefix = link
        extras=() if family==socket.AF_INET else ("nodad",)
        command("ip",flag,"addr","add",f"{listen}/{prefix}","dev","nxclienthost",*extras)
        command("ip",flag,"addr","add",f"{egress}/{prefix}","dev","nxoriginhost",*extras)
        ns(client_ns,"ip",flag,"addr","add",f"{client}/{prefix}","dev","nxclient",*extras)
        ns(origin_ns,"ip",flag,"addr","add",f"{target}/{prefix}","dev","nxorigin",*extras)
        ns(client_ns,"ip",flag,"route","add","default","via",listen)
        command("ip",flag,"rule","add","fwmark","42","lookup","42")
        command("ip",flag,"route","add","local","default","dev","lo","table","42")
        if "--dns-hijack" in sys.argv:
            verify_dns_hijack(sys.argv[1], client_ns, family, listen, target, firewall, command, ns)
            continue
        for tunneled in (False, True):
            verify(sys.argv[1],client_ns,origin_ns,family,listen,client,target,firewall,tunneled,
                   "--route-observation" in sys.argv, "--fakeip" in sys.argv, "--source-interface" in sys.argv)
if "--dns-hijack" not in sys.argv:
    print("UDP TPROXY preserved endpoints and ingress with unknown UID/process for cross-namespace unconnected reuseport sockets")
