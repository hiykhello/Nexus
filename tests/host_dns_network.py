#!/usr/bin/env python3
"""Production endpoint command with two kernel wireguard-go TUN peers in owned namespaces."""
import argparse,base64,hashlib,json,os,pathlib,select,signal,socket,subprocess,sys,tempfile,time,threading
import wireguard_tun_network as t
import wireguard_port_network as port
from host_dns_peer import build_peer

def ready(process):
    if not select.select([process.stdout],[],[],15)[0]: raise RuntimeError("endpoint readiness timed out")
    line=process.stdout.readline()
    if not line: raise RuntimeError(f"endpoint failed before readiness: {process.poll()} {process.stderr.read()}")
    if ' ready: device=' not in line: raise RuntimeError(line)
    return int(line.strip().split(' port=')[1])

def configure(root,keys,setup,family,role,cookie,default_route=False):
    def key(name,hexadecimal):
        path=root/name;path.write_text(base64.b64encode(bytes.fromhex(hexadecimal)).decode()+'\n');path.chmod(0o600);return path
    secret=key('private',keys['private'])
    text=f'''schema-version 1
role "{role}"
endpoint "wg" type="wireguard" {{
 private-key-file "{secret}"
 listen host="{'::' if family==6 else '0.0.0.0'}" port=0
 device name="nx-wg" mtu=1420
 local-address "10.42.0.1/32"
 local-address "fd42::1/128"
 host-dns {{ backend "resolved"; server "{'fd42::3' if os.environ.get('NEXUS_HOST_DNS_SERVER_FAMILY')=='6' else '10.42.0.2'}"; }}
 startup-timeout-ms 10000
 require-cookie #{str(cookie).lower()}
'''
    for node in (2,3):
        item=setup[node-2];public=key('public'+str(node),item['public']);psk=key('psk'+str(node),item['psk'])
        outer=f'fd00:42:{node}::2' if family==6 else f'192.0.2.{(node-2)*4+2}'
        text+=f''' route-include "10.42.0.{node}/32"
 route-include "fd42::{node}/128"
 peer "p{node}" {{
  public-key-file "{public}"
  preshared-key-file "{psk}"
  endpoint host="{outer}" port={item['port']}
  allowed-ip "10.42.0.{node}/32"
  allowed-ip "fd42::{node}/128"
 }}
'''
    if default_route:
        text='\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('route-include'))+'\n'
        text=text.replace(' startup-timeout-ms 10000',' route-mode "default"\n startup-timeout-ms 10000')
        text=text.replace(' peer "p2" {',' peer "p2" {\n  allowed-ip "0.0.0.0/0"\n  allowed-ip "::/0"')
    if os.environ.get('NEXUS_HOST_DNS_PROVIDER')=='warp':text=text.replace(' startup-timeout-ms 10000',' provider-profile \"warp\"\n reserved 17 34 51\n startup-timeout-ms 10000')
    config=root/'endpoint.kdl';config.write_text(text+'}\n');return config

def inner(binary,reference,family,role,mode,parent_net,parent_user,evidence,hostname=False,parent_mount=None,default_route=False):
    assert os.stat('/proc/self/ns/net').st_ino!=parent_net and os.stat('/proc/self/ns/user').st_ino!=parent_user
    if hostname:
        assert os.stat('/proc/self/ns/mnt').st_ino!=parent_mount
        t.run(['mount','--make-rprivate','/'])
    t.run(['ip','link','set','lo','up']);root=pathlib.Path(tempfile.mkdtemp(prefix='nexus-endpoint-kernel-'))
    peers=[];core=None;echo=None;prefixes=[];setup=[];complete=False
    try:
        keys=port.prepare(root)
        for node in (2,3):
            outer=f'fd00:42:{node}::1' if family==6 else f'192.0.2.{(node-2)*4+1}'
            peer=subprocess.Popen(['unshare','-n',reference,str(node),outer],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            peers.append(peer);t.send(peer,keys['public']);setup.append(t.receive(peer))
            prefix=['nsenter','-t',str(peer.pid),'-n'];prefixes.append(prefix)
            assert os.stat(f'/proc/{peer.pid}/ns/net').st_ino!=os.stat('/proc/self/ns/net').st_ino
            first,second=f'n{node}',f'p{node}'
            t.run(['ip','link','add',first,'type','veth','peer','name',second]);t.run(['ip','link','set',second,'netns',str(peer.pid)])
            for commands,device in (([],first),(prefix,second)):
                t.run(['ip','link','set',device,'up'],commands);suffix=(node-2)*4+(2 if commands else 1)
                t.run(['ip','addr','add',f'192.0.2.{suffix}/30','dev',device],commands)
                t.run(['ip','-6','addr','add',f'fd00:42:{node}::{2 if commands else 1}/64','dev',device,'nodad'],commands)
            t.run(['ip','link','set','lo','up'],prefix);t.configure_tun('wg-go',node,prefix)
        if default_route and mode=='roam':
            t.run(['ip','route','add','default','via','192.0.2.2','dev','n2'])
            t.run(['ip','-6','route','add','default','via','fd00:42:2::2','dev','n2'])
        config=configure(root,keys,setup,family,role,mode=='cookie',default_route)
        (root/'host-dns-config.kdl').write_bytes(config.read_bytes())
        original_filters={name:pathlib.Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').read_text() for name in ('all','default','n2','n3')}
        if mode=='roam':
            text=config.read_text().replace(' route-include "10.42.0.2/32"',' route-include "10.42.0.99/32"\n route-include "fd42::99/128"\n route-include "10.42.0.2/32"').replace('  allowed-ip "10.42.0.2/32"','  allowed-ip "10.42.0.99/32"\n  allowed-ip "fd42::99/128"\n  allowed-ip "10.42.0.2/32"')
            if default_route:text=text.replace(' startup-timeout-ms 10000',' local-address \"10.42.0.99/32\"\n local-address \"fd42::99/128\"\n startup-timeout-ms 10000')
            config.write_text(text)
        if hostname:
            text=config.read_text();records=[]
            for node in (2,3):
                outer=f'fd00:42:{node}::2' if family==6 else f'192.0.2.{(node-2)*4+2}'
                text=text.replace(f'endpoint host="{outer}"',f'endpoint host="peer{node}.test"')
                text=text.replace(f'  allowed-ip "10.42.0.{node}/32"',f'  bootstrap-resolver "local"\n  address-strategy "ipv{family}-only"\n  allowed-ip "10.42.0.{node}/32"')
                records.append(f'{outer} peer{node}.test')
            config.write_text(text);hosts=root/'hosts';resolv=root/'resolv.conf'
            hosts.write_text('\n'.join(records)+'\n');resolv.write_text('nameserver 127.0.0.53\n')
            t.run(['mount','--bind',hosts,'/etc/hosts']);t.run(['mount','--bind',resolv,'/etc/resolv.conf'])
        stub_before=pathlib.Path('/etc/resolv.conf').read_bytes()
        checked=subprocess.run([binary,'endpoint','check','--config',config],capture_output=True,text=True,timeout=15)
        if checked.returncode or '(offline)' not in checked.stdout:raise RuntimeError(f'offline check: {checked}')
        command=[binary,'endpoint','run','--config',config]
        if os.environ.get('NEXUS_WG_TRACE'):command=['strace','-s','4096','-e','recvfrom,sendto,openat,read,write','-o',os.environ['NEXUS_WG_TRACE'],*command]
        core=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        actual=ready(core)
        link_index=json.loads(t.run(['ip','-j','link','show','nx-wg']))[0]['ifindex']
        if default_route:
            for ipfamily,destination,outer in [('-4','198.51.100.8','192.0.2.2'),('-6','2001:db8::8','fd00:42:2::2')]:
                route=json.loads(t.run(['ip','-j',ipfamily,'route','get',destination]))[0]
                assert route['dev']=='nx-wg' and str(route['table'])=='60000',route
                route=json.loads(t.run(['ip','-j',ipfamily,'route','get',outer,'mark','0x6e780001']))[0]
                assert route['dev']=='n2' and str(route['table'])=='60001',route
        for peer in peers:t.send(peer,str(actual));t.send(peer,'start');assert t.receive(peer)=={'ready':True}
        dns_observations=[]
        for attempt in range(4):
            name=f'wg-hostdns-{family}-{role}-{mode}-{attempt}.nexus-dns.test'
            for qtype,expected in [(socket.AF_INET,'198.18.42.7'),(socket.AF_INET6,'fd42:9900::7')]:
                result=socket.getaddrinfo(name,80,qtype,socket.SOCK_STREAM)
                values=sorted({row[4][0] for row in result});assert values==[expected],(name,qtype,values)
                dns_observations.append({'name':name,'family':qtype,'values':values,'via':'glibc getaddrinfo / systemd-resolved private stub'})
        pathlib.Path(evidence+'.dns.json').write_text(json.dumps(dns_observations,indent=2)+'\n')
        echo=t.Echo()
        addresses=json.loads(t.run(['ip','-j','addr','show','dev','nx-wg']))
        assert addresses[0]['mtu']==1420 and 'UP' in addresses[0]['flags']
        for node in (2,3):
            for ipv6 in (False,True):
                t.run(['ping','-6' if ipv6 else '-4','-n','-c','1','-W','25' if mode=='cookie' else '3',t.address(node,ipv6)])
                t.run(['ping','-6' if ipv6 else '-4','-n','-c','1','-W','3',t.address(1,ipv6)],prefixes[node-2]);t.probe(node,ipv6)
        for peer in peers:t.send(peer,'probe');assert t.receive(peer,30)=={'probed':True}
        if mode=='roam':
            for index,node in enumerate((2,3)):
                old=setup[index]['port'];t.send(peers[index],'rebind');new=t.receive(peers[index])['port'];assert new!=old
                # Real authenticated traffic selects the new source port; the
                # production owner receives no reconfiguration or peer handle.
                for ipv6 in (False,True):
                    t.run(['ping','-6' if ipv6 else '-4','-n','-c','1','-W','3',t.address(1,ipv6)],prefixes[index])
                    t.probe(node,ipv6)
            if default_route:
                # A new authenticated outer IP lies inside default capture, but
                # the same marked socket must follow the independent physical
                # gateway snapshot without any owner reconfiguration.
                prefix=prefixes[0];device='p2';roamed='fd99::2' if family==6 else '198.51.100.2'
                physical='fd00:42:2::/64' if family==6 else '192.0.2.0/30'
                ordinary='fd00:42:2::2' if family==6 else '192.0.2.2'
                t.run(['ip','-6' if family==6 else '-4','addr','add',roamed+('/128' if family==6 else '/32'),'dev',device,*(['nodad'] if family==6 else [])],prefix)
                t.run(['ip','-6' if family==6 else '-4','route','replace',physical,'dev',device,'src',roamed,*(['metric','256'] if family==6 else [])],prefix)
                t.send(peers[0],'refresh');assert t.receive(peers[0])=={'refreshed':True}
                capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind(('n2',0));capture.settimeout(.05)
                for ipv6 in (False,True):
                    t.run(['ping','-6' if ipv6 else '-4','-n','-c','1','-W','3',t.address(1,ipv6)],prefix);t.probe(2,ipv6)
                frames=[]
                while True:
                    try:packet=capture.recv(65535)
                    except TimeoutError:break
                    if packet[12:14]==b'\x86\xdd':frames.append({'source':socket.inet_ntop(socket.AF_INET6,packet[22:38]),'destination':socket.inet_ntop(socket.AF_INET6,packet[38:54]),'protocol':packet[20]})
                    elif packet[12:14]==b'\x08\x00':frames.append({'source':socket.inet_ntop(socket.AF_INET,packet[26:30]),'destination':socket.inet_ntop(socket.AF_INET,packet[30:34]),'protocol':packet[23]})
                capture.close();assert any(item['source']==roamed and item['protocol']==17 for item in frames),frames
                assert any(item['destination']==roamed and item['protocol']==17 for item in frames),frames
                (root/'default-authenticated-roaming.json').write_text(json.dumps({'outer':roamed,'frames':frames},indent=2))
                t.run(['ip','-6' if family==6 else '-4','route','replace',physical,'dev',device,'src',ordinary,*(['metric','256'] if family==6 else [])],prefix)
                t.send(peers[0],'refresh');assert t.receive(peers[0])=={'refreshed':True}
                for ipv6 in (False,True):
                    t.run(['ping','-6' if ipv6 else '-4','-n','-c','1','-W','3',t.address(1,ipv6)],prefix);t.probe(2,ipv6)
            # Give one remote outer socket a source IP in the configured TUN
            # capture set. Packets arrive physically over veth but must never
            # update the authenticated endpoint or generate a recaptured reply.
            prefix=prefixes[0];device='p2'
            captured='fd42::99' if family==6 else '10.42.0.99'
            t.run(['ip','-6' if family==6 else '-4','addr','add',captured+('/128' if family==6 else '/32'),'dev',device,*(['nodad'] if family==6 else [])],prefix)
            physical='fd00:42:2::/64' if family==6 else '192.0.2.0/30'
            t.run(['ip','-6' if family==6 else '-4','route','replace',physical,'dev',device,'src',captured,*(['metric','256'] if family==6 else [])],prefix)
            t.send(peers[0],'refresh');assert t.receive(peers[0])=={'refreshed':True}
            capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind(('n2',0));capture.settimeout(.05)
            route=t.run(['ip','-6' if family==6 else '-4','route','get','fd00:42:2::1' if family==6 else '192.0.2.1'],prefix)
            failed=subprocess.run([*prefix,'ping','-4','-n','-c','1','-W','1',t.address(1,False)],capture_output=True,text=True,timeout=3)
            frames=[]
            while True:
                try:packet=capture.recv(65535)
                except TimeoutError:break
                if packet[12:14]==b'\x86\xdd':frames.append({'source':socket.inet_ntop(socket.AF_INET6,packet[22:38]),'destination':socket.inet_ntop(socket.AF_INET6,packet[38:54]),'protocol':packet[20]})
                elif packet[12:14]==b'\x08\x00':frames.append({'source':socket.inet_ntop(socket.AF_INET,packet[26:30]),'destination':socket.inet_ntop(socket.AF_INET,packet[30:34]),'protocol':packet[23]})
            capture.close();(root/'captured-source.json').write_text(json.dumps({'route':route,'frames':frames,'ping':failed.stdout,'config':config.read_text()},indent=2))
            assert any(item['source']==captured and item['protocol']==17 for item in frames),('test did not emit a captured source',route,frames)
            assert failed.returncode!=0,('captured outer source was accepted',route,frames)
            ordinary='fd00:42:2::2' if family==6 else '192.0.2.2'
            t.run(['ip','-6' if family==6 else '-4','route','replace',physical,'dev',device,'src',ordinary,*(['metric','256'] if family==6 else [])],prefix)
            t.send(peers[0],'refresh');assert t.receive(peers[0])=={'refreshed':True}
            for ipv6 in (False,True):
                t.run(['ping','-6' if ipv6 else '-4','-n','-c','1','-W','3',t.address(1,ipv6)],prefix);t.probe(2,ipv6)
        if mode in ('pressure','stop-pending'):

            for peer in peers:t.send(peer,'pause');assert t.receive(peer)=={'paused':True}
            done=[];errors=[];threads=[];connections=[]
            for node,ipv6 in ((2,False),(3,True)):
                started=threading.Event();finished=threading.Event();owned=[]
                def transfer(node=node,ipv6=ipv6,started=started,finished=finished,owned=owned):
                    try:t.probe(node,ipv6,bytes(range(256))*16384,started,owned)
                    except Exception as error:errors.append(str(error))
                    finally:finished.set()
                thread=threading.Thread(target=transfer,daemon=True);thread.start();assert started.wait(5)
                threads.append(thread);done.append(finished);connections.extend(owned)
            time.sleep(1.2);assert not any(item.is_set() for item in done)
            if mode=='pressure':
                for peer in peers:t.send(peer,'resume');assert t.receive(peer)=={'resumed':True}
                for thread in threads:thread.join(30)
                assert not any(thread.is_alive() for thread in threads) and not errors,errors
        # A real systemd-resolved stub TCP client reaches the same remote
        # DNS service; this additionally verifies system resolver TCP framing.
        tcp_names=[f'wg-tcp-{family}-{attempt}.nexus-dns.test' for attempt in range(2)]
        for name in tcp_names:
            labels=b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0'
            query=b'\x47\x31\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+labels+b'\x00\x01\x00\x01'
            with socket.create_connection(('127.0.0.53',53),timeout=5) as stream:
                stream.sendall(len(query).to_bytes(2,'big')+query)
                def exact(size):
                    output=b''
                    while len(output)<size:
                        part=stream.recv(size-len(output))
                        if not part:raise RuntimeError('truncated private resolved TCP answer')
                        output+=part
                    return output
                size=int.from_bytes(exact(2),'big');reply=exact(size)
                assert reply[:2]==query[:2] and reply[-4:]==bytes([198,18,42,7]),reply
        if os.environ.get('NEXUS_HOST_DNS_PROVIDER')=='warp':
            profiles=[]
            for peer in peers:t.send(peer,'profile-stats');profiles.append(t.receive(peer))
            assert all(item['inbound'][4]>0 and item['outbound'][4]>0 for item in profiles),profiles
            pathlib.Path(evidence+'.profile.json').write_text(json.dumps(profiles,indent=2)+'\n')
        dns_stats=[]
        for peer in peers:
            t.send(peer,'dns-stats');dns_stats.append(t.receive(peer))
        assert sum(item['udp'] for item in dns_stats)>=8 and sum(item['tcp'] for item in dns_stats)>=2,dns_stats
        pathlib.Path(evidence+'.peer-dns.json').write_text(json.dumps(dns_stats,indent=2)+'\n')
        expected_dns=mode.startswith('dns-drift-')
        if expected_dns:
            manager=['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager']
            if mode=='dns-drift-server':t.run(manager+['SetLinkDNS','ia(iay)',str(link_index),'1','2','4','10','42','0','3'])
            elif mode=='dns-drift-domain':t.run(manager+['SetLinkDomains','ia(sb)',str(link_index),'1','foreign.test','true'])
            else:raise AssertionError(mode)
            drift_begin=time.monotonic()
        expected_drift=mode.startswith('drift-')
        if expected_drift:
            assert default_route
            if mode=='drift-rule':
                t.run(['ip','-4','rule','delete','priority','10002'])
                t.run(['ip','-4','rule','add','not','fwmark','0x6e780001/0xffffffff','table','60000','priority','10002','protocol','static'])
            elif mode=='drift-route':t.run(['ip','route','add','198.18.0.0/15','dev','n2'])
            elif mode=='drift-rpf':
                pathlib.Path('/proc/sys/net/ipv4/conf/n2/rp_filter').write_text('0\n')
                pathlib.Path('/proc/sys/net/ipv4/conf/n2/rp_filter').write_text('2\n')
            else:raise AssertionError(mode)
        elif not expected_dns:core.send_signal(signal.SIGTERM if role=='client' else signal.SIGINT)
        out,err=core.communicate(timeout=5)
        if expected_dns:
            assert core.returncode==1 and 'host DNS settings' in err and 'cleanup could not be fully verified' in err,(core.returncode,out,err)
            elapsed=time.monotonic()-drift_begin;assert elapsed<1.0,elapsed
            pathlib.Path(evidence+'.drift.json').write_text(json.dumps({'detected_seconds':elapsed,'stderr':err},indent=2)+'\n')
        elif expected_drift:
            assert core.returncode==1 and 'default-route policy changed' in err,(core.returncode,out,err)
        elif core.returncode or ' stopped' not in out:raise RuntimeError(f'endpoint stop {core.returncode}: {out} {err}')
        if mode=='stop-pending':
            for connection in connections:
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            for thread in threads:thread.join(3)
            assert not any(thread.is_alive() for thread in threads)
        assert subprocess.run(['ip','link','show','nx-wg'],capture_output=True).returncode!=0
        assert not echo.errors,echo.errors
        assert pathlib.Path('/etc/resolv.conf').read_bytes()==stub_before
        absent=subprocess.run(['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','GetLink','i',str(link_index)],capture_output=True)
        assert absent.returncode!=0,absent.stdout
        if default_route:
            expected_filters=dict(original_filters)
            if mode=='drift-rpf':expected_filters['n2']='2\n'
            assert {name:pathlib.Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').read_text() for name in original_filters}==expected_filters
            for ipfamily in ('-4','-6'):
                assert not json.loads(t.run(['ip','-j',ipfamily,'route','show','table','60000']))
                assert not json.loads(t.run(['ip','-j',ipfamily,'route','show','table','60001']))
                rules=json.loads(t.run(['ip','-j',ipfamily,'rule','show']))
                owned=[rule for rule in rules if 10000<=rule['priority']<=10002]
                assert len(owned)==(1 if mode=='drift-rule' and ipfamily=='-4' else 0),rules
                if owned:assert owned[0]['priority']==10002 and str(owned[0]['table'])=='60000',owned
        complete=True
    finally:
        if echo:echo.close()
        for process in (core,*peers):
            if process and process.poll() is None:process.kill();process.communicate(timeout=5)
        pathlib.Path(evidence).write_text(json.dumps({'complete':complete,'family':family,'role':role,'mode':mode,'hostname_bootstrap':hostname,'default_route':default_route,'two_real_peers':True,'binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),'namespace':os.stat('/proc/self/ns/net').st_ino,'artifacts':str(root)},indent=2)+'\n')
    print(f'endpoint {role} IPv{family} {mode}: two real peers, owned TUN/routes, ICMP/TCP/UDP dual family, half-close, checked signal stop passed',flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--peer');p.add_argument('--family',type=int,choices=[4,6],default=4);p.add_argument('--role',choices=['client','server'],default='client');p.add_argument('--mode',choices=['plain','cookie','pressure','stop-pending','roam','drift-rule','drift-route','drift-rpf','dns-drift-server','dns-drift-domain'],default='plain');p.add_argument('--evidence',required=True);p.add_argument('--hostname',action='store_true');p.add_argument('--default-route',action='store_true');p.add_argument('--parent-mount',type=int);p.add_argument('--inner',action='store_true');p.add_argument('--parent-net',type=int);p.add_argument('--parent-user',type=int);a=p.parse_args()
    if not a.peer:
        with tempfile.TemporaryDirectory(prefix='nexus-endpoint-reference-') as directory:
            peer=build_peer(pathlib.Path(directory))
            subprocess.run([sys.executable,__file__,a.binary,'--peer',peer,'--family',str(a.family),'--role',a.role,'--mode',a.mode,'--evidence',a.evidence,*(['--hostname'] if a.hostname else []),*(['--default-route'] if a.default_route else [])],check=True,timeout=155)
        return
    if a.inner:inner(a.binary,a.peer,a.family,a.role,a.mode,a.parent_net,a.parent_user,a.evidence,a.hostname,a.parent_mount,a.default_route)
    else:subprocess.run(['unshare','-Urnm' if a.hostname else '-Urn',sys.executable,__file__,str(pathlib.Path(a.binary).resolve()),'--peer',a.peer,'--family',str(a.family),'--role',a.role,'--mode',a.mode,'--evidence',a.evidence,'--inner','--parent-net',str(os.stat('/proc/self/ns/net').st_ino),'--parent-user',str(os.stat('/proc/self/ns/user').st_ino),*(['--hostname','--parent-mount',str(os.stat('/proc/self/ns/mnt').st_ino)] if a.hostname else []),*(['--default-route'] if a.default_route else [])],check=True,timeout=150)
if __name__=='__main__':main()
