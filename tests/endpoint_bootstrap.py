#!/usr/bin/env python3
"""Static local endpoint bootstrap uses existing DNS transport and one original budget."""
import argparse,json,os,pathlib,signal,socket,struct,subprocess,sys,tempfile,threading,time
import wireguard_tun_network as t
import wireguard_port_network as port
from dns_rule_support import DnsPeer,question,exact
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import endpoint_network as network

class Peer(DnsPeer):
    def __init__(self):
        super().__init__(host='127.0.0.53',port=53);self.mode='dns';self.first=threading.Event()
    def reply(self,packet,transport):
        name,kind,end=question(packet);self.seen.append((name,kind,transport));self.first.set()
        if self.mode in ('cancel','timeout') or self.mode=='budget' and name.startswith('two'):return None
        if self.mode=='budget':time.sleep(.12)
        code=3 if self.mode=='search' and name.endswith('.first.test') else 0
        if self.mode=='fallback' and transport=='udp':return packet[:2]+struct.pack('!HHHHH',0x8380,1,0,0,0)+packet[12:end]
        node=3 if name.startswith(('two','peer3')) else 2
        host='10.42.0.2' if self.mode=='captured' else f'127.0.0.{node}' if kind==1 else f'::{node}'
        raw=socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,host)
        record=b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(raw))+raw
        return packet[:2]+struct.pack('!HHHHH',0x8180|code,1,0 if code else 1,0,0)+packet[12:end]+(b'' if code else record)

def inner(binary,cli,evidence,parent_net,parent_user,parent_mount):
    assert os.stat('/proc/self/ns/net').st_ino!=parent_net and os.stat('/proc/self/ns/user').st_ino!=parent_user and os.stat('/proc/self/ns/mnt').st_ino!=parent_mount
    t.run(['mount','--make-rprivate','/']);t.run(['ip','link','set','lo','up']);root=pathlib.Path(tempfile.mkdtemp(prefix='nexus-endpoint-bootstrap-'))
    keys=port.prepare(root);a=port.prepare(root);b=port.prepare(root)
    config=network.configure(root,keys,[{'public':a['public'],'psk':a['psk1'],'port':51820},{'public':b['public'],'psk':b['psk1'],'port':51821}],4,'client',False)
    original=config.read_text().replace('listen host="0.0.0.0"','listen host="::"')
    for node,outer in [(2,'192.0.2.2'),(3,'192.0.2.6')]:
        original=original.replace(f'endpoint host="{outer}"',f'endpoint host="{"one" if node==2 else "two"}.test"').replace(f'  allowed-ip "10.42.0.{node}/32"','  bootstrap-resolver "local"\n  address-strategy "ipv4-only"\n'+f'  allowed-ip "10.42.0.{node}/32"')
    hosts=root/'hosts';resolv=root/'resolv.conf';hosts.write_text('');resolv.write_text('nameserver 127.0.0.53\noptions timeout:1 attempts:1\n')
    t.run(['mount','--bind',hosts,'/etc/hosts']);t.run(['mount','--bind',resolv,'/etc/resolv.conf'])
    results=[]
    with Peer() as dns:
        for backend in ('epoll','uring'):
            for mode in ('hosts','hosts-v6','dns','dns-v6','tcp','fallback','search','captured','timeout','cancel','budget'):
                dns.mode=mode;dns.seen.clear();dns.first.clear();hosts.write_text('')
                resolv.write_text('nameserver 127.0.0.53\noptions timeout:1 attempts:1'+(' use-vc' if mode=='tcp' else '')+'\n'+('search first.test second.test\n' if mode=='search' else ''))
                text=original.replace('"one.test"','"one"').replace('"two.test"','"two"') if mode=='search' else original
                if mode in ('hosts-v6','dns-v6'):text=text.replace('ipv4-only','ipv6-only')
                if mode.startswith('hosts'):
                    hosts.write_text('127.0.0.2 one.test\n127.0.0.3 two.test\n::2 one.test\n::3 two.test\n')
                config.write_text(text);begin=time.monotonic()
                process=subprocess.Popen([binary,config,backend,'300' if mode in ('timeout','budget') else '3000','raise'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                if mode=='cancel':
                    assert dns.first.wait(2)
                    assert len(list(pathlib.Path(f'/proc/{process.pid}/task').iterdir()))==1,'bootstrap unexpectedly spawned worker threads'
                    process.send_signal(signal.SIGTERM)
                try:out,err=process.communicate(timeout=5)
                except BaseException:process.kill();process.communicate();raise
                elapsed=time.monotonic()-begin
                expected=3 if mode=='cancel' else 1 if mode in ('captured','timeout','budget') else 0
                assert process.returncode==expected,(backend,mode,process.returncode,out,err,dns.errors)
                if expected==0:
                    assert len(out.splitlines())==2 and all(line.startswith('6 ' if mode in ('hosts-v6','dns-v6') else '4 ') for line in out.splitlines()),out
                    for index,line in enumerate(out.splitlines()):
                        octets=[int(value,16) for value in line.split()[1].split('.') if value]
                        assert octets[15 if mode in ('hosts-v6','dns-v6') else 3]==index+2,(mode,out)
                    if mode.startswith('hosts'):assert not dns.seen,dns.seen
                    elif mode=='tcp':assert all(item[2]=='tcp' for item in dns.seen),dns.seen
                    elif mode=='fallback':assert [item[2] for item in dns.seen]==['udp','tcp','udp','tcp'],dns.seen
                    elif mode=='search':assert [item[0] for item in dns.seen]==['one.first.test','one.second.test','two.first.test','two.second.test'],dns.seen
                elif mode in ('timeout','budget'):
                    assert 'deadline expired' in err and .25<=elapsed<.9,(elapsed,err)
                    if mode=='budget':assert [item[0] for item in dns.seen]==['one.test','two.test'],dns.seen
                elif mode=='captured':assert 'uncaptured usable address' in err
                results.append({'case':backend+'-'+mode,'exit':process.returncode,'seconds':elapsed,'queries':list(dns.seen)})
            # Trigger signal concurrently with the resolving reply; keep process
            # alive at a post-bootstrap input barrier to prove delivery, not exit.
            for attempt in range(20):
                dns.mode='dns';dns.first.clear();dns.seen.clear();config.write_text(original)
                process=subprocess.Popen([binary,config,backend,'3000','race'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                assert dns.first.wait(2);process.send_signal(signal.SIGTERM)
                try:out,err=process.communicate(input='go\n',timeout=5)
                except BaseException:process.kill();process.communicate();raise
                assert process.returncode in (0,3),(backend,attempt,process.returncode,out,err)
            results.append({'case':backend+'-signal-transition','attempts':20,'exit':0})
        # Production offline check does not resolve hostname; --resolve does.
        dns.mode='dns';dns.seen.clear();config.write_text(original)
        done=subprocess.run([cli,'endpoint','check','--config',config],capture_output=True,text=True,timeout=5)
        assert done.returncode==0 and 'require local bootstrap' in done.stdout and not dns.seen
        done=subprocess.run([cli,'endpoint','check','--config',config,'--resolve'],capture_output=True,text=True,timeout=5)
        assert done.returncode==0 and 'local bootstrap checked' in done.stdout and len(dns.seen)==2,(done,dns.seen)
        results.append({'case':'production-check-resolve','exit':0,'queries':dns.seen})
        assert not dns.errors,dns.errors
    pathlib.Path(evidence).write_text(json.dumps({'complete':True,'cases':results,'artifacts':str(root)},indent=2)+'\n')
    print('endpoint static local bootstrap: 22 dual-backend DNS/hosts/strategy/TCP/search/budget/cancel + 40 signal transitions + production check/resolve passed',flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('cli');p.add_argument('--evidence',required=True);p.add_argument('--inner',action='store_true');p.add_argument('--parent-net',type=int);p.add_argument('--parent-user',type=int);p.add_argument('--parent-mount',type=int);a=p.parse_args()
    if a.inner:inner(a.binary,a.cli,a.evidence,a.parent_net,a.parent_user,a.parent_mount)
    else:subprocess.run(['unshare','-Urnm',sys.executable,__file__,str(pathlib.Path(a.binary).resolve()),str(pathlib.Path(a.cli).resolve()),'--evidence',a.evidence,'--inner','--parent-net',str(os.stat('/proc/self/ns/net').st_ino),'--parent-user',str(os.stat('/proc/self/ns/user').st_ino),'--parent-mount',str(os.stat('/proc/self/ns/mnt').st_ino)],check=True,timeout=120)
if __name__=='__main__':main()
