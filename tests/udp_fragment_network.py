import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import threading
import time

def command(args):
    return subprocess.run([str(x) for x in args],check=True,text=True,capture_output=True,timeout=10)

def namespace(kind):
    return os.readlink('/proc/self/ns/'+kind)

def ready(process):
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    try:
        if not selector.select(5):raise RuntimeError('peer readiness timeout')
        line=process.stdout.readline()
        if not line:raise RuntimeError('peer exited: '+process.stderr.read())
        return json.loads(line)
    finally:selector.close()

def peer_main(args):
    assert namespace('net')!=args.parent_net and namespace('user')==args.parent_user
    print(json.dumps({'pid':os.getpid(),'namespace':namespace('net')}),flush=True)
    assert sys.stdin.readline().strip()=='go'
    selector=selectors.DefaultSelector();selector.register(sys.stdin,selectors.EVENT_READ,'control')
    peers=[];seen=[]
    for family,host in [(socket.AF_INET,'10.77.0.2'),(socket.AF_INET6,'fd77::2')]:
        sock=socket.socket(family,socket.SOCK_DGRAM);sock.bind((host,0));peers.append(sock)
        selector.register(sock,selectors.EVENT_READ,4 if family==socket.AF_INET else 6)
    print(json.dumps({'ports':[sock.getsockname()[1] for sock in peers]}),flush=True)
    try:
        while True:
            for key,_ in selector.select(10):
                if key.data=='control':
                    text=sys.stdin.readline().strip()
                    if text=='snapshot':print(json.dumps({'seen':seen}),flush=True)
                    elif text=='stop' or not text:return
                    else:raise RuntimeError(text)
                else:
                    payload,source=key.fileobj.recvfrom(65536)
                    assert source[0]==('10.77.0.1' if key.data==4 else 'fd77::1')
                    assert payload==bytes((i*71)%256 for i in range(len(payload)))
                    seen.append({'family':key.data,'source':source[0],'size':len(payload)})
                    key.fileobj.sendto(payload,source)
    finally:
        selector.close()
        for sock in peers:sock.close()

def capture(sock,stop,frames):
    sock.settimeout(.05)
    while not stop.is_set():
        try:data,_=sock.recvfrom(65536)
        except socket.timeout:continue
        if len(data)<14:continue
        protocol=int.from_bytes(data[12:14],'big');ip=data[14:]
        if protocol==0x0800 and len(ip)>=20 and ip[16:20]==socket.inet_aton('10.77.0.2') and ip[9]==17:
            value=int.from_bytes(ip[6:8],'big')
            frames.append({'family':4,'id':int.from_bytes(ip[4:6],'big'),'offset':(value&8191)*8,
                           'more':bool(value&8192),'size':int.from_bytes(ip[2:4],'big')})
        elif protocol==0x86dd and len(ip)>=40 and ip[24:40]==socket.inet_pton(socket.AF_INET6,'fd77::2'):
            if ip[6]==44 and len(ip)>=48:
                value=int.from_bytes(ip[42:44],'big')
                frames.append({'family':6,'id':int.from_bytes(ip[44:48],'big'),'offset':value&65528,
                               'more':bool(value&1),'size':40+int.from_bytes(ip[4:6],'big')})
            elif ip[6]==17:
                frames.append({'family':6,'id':None,'offset':0,'more':False,'size':40+int.from_bytes(ip[4:6],'big')})

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('binary',type=Path,nargs='?');parser.add_argument('--evidence',type=Path)
    parser.add_argument('--isolated',action='store_true');parser.add_argument('--peer',action='store_true')
    parser.add_argument('--parent-user');parser.add_argument('--parent-net')
    args=parser.parse_args()
    if args.peer:return peer_main(args)
    if not args.binary or not args.evidence:parser.error('provide the existing fixture binary and --evidence')
    binary=args.binary.resolve(strict=True);evidence=args.evidence.resolve()
    if not args.isolated:
        return subprocess.run(['unshare','-Urn',sys.executable,str(Path(__file__).resolve()),str(binary),'--evidence',str(evidence),'--isolated',
            '--parent-user',namespace('user'),'--parent-net',namespace('net')],check=True).returncode
    assert args.parent_net and args.parent_user
    assert namespace('net')!=args.parent_net and namespace('user')!=args.parent_user
    evidence.parent.mkdir(parents=True,exist_ok=True)
    command(['ip','link','set','lo','up'])
    peer=subprocess.Popen(['unshare','-n',sys.executable,str(Path(__file__).resolve()),'--peer',
        '--parent-user',namespace('user'),'--parent-net',namespace('net')],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    stop=threading.Event();frames=[];results=[];complete=False;packet=None;thread=None
    try:
        info=ready(peer);assert info['pid']==peer.pid
        command(['ip','link','add','nxfa','type','veth','peer','name','nxfb'])
        command(['ip','link','set','nxfb','netns',peer.pid])
        for suffix,index in [([],1),(['nsenter','-t',str(peer.pid),'-n'],2)]:
            interface='nxfa' if index==1 else 'nxfb'
            command([*suffix,'ip','link','set','lo','up'])
            command([*suffix,'ip','link','set',interface,'mtu','1280'])
            command([*suffix,'ip','addr','add',f'10.77.0.{index}/24','dev',interface])
            command([*suffix,'ip','-6','addr','add',f'fd77::{index}/64','dev',interface,'nodad'])
            command([*suffix,'ip','link','set',interface,'up'])
        peer.stdin.write('go\n');peer.stdin.flush();ports=ready(peer)['ports']
        packet=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));packet.bind(('nxfa',0))
        thread=threading.Thread(target=capture,args=(packet,stop,frames));thread.start()
        def snapshot():
            peer.stdin.write('snapshot\n');peer.stdin.flush();return ready(peer)['seen']
        def check(family,fragment,binding,label):
            start=len(frames);before=len(snapshot())
            argv=[str(binary),str(family),str(ports[family==6]),str(fragment),str(binding)]
            result=subprocess.run(argv,text=True,capture_output=True,timeout=5)
            if result.returncode:raise RuntimeError((argv,result.returncode,result.stdout,result.stderr))
            observed=snapshot()[before:];time.sleep(.03);wire=frames[start:]
            sizes=sorted(item['size'] for item in observed)
            assert sizes==([0,1200,2048] if fragment else [0,1200]),observed
            fragmented=[f for f in wire if f['family']==family and (f['more'] or f['offset'])]
            if fragment:
                assert len(fragmented)>=2 and any(f['offset']==0 and f['more'] for f in fragmented)
                assert any(f['offset']>0 and not f['more'] for f in fragmented)
                assert all(f['size']<=1280 for f in fragmented),fragmented
            else:assert not fragmented,fragmented
            results.append({'label':label,'argv':argv,'exit':0,'stdout':result.stdout,'received':observed,'wire':wire})
            print(result.stdout.strip(),flush=True)
        for family in [4,6]:
            for fragment in [0,1]:
                for binding in [0,1]:check(family,fragment,binding,'wire-fragmentation')
        for family in [4,6]:
            for call,when in [('setsockopt',2),('setsockopt',3),('getsockopt',1)]:
                before=len(snapshot());trace=evidence.with_name(f'{evidence.stem}-deny-{family}-{call}-{when}.trace')
                argv=['strace','-o',str(trace),'-e','trace=socket,getsockopt,setsockopt,sendto,close',
                    '-e',f'inject={call}:error=EPERM:when={when}',str(binary),str(family),str(ports[family==6]),'1','2']
                result=subprocess.run(argv,text=True,capture_output=True,timeout=5)
                assert result.returncode==0,(argv,result.returncode,result.stdout,result.stderr)
                assert len(snapshot())==before and 'sendto(' not in trace.read_text()
                results.append({'label':'preparation-failure','argv':argv,'exit':0,'stdout':result.stdout,'trace':str(trace)})
                check(family,1,0,'new-owner-after-failure')
        complete=True
    finally:
        stop.set()
        if thread:thread.join(1)
        if packet:packet.close()
        if peer.poll() is None:
            try:peer.stdin.write('stop\n');peer.stdin.flush();peer.communicate(timeout=2)
            except BaseException:peer.kill();peer.communicate()
        evidence.write_text(json.dumps({'complete':complete,'expected_cases':20,
            'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':results,'namespace':{'user':namespace('user'),'net':namespace('net')},
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')

if __name__=='__main__':main()
