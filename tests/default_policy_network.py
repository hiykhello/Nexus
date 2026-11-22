from pathlib import Path
import json,os,socket,subprocess,sys

root=Path(__file__).resolve().parents[1]
def run(*args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,**kwargs)

if len(sys.argv)<2 or sys.argv[1]!='--inner':
    mode=sys.argv[1] if len(sys.argv)>1 else 'normal'
    args=['unshare','-Urn',sys.executable,__file__,'--inner',str(Path('/proc/self/ns/net').stat().st_ino),str(Path('/proc/self/ns/user').stat().st_ino),mode]
    done=subprocess.run(args,capture_output=True,text=True)
    report={'command':args,'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr}
    (root/f'policy-network-{mode}.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));raise SystemExit(done.returncode)

del sys.argv[1]
mode=sys.argv[3]
assert int(sys.argv[1])!=Path('/proc/self/ns/net').stat().st_ino
assert int(sys.argv[2])!=Path('/proc/self/ns/user').stat().st_ino
peer_code='''
import selectors,socket,subprocess,sys
input()
for command in [['ip','link','set','lo','up'],['ip','link','set','nx-peer','up'],['ip','addr','add','192.0.2.2/24','dev','nx-peer'],['ip','-6','addr','add','fd55::2/64','dev','nx-peer','nodad']]:subprocess.run(command,check=True)
selection=selectors.DefaultSelector()
for family,address in [(socket.AF_INET,'192.0.2.2'),(socket.AF_INET6,'fd55::2')]:
 sock=socket.socket(family,socket.SOCK_DGRAM);sock.bind((address,19999));selection.register(sock,selectors.EVENT_READ)
print('ready',flush=True)
for i in range(6):
 events=selection.select(10)
 assert events
 for key,event in events:
  data,source=key.fileobj.recvfrom(4096);key.fileobj.sendto(data,source)
input()
'''
peer=subprocess.Popen(['unshare','-n',sys.executable,'-c',peer_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
run('ip','link','add','nx-phys','type','veth','peer','name','nx-peer')
run('ip','link','set','nx-peer','netns',str(peer.pid))
peer.stdin.write('configure\n');peer.stdin.flush()
assert peer.stdout.readline()=='ready\n'
run('ip','link','set','nx-phys','up')
run('ip','addr','add','192.0.2.1/24','dev','nx-phys')
run('ip','-6','addr','add','fd55::1/64','dev','nx-phys','nodad')
run('ip','route','add','default','via','192.0.2.2','dev','nx-phys')
run('ip','-6','route','add','default','via','fd55::2','dev','nx-phys')
for family,address in [(socket.AF_INET,'192.0.2.2'),(socket.AF_INET6,'fd55::2')]:
    with socket.socket(family,socket.SOCK_DGRAM) as baseline:
        baseline.settimeout(3);baseline.sendto(b'baseline',(address,19999));assert baseline.recv(4096)==b'baseline'
print('rp_filter before',Path('/proc/sys/net/ipv4/conf/nx-phys/rp_filter').read_text().strip(),flush=True)
original_filter=Path('/proc/sys/net/ipv4/conf/nx-phys/rp_filter').read_text()
original_all=Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text()
process=subprocess.Popen([str(root/'policy-import/default_policy_native'),*sys.argv[1:3],'hold'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
line=process.stdout.readline()
assert line=='ready\n',(line,process.communicate(timeout=8))
checks=[]
def marked_echo(family,address):
    with socket.socket(family,socket.SOCK_DGRAM) as outer:
        outer.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x6e780001);outer.settimeout(3)
        token=b'marked-outer-'+str(family).encode();outer.sendto(token,(address,19999))
        assert outer.recv(4096)==token
try:
    for family,destination in [('-4','198.51.100.8'),('-6','2001:db8::8')]:
        for marked in [False,True]:
            command=['ip','-j',family,'route','get',destination]
            if marked:command+=['mark','0x6e780001']
            result=json.loads(run(*command).stdout)[0]
            assert result['dev']==('nx-phys' if marked else 'nx-policy'),result
            assert str(result['table'])==('60001' if marked else '60000'),result
            checks.append({'family':family,'marked':marked,'route':result})
    for family,address,token in [(socket.AF_INET,'198.51.100.8',b'captured-v4'),(socket.AF_INET6,'2001:db8::8',b'captured-v6')]:
        with socket.socket(family,socket.SOCK_DGRAM) as ordinary:ordinary.sendto(token,(address,19999))
    marked_echo(socket.AF_INET,'192.0.2.2');marked_echo(socket.AF_INET6,'fd55::2')
    # Main table rebuild cannot redirect marked outers into our capture table.
    run('ip','route','replace','default','dev','nx-policy')
    run('ip','-6','route','replace','default','dev','nx-policy')
    for family,destination in [('-4','198.51.100.8'),('-6','2001:db8::8')]:
        result=json.loads(run('ip','-j',family,'route','get',destination,'mark','0x6e780001').stdout)[0]
        assert result['dev']=='nx-phys' and str(result['table'])=='60001',result
        checks.append({'main_rebuilt':True,'family':family,'route':result})
    marked_echo(socket.AF_INET,'192.0.2.2');marked_echo(socket.AF_INET6,'fd55::2')
    if mode=='rp-replace':
        Path('/proc/sys/net/ipv4/conf/nx-phys/rp_filter').write_text('0\n')
        Path('/proc/sys/net/ipv4/conf/nx-phys/rp_filter').write_text('2\n')
finally:
    output,error=process.communicate('release\n',timeout=12)
    print('fixture diagnostic',output,error,flush=True)
assert process.returncode==0,(output,error)
assert Path('/proc/sys/net/ipv4/conf/nx-phys/rp_filter').read_text()==('2\n' if mode=='rp-replace' else original_filter)
assert ('settings_preserved=1' if mode=='rp-replace' else 'settings_restored=1') in output
assert Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text()==original_all
peer_output,peer_error=peer.communicate('stop\n',timeout=12)
assert peer.returncode==0,(peer_output,peer_error)
print(json.dumps({'checks':checks,'fixture':output,'stderr':error},indent=2))
