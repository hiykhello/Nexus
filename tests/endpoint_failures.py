#!/usr/bin/env python3
"""Offline credentials and real-kernel fail/rollback/restart for endpoint CLI."""
import argparse,base64,copy,json,os,pathlib,signal,socket,subprocess,sys,tempfile
import wireguard_tun_network as t
import wireguard_port_network as port
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import endpoint_network as network

def inner(binary,evidence,parent_net,parent_user):
    assert os.stat('/proc/self/ns/net').st_ino!=parent_net and os.stat('/proc/self/ns/user').st_ino!=parent_user
    t.run(['ip','link','set','lo','up']);root=pathlib.Path(tempfile.mkdtemp(prefix='nexus-endpoint-failures-'))
    keys=port.prepare(root);a=port.prepare(root);b=port.prepare(root)
    setup=[{'public':a['public'],'psk':a['psk1'],'port':51820},{'public':b['public'],'psk':b['psk1'],'port':51821}]
    path=network.configure(root,keys,setup,4,'client',False)
    original=path.read_text().replace('192.0.2.2','127.0.0.2').replace('192.0.2.6','127.0.0.3')
    results=[]
    def state():
        return [sorted(json.dumps(item,sort_keys=True) for item in json.loads(t.run(cmd))) for cmd in (['ip','-j','link','show'],['ip','-j','-4','route','show','table','all'],['ip','-j','-6','route','show','table','all'])]
    baseline=state()
    def check(label,text=original,mode='check',needle=None):
        path.write_text(text);before=state();done=subprocess.run([binary,'endpoint',mode,'--config',path],capture_output=True,text=True,timeout=15)
        assert done.returncode==1,(label,done.returncode,done.stdout,done.stderr)
        if needle:assert needle in done.stderr,(label,done.stderr)
        assert state()==before,(label,'kernel state changed after failure')
        assert keys['private'] not in done.stderr and base64.b64encode(bytes.fromhex(keys['private'])).decode() not in done.stderr
        results.append({'case':label,'exit':done.returncode,'stderr':done.stderr})
    # Offline check must never create any network socket or open TUN.
    path.write_text(original);trace=root/'offline.trace'
    done=subprocess.run(['strace','-f','-o',trace,'-e','trace=socket,ioctl,openat',binary,'endpoint','check','--config',path],capture_output=True,text=True,timeout=15)
    assert done.returncode==0 and '(offline)' in done.stdout
    wire=trace.read_text();assert 'socket(' not in wire and '/dev/net/tun' not in wire
    assert state()==baseline;results.append({'case':'offline-no-socket-no-tun','exit':0})
    check('missing-private',original.replace(str(root/'private'),str(root/'missing')),needle='private key:')
    private=root/'private';saved=private.read_bytes()
    for content,label in [(b'x\n','short-private'),(base64.b64encode(bytes(32))[:-1]+b'?\n','noncanonical-private')]:
        private.write_bytes(content);check(label,needle='canonical base64')
    private.write_bytes(saved);private.chmod(0o644);check('world-readable-private',needle='private key:');private.chmod(0o600)
    symlink=root/'private-link';symlink.symlink_to(private);check('symlink-private',original.replace(str(private),str(symlink)),needle='private key:')
    public=root/'public2';public_saved=public.read_bytes();public.write_bytes(base64.b64encode(bytes.fromhex(keys['public']))+b'\n');check('self-peer',needle='local identity')
    public.write_bytes(base64.b64encode(bytes(32))+b'\n');check('zero-peer',needle='invalid public identity');public.write_bytes(public_saved)
    second=root/'public3';second_saved=second.read_bytes();second.write_bytes(public_saved);check('duplicate-peer',needle='duplicate peer public identity');second.write_bytes(second_saved)
    psk=root/'psk2';psk_saved=psk.read_bytes();psk.chmod(0o644);check('world-readable-psk',needle='preshared key:');psk.chmod(0o600)
    psk.write_bytes(b'!\n');check('malformed-psk',needle='canonical base64');psk.write_bytes(psk_saved)
    check('bad-interface',original.replace('startup-timeout-ms 10000','bind-interface "no-such-if"\n startup-timeout-ms 10000'),'run',needle='cannot bind')
    check('unreachable-outer',original.replace('127.0.0.2','192.0.2.2'),'run',needle='route lookup failed')
    reservation=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);reservation.bind(('0.0.0.0',0));selected=reservation.getsockname()[1]
    check('occupied-udp-port',original.replace('port=0',f'port={selected}'),'run',needle='cannot bind');reservation.close()
    t.run(['ip','tuntap','add','dev','nx-wg','mode','tun'])
    try:check('existing-tun-not-taken',mode='run',needle='exclusive endpoint TUN')
    finally:t.run(['ip','link','delete','nx-wg'])
    t.run(['ip','route','add','10.42.0.2/32','dev','lo'])
    try:check('conflicting-route-not-taken',mode='run',needle='network lease')
    finally:t.run(['ip','route','delete','10.42.0.2/32','dev','lo'])
    # Active signal behavior and repeated use of the same real port/device.
    chosen=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);chosen.bind(('127.0.0.1',0));selected=chosen.getsockname()[1];chosen.close()
    for index,stop in enumerate((signal.SIGTERM,signal.SIGINT,signal.SIGHUP)):
        path.write_text(original.replace('port=0',f'port={selected}'))
        process=subprocess.Popen([binary,'endpoint','run','--config',path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        assert network.ready(process)==selected;process.send_signal(stop);out,err=process.communicate(timeout=5)
        assert process.returncode==(1 if stop==signal.SIGHUP else 0),(process.returncode,out,err)
        assert state()==baseline
        if stop==signal.SIGHUP:assert 'reload is unsupported' in err
        results.append({'case':f'signal-{stop}-same-port-restart-{index}','exit':process.returncode})
    pathlib.Path(evidence).write_text(json.dumps({'complete':True,'cases':results,'artifacts':str(root)},indent=2)+'\n')
    print(f'{len(results)} endpoint offline/credential/kernel failure/rollback/signal/restart checks passed',flush=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--evidence',required=True);p.add_argument('--inner',action='store_true');p.add_argument('--parent-net',type=int);p.add_argument('--parent-user',type=int);a=p.parse_args()
    if a.inner:inner(a.binary,a.evidence,a.parent_net,a.parent_user)
    else:subprocess.run(['unshare','-Urn',sys.executable,__file__,str(pathlib.Path(a.binary).resolve()),'--evidence',a.evidence,'--inner','--parent-net',str(os.stat('/proc/self/ns/net').st_ino),'--parent-user',str(os.stat('/proc/self/ns/user').st_ino)],check=True,timeout=120)
if __name__=='__main__':main()
