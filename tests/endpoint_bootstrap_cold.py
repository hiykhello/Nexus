#!/usr/bin/env python3
"""Fresh-process ordinary/array/aligned allocation failures through local bootstrap."""
import argparse,json,os,pathlib,subprocess,sys,tempfile
import wireguard_tun_network as t
import wireguard_port_network as port
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import endpoint_network as network
from endpoint_bootstrap import Peer

def inner(binary,evidence,parent_net,parent_user,parent_mount):
    assert os.stat('/proc/self/ns/net').st_ino!=parent_net and os.stat('/proc/self/ns/user').st_ino!=parent_user and os.stat('/proc/self/ns/mnt').st_ino!=parent_mount
    t.run(['mount','--make-rprivate','/']);t.run(['ip','link','set','lo','up']);root=pathlib.Path(tempfile.mkdtemp(prefix='nexus-endpoint-cold-'))
    keys=port.prepare(root);a=port.prepare(root);b=port.prepare(root)
    config=network.configure(root,keys,[{'public':a['public'],'psk':a['psk1'],'port':51820},{'public':b['public'],'psk':b['psk1'],'port':51821}],4,'client',False)
    original=config.read_text()
    for node,outer in ((2,'192.0.2.2'),(3,'192.0.2.6')):
        original=original.replace(f'endpoint host="{outer}"',f'endpoint host="peer{node}.test"').replace(f'  allowed-ip "10.42.0.{node}/32"',f'  bootstrap-resolver "local"\n  address-strategy "ipv4-only"\n  allowed-ip "10.42.0.{node}/32"')
    config.write_text(original);hosts=root/'hosts';resolv=root/'resolv.conf';hosts.write_text('127.0.0.2 peer2.test\n127.0.0.3 peer3.test\n');resolv.write_text('nameserver 127.0.0.53\n')
    t.run(['mount','--bind',hosts,'/etc/hosts']);t.run(['mount','--bind',resolv,'/etc/resolv.conf'])
    results=[]
    pathlib.Path(evidence).write_text(json.dumps({'complete':False,'cases':results,'artifacts':str(root)},indent=2)+'\n')
    mode='hosts'
    def run(backend,index):
        command=[binary,str(config),backend,str(index)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=5)
        item={'mode':mode,'command':command,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
        results.append(item);pathlib.Path(evidence).write_text(json.dumps({'complete':False,'cases':results,'artifacts':str(root)},indent=2)+'\n')
        assert result.returncode==0,(backend,index,result.returncode,result.stdout,result.stderr)
        assert 'allocations=0 after upstream' in result.stdout,(backend,index,result.stdout)
        return 'denied=1' in result.stdout
    with Peer() as dns:
        for mode in ('hosts','dns'):
            hosts.write_text('127.0.0.2 peer2.test\n127.0.0.3 peer3.test\n' if mode=='hosts' else '')
            for backend in ('epoll','uring'):
                assert not run(backend,-1)
                for index in range(2000):
                    denied=run(backend,index)
                    if not denied:
                        print(f'endpoint {mode} {backend}: {index} fresh allocation failures and first success, same-process resolver/signal recovery and natural process-exit tracked0',flush=True);break
                else:raise RuntimeError('no first success within bound')
        assert not dns.errors,dns.errors
    pathlib.Path(evidence).write_text(json.dumps({'complete':True,'cases':results,'artifacts':str(root)},indent=2)+'\n')

def main():
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('--evidence',required=True);p.add_argument('--inner',action='store_true');p.add_argument('--parent-net',type=int);p.add_argument('--parent-user',type=int);p.add_argument('--parent-mount',type=int);a=p.parse_args()
    if a.inner:inner(a.binary,a.evidence,a.parent_net,a.parent_user,a.parent_mount)
    else:subprocess.run(['unshare','-Urnm',sys.executable,__file__,str(pathlib.Path(a.binary).resolve()),'--evidence',a.evidence,'--inner','--parent-net',str(os.stat('/proc/self/ns/net').st_ino),'--parent-user',str(os.stat('/proc/self/ns/user').st_ino),'--parent-mount',str(os.stat('/proc/self/ns/mnt').st_ino)],check=True,timeout=300)
if __name__=='__main__':main()
