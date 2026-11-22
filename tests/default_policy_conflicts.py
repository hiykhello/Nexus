from pathlib import Path
import json,subprocess,sys

root=Path(__file__).resolve().parents[1]
def run(*args):
    done=subprocess.run(args,capture_output=True,text=True)
    if done.returncode:print(done.stdout,done.stderr,flush=True)
    done.check_returncode();return done.stdout
if len(sys.argv)==1:
    records=[]
    for mode in ['capture-table','bypass-table','priority','higher-mark','early-rule','complex-route','down-link','too-many-routes']:
        command=['unshare','-Urn',sys.executable,__file__,str(Path('/proc/self/ns/net').stat().st_ino),str(Path('/proc/self/ns/user').stat().st_ino),mode]
        done=subprocess.run(command,capture_output=True,text=True,timeout=15)
        record={'command':command,'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr};records.append(record)
        print(json.dumps(record),flush=True)
    (root/'policy-preflight.json').write_text(json.dumps({'complete':all(not item['exit'] for item in records),'cases':records},indent=2)+'\n')
    raise SystemExit(any(item['exit'] for item in records))
assert int(sys.argv[1])!=Path('/proc/self/ns/net').stat().st_ino
assert int(sys.argv[2])!=Path('/proc/self/ns/user').stat().st_ino
mode=sys.argv[3]
run('ip','link','add','nx-phys','type',*(['veth','peer','name','nx-down'] if mode=='down-link' else ['dummy']));run('ip','link','set','nx-phys','up')
run('ip','addr','add','192.0.2.1/24','dev','nx-phys')
run('ip','-6','addr','add','fd55::1/64','dev','nx-phys','nodad')
if mode=='capture-table':run('ip','route','add','198.51.100.0/24','dev','nx-phys','table','60000')
elif mode=='bypass-table':run('ip','-6','route','add','2001:db8::/32','dev','nx-phys','table','60001')
elif mode=='priority':run('ip','-4','rule','add','priority','10001','table','65000')
elif mode=='higher-mark':run('ip','-6','rule','add','priority','50000','fwmark','0x6e780001/0xffffffff','table','65000')
elif mode=='early-rule':run('ip','-4','rule','add','priority','1','table','65000')
elif mode=='complex-route':run('ip','route','add','blackhole','198.18.0.0/15')
elif mode=='down-link':
    # Administrative down removes routes; carrier-down with IFF_UP retains the
    # actual main route and must not be accepted as a verified physical bypass.
    assert 'LOWER_UP' not in json.loads(run('ip','-j','link','show','nx-phys'))[0]['flags']
elif mode=='too-many-routes':
    for value in range(65):run('ip','route','add',f'198.18.{value}.0/24','dev','nx-phys')
def snapshot():
    return {f'{family}-{kind}':json.loads(run('ip','-j',family,kind,'show',*(['table','all'] if kind=='route' else []))) for family in ['-4','-6'] for kind in ['rule','route']}
before=snapshot();filters={name:Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').read_text() for name in ['all','default','nx-phys']}
output=run(str(root/'policy-import/default_policy_native'),*sys.argv[1:3],'reject')
assert snapshot()==before
assert {name:Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').read_text() for name in filters}==filters
print(mode,output,flush=True)
