import argparse,concurrent.futures,hashlib,json,re,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from quic_udp_network import credential
parser=argparse.ArgumentParser();parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path,required=True);parser.add_argument('--quick',action='store_true');args=parser.parse_args()
binary=args.binary.resolve();report={'complete':False,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'groups':[]}
def run(cert,key,backend,target):
    p=subprocess.run([str(binary),str(cert),str(key),str(backend),str(target)],text=True,capture_output=True,timeout=15)
    item={'target':target,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    if p.returncode not in (0,6):return item
    match=re.search(r'denied=(true|false) calls=(\d+)',p.stdout)
    if not match or 'process-exit tracked ordinary/array/aligned allocations=0' not in p.stdout:raise RuntimeError(json.dumps(item,indent=2))
    item.update(denied=match[1]=='true',calls=int(match[2]));return item
try:
    with tempfile.TemporaryDirectory(prefix='hy2-cpp-cold-') as directory:
        algorithms=[('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'])]
        if not args.quick:algorithms += [('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048']),('ed25519','ED25519',[])]
        for name,algorithm,options in algorithms:
            cert,key=credential(Path(directory),name,algorithm,options)
            for backend in (['0'] if args.quick else ['0','1']):
                baseline=run(cert,key,backend,0)
                if baseline['exit']:raise RuntimeError(json.dumps(baseline,indent=2))
                group={'certificate':name,'backend':backend,'baseline':baseline,'cases':[]};report['groups'].append(group)
                count=baseline['calls'];print(name,backend,'baseline C++ calls',count,flush=True)
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    futures={pool.submit(run,cert,key,backend,point):point for point in range(1,count+1)}
                    for future in concurrent.futures.as_completed(futures):
                        item=future.result();group['cases'].append(item)
                group['cases'].sort(key=lambda item:item['target'])
                # Native UDP scheduling can remove one terminal timeout frame;
                # keep that real first-success result, and require each lower
                # ordinal to have actually denied in a fresh process.
                unexpected=[item for item in group['cases'] if item['exit'] not in (0,6)]
                if unexpected:raise RuntimeError(json.dumps(unexpected,indent=2))
                for item in group['cases']:
                    if item['exit']==6:
                        attempts=[]
                        for _ in range(20):
                            retry=run(cert,key,backend,item['target']);attempts.append(retry)
                            if retry['exit'] not in (0,6):raise RuntimeError(json.dumps(retry,indent=2))
                            if retry.get('denied'):
                                item['attempts']=attempts;item['denial_observed']=True;break
                        else:item['attempts']=attempts;item['first_success_boundary']=True
                lower=[item['target'] for item in group['cases'] if item.get('denied') or item.get('denial_observed')]
                if not lower or lower!=list(range(1,max(lower)+1)):raise RuntimeError('noncontiguous actual denial sweep')
                if not any(item.get('first_success_boundary') for item in group['cases']):
                    for point in range(max(lower)+1,max(lower)+65):
                        item=run(cert,key,backend,point);group['cases'].append(item)
                        if item['exit'] not in (0,6):raise RuntimeError(json.dumps(item,indent=2))
                        if item.get('denied'):lower.append(point)
                        else:
                            item['first_success_boundary']=True;break
                    else:raise RuntimeError('no actual first-success boundary within bounded extension')
                group['actual_failure_points']=max(lower)
                group['tail_successes']=[item for item in group['cases'] if item.get('first_success_boundary')]
                print(name,backend,'fresh-process actual failure points',group['actual_failure_points'],'all recovered and natural allocations0',flush=True)
    report['complete']=True
finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
