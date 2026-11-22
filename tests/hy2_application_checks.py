import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,'/home/yk/Code/Nexus/tests')
from quic_udp_network import credential
parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,default=Path('build'));parser.add_argument('--report',type=Path,required=True);parser.add_argument('--resource',action='store_true');parser.add_argument('--abandon',action='store_true');args=parser.parse_args()
report={'complete':False,'cases':[]}
try:
    with tempfile.TemporaryDirectory(prefix='hy2-checks-') as directory:
        for name,algorithm,options,scheme in [('p256','EC',['-pkeyopt','ec_paramgen_curve:P-256'],'0x0403'),('rsa','RSA',['-pkeyopt','rsa_keygen_bits:2048'],'0x0804'),('ed25519','ED25519',[],'0x0807')]:
            cert,key=credential(Path(directory),name,algorithm,options)
            test='hy2_shared_port_resources' if args.resource else 'hy2_shared_port_abandon' if args.abandon else 'hy2_application_lifecycle'
            binary=(args.build/test).resolve();p=subprocess.run([binary,cert,key],text=True,capture_output=True,timeout=100)
            item={'certificate':name,'test':test,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};report['cases'].append(item)
            print(name,test,'exit',p.returncode,flush=True)
            if p.returncode:raise RuntimeError(json.dumps(item,indent=2))
        if not args.abandon and not args.resource:
            for name in ['hy2_stream_buffer','hy2_udp_owners','hysteria2_auth','hysteria2_wire','hysteria2_udp','hysteria2_fragment_allocation','hysteria2_vectors']:
                binary=(args.build/name).resolve();p=subprocess.run([binary],text=True,capture_output=True,timeout=40);item={'test':name,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};report['cases'].append(item)
                print(name,'exit',p.returncode,flush=True)
                if p.returncode:raise RuntimeError(json.dumps(item,indent=2))
    report['complete']=True
finally:args.report.write_text(json.dumps(report,indent=2)+'\n')
