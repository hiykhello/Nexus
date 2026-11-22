#!/usr/bin/env python3
"""Cancel each native startup exchange and verify checked rollback in an owned namespace."""
import argparse,hashlib,json,os,pathlib,subprocess,sys

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=pathlib.Path);parser.add_argument('--evidence',type=pathlib.Path,required=True);parser.add_argument('--inner',action='store_true');parser.add_argument('--parent-net',type=int);parser.add_argument('--parent-user',type=int);args=parser.parse_args()
    if not args.inner:
        subprocess.run(['unshare','-Urn',sys.executable,__file__,str(args.binary.resolve()),'--evidence',str(args.evidence.resolve()),'--inner','--parent-net',str(os.stat('/proc/self/ns/net').st_ino),'--parent-user',str(os.stat('/proc/self/ns/user').st_ino)],check=True,timeout=60);return
    assert os.stat('/proc/self/ns/net').st_ino!=args.parent_net and os.stat('/proc/self/ns/user').st_ino!=args.parent_user
    for command in [['ip','link','set','lo','up'],['ip','link','add','nx-phys','type','dummy'],['ip','link','set','nx-phys','up'],['ip','addr','add','192.0.2.1/24','dev','nx-phys'],['ip','-6','addr','add','fd55::1/64','dev','nx-phys','nodad']]:subprocess.run(command,check=True)
    done=subprocess.run([args.binary,str(args.parent_net),str(args.parent_user)],capture_output=True,text=True,timeout=55)
    args.evidence.write_text(json.dumps({'complete':done.returncode==0,'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr,'binary_sha256':hashlib.sha256(args.binary.read_bytes()).hexdigest()},indent=2)+'\n')
    print(done.stdout,done.stderr);raise SystemExit(done.returncode)
if __name__=='__main__':main()
