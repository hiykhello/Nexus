from pathlib import Path
import argparse,hashlib,json,subprocess,tempfile,sys
root=Path(__file__).resolve().parents[1];parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,default=root/'endpoint-import/nexus-endpoint-no-host-dns');parser.add_argument('--evidence',type=Path,default=root/'closed-final.json');args=parser.parse_args();binary=args.binary.resolve(strict=True);rows=[]
with tempfile.TemporaryDirectory(prefix='host-dns-closed-',dir=root) as td:
 config=Path(td)/'closed.kdl';config.write_text('''schema-version 1
role "client"
endpoint "wg" type="wireguard" {
 private-key-file "/this-file-must-not-be-opened-by-closed-backend"
 listen host="127.0.0.1" port=0
 device name="nx-wg" mtu=1420
 local-address "10.42.0.1/32"
 route-include "10.42.0.2/32"
 host-dns { backend "resolved"; server "10.42.0.2"; }
 peer "a" { public-key-file "/also-never-opened"; endpoint host="127.0.0.1" port=51820; allowed-ip "10.42.0.2/32"; }
}
''')
 for mode in ('check','run'):
  p=subprocess.run([binary,'endpoint',mode,'--config',config],capture_output=True,text=True,timeout=5);assert p.returncode==1 and 'backend is not enabled in this build' in p.stderr and 'private key' not in p.stderr,(p.returncode,p.stderr);rows.append({'mode':mode,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
ldd=subprocess.run(['ldd',binary],capture_output=True,text=True,check=True).stdout;undefined=subprocess.run(['nm','-u',binary],capture_output=True,text=True,check=True).stdout;assert 'libsystemd' not in ldd and 'sd_bus_' not in undefined
report={'complete':True,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'runs':rows,'ldd':ldd,'undefined_sd_bus_symbols':False};args.evidence.write_text(json.dumps(report,indent=2)+'\n');print('closed hostDNS check/run reject before credential reads; real ELF has no libsystemd dependency or sd_bus symbols')
