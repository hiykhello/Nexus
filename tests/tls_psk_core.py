import argparse
import hashlib
import hmac
import json
from pathlib import Path
import subprocess

parser=argparse.ArgumentParser()
parser.add_argument('binary',type=Path)
parser.add_argument('report',type=Path)
args=parser.parse_args()
binary=args.binary.resolve()
done=subprocess.run([binary],capture_output=True,text=True,timeout=60)
if done.returncode:raise RuntimeError(f'core exited {done.returncode}: {done.stdout}{done.stderr}')
rows=[json.loads(line) for line in done.stdout.splitlines()]

def expand(hash_name,secret,info,length):
    previous=b'';out=b''
    for counter in range(1,256):
        previous=hmac.digest(secret,previous+info+bytes([counter]),hash_name)
        out+=previous
        if len(out)>=length:return out[:length]
    raise ValueError('output too long')

def label(hash_name,secret,label,context,length):
    label=b'tls13 '+label
    info=length.to_bytes(2,'big')+bytes([len(label)])+label+bytes([len(context)])+context
    return expand(hash_name,secret,info,length)

def parse(wire):
    p=4+2+32
    p+=1+wire[p]
    p+=2+int.from_bytes(wire[p:p+2],'big')
    p+=1+wire[p]
    total=int.from_bytes(wire[p:p+2],'big');p+=2
    if p+total!=len(wire):raise ValueError('bad extension block')
    while p<len(wire):
        kind=int.from_bytes(wire[p:p+2],'big');size=int.from_bytes(wire[p+2:p+4],'big');p+=4
        if kind!=41:p+=size;continue
        if p+size!=len(wire):raise ValueError('PSK is not last')
        identities_end=p+2+int.from_bytes(wire[p:p+2],'big')
        identities=[];q=p+2
        while q<identities_end:
            n=int.from_bytes(wire[q:q+2],'big');q+=2
            identities.append(wire[q:q+n]);q+=n+4
        if q!=identities_end:raise ValueError('bad identities')
        binder_end=identities_end+2+int.from_bytes(wire[identities_end:identities_end+2],'big')
        binders=[];q=identities_end+2
        while q<binder_end:n=wire[q];q+=1;binders.append(wire[q:q+n]);q+=n
        if q!=len(wire) or len(binders)!=len(identities):raise ValueError('bad binders')
        return wire[:identities_end],dict(zip(identities,binders)),binders[0]
    raise ValueError('missing PSK')

checked=0
for row in rows:
    if 'wire' not in row:continue
    hash_name=row['hash'];size=hashlib.new(hash_name).digest_size
    secret=bytes.fromhex(row['secret']);wire=bytes.fromhex(row['wire']);partial,binders,actual=parse(wire)
    if row.get('multi'):actual=binders[bytes.fromhex(row['identity'])]
    first=bytes.fromhex(row.get('first',''));retry=bytes.fromhex(row.get('retry',''))
    transcript=partial
    if first:
        digest=hashlib.new(hash_name,first).digest()
        transcript=bytes([254,0,0,len(digest)])+digest+retry+partial
    early=hmac.digest(bytes(size),secret,hash_name)
    empty=hashlib.new(hash_name).digest()
    binder_key=label(hash_name,early,b'res binder' if row['kind']=='resumption' else b'ext binder',empty,size)
    finished=label(hash_name,binder_key,b'finished',b'',size)
    expected=hmac.digest(finished,hashlib.new(hash_name,transcript).digest(),hash_name)
    if actual!=expected:raise ValueError('independent binder mismatch')
    checked+=1
for row in rows:
    if not row.get('ticket'):continue
    master=bytes.fromhex(row['master']);nonce=bytes.fromhex(row['nonce']);expected=label(row['hash'],master,b'resumption',nonce,len(master))
    if bytes.fromhex(row['psk'])!=expected:raise ValueError('independent ticket derivation mismatch')
if checked!=10 or not rows[-1].get('complete'):raise ValueError('missing test matrix')
args.report.write_text(json.dumps({'complete':True,'exit':done.returncode,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'independent_binder_vectors':checked,'ticket_vectors':2,'stdout':done.stdout,'stderr':done.stderr},indent=2)+'\n')
print('Independent Python HKDF/HMAC binder10 and ticket2 plus cache/parser negative tests passed')
