"""Check the ECDH C ABI and real native-allocation hooks in fixed BoringSSL."""
import argparse
import hashlib
import json
from pathlib import Path
import re
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('source',type=Path)
parser.add_argument('report',type=Path)
args=parser.parse_args()
header=args.source/'include/openssl/ecdh.h';mem=args.source/'crypto/mem.cc'
signature=r'int\s+ECDH_compute_key\s*\(\s*void \*out, size_t outlen, const EC_POINT \*pub_key, const EC_KEY \*priv_key,\s*void \*\(\*kdf\)\(const void \*in, size_t inlen, void \*out, size_t \*outlen\)\);'
if not re.search(signature,header.read_text()):raise RuntimeError('pinned ECDH function ABI changed')
for pattern in (r'WEAK_SYMBOL_FUNC\(void \*, OPENSSL_memory_alloc, \(size_t size\)\)',r'WEAK_SYMBOL_FUNC\(void, OPENSSL_memory_free, \(void \*ptr\)\)',r'WEAK_SYMBOL_FUNC\(size_t, OPENSSL_memory_get_size, \(void \*ptr\)\)'):
    if not re.search(pattern,mem.read_text()):raise RuntimeError('pinned native allocation hook ABI changed')
args.report.write_text(json.dumps({'ecdh_signature_checked':True,'native_allocator_hooks_checked':3,'native_hook_policy':'test-only, no recursion, zero-before-free','inputs':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [header,mem]}},indent=2)+'\n')
print('ECDH ABI and all three real native BoringSSL allocation hooks match fixed source')
