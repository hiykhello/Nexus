"""Check the narrow C declaration against the fixed BoringSSL public header."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument("source",type=Path)
parser.add_argument("--module",type=Path,required=True)
args=parser.parse_args()
header=args.source/"include/openssl/chacha.h"
signature=r"void\s+CRYPTO_chacha_20\s*\(uint8_t\s*\*out,\s*const uint8_t\s*\*in,\s*size_t in_len,\s*const uint8_t key\[32\],\s*const uint8_t nonce\[12\],\s*uint32_t counter\);"
if not re.search(signature,header.read_text()):raise RuntimeError("ChaCha C signature changed")
with tempfile.TemporaryDirectory(prefix="nexus-chacha-native-") as directory:
    root=Path(directory)
    native=root/"native.cpp"
    native.write_text('#include <openssl/chacha.h>\n#include <type_traits>\nusing Signature=void (*)(uint8_t*,uint8_t const*,size_t,uint8_t const*,uint8_t const*,uint32_t);\nstatic_assert(std::is_same_v<decltype(&CRYPTO_chacha_20),Signature>);\nint main() {}\n')
    subprocess.run(["g++","-std=c++26","-I"+str(args.source/"include"),"-c",str(native),"-o",str(root/"native.o")],check=True)
assert "extern \"C\" void CRYPTO_chacha_20(uint8_t*,uint8_t const*,size_t,uint8_t const[32],uint8_t const[12],uint32_t);" in args.module.read_text()
print("ChaCha function exact native C signature and narrow module declaration match pinned header")
