#!/usr/bin/env python3
"""Check the narrow Poly1305 C declarations against the fixed public header."""
import argparse
import pathlib
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    args = parser.parse_args()
    header = (args.source / "include/openssl/poly1305.h").read_text()
    if not re.search(r"typedef\s+uint8_t\s+poly1305_state\s*\[512\]\s*;", header):
        raise RuntimeError("pinned Poly1305 state ABI changed")
    signatures = (
        r"void\s+CRYPTO_poly1305_init\s*\(poly1305_state\s*\*state,\s*const uint8_t key\[32\]\);",
        r"void\s+CRYPTO_poly1305_update\s*\(poly1305_state\s*\*state,\s*const uint8_t \*in, size_t in_len\);",
        r"void\s+CRYPTO_poly1305_finish\s*\(poly1305_state\s*\*state,\s*uint8_t mac\[16\]\);",
    )
    if not all(re.search(pattern, header) for pattern in signatures):
        raise RuntimeError("pinned Poly1305 function ABI changed")
    print("Poly1305 state and all three C declarations match the pinned BoringSSL public header")


if __name__ == "__main__":
    main()
