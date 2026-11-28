"""TLS ClientHello wire parser, JA4 calculator, and upstream uTLS Go spec parser."""
from __future__ import annotations

import hashlib
import re

CIPHER_NAME_TO_ID = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xC030,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": 0xCCA9,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA9,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": 0xCCA8,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA8,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xC009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xC00A,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xC013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xC014,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
    "FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": 0xC008,
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": 0xC012,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    "DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xC024,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xC023,
    "DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 0xC028,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 0xC027,
    "DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
    "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
}

GROUP_NAME_TO_ID = {
    "X25519MLKEM768": 0x11EC, "X25519Kyber768Draft00": 0x6399,
    "X25519": 0x001D, "CurveP256": 0x0017, "CurveP384": 0x0018, "CurveP521": 0x0019,
}

SIG_NAME_TO_ID = {
    "ECDSAWithP256AndSHA256": 0x0403, "ECDSAWithP384AndSHA384": 0x0503,
    "ECDSAWithP521AndSHA512": 0x0603, "PSSWithSHA256": 0x0804,
    "PSSWithSHA384": 0x0805, "PSSWithSHA512": 0x0806, "Ed25519": 0x0807,
    "PKCS1WithSHA256": 0x0401, "PKCS1WithSHA384": 0x0501, "PKCS1WithSHA512": 0x0601,
    "ECDSAWithSHA1": 0x0203, "PKCS1WithSHA1": 0x0201,
    "MLDSA44": 0x0904, "MLDSA65": 0x0905, "MLDSA87": 0x0906,
}

CERT_COMP_NAME_TO_ID = {
    "CertCompressionZlib": 1, "CertCompressionBrotli": 2, "CertCompressionZstd": 3,
}

GO_EXT_TO_ID = {
    "SNIExtension": 0, "StatusRequestExtension": 5, "SupportedCurvesExtension": 10,
    "SupportedPointsExtension": 11, "SignatureAlgorithmsExtension": 13,
    "ALPNExtension": 16, "SCTExtension": 18, "UtlsPaddingExtension": 21,
    "ExtendedMasterSecretExtension": 23, "UtlsCompressCertExtension": 27,
    "FakeRecordSizeLimitExtension": 28, "FakeDelegatedCredentialsExtension": 34,
    "SessionTicketExtension": 35, "SupportedVersionsExtension": 43,
    "PSKKeyExchangeModesExtension": 45, "KeyShareExtension": 51,
    "ApplicationSettingsExtension": 0x4469, "ApplicationSettingsExtensionNew": 0x44CD,
    "TrustAnchorsExtension": 0xCA34, "GREASEEncryptedClientHelloExtension": 0xFE0D,
    "BoringGREASEECH": 0xFE0D, "RenegotiationInfoExtension": 0xFF01,
}

EXT_ID_TO_NAME = {v: k.removesuffix("Extension") for k, v in GO_EXT_TO_ID.items()}
EXT_ID_TO_NAME.update({0x0039: "quic_transport_parameters", 0xFE0D: "ECH"})


def is_grease(val: int) -> bool:
    return (val & 0x0F0F) == 0x0A0A and (val >> 8) == (val & 0xFF)


def fmt_hex_list(items: list[int]) -> list[str]:
    return [f"0x{x:04x}" for x in items]


def parse_client_hello(raw: bytes) -> dict:
    """Parse raw TLS ClientHello bytes (TLS record, handshake message, or raw ClientHello body)."""
    data = raw
    if len(data) >= 9 and data[0] == 22 and data[5] == 1:
        data = data[5 : 5 + int.from_bytes(data[3:5], "big")]
    if len(data) >= 42 and data[0] == 1:
        body = data[4 : 4 + int.from_bytes(data[1:4], "big")]
    elif len(data) >= 38 and data[0] == 3 and data[1] in (1, 2, 3, 4):
        body = data
    else:
        raise ValueError("not a TLS ClientHello message")
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    cs_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    raw_ciphers = [int.from_bytes(body[i : i + 2], "big") for i in range(pos, pos + cs_len, 2)]
    pos += cs_len
    pos += 1 + body[pos]
    ext_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    end = pos + ext_len

    raw_exts: list[tuple[int, bytes]] = []
    while pos < end:
        etype = int.from_bytes(body[pos : pos + 2], "big")
        elen = int.from_bytes(body[pos + 2 : pos + 4], "big")
        pos += 4
        raw_exts.append((etype, body[pos : pos + elen]))
        pos += elen

    ciphers = [c for c in raw_ciphers if not is_grease(c)]
    ext_ids = [t for t, _ in raw_exts if not is_grease(t)]
    groups: list[int] = []
    key_shares: list[int] = []
    sigalgs: list[int] = []
    versions: list[int] = []
    cert_comp: list[int] = []
    alpn: list[str] = []
    grease_groups = grease_ks = grease_sigs = grease_vers = False
    rsl = alps_code = padding_len = None
    has_ech = has_sni = False

    for etype, ed in raw_exts:
        if etype == 0:
            has_sni = True
        elif etype == 10 and len(ed) >= 2:
            for i in range(2, 2 + int.from_bytes(ed[0:2], "big"), 2):
                g = int.from_bytes(ed[i : i + 2], "big")
                if is_grease(g):
                    grease_groups = True
                else:
                    groups.append(g)
        elif etype == 13 and len(ed) >= 2:
            for i in range(2, 2 + int.from_bytes(ed[0:2], "big"), 2):
                s = int.from_bytes(ed[i : i + 2], "big")
                if is_grease(s):
                    grease_sigs = True
                else:
                    sigalgs.append(s)
        elif etype == 16 and len(ed) >= 2:
            p, lim = 2, 2 + int.from_bytes(ed[0:2], "big")
            while p < lim:
                n = ed[p]
                alpn.append(ed[p + 1 : p + 1 + n].decode("ascii", "replace"))
                p += 1 + n
        elif etype == 21:
            padding_len = len(ed)
        elif etype == 27 and len(ed) >= 1:
            cert_comp = [int.from_bytes(ed[i : i + 2], "big") for i in range(1, 1 + ed[0], 2)]
        elif etype == 28 and len(ed) == 2:
            rsl = int.from_bytes(ed, "big")
        elif etype == 43 and len(ed) >= 1:
            for i in range(1, 1 + ed[0], 2):
                v = int.from_bytes(ed[i : i + 2], "big")
                if is_grease(v):
                    grease_vers = True
                else:
                    versions.append(v)
        elif etype == 51 and len(ed) >= 2:
            p, lim = 2, 2 + int.from_bytes(ed[0:2], "big")
            while p + 4 <= lim:
                g = int.from_bytes(ed[p : p + 2], "big")
                p += 4 + int.from_bytes(ed[p + 2 : p + 4], "big")
                if is_grease(g):
                    grease_ks = True
                else:
                    key_shares.append(g)
        elif etype in (0x4469, 0x44CD):
            alps_code = etype
        elif etype == 0xFE0D:
            has_ech = True

    proto = "q" if 0x0039 in ext_ids else "t"
    ver = "13" if 0x0304 in versions else "12"
    alpn_tag = (alpn[0][0] + alpn[0][-1]) if alpn else "00"
    cs_hash = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12]
    ja4_exts = sorted(e for e in ext_ids if e not in (0, 16))
    ext_sig = ",".join(f"{e:04x}" for e in ja4_exts) + "_" + ",".join(f"{s:04x}" for s in sigalgs)
    ext_hash = hashlib.sha256(ext_sig.encode()).hexdigest()[:12]
    ja4 = f"{proto}{ver}{'d' if has_sni else 'i'}{len(ciphers):02d}{len(ext_ids):02d}{alpn_tag}_{cs_hash}_{ext_hash}"

    return {
        "session_id_len": sid_len, "ciphers": ciphers,
        "grease_cipher": bool(raw_ciphers and is_grease(raw_ciphers[0])),
        "extensions": ext_ids,
        "grease_ext_bookends": len(raw_exts) >= 2 and is_grease(raw_exts[0][0]) and is_grease(raw_exts[-1][0]),
        "groups": groups, "grease_groups": grease_groups,
        "key_shares": key_shares, "grease_key_share": grease_ks,
        "sigalgs": sigalgs, "grease_sigalgs": grease_sigs,
        "versions": versions, "grease_versions": grease_vers,
        "cert_comp": cert_comp, "alpn": alpn, "record_size_limit": rsl,
        "alps_code": alps_code, "has_ech": has_ech, "padding_len": padding_len, "ja4": ja4,
    }


def _extract_balanced(text: str, start: int) -> str:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def _parse_val(tok: str, table: dict[str, int]) -> int | None:
    tok = re.sub(r"^(?:CurveID|SignatureScheme|uint16)\((.+)\)$", r"\1", tok.strip()).strip()
    if tok in table:
        return table[tok]
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    return int(tok) if tok.isdigit() else None


def parse_utls_go(u_common_text: str, u_parrots_text: str) -> dict[str, dict]:
    """Extract Auto browser ClientHelloSpec baselines from u_common.go & u_parrots.go."""
    auto_map = {"android": "HelloAndroid_11_OkHttp"}
    for fam, var in [
        ("chrome", "HelloChrome_Auto"), ("firefox", "HelloFirefox_Auto"),
        ("safari", "HelloSafari_Auto"), ("ios", "HelloIOS_Auto"), ("edge", "HelloEdge_Auto"),
    ]:
        if m := re.search(rf"\b{var}\s*=\s*(Hello\w+)", u_common_text):
            auto_map[fam] = m.group(1)

    results: dict[str, dict] = {}
    for fam, cid in auto_map.items():
        m = re.search(rf"case\s+{re.escape(cid)}\s*:", u_parrots_text)
        if not m:
            continue
        sp = u_parrots_text.find("ClientHelloSpec{", m.end())
        if sp == -1:
            continue
        blk = re.sub(r"//.*", "", _extract_balanced(u_parrots_text, sp + len("ClientHelloSpec")))

        ciphers, grease_cipher = [], False
        if cm := re.search(r"CipherSuites\s*:\s*\[\]uint16\s*\{", blk):
            for tok in re.findall(r"[A-Za-z0-9_]+", _extract_balanced(blk, cm.end() - 1)):
                if tok == "GREASE_PLACEHOLDER":
                    grease_cipher = True
                elif (v := _parse_val(tok, CIPHER_NAME_TO_ID)) is not None:
                    ciphers.append(v)

        exts, groups, key_shares, sigalgs, cert_comp = [], [], [], [], []
        grease_exts = 0
        grease_g = grease_ks = grease_s = has_ech = False
        rsl = alps_code = None

        if em := re.search(r"Extensions\s*:\s*(?:ShuffleChromeTLSExtensions\()?\s*\[\]TLSExtension\s*\{", blk):
            eblk = _extract_balanced(blk, em.end() - 1)
            for ematch in re.finditer(r"(&?[A-Z][A-Za-z0-9_]+)\s*([{(])", eblk):
                name = ematch.group(1).lstrip("&")
                if name == "UtlsGREASEExtension":
                    grease_exts += 1
                    continue
                if name not in GO_EXT_TO_ID:
                    continue
                eid = GO_EXT_TO_ID[name]
                exts.append(eid)
                if eid in (0x4469, 0x44CD):
                    alps_code = eid
                if eid == 0xFE0D:
                    has_ech = True
                if ematch.group(2) != "{":
                    continue
                sub = _extract_balanced(eblk, ematch.end() - 1)
                if name == "SupportedCurvesExtension":
                    for tok in re.findall(r"GREASE_PLACEHOLDER|CurveID\([^)]+\)|[A-Za-z0-9_]+", sub):
                        if "GREASE_PLACEHOLDER" in tok:
                            grease_g = True
                        elif (v := _parse_val(tok, GROUP_NAME_TO_ID)) is not None:
                            groups.append(v)
                elif name == "KeyShareExtension":
                    for km in re.finditer(r"Group\s*:\s*([^,\n}]+)", sub):
                        if "GREASE_PLACEHOLDER" in km.group(1):
                            grease_ks = True
                        elif (v := _parse_val(km.group(1), GROUP_NAME_TO_ID)) is not None:
                            key_shares.append(v)
                elif name == "SignatureAlgorithmsExtension":
                    for tok in re.findall(r"GREASE_PLACEHOLDER|[A-Za-z0-9_]+", sub):
                        if tok == "GREASE_PLACEHOLDER":
                            grease_s = True
                        elif (v := _parse_val(tok, SIG_NAME_TO_ID)) is not None:
                            sigalgs.append(v)
                elif name == "UtlsCompressCertExtension":
                    cert_comp.extend(CERT_COMP_NAME_TO_ID[t] for t in re.findall(r"CertCompression\w+", sub) if t in CERT_COMP_NAME_TO_ID)
                elif name == "FakeRecordSizeLimitExtension":
                    if rm := re.search(r"Limit\s*:\s*(0x[0-9a-fA-F]+|\d+)", sub):
                        rsl = int(rm.group(1), 0)

        results[fam] = {
            "upstream_id": cid, "shuffled": "ShuffleChromeTLSExtensions" in blk,
            "ciphers": ciphers, "grease_cipher": grease_cipher,
            "extensions": exts, "grease_ext_bookends": grease_exts >= 2,
            "groups": groups, "grease_groups": grease_g,
            "key_shares": key_shares, "grease_key_share": grease_ks,
            "sigalgs": sigalgs, "grease_sigalgs": grease_s,
            "cert_comp": cert_comp, "record_size_limit": rsl,
            "alps_code": alps_code, "has_ech": has_ech,
        }
    return results
