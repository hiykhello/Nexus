#!/usr/bin/env python3
"""Generate independent credentials and verify Nexus CertificateVerify signatures."""
import pathlib
import subprocess
import sys
import tempfile

fixture = pathlib.Path(sys.argv[1]).resolve()
profile_fixture = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)

with tempfile.TemporaryDirectory(prefix="nexus-server-credential-") as directory:
    root = pathlib.Path(directory)
    wrong = root / "wrong.der"
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(root / "wrong.pem"))
    run("openssl", "pkey", "-in", str(root / "wrong.pem"), "-outform", "DER", "-out", str(wrong))
    data = root / "input.bin"
    data.write_bytes(b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + bytes([0x42]) * 32)
    for algorithm, options, scheme in [("RSA", ["-pkeyopt", "rsa_keygen_bits:2048"], "0804"),
                                       ("EC", ["-pkeyopt", "ec_paramgen_curve:P-256"], "0403"),
                                       ("ED25519", [], "0807")]:
        key = root / "key.pem"; der = root / "key.der"; cert = root / "cert.der"; pub = root / "public.pem"; sig = root / "signature.bin"
        run("openssl", "genpkey", "-algorithm", algorithm, *options, "-out", str(key))
        run("openssl", "pkey", "-in", str(key), "-outform", "DER", "-out", str(der))
        run("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub))
        run("openssl", "req", "-new", "-x509", "-key", str(key), "-subj", "/CN=localhost", "-days", "1", "-outform", "DER", "-out", str(cert))
        run(str(fixture), str(cert), str(der), str(wrong), scheme, str(sig))
        if profile_fixture:
            run(str(profile_fixture), str(cert), str(der), str(wrong))
            uuid = root / "uuid"; uuid.write_text("00010203-0405-0607-0809-0a0b0c0d0e0f\n"); uuid.chmod(0o600)
            der.chmod(0o600)
            run(str(profile_fixture), str(cert), str(der), str(wrong), str(uuid), "accept")
            cert_pem=root / "cert.pem"
            run("openssl", "x509", "-inform", "DER", "-in", str(cert), "-out", str(cert_pem))
            key.chmod(0o600)
            (root / "wrong.pem").chmod(0o600)
            run(str(profile_fixture),str(cert_pem),str(root / "wrong.pem"),str(wrong),str(uuid),"reject")
            for cert_input,key_input in [(cert_pem,key),(cert_pem,der),(cert,key)]:
                run(str(profile_fixture),str(cert_input),str(key_input),str(wrong),str(uuid),"accept")
            bad=root / "bad.pem"
            bad.write_text(cert_pem.read_text()+cert_pem.read_text())
            run(str(profile_fixture),str(bad),str(key),str(wrong),str(uuid),"reject")
            bad.write_text("junk\n"+cert_pem.read_text())
            run(str(profile_fixture),str(bad),str(key),str(wrong),str(uuid),"reject")
            bad.write_text(key.read_text()+"junk\n"); bad.chmod(0o600)
            run(str(profile_fixture),str(cert_pem),str(bad),str(wrong),str(uuid),"reject")
            bad.write_text(key.read_text()+key.read_text())
            run(str(profile_fixture),str(cert_pem),str(bad),str(wrong),str(uuid),"reject")
            encrypted=root / "encrypted.pem"
            run("openssl","pkey","-in",str(key),"-aes-256-cbc","-passout","pass:test","-out",str(encrypted))
            encrypted.chmod(0o600)
            run(str(profile_fixture),str(cert_pem),str(encrypted),str(wrong),str(uuid),"reject")

            der.chmod(0o644)
            run(str(profile_fixture), str(cert), str(der), str(wrong), str(uuid), "reject")
            der.chmod(0o600); uuid.chmod(0o644)
            run(str(profile_fixture), str(cert), str(der), str(wrong), str(uuid), "reject")
            uuid.chmod(0o600)
            link = root / "key-link"; link.symlink_to(der)
            run(str(profile_fixture), str(cert), str(link), str(wrong), str(uuid), "reject")
            link.unlink()
            uuid.write_text("not-a-uuid")
            run(str(profile_fixture), str(cert), str(der), str(wrong), str(uuid), "reject")
            uuid.write_bytes(b"x" * 1048577)
            run(str(profile_fixture), str(cert), str(der), str(wrong), str(uuid), "reject")
        if algorithm == "ED25519":
            run("openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-rawin", "-in", str(data), "-sigfile", str(sig))
        else:
            extra = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32"] if algorithm == "RSA" else []
            run("openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig), *extra, str(data))
        print(f"{algorithm} credential and OpenSSL signature verification passed")

    for algorithm, options in [("RSA", ["-pkeyopt", "rsa_keygen_bits:1024"]),
                               ("EC", ["-pkeyopt", "ec_paramgen_curve:P-384"])]:
        key = root / "unsupported.pem"; der = root / "unsupported.der"; cert = root / "unsupported-cert.der"
        run("openssl", "genpkey", "-algorithm", algorithm, *options, "-out", str(key))
        run("openssl", "pkey", "-in", str(key), "-outform", "DER", "-out", str(der))
        run("openssl", "req", "-new", "-x509", "-key", str(key), "-subj", "/CN=localhost", "-days", "1", "-outform", "DER", "-out", str(cert))
        run(str(fixture), str(cert), str(der), "unsupported")
        print(f"unsupported {algorithm} key rejected")
