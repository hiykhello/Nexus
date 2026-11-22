"""Authenticate shaped TLS1.3 hellos against OpenSSL and inspect actual wire."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

BINARY = Path(sys.argv[1]).resolve()
REPORT = Path(sys.argv[2]).resolve()

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def exact(peer, size):
    data = b""
    while len(data) < size:
        part = peer.recv(size - len(data))
        if not part:
            raise RuntimeError("truncated record")
        data += part
    return data

def shape(record):
    assert len(record) == 1600 and record[:3] == b"\x16\x03\x01"
    b = record[9:]
    assert len(b) == int.from_bytes(record[6:9], "big")
    pos = 34
    sid = b[pos+1:pos+1+b[pos]]
    assert len(sid) == 32
    pos += 1 + b[pos]
    size = int.from_bytes(b[pos:pos+2], "big")
    suites = [int.from_bytes(b[i:i+2], "big") for i in range(pos+2,pos+2+size,2)]
    pos += 2 + size
    pos += 1 + b[pos]
    size = int.from_bytes(b[pos:pos+2], "big"); pos += 2
    assert pos + size == len(b)
    extensions = []
    while pos < len(b):
        kind = int.from_bytes(b[pos:pos+2], "big")
        size = int.from_bytes(b[pos+2:pos+4], "big")
        data = b[pos+4:pos+4+size]; assert len(data) == size
        extensions.append((kind, data)); pos += 4 + size
    def grease(value):
        return value & 0x0f0f == 0x0a0a and value >> 8 == value & 255
    assert len(set(k for k,_ in extensions)) == len(extensions)
    assert grease(suites[0]) and set(suites[1:]) == {0x1301,0x1302,0x1303}
    assert grease(extensions[0][0]) and extensions[-1][0] == 21
    data = dict(extensions)
    assert not any(data[21]) and 41 not in data and 42 not in data
    groups = [int.from_bytes(data[10][i:i+2], "big") for i in range(2,len(data[10]),2)]
    shares, pos = [], 2
    while pos < len(data[51]):
        group = int.from_bytes(data[51][pos:pos+2], "big")
        size = int.from_bytes(data[51][pos+2:pos+4], "big")
        value = data[51][pos+4:pos+4+size]; assert len(value) == size
        if group in (29,4588):
            assert size == (32 if group == 29 else 1216) and any(value)
        else:
            assert grease(group) and size == 1
        shares.append(group); pos += 4 + size
    assert grease(groups[0]) and shares[0] == groups[0]
    return {"suites":suites,"extensions":[k for k,_ in extensions],"groups":groups,"shares":shares,
            "sha256":hashlib.sha256(record).hexdigest()}

results = []
with tempfile.TemporaryDirectory(prefix="nexus-fingerprint-network-") as directory:
    root = Path(directory)
    run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(root/"ca.key"),"-out",str(root/"ca.pem"),"-days","1","-subj","/CN=Fingerprint CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign")
    run("openssl","req","-new","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-keyout",str(root/"server.key"),"-out",str(root/"server.csr"),"-subj","/CN=server.example")
    (root/"ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.example\n")
    run("openssl","x509","-req","-in",str(root/"server.csr"),"-CA",str(root/"ca.pem"),"-CAkey",str(root/"ca.key"),"-set_serial","2","-days","1","-extfile",str(root/"ext"),"-out",str(root/"server.pem"))
    run("openssl","x509","-in",str(root/"ca.pem"),"-outform","DER","-out",str(root/"ca.der"))
    run("openssl","req","-x509","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-nodes","-keyout",str(root/"other.key"),"-out",str(root/"other.pem"),"-days","1","-subj","/CN=Other CA","-addext","basicConstraints=critical,CA:TRUE")
    run("openssl","x509","-in",str(root/"other.pem"),"-outform","DER","-out",str(root/"other.der"))
    for profile in ("grease","randomized"):
      for mode, group in (("x25519","X25519"),("hybrid","X25519MLKEM768"),("dual","X25519"),("dual","X25519MLKEM768"),("x25519-retry","X25519"),("hybrid-retry","X25519MLKEM768")):
       for cipher in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"):
        for identity in ("valid","wrong","untrusted"):
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1",0)); port = reserve.getsockname()[1]
            server = subprocess.Popen(["openssl","s_server","-accept",f"127.0.0.1:{port}","-tls1_3","-cert",str(root/"server.pem"),"-key",str(root/"server.key"),"-groups",group,"-ciphersuites",cipher,"-alpn","http/1.1","-www"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            client = None
            try:
                deadline = time.monotonic()+5
                while True:
                    try:
                        peer = socket.create_connection(("127.0.0.1",port),timeout=5); break
                    except ConnectionRefusedError:
                        if server.poll() is not None or time.monotonic()>deadline: raise
                        time.sleep(.02)
                with peer:
                    left,right = socket.socketpair()
                    client = subprocess.Popen([str(BINARY),mode,str(root/("other.pem" if identity=="untrusted" else "ca.pem")),identity,profile],stdin=right,stdout=right,stderr=subprocess.PIPE)
                    right.close()
                    with left:
                        header = exact(left,5); first = header+exact(left,int.from_bytes(header[3:5],"big"))
                        observed = shape(first)
                        peer.sendall(first)
                        errors = []
                        def copy(source,destination):
                            try:
                                while data:=source.recv(65536): destination.sendall(data)
                                destination.shutdown(socket.SHUT_WR)
                            except OSError as e: errors.append(str(e))
                        incoming = threading.Thread(target=copy,args=(peer,left)); outgoing = threading.Thread(target=copy,args=(left,peer))
                        incoming.start(); outgoing.start()
                        _,stderr = client.communicate(timeout=15)
                        left.shutdown(socket.SHUT_RDWR)
                        incoming.join(2); outgoing.join(2)
                        if client.returncode: raise RuntimeError(f"{profile} {mode} {group} {cipher} {identity}: {client.returncode} {stderr.decode()}")
                        results.append({"profile":profile,"mode":mode,"group":group,"cipher":cipher,"identity":identity,"exit":0,"wire":observed})
                        REPORT.write_text(json.dumps({"complete":len(results)==108,"expected_cases":108,"driver_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"cases":results,"binary_sha256":hashlib.sha256(BINARY.read_bytes()).hexdigest()},indent=2)+"\n")
                        print(profile,mode,group,cipher,identity,"passed",flush=True)
            finally:
                if client and client.poll() is None: client.kill();client.communicate()
                server.terminate()
                try: server.communicate(timeout=2)
                except subprocess.TimeoutExpired: server.kill();server.communicate()
REPORT.write_text(json.dumps({"complete":len(results)==108,"expected_cases":108,"driver_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"cases":results,"binary_sha256":hashlib.sha256(BINARY.read_bytes()).hexdigest()},indent=2)+"\n")
