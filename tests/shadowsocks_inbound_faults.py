#!/usr/bin/env python3
"""Exercise malformed and stalled SS-2022 handshakes through the Nexus CLI."""
import base64
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
wire_tool=nexus.with_name("nexus-shadowsocks-replay-wire")
client_tool=nexus.with_name("nexus-shadowsocks-singbox-client")

def exact(sock,size):
    data=bytearray()
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk: raise RuntimeError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)

def scenario(root,size,workers):
    with socket.socket() as target, socket.socket() as reservation:
        target.bind(("127.0.0.1",0)); target.listen(8); target.settimeout(.2)
        reservation.bind(("127.0.0.1",0)); port=reservation.getsockname()[1]; reservation.close()
        key=root/"key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
        config=root/"server.kdl"; config.write_text(f'''schema-version 1
role "server"
workers {workers}
inbounds {{ shadowsocks "ss" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{size*8}-gcm"; key-file "{key}"; }} }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
''')
        proxy=subprocess.Popen([nexus,"run","--config",config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        peer=None
        try:
            deadline=time.monotonic()+5
            while True:
                if proxy.poll() is not None: raise RuntimeError(proxy.stderr.read().decode())
                try: check=socket.create_connection(("127.0.0.1",port),timeout=.2); check.close(); break
                except OSError:
                    if time.monotonic()>=deadline: raise
                    time.sleep(.02)
            wire=subprocess.run([wire_tool,str(size),str(target.getsockname()[1])],check=True,capture_output=True).stdout
            damaged_fixed=bytearray(wire); damaged_fixed[size]^=1
            damaged_variable=bytearray(wire); damaged_variable[-1]^=1
            for payload in (b"x",damaged_fixed,damaged_variable):
                with socket.create_connection(("127.0.0.1",port),timeout=5) as probe:
                    probe.settimeout(5); probe.sendall(payload)
                    try: received=probe.recv(1)
                    except ConnectionResetError: pass
                    else: raise RuntimeError(f"invalid handshake did not reset: {received!r}")
            partial=subprocess.run([wire_tool,str(size),str(target.getsockname()[1]),"70"],check=True,capture_output=True).stdout
            stalled=socket.create_connection(("127.0.0.1",port),timeout=5)
            incomplete=socket.create_connection(("127.0.0.1",port),timeout=5)
            start=time.monotonic()
            stalled.settimeout(15); incomplete.settimeout(15)
            incomplete.sendall(partial[:size+27])
            # A fresh valid salt is needed: the malformed variable header above
            # already registered its authenticated fixed header in the replay table.
            # Use the other fixed test salt for the subsequent healthy session.
            with socket.create_connection(("127.0.0.1",port),timeout=5) as connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client_tool,str(connection.fileno()),str(size),str(target.getsockname()[1]),"half-close"],
                                      pass_fds=(connection.fileno(),))
                target.settimeout(5)
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    if exact(upstream,10)!=b"helloagain" or upstream.recv(1)!=b"": raise RuntimeError("valid upload failed")
                    upstream.sendall(b"worldagain"); upstream.shutdown(socket.SHUT_WR)
                if peer.wait(timeout=5)!=0: raise RuntimeError(f"valid client failed: {peer.returncode}")
            target.settimeout(.2)
            try: extra,_=target.accept()
            except TimeoutError: pass
            else: extra.close(); raise RuntimeError("invalid handshake reached target")
            # Both pending handshakes must expire from their common start,
            # while the valid session above can still make progress.
            try:
                for sock in (stalled,incomplete):
                    try: result=sock.recv(1)
                    except ConnectionResetError: result=b""
                    elapsed=time.monotonic()-start
                    if result or not 8<=elapsed<=14: raise RuntimeError(f"stalled handshake: {result!r}, {elapsed:.2f}s")
            finally:
                stalled.close(); incomplete.close()
            active_wire=subprocess.run([wire_tool,str(size),str(target.getsockname()[1]),"140"],check=True,capture_output=True).stdout
            partial_wire=subprocess.run([wire_tool,str(size),str(target.getsockname()[1]),"180"],check=True,capture_output=True).stdout
            with socket.create_connection(("127.0.0.1",port),timeout=5) as active, \
                 socket.create_connection(("127.0.0.1",port),timeout=5) as pending:
                active.settimeout(5); pending.settimeout(5)
                active.sendall(active_wire); pending.sendall(partial_wire[:size+27])
                target.settimeout(5)
                with target.accept()[0] as upstream:
                    upstream.settimeout(5)
                    proxy.terminate(); proxy.wait(timeout=5)
                    for sock in (active,pending,upstream):
                        try: data=sock.recv(1)
                        except ConnectionResetError: data=b""
                        if data: raise RuntimeError("connection remained active after stop")
        finally:
            if peer is not None and peer.poll() is None: peer.kill(); peer.wait()
            proxy.terminate()
            try: _,err=proxy.communicate(timeout=5)
            except subprocess.TimeoutExpired: proxy.kill(); _,err=proxy.communicate()
            if proxy.returncode!=0: raise RuntimeError(f"proxy failed: {err.decode()}")

with tempfile.TemporaryDirectory(prefix="nexus-ss-fault-") as directory:
    for size,workers in ((16,1),(32,2)): scenario(pathlib.Path(directory),size,workers)
print("SS-2022 inbound malformed and stalled handshake tests passed")
