#!/usr/bin/env python3
"""Check real TCP rejection of short and unauthenticated SS-2022 headers."""
import pathlib
import socket
import subprocess
import sys

fixture=pathlib.Path(sys.argv[1]).resolve()
for size in (16,32):
    for payload in (b"x",bytes(size+27),bytes(size+27)+b"x"*1024):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1",0)); listener.listen(1)
            peer=subprocess.Popen([fixture,str(listener.fileno()),str(size)],pass_fds=(listener.fileno(),),stderr=subprocess.PIPE)
            try:
                with socket.create_connection(listener.getsockname(),timeout=5) as client:
                    client.settimeout(5); client.sendall(payload)
                    try: result=client.recv(1)
                    except ConnectionResetError: pass
                    else: raise RuntimeError(f"probe got {result!r}, expected TCP reset")
                if peer.wait(timeout=5)!=5: raise RuntimeError(f"fixture exit {peer.returncode}")
            finally:
                if peer.poll() is None: peer.kill(); peer.wait()
                peer.stderr.close()
print("SS-2022 async inbound invalid-header TCP reset passed")
