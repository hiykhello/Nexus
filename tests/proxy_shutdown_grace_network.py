#!/usr/bin/env python3
"""Check both successful and deadline-bound shutdown draining."""
from pathlib import Path
import socket
import sys
import tempfile
import time

from detour_network import running, socks
from dns_rule_support import Echo, exact, free_port


def wait_for_no_new_sessions(port):
    deadline=time.monotonic()+1.5
    while time.monotonic()<deadline:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.1):
                pass
        except ConnectionRefusedError:
            return
        time.sleep(.01)
    raise RuntimeError("proxy continued to accept during shutdown drain")


binary=str(Path(sys.argv[1]).resolve(strict=True))
for workers in (1,2):
    for finish in (True,False):
        with tempfile.TemporaryDirectory() as folder, Echo() as origin:
            root=Path(folder)
            path=root/"proxy.kdl"
            port=free_port()
            grace=1500 if finish else 800
            path.write_text(f"""schema-version 1
role "client"
workers {workers}
shutdown-grace-ms {grace}
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
routing {{ default-outbound "direct"; }}
""")
            with running([binary,"run","--config",str(path)],port,root/"proxy.log") as proxy:
                client,_=socks(port,1,("127.0.0.1",origin.port))
                with client:
                    started=time.monotonic()
                    proxy.terminate()
                    wait_for_no_new_sessions(port)
                    if finish:
                        client.sendall(b"drained")
                        assert exact(client,7)==b"drained"
                        client.close()
                    proxy.wait(timeout=3)
                    elapsed=time.monotonic()-started
                    assert proxy.returncode==0
                    if finish:
                        assert elapsed<grace/1000,elapsed
                    else:
                        assert .65<=elapsed<1.7,elapsed
                        assert client.recv(1)==b""
print("Single- and multi-worker listeners closed admission, drained old TCP, and enforced the deadline")
