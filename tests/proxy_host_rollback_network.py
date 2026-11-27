#!/usr/bin/env python3
"""Verify a failed multi-listener startup unbinds the ports it acquired."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from dns_rule_support import Echo, free_port, stream_request
from detour_network import running


def bind_port(port, kind=socket.SOCK_STREAM):
    sock=socket.socket(socket.AF_INET,kind)
    sock.bind(("127.0.0.1",port))
    if kind==socket.SOCK_STREAM:
        sock.listen()
    return sock


def fails(args, expected):
    result=subprocess.run(args,capture_output=True,text=True,timeout=5)
    assert result.returncode and not result.stdout and expected in result.stderr,result


binary=str(Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory() as folder, Echo() as echo:
    root=Path(folder)
    config=root/"proxy.kdl"
    first, second, dns_port = free_port(), free_port(), free_port()
    config.write_text(f"""schema-version 1
role "client"
workers 2
log {{ privacy "verbose"; }}
inbounds {{
  socks5 "first" {{ listen host="127.0.0.1" port={first}; authentication "none"; }}
  mixed "second" {{ listen host="127.0.0.1" port={second}; authentication "none"; }}
}}
outbounds {{ direct "direct"; }}
dns {{
  listen host="127.0.0.1" port={dns_port}
  server "business" type="local"
  final "business"
}}
routing {{ final "direct"; }}
""")
    command=[binary,"run","--config",str(config)]
    with bind_port(dns_port,socket.SOCK_DGRAM):
        fails(command,"DNS UDP listen")
        with bind_port(first),bind_port(second),bind_port(dns_port):
            pass
    with bind_port(second):
        fails(command,"cannot listen")
        with bind_port(first),bind_port(dns_port),bind_port(dns_port,socket.SOCK_DGRAM):
            pass
    with running(command,first,root/"success.log"):
        for front in (first,second):
            stream_request(front,echo.port,"127.0.0.1")
print("Host rollback closed DNS TCP/UDP and prior proxy listeners, then startup recovered")
