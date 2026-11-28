#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile

from dns_rule_support import Echo, datagram_request, free_port, stream_request, udp_client
from detour_network import running

binary=str(Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory() as folder, Echo() as echo:
    root=Path(folder)
    config=root/"proxy.kdl"
    port=free_port()
    template=f"""schema-version 1
role "client"
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
routing {{ final "direct"; }}
"""
    dns_port=free_port()
    tests=[
        ('DNS over TLS is unavailable',f"""
dns {{
  server "protected" type="tls" host="127.0.0.1" port={dns_port} server-name="dot.test" ca-file="/unused.pem"
  final "protected"
}}"""),
        ("FakeIP requires the dns-fakeip",f"""
state {{ directory "/tmp/nexus-closed-fakeip"; }}
dns {{
  listen host="127.0.0.1" port={dns_port}
  server "business" type="local"
  final "business"
  fake-ip server="business" ipv4-pool="198.18.0.0/29"
}}"""),
    ]
    args=[binary,"run","--config",str(config)]
    for expected,dns in tests:
        config.write_text(template+dns)
        result=subprocess.run(args,capture_output=True,text=True,timeout=5)
        assert result.returncode and expected in result.stderr,result.stderr
    config.write_text(template)
    with running(args,port,root/"off.log"):
        stream_request(port,echo.port,"127.0.0.1")
        with udp_client(port) as (client,relay):
            datagram_request(client,relay,echo.port,"127.0.0.1")
print("Disabled graph refused DNS TLS and FakeIP explicitly and relayed ordinary SOCKS TCP/UDP")
