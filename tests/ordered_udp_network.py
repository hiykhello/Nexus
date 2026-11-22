import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from ordered_tcp_network import exact


def main():
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    echo.settimeout(3)
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "blocked.kdl").write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.example"\n')
        (root / "config.kdl").write_text(f'''schema-version 1
role "client"
inbounds {{ socks5 "local" {{ listen host="127.0.0.1" port={port}; authentication "none"; }}; }}
outbounds {{ direct "direct"; }}
routing {{
    rule-set "blocked" path="blocked.kdl" format="kdl"
    tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
        rule action="sniff"
        rule action="reject" rule-set="blocked" domain-source="sniffed"
        rule action="route" outbound="direct"
    }}
    default-outbound "direct"
}}
''')
        proc = subprocess.Popen([sys.argv[1], "run", "--config", str(root / "config.kdl")], stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if proc.poll() is not None: raise AssertionError(proc.stderr.read().decode())
                try: control=socket.create_connection(("127.0.0.1", port), timeout=.1);break
                except OSError: time.sleep(.05)
            else: raise AssertionError("listener did not start")
            with control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                control.settimeout(3);client.bind(("127.0.0.1",0));client.settimeout(3)
                control.sendall(b"\x05\x01\x00");assert exact(control,2)==b"\x05\x00"
                control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                reply=exact(control,10);assert reply[:4]==b"\x05\x00\x00\x01",reply
                relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],"big"))
                dest=echo.getsockname(); prefix=b"\x00\x00\x00\x01"+socket.inet_aton(dest[0])+dest[1].to_bytes(2,"big")
                client.sendto(prefix+b"hello",relay)
                data,source=echo.recvfrom(100);assert data==b"hello";echo.sendto(b"world",source)
                received,_=client.recvfrom(100);assert received==prefix+b"world",received
                query=bytes.fromhex("123401000001000000000000")+b"\x07blocked\x07example\x00\x00\x01\x00\x01"
                client.sendto(prefix+query,relay);echo.settimeout(.3)
                try: echo.recvfrom(200);raise AssertionError("blocked DNS forwarded")
                except TimeoutError: pass
                # DNS service labels are valid on the wire but do not meet the
                # route engine's hostname syntax; skip leaves them routable.
                service=bytes.fromhex("123501000001000000000000")+b"\x04_sip\x07example\x00\x00\x21\x00\x01"
                echo.settimeout(3);client.sendto(prefix+service,relay)
                data,_=echo.recvfrom(200);assert data==service
                print("ordered SOCKS UDP direct, DNS sniff rejection and non-host DNS labels passed")
        finally:
            proc.terminate();proc.wait(timeout=5);echo.close()


if __name__ == "__main__": main()
