#!/usr/bin/env python3
"""Reject socket fields that a physical carrier cannot execute."""
from pathlib import Path
import subprocess
import sys
import tempfile

from detour_network import reserve


def reject(binary, config, direct, outbound, error, route="direct"):
    config.write_text(f'''schema-version 1
role "client"
inbound "entry" type="socks5" {{ listen host="127.0.0.1" port={reserve()}; authentication "none"; }}
outbound "direct" type="direct" {{ {direct} }}
{outbound}
routing {{ final "{route}"; }}
''')
    result = subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=4)
    assert result.returncode == 1 and error in result.stderr and "listening" not in result.stdout, result


def check(binary, config):
    tls = 'tls { server-name "localhost"; ca-file "/unused/cert"; verify #true; }'
    protocols = {
        "tuic": f'authentication {{ uuid-file "/unused/uuid"; password-file "/unused/secret"; }}; {tls};',
        "masque": f'authority "localhost"; authentication {{ bearer-file "/unused/token"; }}; {tls};',
        "wireguard": 'private-key-file "/unused/private"; peer-public-key-file "/unused/public"; local-address "192.0.2.2/32";',
    }
    for name, setup in protocols.items():
        for field in ("tcp-keepalive #false", "bind-address-no-port #false", "multipath-tcp #false"):
            outbound = f'outbound "edge" type="{name}" {{ server host="127.0.0.1" port=443; {setup} {field}; }}'
            reject(binary, config, "", outbound, "TCP-only dial options")
    for field in ("netns", "protect-path"):
        reject(binary, config, f'{field} "relative";', "", f"invalid {field} path")
        reject(binary, config, f'{field} "/unused"; {field} "/other";', "", "cannot repeat")
        outbound = f'''outbound "edge" type="trojan" {{ server host="127.0.0.1" port=443;
            authentication {{ password-file "/unused/secret"; }}; {tls}; detour "direct"; {field} "/unused"; }}'''
        reject(binary, config, "", outbound, "invalid Trojan detour", route="edge")
    print("Physical UDP rejected TCP-only fields and layered nodes rejected their own netns/protect-path")


if __name__ == "__main__":
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nexus-dial-capabilities-") as directory:
        check(binary, Path(directory) / "proxy.kdl")
