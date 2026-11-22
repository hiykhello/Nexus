#!/usr/bin/env python3
"""Verify SOCKS UDP advertisement, authenticated TLS pins and Unix stream forwarding."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import time

from batch94c_utls_network import accept_one, command, create_certificate, test_once, version_context
from detour_network import exact, reserve, running


def check_process(binary, config):
    return subprocess.run([binary, "run", "--config", config], capture_output=True, text=True, timeout=8)


def socks_udp(binary, root):
    for family, local, advertised in ((socket.AF_INET, "127.0.0.1", "198.51.100.91"),
                                      (socket.AF_INET6, "::1", "2001:db8::91")):
        with socket.socket(family) as pick:
            pick.bind((local, 0))
            port = pick.getsockname()[1]
        cfg = root / "udp.kdl"
        source = f'''schema-version 1
role "client"
inbound "socks" type="socks5" {{
  listen host="{local}" port={port}
  authentication "none"
  udp-advertise-ip "{advertised}"
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
        cfg.write_text(source.replace(advertised, "invalid-host"))
        bad = check_process(binary, cfg)
        assert bad.returncode and "udp-advertise-ip" in bad.stderr, bad
        cfg.write_text(source)
        with listener_process(binary, cfg, lambda: socket.create_connection((local, port), .1)):
            with socket.create_connection((local, port), 3) as control, \
                    socket.socket(family, socket.SOCK_DGRAM) as datagram, \
                    socket.socket(family, socket.SOCK_DGRAM) as echo:
                address_size = 4 if family == socket.AF_INET else 16
                atype = b"\x01" if address_size == 4 else b"\x04"
                control.sendall(b"\x05\x01\0")
                assert exact(control, 2) == b"\x05\0"
                control.sendall(b"\x05\x03\0" + atype + bytes(address_size + 2))
                assert exact(control, 4) == b"\x05\0\0" + atype
                assert socket.inet_ntop(family, exact(control, address_size)) == advertised
                bound_port = int.from_bytes(exact(control, 2), "big")
                echo.bind((local, 0))
                echo.settimeout(3)
                datagram.settimeout(3)
                request = b"\0\0\0" + atype + socket.inet_pton(family, local)
                request += echo.getsockname()[1].to_bytes(2, "big") + b"udp-advertise"
                datagram.sendto(request, (local, bound_port))
                received, peer = echo.recvfrom(1024)
                assert received == b"udp-advertise"
                echo.sendto(received, peer)
                response, peer = datagram.recvfrom(1024)
                assert response == request and peer[1] == bound_port
        print(f"SOCKS UDP {advertised}, retained actual port, bidirectional relay and invalid IP rejection")


@contextmanager
def listener_process(binary, config, connect):
    with subprocess.Popen([binary, "run", "--config", config], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True) as process:
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(process.stdout.read())
                try:
                    with connect():
                        break
                except OSError:
                    time.sleep(.04)
            else:
                raise RuntimeError("listener startup timed out")
            yield
        finally:
            if process.poll() is None:
                process.terminate()
            output, _ = process.communicate(timeout=6)
            if process.returncode:
                raise RuntimeError(output)


def unix_connect(path):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(2)
    try:
        client.connect(path)
        return client
    except OSError:
        client.close()
        raise


def uds(binary, root):
    for scheme in ("filesystem", "abstract", "tcp"):
        path = str(root / "local.sock") if scheme == "filesystem" else f"@nexus94d-{root.name}"
        origin_path = "-" if scheme == "filesystem" else str(root / "origin.sock")
        with socket.socket(socket.AF_UNIX if origin_path != "-" else socket.AF_INET) as origin, ThreadPoolExecutor(1) as pool:
            origin.bind(origin_path if origin_path != "-" else ("127.0.0.1", 0))
            origin.listen()
            origin.settimeout(4)
            front = reserve()
            listen = f'unix-path="{path}"' if scheme != "tcp" else f'host="127.0.0.1" port={front}'
            target = f'unix-path="{origin_path}"' if origin_path != "-" else f'host="127.0.0.1" port={origin.getsockname()[1]}'
            cfg = root / "uds.kdl"
            config = f'''schema-version 1
role "client"
inbound "local" type="fixed-tcp" {{ listen {listen}; target {target}; }}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
'''
            cfg.write_text(config)
            if scheme == "filesystem":
                with socket.socket(socket.AF_UNIX) as stale:
                    stale.bind(path)
            def connect():
                if scheme == "tcp":
                    return socket.create_connection(("127.0.0.1", front), .2)
                return unix_connect(path if scheme == "filesystem" else "\0" + path[1:])

            def echo():
                # Startup probes may create one connection with no application bytes.
                while True:
                    with origin.accept()[0] as peer:
                        peer.settimeout(3)
                        data = bytearray()
                        while chunk := peer.recv(65536):
                            data.extend(chunk)
                        if data:
                            peer.sendall(data[::-1])
                            return

            job = pool.submit(echo)
            with listener_process(binary, cfg, connect):
                with connect() as client:
                    data = bytes(range(256)) * 1024
                    client.sendall(data)
                    client.shutdown(socket.SHUT_WR)
                    assert exact(client, len(data)) == data[::-1]
                    assert not client.recv(1)
                if scheme == "filesystem":
                    assert stat.S_IMODE(Path(path).stat().st_mode) == 0o600
                    collision = subprocess.run([binary, "run", "--config", cfg], capture_output=True, timeout=5)
                    assert collision.returncode and Path(path).is_socket()
            job.result(timeout=5)
            if scheme == "filesystem":
                assert not Path(path).exists()
            if origin_path != "-":
                Path(origin_path).unlink()
            print(f"UDS {scheme} bidirectional 256 KiB and independent half-closes")
    cfg.write_text(config.replace(origin_path, "/"+"x"*108))
    bad = check_process(binary, cfg)
    assert bad.returncode and "unix-path" in bad.stderr, bad


def tls_pins(binary, root):
    create_certificate(root)
    digest = subprocess.check_output(["openssl", "x509", "-in", root / "origin.crt", "-noout", "-fingerprint", "-sha256"],
                                     text=True).strip().split("=")[1]
    pk = subprocess.check_output(["openssl", "x509", "-in", root / "origin.crt", "-pubkey", "-noout"])
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pk, check=True, capture_output=True).stdout
    from hashlib import sha256
    spki = sha256(der).hexdigest()
    wrong = "01" * 32
    for version, profile in ((ssl.TLSVersion.TLSv1_3, "native"), (ssl.TLSVersion.TLSv1_2, "chrome-133")):
        server = version_context(root, version)
        for pins, accepted in (((digest,), True), ((wrong, spki), True), ((wrong,), False)):
            with socket.socket() as remote, ThreadPoolExecutor(1) as pool:
                remote.bind(("127.0.0.1", 0))
                remote.listen()
                remote.settimeout(3)
                front = reserve()
                args = command(binary, root, front, remote.getsockname()[1], profile, "localhost", "origin.crt")
                cfg = args[-1]
                value = " ".join(f'"{pin}"' for pin in pins)
                cfg.write_text(cfg.read_text().replace("verify #true;", f"verify #true; certificate-sha256 {value};"))
                with running(args, front, root / "pin.log"):
                    if accepted:
                        test_once(front, remote, server, pool)
                    else:
                        job = pool.submit(accept_one, remote, server)
                        with socket.create_connection(("127.0.0.1", front), 3) as client:
                            client.sendall(b"\x05\x01\0")
                            assert exact(client, 2) == b"\x05\0"
                            client.sendall(b"\x05\x01\0\x01\x7f\0\0\x01\x1f\x90")
                            assert exact(client, 2)[1] != 0
                        try:
                            job.result(timeout=4)
                        except (ssl.SSLError, RuntimeError, ConnectionResetError):
                            pass
                        else:
                            raise AssertionError("wrong pin reached authenticated Trojan peer")
                print(f"{version.name} certificate-sha256 accepted={accepted} pin_count={len(pins)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("case", choices=("socks", "uds", "pins"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="nexus-94d-") as name:
        {"socks": socks_udp, "uds": uds, "pins": tls_pins}[args.case](args.binary, Path(name))
