#!/usr/bin/env python3
"""Batch 150 live end-to-end SSHv2 outbound integration tests against real unprivileged sshd."""
import base64, concurrent.futures, hashlib, os, pathlib, signal, socket, struct, subprocess, sys, tempfile, threading, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
NEXUS_BIN = pathlib.Path(os.environ.get("NEXUS_BIN", str(ROOT / "target/x86_64-linux-gnu/a5c87b0b409ddfec/bin/nexus")))
SSHD_BIN = pathlib.Path("/usr/bin/sshd")
SSH_KEYGEN = pathlib.Path("/usr/bin/ssh-keygen")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_tcp(port: int, proc: subprocess.Popen, name: str, timeout: float = 6.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate()
            raise RuntimeError(f"{name} exited early rc={proc.returncode}\nout={out}\nerr={err}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.04)
    raise RuntimeError(f"timed out waiting for {name} on 127.0.0.1:{port}")


def kill_tree(pid: int) -> None:
    children: list[int] = []
    for p in pathlib.Path(f"/proc/{pid}/task").glob("*/children"):
        try:
            for c in p.read_text().split():
                children.append(int(c))
        except OSError:
            pass
    for c in children:
        kill_tree(c)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def stop_proc(proc: subprocess.Popen | None, tree: bool = False) -> int | None:
    if not proc:
        return None
    if proc.poll() is None:
        if tree:
            kill_tree(proc.pid)
        else:
            proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            if tree:
                kill_tree(proc.pid)
            else:
                proc.kill()
            proc.wait(timeout=2)
    return proc.returncode


class TcpEchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop_ev = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(6.0)
            try:
                while data := conn.recv(16384):
                    conn.sendall(data)
            except OSError:
                pass

    def _run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                c, _ = self.sock.accept()
                threading.Thread(target=self._handle, args=(c,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self) -> None:
        self.stop_ev.set()
        self.sock.close()


def gen_keypair(kind: str, path: pathlib.Path, bits: int | None = None) -> tuple[pathlib.Path, pathlib.Path, str]:
    cmd = [str(SSH_KEYGEN), "-q", "-t", kind, "-N", "", "-f", str(path)]
    if bits:
        cmd.extend(["-b", str(bits)])
    subprocess.run(cmd, check=True)
    os.chmod(path, 0o600)
    pub_path = pathlib.Path(str(path) + ".pub")
    blob = base64.b64decode(pub_path.read_text().split()[1])
    pin = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return path, pub_path, pin


def start_sshd(d: pathlib.Path, host_key: pathlib.Path, auth_keys: pathlib.Path, port: int, name: str) -> subprocess.Popen:
    cfg = d / f"{name}.sshd_config"
    pid = d / f"{name}.pid"
    cfg.write_text(
        f"Port {port}\n"
        f"ListenAddress 127.0.0.1\n"
        f"HostKey {host_key}\n"
        f"AuthorizedKeysFile {auth_keys}\n"
        f"StrictModes no\n"
        f"PasswordAuthentication no\n"
        f"KbdInteractiveAuthentication no\n"
        f"AllowTcpForwarding yes\n"
        f"PermitOpen any\n"
        f"PermitTTY no\n"
        f"PidFile {pid}\n"
    )
    proc = subprocess.Popen(
        [str(SSHD_BIN), "-D", "-e", "-f", str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    wait_tcp(port, proc, f"sshd({name})")
    return proc


def start_nexus(cfg: pathlib.Path, socks_port: int, name: str) -> subprocess.Popen:
    proc = subprocess.Popen([str(NEXUS_BIN), "run", "--config", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    wait_tcp(socks_port, proc, f"nexus({name})")
    return proc


def socks5_connect(proxy_port: int, dst_host: str, dst_port: int, timeout: float = 6.0) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise RuntimeError("SOCKS5 greeting failed")
    try:
        ip = socket.inet_aton(dst_host)
        req = b"\x05\x01\x00\x01" + ip + struct.pack("!H", dst_port)
    except OSError:
        hb = dst_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", dst_port)
    s.sendall(req)
    hdr = s.recv(4)
    if len(hdr) < 4 or hdr[1] != 0:
        s.close()
        raise RuntimeError(f"SOCKS5 connect rejected: {hdr!r}")
    atyp = hdr[3]
    if atyp == 1:
        s.recv(6)
    elif atyp == 3:
        ln = s.recv(1)[0]
        s.recv(ln + 2)
    elif atyp == 4:
        s.recv(18)
    return s


def socks5_echo(proxy_port: int, dst_port: int, payload: bytes, host: str = "127.0.0.1", half_close: bool = False) -> bytes:
    with socks5_connect(proxy_port, host, dst_port) as s:
        s.sendall(payload)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        got = bytearray()
        deadline = time.monotonic() + 8.0
        while len(got) < len(payload) and time.monotonic() < deadline:
            chunk = s.recv(len(payload) - len(got))
            if not chunk:
                break
            got.extend(chunk)
        return bytes(got)


def write_ssh_config(path: pathlib.Path, socks_port: int, ssh_port: int, key_file: pathlib.Path, pin: str,
                     cipher: str = "chacha20-poly1305@openssh.com", max_sessions: int = 4,
                     detour_socks_port: int | None = None) -> None:
    user = os.environ.get("USER") or "nobody"
    extra_ob = ""
    detour_line = ""
    if detour_socks_port is not None:
        extra_ob = f'outbound "hop1" type="socks5" {{ server host="127.0.0.1" port={detour_socks_port}; }}\n'
        detour_line = '    detour "hop1"\n'
    path.write_text(
        f'schema-version 1\nrole "client"\n'
        f'inbound "in" type="socks5" {{ listen host="127.0.0.1" port={socks_port}; authentication "none"; }}\n'
        f'outbound "direct" type="direct"\n'
        f'{extra_ob}'
        f'outbound "ssh0" type="ssh" {{\n'
        f'    server host="127.0.0.1" port={ssh_port}\n'
        f'    user "{user}"\n'
        f'    private-key-file "{key_file}"\n'
        f'    host-key-sha256 "{pin}"\n'
        f'    cipher "{cipher}"\n'
        f'    keepalive-interval-ms 10000\n'
        f'    max-sessions {max_sessions}\n'
        f'{detour_line}'
        f'}}\n'
        f'routing {{ default-outbound "ssh0"; }}\n'
    )


def main() -> int:
    if not NEXUS_BIN.is_file() or not SSHD_BIN.is_file() or not SSH_KEYGEN.is_file():
        print("missing nexus binary or openssh binaries", file=sys.stderr)
        return 1

    echo = TcpEchoServer()
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="nexus-batch150-"))
    os.chmod(tmp_dir, 0o700)
    sshd_proc = None
    procs: list[tuple[subprocess.Popen, bool]] = []
    try:
        # 150.1: Ed25519 + chacha20-poly1305 + concurrency + reuse + half-close
        host_ed, _, pin_ed = gen_keypair("ed25519", tmp_dir / "host_ed25519")
        cli_ed, cli_ed_pub, _ = gen_keypair("ed25519", tmp_dir / "cli_ed25519")
        auth_ed = tmp_dir / "auth_ed"
        auth_ed.write_text(cli_ed_pub.read_text())
        os.chmod(auth_ed, 0o600)

        sshd_port = free_port()
        sshd_proc = start_sshd(tmp_dir, host_ed, auth_ed, sshd_port, "ed")
        procs.append((sshd_proc, True))

        socks1 = free_port()
        cfg1 = tmp_dir / "n1.kdl"
        write_ssh_config(cfg1, socks1, sshd_port, cli_ed, pin_ed, "chacha20-poly1305@openssh.com", max_sessions=4)
        nx1 = start_nexus(cfg1, socks1, "n1")
        procs.append((nx1, False))

        assert socks5_echo(socks1, echo.port, b"hello-ssh-150.1") == b"hello-ssh-150.1"
        assert socks5_echo(socks1, echo.port, b"domain-direct-tcpip", host="localhost") == b"domain-direct-tcpip"
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(socks5_echo, socks1, echo.port, f"conc-{i}-".encode() * 64) for i in range(4)]
            for i, f in enumerate(futs):
                assert f.result() == f"conc-{i}-".encode() * 64
        for i in range(2):
            assert socks5_echo(socks1, echo.port, f"seq-reuse-{i}".encode()) == f"seq-reuse-{i}".encode()
        big = os.urandom(512 * 1024)
        assert socks5_echo(socks1, echo.port, big, half_close=True) == big
        print("150.1 PASS: Ed25519 + chacha20-poly1305 + 4x concurrent + 512KiB half-close")

        # 150.4: kill & restart sshd (process tree incl. forked sshd-session) -> auto-reconnect
        stop_proc(sshd_proc, tree=True)
        time.sleep(0.1)
        failed = False
        try:
            res = socks5_echo(socks1, echo.port, b"must-fail")
            failed = (res != b"must-fail")
        except (RuntimeError, OSError):
            failed = True
        assert failed, "150.4 expected failure while sshd down"
        sshd_proc2 = start_sshd(tmp_dir, host_ed, auth_ed, sshd_port, "ed2")
        procs.append((sshd_proc2, True))
        assert socks5_echo(socks1, echo.port, b"reconnected-after-sshd-restart") == b"reconnected-after-sshd-restart"
        print("150.4 PASS: transparent reconnect after sshd restart")

        # 150.3: wrong host-key-sha256 pin rejected
        socks_bad = free_port()
        cfg_bad = tmp_dir / "nbad.kdl"
        write_ssh_config(cfg_bad, socks_bad, sshd_port, cli_ed, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        nx_bad = start_nexus(cfg_bad, socks_bad, "nbad")
        procs.append((nx_bad, False))
        pin_rejected = False
        try:
            res = socks5_echo(socks_bad, echo.port, b"should-not-pass")
            pin_rejected = (res != b"should-not-pass")
        except (RuntimeError, OSError):
            pin_rejected = True
        assert pin_rejected, "150.3 wrong host key pin must fail"
        stop_proc(nx_bad)
        print("150.3 PASS: mismatched host-key-sha256 rejected")

        # 150.2: ECDSA P-256 + aes256-gcm@openssh.com and aes128-gcm@openssh.com
        host_ec, _, pin_ec = gen_keypair("ecdsa", tmp_dir / "host_ecdsa", bits=256)
        cli_ec, cli_ec_pub, _ = gen_keypair("ecdsa", tmp_dir / "cli_ecdsa", bits=256)
        auth_ec = tmp_dir / "auth_ec"
        auth_ec.write_text(cli_ec_pub.read_text())
        os.chmod(auth_ec, 0o600)
        sshd_ec_port = free_port()
        sshd_ec = start_sshd(tmp_dir, host_ec, auth_ec, sshd_ec_port, "ecdsa")
        procs.append((sshd_ec, True))
        for ciph in ("aes256-gcm@openssh.com", "aes128-gcm@openssh.com"):
            sp = free_port()
            cp = tmp_dir / f"ec-{ciph}.kdl"
            write_ssh_config(cp, sp, sshd_ec_port, cli_ec, pin_ec, ciph)
            nx_ec = start_nexus(cp, sp, ciph)
            procs.append((nx_ec, False))
            assert socks5_echo(sp, echo.port, f"ecdsa-{ciph}".encode()) == f"ecdsa-{ciph}".encode()
            stop_proc(nx_ec)
        print("150.2 PASS: ECDSA P-256 + aes256-gcm + aes128-gcm")

        # 150.5: detour chain (socks5 -> ssh -> socks5 -> direct) + FD leak check + clean SIGTERM
        hop_port = free_port()
        cfg_hop = tmp_dir / "hop.kdl"
        cfg_hop.write_text(
            f'schema-version 1\nrole "client"\n'
            f'inbound "in" type="socks5" {{ listen host="127.0.0.1" port={hop_port}; authentication "none"; }}\n'
            f'outbound "direct" type="direct"\nrouting {{ default-outbound "direct"; }}\n'
        )
        nx_hop = start_nexus(cfg_hop, hop_port, "hop")
        procs.append((nx_hop, False))
        socks_det = free_port()
        cfg_det = tmp_dir / "detour.kdl"
        write_ssh_config(cfg_det, socks_det, sshd_port, cli_ed, pin_ed, "chacha20-poly1305@openssh.com",
                         detour_socks_port=hop_port)
        nx_det = start_nexus(cfg_det, socks_det, "detour")
        procs.append((nx_det, False))
        fd_dir = pathlib.Path(f"/proc/{nx_det.pid}/fd")
        base_fds = len(list(fd_dir.iterdir()))
        for i in range(8):
            msg = f"detour-chain-{i}".encode()
            assert socks5_echo(socks_det, echo.port, msg) == msg
        time.sleep(0.25)
        after_fds = len(list(fd_dir.iterdir()))
        assert after_fds <= base_fds + 6, f"FD leak detected: base={base_fds} after={after_fds}"
        rc1 = stop_proc(nx1)
        rc2 = stop_proc(nx_det)
        assert rc1 in (0, -15) and rc2 in (0, -15), f"unexpected SIGTERM return codes: {rc1}, {rc2}"
        print(f"150.5 PASS: detour chain + FD bounded ({base_fds}->{after_fds}) + clean SIGTERM")
        print("batch150_live_integration: ALL PASSED")
        return 0
    finally:
        for p, tree in reversed(procs):
            stop_proc(p, tree=tree)
        echo.close()
        subprocess.run(["rm", "-rf", str(tmp_dir)], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
