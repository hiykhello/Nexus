#!/usr/bin/env python3
"""Wave 25 Track A: Native TCP TLS 1.3 ECH (RFC 9849 + RFC 9460 HTTPS/SVCB) E2E test."""
import argparse
import contextlib
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

INNER_SNI = "inner.ech.test"
PUBLIC_SNI = "public.ech.test"
TROJAN_PASS = "wave25-ech-trojan-secret"
VLESS_UUID = "7b8c9d0e-1f2a-4b3c-8d4e-5f6a7b8c9d0e"

GO_ECH_PEER = r'''package main

import (
	"bufio"; "crypto/ecdh"; "crypto/ecdsa"; "crypto/elliptic"; "crypto/rand"
	"crypto/sha256"; "crypto/tls"; "crypto/x509"; "crypto/x509/pkix"
	"encoding/binary"; "encoding/hex"; "encoding/pem"; "flag"; "fmt"
	"io"; "math/big"; "net"; "os"; "path/filepath"; "strings"; "time"
)

func must(err error) {
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func buildECHConfig(id byte, pub []byte, publicName string) ([]byte, []byte) {
	suites := []byte{0, 1, 0, 1, 0, 1, 0, 2, 0, 1, 0, 3}
	b := []byte{id}
	b = binary.BigEndian.AppendUint16(b, 0x0020)
	b = binary.BigEndian.AppendUint16(b, uint16(len(pub)))
	b = append(b, pub...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(suites)))
	b = append(b, suites...)
	b = append(b, 64, byte(len(publicName)))
	b = append(b, []byte(publicName)...)
	b = binary.BigEndian.AppendUint16(b, 0)
	cfg := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(b)))
	cfg = append(cfg, b...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(cfg)))
	return cfg, append(list, cfg...)
}

func writePair(dir, prefix, publicName string) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader); must(err)
	cfg, list := buildECHConfig(1, priv.PublicKey().Bytes(), publicName)
	must(os.WriteFile(filepath.Join(dir, prefix+"_cfg.bin"), cfg, 0600))
	must(os.WriteFile(filepath.Join(dir, prefix+"_key.bin"), priv.Bytes(), 0600))
	must(os.WriteFile(filepath.Join(dir, prefix+".bin"), list, 0644))
}

func genCmd(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	out := fs.String("out", "", ""); inner := fs.String("inner", "inner.ech.test", ""); pub := fs.String("public", "public.ech.test", "")
	_ = fs.Parse(args)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: *inner},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: []string{*inner, *pub},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key); must(err)
	keyDER, err := x509.MarshalECPrivateKey(key); must(err)
	must(os.WriteFile(filepath.Join(*out, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))
	must(os.WriteFile(filepath.Join(*out, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))
	writePair(*out, "ech", *pub); writePair(*out, "wrong_ech", *pub); writePair(*out, "same_name_ech", *inner)
}

func skipAddr(br *bufio.Reader, vless bool) error {
	if vless {
		if _, err := io.CopyN(io.Discard, br, 2); err != nil { return err }
	}
	atyp, err := br.ReadByte()
	if err != nil { return err }
	switch {
	case atyp == 1:
		_, err = io.CopyN(io.Discard, br, 4)
	case (!vless && atyp == 4) || (vless && atyp == 3):
		_, err = io.CopyN(io.Discard, br, 16)
	case (!vless && atyp == 3) || (vless && atyp == 2):
		n, e := br.ReadByte(); if e != nil { return e }
		_, err = io.CopyN(io.Discard, br, int64(n))
	default:
		return fmt.Errorf("bad atyp %d", atyp)
	}
	if err != nil || vless { return err }
	_, err = io.CopyN(io.Discard, br, 4)
	return err
}

func handleConn(c net.Conn, cfg *tls.Config, mode, secret, innerSNI string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	tc := tls.Server(c, cfg)
	if err := tc.Handshake(); err != nil { return }
	cs := tc.ConnectionState()
	if !cs.ECHAccepted || cs.ServerName != innerSNI { return }
	br := bufio.NewReader(tc)
	switch mode {
	case "trojan":
		sum := sha256.Sum224([]byte(secret)); want := hex.EncodeToString(sum[:])
		var hdr [58]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil || string(hdr[:56]) != want || hdr[56] != '\r' || hdr[57] != '\n' { return }
		if cmd, err := br.ReadByte(); err != nil || cmd != 1 || skipAddr(br, false) != nil { return }
	case "vless":
		want, err := hex.DecodeString(strings.ReplaceAll(secret, "-", ""))
		if err != nil || len(want) != 16 { return }
		var hdr [18]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != 0 || string(hdr[1:17]) != string(want) { return }
		if hdr[17] > 0 { if _, err := io.CopyN(io.Discard, br, int64(hdr[17])); err != nil { return } }
		if cmd, err := br.ReadByte(); err != nil || cmd != 1 || skipAddr(br, true) != nil { return }
		if _, err := tc.Write([]byte{0, 0}); err != nil { return }
	case "http-connect":
		for {
			line, err := br.ReadString('\n'); if err != nil { return }
			if line == "\r\n" { break }
		}
		if _, err := tc.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil { return }
	default:
		return
	}
	_, _ = io.Copy(tc, br)
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	mode := fs.String("mode", "trojan", ""); certP := fs.String("cert", "", ""); keyP := fs.String("key", "", "")
	echCfgP := fs.String("ech-cfg", "", ""); echKeyP := fs.String("ech-key", "", "")
	secret := fs.String("secret", "", ""); inner := fs.String("inner-sni", "inner.ech.test", ""); hrr := fs.Bool("hrr", false, "")
	_ = fs.Parse(args)
	cert, err := tls.LoadX509KeyPair(*certP, *keyP); must(err)
	echCfg, err := os.ReadFile(*echCfgP); must(err)
	echKey, err := os.ReadFile(*echKeyP); must(err)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: echCfg, PrivateKey: echKey, SendAsRetry: true}},
	}
	if *mode == "http-connect" { tlsCfg.NextProtos = []string{"http/1.1"} }
	if *hrr { tlsCfg.CurvePreferences = []tls.CurveID{tls.CurveP256} }
	ln, err := net.Listen("tcp", "127.0.0.1:0"); must(err)
	defer ln.Close()
	fmt.Printf("READY %d\n", ln.Addr().(*net.TCPAddr).Port)
	for {
		c, err := ln.Accept(); if err != nil { return }
		go handleConn(c, tlsCfg, *mode, *secret, *inner)
	}
}

func main() {
	if len(os.Args) < 2 { os.Exit(2) }
	if os.Args[1] == "gen" { genCmd(os.Args[2:]) } else if os.Args[1] == "serve" { serveCmd(os.Args[2:]) } else { os.Exit(2) }
}
'''


def find_default_binary() -> Path:
    if env_bin := os.environ.get("NEXUS_BIN"):
        return Path(env_bin).resolve(strict=True)
    root = Path(__file__).resolve().parent.parent
    cands = sorted((root / "target").glob("**/bin/nexus"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not cands:
        raise FileNotFoundError("nexus binary not found under target/; pass binary path explicitly")
    return cands[0]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def parse_dns_question(packet: bytes) -> tuple[str, int, int]:
    pos, labels = 12, []
    while pos < len(packet):
        n = packet[pos]
        pos += 1
        if n == 0:
            break
        labels.append(packet[pos:pos + n].decode("ascii").lower())
        pos += n
    return ".".join(labels), struct.unpack("!H", packet[pos:pos + 2])[0], pos + 4


def encode_svcb_rdata(config_list: bytes, alpns: list[str] | None, no_default_alpn: bool) -> bytes:
    out = bytearray(b"\x00\x01\x00")
    if alpns is not None:
        alpn_wire = b"".join(bytes([len(a)]) + a.encode("ascii") for a in alpns)
        out += struct.pack("!HH", 1, len(alpn_wire)) + alpn_wire
    if no_default_alpn:
        out += struct.pack("!HH", 2, 0)
    out += struct.pack("!HH", 5, len(config_list)) + config_list
    return bytes(out)


class EchDnsServer:
    def __init__(self, match_name: str, qtype: int, rdata: bytes | None):
        self.match_name, self.qtype, self.rdata = match_name.lower(), qtype, rdata
        self.seen: list[tuple[str, int]] = []
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join(timeout=2.0)
        self._sock.close()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            qname, qtype, qend = parse_dns_question(data)
            self.seen.append((qname, qtype))
            ans = b""
            if self.rdata is not None and qname == self.match_name and qtype == self.qtype:
                ans = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(self.rdata)) + self.rdata
            hdr = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1 if ans else 0, 0, 0)
            self._sock.sendto(hdr + data[12:qend] + ans, addr)


@contextlib.contextmanager
def run_peer(peer_bin: Path, root: Path, mode: str, secret: str, hrr: bool = False):
    cmd = [
        str(peer_bin), "serve", "--mode", mode,
        "--cert", str(root / "cert.pem"), "--key", str(root / "key.pem"),
        "--ech-cfg", str(root / "ech_cfg.bin"), "--ech-key", str(root / "ech_key.bin"),
        "--secret", secret, "--inner-sni", INNER_SNI,
    ] + (["--hrr"] if hrr else [])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([proc.stdout], [], [], 5.0)[0]:
            raise RuntimeError(f"Go ECH peer ({mode}) failed to start: {proc.stderr.read()}")
        line = proc.stdout.readline().strip()
        if not line.startswith("READY "):
            raise RuntimeError(f"Unexpected Go ECH peer output: {line!r}")
        yield int(line.split()[1])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3.0)


@contextlib.contextmanager
def run_nexus(binary: Path, cfg_path: Path, listen_port: int):
    proc = subprocess.Popen(
        [str(binary), "run", "--config", str(cfg_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"nexus exited early ({proc.returncode}): {proc.stderr.read()}")
            try:
                with socket.create_connection(("127.0.0.1", listen_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError(f"nexus failed to listen on {listen_port}: {proc.stderr.read()}")
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=4.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3.0)


def write_config(root: Path, mode: str, upstream_port: int, tls_extra: str, dns_port: int | None = None) -> tuple[Path, int]:
    front = free_port()
    cfg = root / f"nexus-{mode}-{front}.kdl"
    auth = {
        "trojan": f'authentication {{ password-file "{root / "trojan.pass"}"; }}',
        "vless": f'authentication {{ uuid-file "{root / "vless.uuid"}"; }}',
        "http-connect": "",
    }[mode]
    dns_block = f'dns {{ server "echdns" type="udp" host="127.0.0.1" port={dns_port}; final "echdns"; }}' if dns_port else ""
    cfg.write_text(f'''schema-version 1
role "client"
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="{mode}" {{
    server host="127.0.0.1" port={upstream_port}
    {auth}
    tls {{ server-name "{INNER_SNI}"; ca-file "{root / 'cert.pem'}"; verify #true; {tls_extra}; }}
    connect-timeout-ms 2500
}}
routing {{ default-outbound "edge"; }}
{dns_block}
''')
    return cfg, front


def socks5_roundtrip(front: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", front), timeout=5.0) as s:
        s.settimeout(5.0)
        s.sendall(b"\x05\x01\x00")
        if recv_exact(s, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 greeting rejected")
        s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        reply = recv_exact(s, 10)
        if reply[1] != 0:
            raise RuntimeError(f"SOCKS5 CONNECT failed with code {reply[1]}")
        s.sendall(payload)
        return recv_exact(s, len(payload))


def expect_socks5_fail(front: int, label: str) -> None:
    with socket.create_connection(("127.0.0.1", front), timeout=5.0) as s:
        s.settimeout(5.0)
        s.sendall(b"\x05\x01\x00")
        if recv_exact(s, 2) != b"\x05\x00":
            raise RuntimeError(f"{label}: SOCKS5 greeting rejected")
        s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
        if recv_exact(s, 10)[1] == 0:
            raise RuntimeError(f"{label}: connection unexpectedly succeeded")


def run_suite(binary: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="nexus-tcp-ech-") as tmp:
        root = Path(tmp)
        (root / "ech_peer.go").write_text(GO_ECH_PEER)
        peer_bin = root / "ech_peer"
        subprocess.run(["go", "build", "-o", str(peer_bin), str(root / "ech_peer.go")], check=True)
        subprocess.run([str(peer_bin), "gen", "--out", str(root), "--inner", INNER_SNI, "--public", PUBLIC_SNI], check=True)
        for fname, val in (("trojan.pass", TROJAN_PASS), ("vless.uuid", VLESS_UUID)):
            (root / fname).write_text(val + "\n")
            (root / fname).chmod(0o600)
        ech_list = (root / "ech.bin").read_bytes()

        # 1. Static ech-config-file across Trojan, VLESS, HTTP-CONNECT TLS.
        for mode, secret in (("trojan", TROJAN_PASS), ("vless", VLESS_UUID), ("http-connect", "")):
            with run_peer(peer_bin, root, mode, secret) as port:
                cfg, front = write_config(root, mode, port, f'ech-config-file "{root / "ech.bin"}"')
                with run_nexus(binary, cfg, front):
                    msg = f"static-ech-{mode}".encode()
                    if socks5_roundtrip(front, msg) != msg:
                        raise RuntimeError(f"{mode} static ECH echo mismatch")
        print("[PASS] Static ech-config-file across Trojan, VLESS, HTTP-CONNECT TLS", flush=True)

        # 2. RFC 9849 HelloRetryRequest + fingerprint "chrome" (server forces P-256 HRR).
        with run_peer(peer_bin, root, "trojan", TROJAN_PASS, hrr=True) as port:
            cfg, front = write_config(root, "trojan", port, f'ech-config-file "{root / "ech.bin"}"; fingerprint "chrome"')
            with run_nexus(binary, cfg, front):
                if socks5_roundtrip(front, b"hrr-chrome-ech-ok") != b"hrr-chrome-ech-ok":
                    raise RuntimeError("HRR + chrome fingerprint ECH echo mismatch")
        print("[PASS] HelloRetryRequest + fingerprint \"chrome\" TCP TLS 1.3 ECH", flush=True)

        # 3. DNS HTTPS RR discovery (port-prefixed + RFC 9460 ALPN / default-ALPN compatibility).
        with run_peer(peer_bin, root, "trojan", TROJAN_PASS) as port:
            rdata = encode_svcb_rdata(ech_list, ["h2", "http/1.1"], False)
            with EchDnsServer(f"_{port}._https.{INNER_SNI}", 65, rdata) as dns:
                cfg, front = write_config(root, "trojan", port, "ech-dns #true", dns.port)
                with run_nexus(binary, cfg, front):
                    if socks5_roundtrip(front, b"dns-https-prefixed") != b"dns-https-prefixed":
                        raise RuntimeError("Trojan DNS HTTPS RR ECH failed")
                if (f"_{port}._https.{INNER_SNI}", 65) not in dns.seen:
                    raise RuntimeError("Trojan did not query port-prefixed HTTPS RR")
        with run_peer(peer_bin, root, "vless", VLESS_UUID) as port:
            rdata = encode_svcb_rdata(ech_list, ["h3"], False)
            with EchDnsServer(INNER_SNI, 65, rdata) as dns:
                cfg, front = write_config(root, "vless", port, "ech-dns #true", dns.port)
                with run_nexus(binary, cfg, front):
                    if socks5_roundtrip(front, b"dns-https-implicit-h1") != b"dns-https-implicit-h1":
                        raise RuntimeError("VLESS implicit default-ALPN DNS HTTPS ECH failed")
        print("[PASS] DNS HTTPS RR discovery (port-prefixed + RFC 9460 ALPN)", flush=True)

        # 4. Incompatible h3-only + no-default-alpn HTTPS RR rejected before TCP connect.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as monitor:
            monitor.bind(("127.0.0.1", 0))
            monitor.listen(4)
            with EchDnsServer(INNER_SNI, 65, encode_svcb_rdata(ech_list, ["h3"], True)) as dns:
                cfg, front = write_config(root, "trojan", monitor.getsockname()[1], "ech-dns #true", dns.port)
                with run_nexus(binary, cfg, front):
                    expect_socks5_fail(front, "h3-only no-default-alpn")
                if select.select([monitor], [], [], 0.15)[0]:
                    raise RuntimeError("TCP connect leaked despite h3-only no-default-alpn HTTPS RR")
        print("[PASS] h3-only + no-default-alpn HTTPS RR rejected with zero TCP leak", flush=True)

        # 5. Wrong ECH key rejected cleanly.
        with run_peer(peer_bin, root, "trojan", TROJAN_PASS) as port:
            cfg, front = write_config(root, "trojan", port, f'ech-config-file "{root / "wrong_ech.bin"}"')
            with run_nexus(binary, cfg, front):
                expect_socks5_fail(front, "wrong ECH key")
        print("[PASS] Wrong ECH key rejected cleanly", flush=True)

        # 6. Missing DNS ECH aborts BEFORE TCP connect (zero TCP SYN / plaintext SNI leak).
        for mode in ("trojan", "vless", "http-connect"):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as monitor:
                monitor.bind(("127.0.0.1", 0))
                monitor.listen(4)
                with EchDnsServer(INNER_SNI, 65, None) as dns:
                    cfg, front = write_config(root, mode, monitor.getsockname()[1], "ech-dns #true", dns.port)
                    with run_nexus(binary, cfg, front):
                        expect_socks5_fail(front, f"missing-dns-{mode}")
                    if (INNER_SNI, 65) not in dns.seen or select.select([monitor], [], [], 0.15)[0]:
                        raise RuntimeError(f"{mode}: missing DNS query or leaked TCP connect")
        print("[PASS] Missing DNS ECH aborts before TCP connect (Trojan, VLESS, HTTP-CONNECT)", flush=True)

        # 7. Same public_name == server_name rejected before TCP connect (Trojan & HTTP-CONNECT TLS).
        for mode in ("trojan", "http-connect"):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as monitor:
                monitor.bind(("127.0.0.1", 0))
                monitor.listen(4)
                cfg, front = write_config(root, mode, monitor.getsockname()[1], f'ech-config-file "{root / "same_name_ech.bin"}"')
                with run_nexus(binary, cfg, front):
                    expect_socks5_fail(front, f"same-name-{mode}")
                if select.select([monitor], [], [], 0.15)[0]:
                    raise RuntimeError(f"{mode}: same public_name/server_name leaked TCP connect")
        print("[PASS] Same public_name == server_name rejected before TCP connect (Trojan, HTTP-CONNECT)", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", type=Path, default=None)
    args = parser.parse_args()
    run_suite(args.binary.resolve(strict=True) if args.binary else find_default_binary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
