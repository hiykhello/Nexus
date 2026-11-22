#!/usr/bin/env python3
"""Noise IK/records against the pinned official controlbase TCP implementation."""
import argparse
import hashlib
import os
import pathlib
import select
import subprocess

VERSION = "v1.104.1"
SOURCE = r'''package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"
)

func fixedKey(first byte) key.MachinePrivate {
	raw := make([]byte, 32)
	for i := range raw { raw[i] = byte(i) + first }
	var result key.MachinePrivate
	if err := result.UnmarshalText([]byte("privkey:"+hex.EncodeToString(raw))); err != nil { panic(err) }
	return result
}

func writeAll(connection io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := connection.Write(data)
		if err != nil { return err }
		if n == 0 { return io.ErrShortWrite }
		data = data[n:]
	}
	return nil
}

var sizes = []int{1, 17, 4077, 4078, 16384, 262144}

func bytesFor(size int, invert bool) []byte {
	result := make([]byte, size)
	for i := range result { result[i] = byte(i*17+size); if invert { result[i] ^= 0x5a } }
	return result
}

func transfer(connection *controlbase.Conn, initiator bool) error {
	if err := connection.SetDeadline(time.Now().Add(8*time.Second)); err != nil { return err }
	hash := connection.HandshakeHash()
	if initiator {
		if err := writeAll(connection, hash[:]); err != nil { return err }
		var reply [32]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil { return err }
		if reply != hash { return fmt.Errorf("handshake hash mismatch") }
	} else {
		var request [32]byte
		if _, err := io.ReadFull(connection, request[:]); err != nil { return err }
		if request != hash { return fmt.Errorf("handshake hash mismatch") }
		if err := writeAll(connection, hash[:]); err != nil { return err }
	}
	for _, size := range sizes {
		original := bytesFor(size, false)
		reply := bytesFor(size, true)
		if initiator {
			if err := writeAll(connection, original); err != nil { return err }
			actual := make([]byte, size)
			if _, err := io.ReadFull(connection, actual); err != nil { return err }
			if !bytes.Equal(actual, reply) { return fmt.Errorf("reply payload size=%d", size) }
		} else {
			actual := make([]byte, size)
			if _, err := io.ReadFull(connection, actual); err != nil { return err }
			if !bytes.Equal(actual, original) { return fmt.Errorf("request payload size=%d", size) }
			if err := writeAll(connection, reply); err != nil { return err }
		}
	}
	// Both writers remain active while the opposite side drains records.
	const duplexSize = 1024*1024
	result := make(chan error, 1)
	go func() { result <- writeAll(connection, bytesFor(duplexSize, initiator)) }()
	actual := make([]byte, duplexSize)
	if _, err := io.ReadFull(connection, actual); err != nil { return err }
	if !bytes.Equal(actual, bytesFor(duplexSize, !initiator)) { return fmt.Errorf("duplex payload") }
	return <-result
}

func secured(ctx context.Context, raw net.Conn, role string, version uint16) (*controlbase.Conn, error) {
	control, machine := fixedKey(71), fixedKey(3)
	var connection *controlbase.Conn
	var err error
	if role == "server" {
		connection, err = controlbase.Server(ctx, raw, control, nil)
		if err == nil && connection.Peer() != machine.Public() { return nil, fmt.Errorf("wrong machine identity") }
	} else {
		connection, err = controlbase.Client(ctx, raw, machine, control.Public(), version)
		if err == nil && connection.Peer() != control.Public() { return nil, fmt.Errorf("wrong control identity") }
	}
	if err != nil { return nil, err }
	if connection.ProtocolVersion() != int(version) { return nil, fmt.Errorf("wrong version") }
	return connection, nil
}

func serve(role string, version uint16, listener net.Listener) error {
	raw, err := listener.Accept()
	if err != nil { return err }
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	connection, err := secured(ctx, raw, role, version)
	if err != nil { return err }
	return transfer(connection, role == "client")
}

func selftest() error {
	for _, version := range []uint16{1, 148, 65535} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil { return err }
		result := make(chan error, 1)
		go func() { result <- serve("server", version, listener) }()
		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil { return err }
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		connection, err := secured(ctx, raw, "client", version)
		cancel()
		if err == nil { err = transfer(connection, true) }
		raw.Close()
		listener.Close()
		peerErr := <-result
		if err != nil { return err }
		if peerErr != nil { return peerErr }
		fmt.Printf("control-selftest-version:%d\n", version)
	}
	return nil
}

func main() {
	role := flag.String("role", "server", "server or client Noise role; peer always listens on TCP")
	version := flag.Uint("version", 148, "uint16 capability version")
	check := flag.Bool("selftest", false, "exercise both official roles")
	flag.Parse()
	if *check { if err := selftest(); err != nil { panic(err) }; return }
	if (*role != "server" && *role != "client") || *version > 65535 { panic("invalid arguments") }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { panic(err) }
	defer listener.Close()
	fmt.Printf("%d %s %s\n", listener.Addr().(*net.TCPAddr).Port,
		fixedKey(71).Public().UntypedHexString(), fixedKey(3).Public().UntypedHexString())
	if err := serve(*role, uint16(*version), listener); err != nil { panic(err) }
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(sizes)))
	fmt.Printf("control-peer-complete:%d\n", binary.BigEndian.Uint16(count[:]))
	var stop [1]byte
	if _, err := io.ReadFull(os.Stdin, stop[:]); err != nil { panic(err) }
}
'''


def reference_binary():
    root = pathlib.Path("/tmp/nexus-tailscale-control-peer-v1.104.1")
    root.mkdir(exist_ok=True)
    binary, stamp = root / "control-peer", root / "build-id"
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text().strip() != digest:
        (root / "go.mod").write_text(f"module nexus-tailscale-control-peer\n\ngo 1.27.1\n\nrequire tailscale.com {VERSION}\n")
        (root / "main.go").write_text(SOURCE)
        env = dict(os.environ, GOTOOLCHAIN="local", GOMODCACHE=str(root / "modules"), GOCACHE=str(root / "cache"),
                   GOPROXY="file:///home/yk/go/pkg/mod/cache/download,https://proxy.golang.org")
        checked = subprocess.run(["go", "build", "-p", "1", "-mod=mod", "-o", binary, "."], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=240)
        if checked.returncode:
            raise RuntimeError(checked.stderr)
        stamp.write_text(digest + "\n")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    reference = reference_binary()
    checked = subprocess.check_output([reference, "--selftest"], text=True, timeout=15)
    if checked.splitlines() != [f"control-selftest-version:{version}" for version in (1, 148, 65535)]:
        raise RuntimeError(f"official controlbase peer self-check failed: {checked!r}")
    print(f"Official controlbase {VERSION} TCP peer self-check passed: versions 1/148/65535", flush=True)
    if not args.fixture:
        return
    for backend in (0, 1):
        for version in (1, 148, 65535):
            for role in ("client", "server"):
                peer_role = "server" if role == "client" else "client"
                peer = subprocess.Popen([reference, "--role", peer_role, "--version", str(version)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    if not select.select([peer.stdout], [], [], 8)[0]:
                        raise RuntimeError("official controlbase peer did not start")
                    fields = peer.stdout.readline().decode().strip().split()
                    if len(fields) != 3 or not fields[0].isdigit() or any(len(value) != 64 for value in fields[1:]):
                        raise RuntimeError(f"invalid control peer readiness: {fields!r}")
                    checked = subprocess.run([args.fixture.resolve(), *fields, str(backend), role, str(version)],
                                             capture_output=True, timeout=18)
                    if checked.returncode or checked.stdout.strip() != b"control-network-passed":
                        raise RuntimeError(f"control role={role} version={version} backend={backend}: {checked.returncode}, {checked.stdout!r}, {checked.stderr!r}")
                    stdout, stderr = peer.communicate(b"x", timeout=5)
                    if peer.returncode or stdout.strip() != b"control-peer-complete:6":
                        raise RuntimeError(f"official controlbase peer: {peer.returncode}, {stdout!r}, {stderr!r}")
                    print(f"Control {VERSION} real TCP, role={role}, version={version}, backend={backend}: identity/hash, records and simultaneous MiB passed", flush=True)
                finally:
                    if peer.poll() is None:
                        peer.kill()
                        peer.communicate(timeout=3)


if __name__ == "__main__":
    main()
