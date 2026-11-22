#!/usr/bin/env python3
"""Compare Nexus Hy2 output with fixed sing-quic protocol readers and Go QUIC varints."""
import argparse
import os
import pathlib
import subprocess
import tempfile

VERSION = "v0.7.2-0.20261020082049-7e0a5869a5f4"
ORACLE = r'''package main

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "io"
    "github.com/sagernet/quic-go/quicvarint"
    "github.com/sagernet/sing-quic/hysteria2/internal/protocol"
)

func emit(name string, wire []byte) { fmt.Printf("%s %s\n", name, hex.EncodeToString(wire)) }
func request(address string) {
    wire := quicvarint.Append(nil, protocol.FrameTypeTCPRequest)
    wire = quicvarint.Append(wire, uint64(len(address)))
    wire = append(wire, []byte(address)...)
    wire = quicvarint.Append(wire, 3)
    wire = append(wire, 0, 1, 255)
    input := bytes.NewReader(append(append([]byte{}, wire...), 0xde, 0xad))
    kind, err := quicvarint.Read(input)
    if err != nil || kind != protocol.FrameTypeTCPRequest { panic("request type") }
    parsed, err := protocol.ReadTCPRequest(input)
    suffix, _ := io.ReadAll(input)
    if err != nil || parsed != address || !bytes.Equal(suffix, []byte{0xde, 0xad}) { panic("request parse") }
    emit("request-" + address, wire)
}
func response(success bool, message string, padding []byte) {
    wire := []byte{1}; label := "response-error"
    if success { wire[0] = 0; label = "response-success" }
    wire = quicvarint.Append(wire, uint64(len(message)))
    wire = append(wire, []byte(message)...)
    wire = quicvarint.Append(wire, uint64(len(padding)))
    wire = append(wire, padding...)
    input := bytes.NewReader(append(append([]byte{}, wire...), 0xde, 0xad))
    ok, parsed, err := protocol.ReadTCPResponse(input)
    suffix, _ := io.ReadAll(input)
    if err != nil || ok != success || parsed != message || !bytes.Equal(suffix, []byte{0xde, 0xad}) { panic("response parse") }
    emit(label, wire)
}
func datagram(name, address string, id uint16, fragment, count byte) {
    var output bytes.Buffer
    if err := binary.Write(&output, binary.BigEndian, uint32(0x01020304)); err != nil { panic(err) }
    if err := binary.Write(&output, binary.BigEndian, id); err != nil { panic(err) }
    output.WriteByte(fragment); output.WriteByte(count)
    output.Write(quicvarint.Append(nil, uint64(len(address))))
    output.WriteString(address); output.Write([]byte{0,1,127,128,255})
    emit(name, output.Bytes())
}
func main() {
    for _, value := range []uint64{0,37,63,64,16383,16384,1073741823,1073741824,4611686018427387903} {
        wire := quicvarint.Append(nil, value)
        decoded, err := quicvarint.Read(bytes.NewReader(wire))
        if err != nil || decoded != value { panic("varint") }
        emit(fmt.Sprintf("varint-%d", value), wire)
    }
    request("example.test:443"); request("[2001:db8::1]:53")
    response(true, "", nil); response(false, "connection refused", []byte{1,2,3})
    datagram("udp-single", "example.test:53", 0x0506, 127, 1)
    datagram("udp-fragment", "[2001:db8::1]:53", 0xffff, 2, 3)
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path, nargs="?")
    parser.add_argument("--cache-root", type=pathlib.Path)
    args = parser.parse_args()
    root = args.cache_root or pathlib.Path(tempfile.mkdtemp(prefix="nexus-hy2-oracle-"))
    root.mkdir(parents=True, exist_ok=True)
    source = root / "oracle"
    source.mkdir(exist_ok=True)
    (source / "go.mod").write_text(
        "module github.com/sagernet/sing-quic/hysteria2/nexus-oracle\n\ngo 1.25.0\n\n"
        f"require github.com/sagernet/sing-quic {VERSION}\n")
    (source / "main.go").write_text(ORACLE)
    env = dict(os.environ, GOWORK="off", GOENV="off", GOTOOLCHAIN="local",
               GOMODCACHE=str(root / "gomodcache"), GOCACHE=str(root / "gocache"))
    expected = subprocess.run(["go", "run", "-mod=mod", "-p", "1", "."], cwd=source, env=env,
                              check=True, capture_output=True, timeout=300).stdout
    if args.fixture:
        actual = subprocess.run([args.fixture.resolve()], check=True, capture_output=True, timeout=10).stdout
        if actual != expected:
            raise RuntimeError(f"Hy2 Go/Nexus vectors differ\nGo: {expected!r}\nNexus: {actual!r}")
        print(f"Hy2 QUIC varints/TCP fixed-reader/UDP vectors matched fixed sing-quic {VERSION}")
    else:
        print(expected.decode(), end="")
        print(f"Go oracle validated upstream readers; cache root: {root}", file=__import__("sys").stderr)


if __name__ == "__main__":
    main()

