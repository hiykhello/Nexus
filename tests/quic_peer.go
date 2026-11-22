package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "io"
    "net"
    "os"
    "strconv"
    "strings"
    "time"

    quic "github.com/sagernet/quic-go"
)

func check(err error) { if err != nil { panic(err) } }

func payload() []byte {
    output := make([]byte, 12000)
    for i := range output { output[i] = byte(i*73) }
    return output
}

func exchange(ctx context.Context, connection *quic.Conn, server bool) error {
    if !connection.ConnectionState().TLS.HandshakeComplete || connection.ConnectionState().TLS.NegotiatedProtocol != "h3" {
        return errors.New("QUIC TLS identity/ALPN completion missing")
    }
    datagrams := make(chan error, 1)
    go func() {
        if server {
            received, err := connection.ReceiveDatagram(ctx)
            if err == nil && !bytes.Equal(received, []byte{0,1,255,127,0}) { err = errors.New("DATAGRAM payload differs") }
            if err == nil { err = connection.SendDatagram(received) }
            datagrams <- err
        } else {
            check(connection.SendDatagram([]byte{0,1,255,127,0}))
            received, err := connection.ReceiveDatagram(ctx)
            if err == nil && !bytes.Equal(received, []byte{0,1,255,127,0}) { err = errors.New("DATAGRAM echo differs") }
            datagrams <- err
        }
    }()
    var stream *quic.Stream
    var err error
    if server {
        stream, err = connection.AcceptStream(ctx)
    } else {
        stream, err = connection.OpenStreamSync(ctx)
    }
    if err != nil { return err }
    check(stream.SetDeadline(time.Now().Add(8*time.Second)))
    original := payload()
    if !server {
        if _, err = stream.Write(original); err != nil { return err }
        if err = stream.Close(); err != nil { return err }
    }
    received, err := io.ReadAll(stream)
    if err != nil { return err }
    if !bytes.Equal(received, original) { return errors.New("12000B stream payload differs") }
    if server {
        if _, err = stream.Write(received); err != nil { return err }
        if err = stream.Close(); err != nil { return err }
    }
    if err = <-datagrams; err != nil { return err }
    // Allow the peer's ACK callbacks and application close to cross the socket.
    if server {
        select {
        case <-connection.Context().Done():
            var closed *quic.ApplicationError
            if err = context.Cause(connection.Context()); errors.As(err,&closed) && closed.ErrorCode == 0 { return nil }
            return err
        case <-ctx.Done(): return ctx.Err()
        }
    }
    time.Sleep(150*time.Millisecond)
    return connection.CloseWithError(0,"done")
}

func main() {
    if len(os.Args) != 9 { panic("usage: quic-peer client|server 4|6 PORT CERT.der KEY.der NAME MODE CURVE") }
    server := os.Args[1] == "server"
    port, err := strconv.Atoi(os.Args[3]); check(err)
    network, host := "udp4", "127.0.0.1"
    if os.Args[2] == "6" { network, host = "udp6", "::1" }
    socket, err := net.ListenUDP(network, &net.UDPAddr{IP:net.ParseIP(host)}); check(err)
    defer socket.Close()
    transport := &quic.Transport{Conn:socket, ConnectionIDLength:8}
    defer transport.Close()
    failedHandshake := make(chan error,1)
    if server && (os.Args[7] == "reject" || os.Args[7] == "stop") {
        transport.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context,error) {
            go func() { <-ctx.Done(); failedHandshake <- context.Cause(ctx) }()
            return ctx,nil
        }
    }
    certDER, err := os.ReadFile(os.Args[4]); check(err)
    tlsConf := &tls.Config{MinVersion:tls.VersionTLS13, MaxVersion:tls.VersionTLS13, NextProtos:[]string{"h3"}, ServerName:os.Args[6]}
    tlsConf.CurvePreferences = []tls.CurveID{tls.X25519}
    if os.Args[8] == "hybrid" { tlsConf.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768} }
    // Go fixes curve ordering independent of the Config slice order. Offer a
    // supported higher-preference group absent from Nexus's implemented pair,
    // then X25519, and require the observed server HRR in the C++ fixture.
    if !server && os.Args[8] == "retry" { tlsConf.CurvePreferences = []tls.CurveID{tls.SecP256r1MLKEM768,tls.X25519} }
    if server {
        keyDER, err := os.ReadFile(os.Args[5]); check(err)
        cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:certDER}),pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER})); check(err)
        tlsConf.Certificates = []tls.Certificate{cert}
    } else {
        roots := x509.NewCertPool()
        cert, err := x509.ParseCertificate(certDER); check(err); roots.AddCert(cert); tlsConf.RootCAs = roots
    }
    config := &quic.Config{Versions:[]quic.Version{quic.Version1}, HandshakeIdleTimeout:5*time.Second,
        MaxIdleTimeout:10*time.Second, InitialStreamReceiveWindow:4096, MaxStreamReceiveWindow:65536,
        InitialConnectionReceiveWindow:65536, MaxConnectionReceiveWindow:65536, EnableDatagrams:true,
        InitialPacketSize:1200}
    timeout := 10*time.Second
    if os.Args[7] == "stop" { timeout = 1500*time.Millisecond }
    ctx, cancel := context.WithTimeout(context.Background(),timeout); defer cancel()
    var connection *quic.Conn
    if server {
        listener, listenErr := transport.Listen(tlsConf,config); check(listenErr); defer listener.Close()
        fmt.Printf("READY %d\n",socket.LocalAddr().(*net.UDPAddr).Port)
        if os.Args[7] == "reject" || os.Args[7] == "stop" {
            // Accept exposes authenticated connections only. ConnContext's
            // cancellation cause preserves the actual failed handshake error.
            select { case err = <-failedHandshake: case <-ctx.Done(): err = ctx.Err() }
        } else { connection, err = listener.Accept(ctx) }
    } else {
        fmt.Printf("READY %d\n",socket.LocalAddr().(*net.UDPAddr).Port)
        connection, err = transport.Dial(ctx,&net.UDPAddr{IP:net.ParseIP(host),Port:port},tlsConf,config)
    }
    if os.Args[7] == "reject" || os.Args[7] == "stop" {
        if err == nil { <-connection.Context().Done(); err = context.Cause(connection.Context()) }
        if err == nil { panic("expected peer rejection") }
        if os.Args[7] == "reject" && !strings.Contains(err.Error(),"x509:") && !strings.Contains(err.Error(),"CRYPTO_ERROR 0x12a") {
            panic(fmt.Sprintf("expected certificate rejection, got %v",err))
        }
        fmt.Printf("QUIC peer rejection observed: %v\n",err)
        return
    }
    check(err)
    check(exchange(ctx,connection,server))
    fmt.Printf("QUIC UDP Go %s authenticated 12000B FIN/echo and DATAGRAM passed cipher=%#x\n",os.Args[1],connection.ConnectionState().TLS.CipherSuite)
}
