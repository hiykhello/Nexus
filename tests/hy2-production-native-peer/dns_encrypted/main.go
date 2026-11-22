package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/quicvarint"
)

func reply(query []byte) (string, []byte, error) {
	if len(query) < 17 || query[0] != 0 || query[1] != 0 || binary.BigEndian.Uint16(query[4:]) != 1 {
		return "", nil, fmt.Errorf("invalid protected DNS query")
	}
	var labels []string
	position := 12
	for position < len(query) && query[position] != 0 {
		size := int(query[position])
		position++
		if size > 63 || size > len(query)-position {
			return "", nil, fmt.Errorf("invalid DNS label")
		}
		labels = append(labels, string(query[position:position+size]))
		position += size
	}
	position++
	if position+4 > len(query) {
		return "", nil, io.ErrUnexpectedEOF
	}
	qtype := binary.BigEndian.Uint16(query[position:])
	answer := bytes.Clone(query[:position+4])
	copy(answer[2:12], []byte{0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0})
	answer = append(answer, 0xc0, 0x0c, 0, byte(qtype), 0, 1, 0, 0, 0, 40)
	switch qtype {
	case 1:
		answer = append(answer, 0, 4, 127, 0, 0, 1)
	case 28:
		answer = append(answer, 0, 16)
		answer = append(answer, net.IPv6loopback...)
	default:
		return "", nil, fmt.Errorf("unexpected question type %d", qtype)
	}
	return strings.Join(labels, "."), answer, nil
}

type http3ConnectionID struct{}

func httpHandler(port int, tracePool bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		expectedHost := "dns.test:" + strconv.Itoa(port)
		if req.Method != http.MethodPost || req.URL.RequestURI() != "/resolve?profile=edge" ||
			req.Host != expectedHost || req.Header.Get("Content-Type") != "application/dns-message" ||
			req.Header.Get("Accept") != "application/dns-message" {
			http.Error(w, "invalid DoH request", http.StatusBadRequest)
			return
		}
		query, err := io.ReadAll(io.LimitReader(req.Body, 65536))
		if err != nil || len(query) > 65535 {
			http.Error(w, "invalid DoH body", http.StatusBadRequest)
			return
		}
		name, answer, err := reply(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if tracePool {
			connection := req.RemoteAddr
			if id, ok := req.Context().Value(http3ConnectionID{}).(uint64); ok {
				connection = strconv.FormatUint(id, 10)
			}
			fmt.Printf("request %s %s %s\n", name, req.Proto, connection)
		} else {
			fmt.Printf("request %s %s\n", name, req.Proto)
		}
		if name == "switch-slow.test" {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-req.Context().Done():
				return
			}
		}
		if name == "held.test" {
			<-req.Context().Done()
			fmt.Println("canceled held.test")
			return
		}
		if name == "redirect.test" {
			http.Redirect(w, req, "https://dns.test/wrong", http.StatusFound)
			return
		}
		if name == "wrong-type.test" {
			w.Header().Set("Content-Type", "application/octet-stream")
		} else {
			w.Header().Set("Content-Type", "application/dns-message")
		}
		w.Header().Set("Age", "11")
		w.Header().Set("Content-Length", strconv.Itoa(len(answer)))
		_, _ = w.Write(answer)
	})
}

func serveHTTP(listener net.Listener, cfg *tls.Config, mode string, tracePool bool) error {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(mode == "h1")
	protocols.SetHTTP2(mode == "h2")
	server := http.Server{
		TLSConfig: cfg, Protocols: protocols, ReadHeaderTimeout: 3 * time.Second,
		Handler: httpHandler(listener.Addr().(*net.TCPAddr).Port, tracePool),
	}
	fmt.Println(listener.Addr().String())
	return server.ServeTLS(listener, "", "")
}

func serveHTTP3(address string, cfg *tls.Config, tracePool bool) error {
	socket, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer socket.Close()
	var connections atomic.Uint64
	server := http3.Server{
		TLSConfig: cfg, Handler: httpHandler(socket.LocalAddr().(*net.UDPAddr).Port, tracePool),
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			return context.WithValue(ctx, http3ConnectionID{}, connections.Add(1))
		},
	}
	if os.Getenv("NEXUS_TEST_QUIC_1200") == "1" {
		server.QUICConfig = &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, Tracer: qlog.DefaultConnectionTracer}
	}
	fmt.Println(socket.LocalAddr().String())
	return server.Serve(socket)
}

func serveStream(stream *quic.Stream, connection uint64, heldCanceled chan struct{}, rejectNext *atomic.Bool) {
	var prefix [2]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(stream, query); err != nil {
		return
	}
	var extra [1]byte
	if count, err := stream.Read(extra[:]); count != 0 || err != io.EOF {
		stream.CancelWrite(2)
		return
	}
	name, answer, err := reply(query)
	if err != nil {
		stream.CancelWrite(2)
		return
	}
	fmt.Printf("request %s %d %d\n", name, connection, stream.StreamID())
	if name == "reject-next-ticket.test" {
		rejectNext.Store(true)
	}
	if name == "held.test" {
		<-stream.Context().Done()
		cause := context.Cause(stream.Context())
		if failure, ok := cause.(*quic.StreamError); ok && failure.ErrorCode == 3 {
			close(heldCanceled)
			fmt.Println("canceled held.test")
		} else {
			fmt.Printf("held stream closed: %v\n", cause)
		}
		return
	}
	if name == "partner.test" {
		select {
		case <-heldCanceled:
		case <-time.After(2 * time.Second):
			stream.CancelWrite(3)
			return
		}
	}
	if name == "reset.test" {
		stream.CancelWrite(3)
		return
	}
	if name == "bad-id.test" {
		answer[1] = 1
	}
	if name == "extra.test" {
		answer = append(answer, 1)
	}
	length := len(answer)
	if name == "extra.test" {
		length--
	}
	binary.BigEndian.PutUint16(prefix[:], uint16(length))
	// Write both size bytes separately so the client cannot assume record
	// and stream boundaries coincide.
	if _, err = stream.Write(prefix[:1]); err != nil {
		return
	}
	if _, err = stream.Write(prefix[1:]); err != nil {
		return
	}
	if _, err = stream.Write(answer); err != nil {
		return
	}
	_ = stream.Close()
}

type earlyPacketLog struct {
	net.PacketConn
	mu       sync.Mutex
	observed map[string]bool
}

func containsEarlyPacket(datagram []byte) bool {
	for len(datagram) >= 7 && datagram[0]&0x80 != 0 && binary.BigEndian.Uint32(datagram[1:5]) == 1 {
		kind := (datagram[0] >> 4) & 3
		if kind == 1 {
			return true
		}
		cursor := 6 + int(datagram[5])
		if kind == 3 || cursor >= len(datagram) {
			return false
		}
		cursor += 1 + int(datagram[cursor])
		if cursor > len(datagram) {
			return false
		}
		if kind == 0 {
			token, prefix, err := quicvarint.Parse(datagram[cursor:])
			if err != nil || token > uint64(len(datagram)-cursor-prefix) {
				return false
			}
			cursor += prefix + int(token)
		}
		size, prefix, err := quicvarint.Parse(datagram[cursor:])
		if err != nil || size > uint64(len(datagram)-cursor-prefix) {
			return false
		}
		datagram = datagram[cursor+prefix+int(size):]
	}
	return false
}

func (log *earlyPacketLog) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, address, err := log.PacketConn.ReadFrom(buffer)
	if err == nil && containsEarlyPacket(buffer[:n]) {
		log.mu.Lock()
		log.observed[address.String()] = true
		log.mu.Unlock()
	}
	return n, address, err
}

func (log *earlyPacketLog) take(address net.Addr) bool {
	log.mu.Lock()
	defer log.mu.Unlock()
	key := address.String()
	found := log.observed[key]
	delete(log.observed, key)
	return found
}

func serveQUIC(address string, cfg *tls.Config, traceResumption, traceEarly bool) error {
	cfg.NextProtos = []string{"doq"}
	var rejectNext atomic.Bool
	if traceResumption {
		cfg.WrapSession = cfg.EncryptTicket
		cfg.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
			if rejectNext.Swap(false) {
				fmt.Println("ticket rejected")
				return nil, nil
			}
			return cfg.DecryptTicket(identity, state)
		}
	}
	transport := &quic.Config{
		MaxIdleTimeout: 8 * time.Second, MaxIncomingStreams: 32, Allow0RTT: traceResumption,
	}
	if traceResumption {
		var connections atomic.Uint64
		transport.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
			config := transport.Clone()
			config.GetConfigForClient = nil
			attempt := connections.Add(1)
			if traceEarly {
				if attempt == 6 {
					time.Sleep(250 * time.Millisecond)
				} else {
					time.Sleep(30 * time.Millisecond)
				}
				if attempt == 3 || attempt == 6 {
					config.MaxIncomingStreams = 2
				}
			} else if attempt%2 == 0 {
				config.MaxIncomingStreams = 2
			}
			return config, nil
		}
	}
	var wire *earlyPacketLog
	var listener *quic.Listener
	var err error
	if traceEarly {
		socket, openError := net.ListenPacket("udp", address)
		if openError != nil {
			return openError
		}
		defer socket.Close()
		wire = &earlyPacketLog{PacketConn: socket, observed: make(map[string]bool)}
		listener, err = quic.Listen(wire, cfg, transport)
	} else {
		listener, err = quic.ListenAddr(address, cfg, transport)
	}
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Println(listener.Addr().String())
	var sequence atomic.Uint64
	for {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		id := sequence.Add(1)
		if traceResumption {
			state := connection.ConnectionState()
			if wire != nil {
				fmt.Printf("handshake %d resumed=%t early=%t sent=%t\n",
					id, state.TLS.DidResume, state.Used0RTT, wire.take(connection.RemoteAddr()))
			} else {
				fmt.Printf("handshake %d resumed=%t early=%t\n", id, state.TLS.DidResume, state.Used0RTT)
			}
		}
		go func() {
			heldCanceled := make(chan struct{})
			for {
				stream, err := connection.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go serveStream(stream, id, heldCanceled, &rejectNext)
			}
		}()
	}
}

func main() {
	mode := flag.String("protocol", "h2", "h1, h2, h3 or quic")
	address := flag.String("address", "127.0.0.1:0", "listen address")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS private key")
	tracePool := flag.Bool("trace-doh-pool", false, "report the connection of each DoH request")
	dohHandshakeDelay := flag.Duration("delay-doh-handshake", 0, "delay the DoH TLS handshake and report each attempt")
	traceResumption := flag.Bool("trace-quic-resumption", false, "report DoQ connection resumption and early-data state")
	traceEarly := flag.Bool("trace-quic-early", false, "keep transport parameters stable except on the third attempt")
	flag.Parse()
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		panic(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	if *dohHandshakeDelay > 0 && *mode == "h2" {
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Println("handshake")
			time.Sleep(*dohHandshakeDelay)
			return nil, nil
		}
	}
	if *mode == "quic" {
		err = serveQUIC(*address, cfg, *traceResumption || *traceEarly, *traceEarly)
	} else if *mode == "h3" {
		err = serveHTTP3(*address, cfg, *tracePool)
	} else if *mode == "h1" || *mode == "h2" {
		var listener net.Listener
		listener, err = net.Listen("tcp", *address)
		if err == nil {
			err = serveHTTP(listener, cfg, *mode, *tracePool)
		}
	} else {
		err = fmt.Errorf("unsupported protocol %s", *mode)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
