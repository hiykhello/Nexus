package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

func serve(connection net.Conn) {
	defer connection.Close()
	ready := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/map", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, []byte{1, 2, 3}) || r.Host != "control.example" {
			http.Error(w, "bad Map request", 400)
			return
		}
		w.Header().Set("Trailer", "X-Map-End")
		w.Header().Set("Content-Length", "786432")
		w.WriteHeader(200)
		payload := make([]byte, 786432)
		for i := range payload {
			payload[i] = byte(i * 17 % 251)
		}
		if _, err := w.Write(payload[:4096]); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		close(ready)
		if _, err := w.Write(payload[4096:]); err != nil {
			return
		}
		w.Header().Set("X-Map-End", "complete")
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 65536 || !bytes.Equal(body, bytes.Repeat([]byte{42}, 65536)) {
			http.Error(w, "bad borrowed AuthKey body", 400)
			return
		}
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			http.Error(w, "Map did not start", 500)
			return
		}
		time.Sleep(1100 * time.Millisecond)
		w.Header().Set("Trailer", "X-Register-End")
		w.WriteHeader(200)
		fmt.Fprint(w, "registered\n")
		w.Header().Set("X-Register-End", "complete")
	})
	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 36864 || !bytes.Equal(body[:32768], bytes.Repeat([]byte{51}, 32768)) || !bytes.Equal(body[32768:], bytes.Repeat([]byte{52}, 4096)) {
			http.Error(w, "bad deferred body", 400)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	server := http2.Server{MaxConcurrentStreams: 4, MaxReadFrameSize: 16384,
		MaxUploadBufferPerConnection: 1024 * 1024, MaxUploadBufferPerStream: 128 * 1024}
	server.ServeConn(connection, &http2.ServeConnOpts{Handler: mux})
}

func main() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		go serve(connection)
	}
}
