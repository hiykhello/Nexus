package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 4 {
		panic("usage: named-http2-rule-peer CERT KEY RULES")
	}
	rules, err := os.ReadFile(os.Args[3])
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	server := http.Server{
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			source, _, _ := net.SplitHostPort(r.RemoteAddr)
			if r.ProtoMajor != 2 || r.TLS.NegotiatedProtocol != "h2" ||
				r.TLS.ServerName != "localhost" || source != "127.0.0.2" ||
				r.Method != "GET" || r.Header.Get("Accept-Encoding") != "identity" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case "/conditional":
				if r.Header.Get("If-None-Match") == `W/"rules-1"` {
					fmt.Println("conditional 304")
					w.Header().Set("ETag", `"rules-1"`)
					w.WriteHeader(http.StatusNotModified)
				} else {
					fmt.Println("conditional 200")
					w.Header().Set("ETag", `W/"rules-1"`)
					_, _ = w.Write(rules)
				}
			case "/redirect":
				fmt.Println("redirect", r.RemoteAddr)
				w.Header().Set("Location", "/with-header")
				w.WriteHeader(http.StatusTemporaryRedirect)
			case "/with-header":
				fmt.Println("final", r.RemoteAddr)
				if r.Header.Get("X-Nexus-Test") != "custom value" {
					http.Error(w, "missing configured header", http.StatusBadRequest)
					return
				}
				fallthrough
			case "/rules":
				w.Header().Set("Content-Length", strconv.Itoa(len(rules)))
				_, _ = w.Write(rules)
			case "/stream", "/stream-limit":
				w.Header().Set("Trailer", "X-Complete")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				count := 1
				if r.URL.Path == "/stream-limit" {
					count = 2
				}
				for range count {
					if _, err := w.Write(rules); err != nil {
						return
					}
				}
				w.Header().Set("X-Complete", "yes")
			case "/reset":
				_, _ = w.Write(rules[:16])
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			case "/short":
				w.Header().Set("Content-Length", strconv.Itoa(len(rules)+7))
				_, _ = w.Write(rules)
			case "/encoded":
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(rules)
			case "/timeout":
				<-r.Context().Done()
			default:
				http.NotFound(w, r)
			}
		}),
	}
	if err := server.ServeTLS(listener, os.Args[1], os.Args[2]); err != nil {
		panic(err)
	}
}
