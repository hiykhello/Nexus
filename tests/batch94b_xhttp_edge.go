package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/apernet/quic-go/http3"
)

// The two physical endpoints share XHTTP session IDs through this local
// reverse proxy. Its front and back use independent HTTP versions and TLS.
func main() {
	if len(os.Args) != 7 {
		log.Fatal("usage: xhttp-edge FRONT_PROTOCOL LISTEN BACK_PROTOCOL URL CERT KEY")
	}
	protocol, address, upstreamProtocol := os.Args[1], os.Args[2], os.Args[3]
	target, err := url.Parse(os.Args[4])
	if err != nil {
		log.Fatal(err)
	}
	cert, err := os.ReadFile(os.Args[5])
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		log.Fatal("invalid test CA")
	}
	identity := &tls.Config{RootCAs: roots, ServerName: "localhost"}
	var transport http.RoundTripper
	switch upstreamProtocol {
	case "h1", "h2":
		transport = &http.Transport{TLSClientConfig: identity, ForceAttemptHTTP2: upstreamProtocol == "h2"}
	case "h3":
		transport = &http3.Transport{TLSClientConfig: identity}
	default:
		log.Fatal("invalid upstream HTTP version")
	}

	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = request.In.Host
		},
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fmt.Println(request.Proto, request.Method, request.URL.Path)
		if protocol == "h1" {
			_ = http.NewResponseController(response).EnableFullDuplex()
		}
		proxy.ServeHTTP(response, request)
	})

	if protocol == "h3" {
		server := &http3.Server{Addr: address, Handler: handler}
		log.Fatal(server.ListenAndServeTLS(os.Args[5], os.Args[6]))
	}
	protocols := new(http.Protocols)
	switch protocol {
	case "h1":
		protocols.SetHTTP1(true)
	case "h2":
		protocols.SetHTTP2(true)
	default:
		log.Fatal("invalid front HTTP version")
	}
	server := &http.Server{Addr: address, Handler: handler, Protocols: protocols}
	log.Fatal(server.ListenAndServeTLS(os.Args[5], os.Args[6]))
}
