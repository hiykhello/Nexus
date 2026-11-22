package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

var meshMode = os.Getenv("NEXUS_TS_MESH_MODE")
var meshPorts [2]int
var meshKeys sync.Map

func meshStun(host string) (int, error) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		return 0, err
	}
	observation := os.Getenv("NEXUS_TS_MESH_STUN_OBSERVED")
	go func() {
		var bytes [128]byte
		previous := make(map[netip.AddrPort]stun.TxID)
		for {
			size, source, err := socket.ReadFromUDPAddrPort(bytes[:])
			if err != nil {
				return
			}
			id, err := stun.ParseBindingRequest(bytes[:size])
			if err != nil {
				continue
			}
			mapped := source
			if source.Port() < 65535 {
				mapped = netip.AddrPortFrom(source.Addr(), source.Port()+1)
			}
			if source.Port() == 41234 {
				if _, err := os.Stat(observation + ".change"); err == nil {
					mapped = netip.AddrPortFrom(source.Addr(), 41237)
				}
			}
			stale := netip.AddrPortFrom(source.Addr(), 41236)
			if older, ok := previous[source]; ok {
				_, _ = socket.WriteToUDPAddrPort(stun.Response(older, stale), source)
			}
			_, _ = socket.WriteToUDPAddrPort(stun.Response(id, mapped), source)
			previous[source] = id
		}
	}()
	return socket.LocalAddr().(*net.UDPAddr).Port, nil
}

func meshRelay() http.Handler {
	if meshMode != "relay" && meshMode != "dynamic" && meshMode != "paths" {
		return nil
	}
	relay := derpserver.New(fixedNode(91), func(string, ...any) {})
	if path := os.Getenv("NEXUS_TS_MESH_DERP_STATS"); path != "" && meshMode == "paths" {
		go func() {
			for range time.Tick(100 * time.Millisecond) {
				if os.WriteFile(path+".tmp", []byte(relay.ExpVar(false).String()), 0600) == nil {
					_ = os.Rename(path+".tmp", path)
				}
			}
		}()
	}
	return derpserver.Handler(relay)
}

func secondMeshRelay(host, certificate, privateKey string) (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	key, err := tls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		listener.Close()
		return 0, err
	}
	secure := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{key}, NextProtos: []string{"http/1.1"}})
	server := &http.Server{Handler: derpserver.Handler(derpserver.New(fixedNode(111), func(string, ...any) {})), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(secure) }()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func meshRegion() int {
	value, err := os.ReadFile(os.Getenv("NEXUS_TS_MESH_REGION"))
	if err != nil {
		return 901
	}
	region, err := strconv.Atoi(string(value))
	if err != nil || region < 0 || region > 903 {
		return 0
	}
	return region
}

func meshDerpMap(region int) map[string]any {
	regions := map[string]any{}
	if region >= 901 && region <= 903 {
		port := meshPorts[0]
		if region != 901 {
			port = meshPorts[1]
		}
		regions[strconv.Itoa(region)] = map[string]any{"RegionID": region, "Nodes": []any{
			map[string]any{"Name": "fixture", "RegionID": region, "HostName": "localhost", "IPv4": "192.0.2.1", "DERPPort": port},
		}}
	}
	return map[string]any{"Regions": regions}
}

func meshMap(w http.ResponseWriter, r *http.Request, request tailcfg.MapRequest) error {
	index := 1
	if request.NodeKey == fixedNode(51).Public() {
		index = 2
	} else if request.NodeKey != fixedNode(17).Public() {
		http.Error(w, "unknown fixture node", 403)
		return nil
	}
	remote := 3 - index
	region := 901
	if meshMode == "dynamic" {
		region = meshRegion()
	}
	node := func(id int) map[string]any {
		addresses := [2][]string{{"100.64.21.1/32", "fd7a:115c:a1e0::1/128"}, {"100.64.21.2/32", "fd7a:115c:a1e0::2/128"}}
		key := fixedNode(17).Public()
		if id == 2 {
			key = fixedNode(51).Public()
		}
		result := map[string]any{"ID": id, "Key": key.String(), "Addresses": addresses[id-1], "MachineAuthorized": true}
		if meshMode == "direct" {
			result["Endpoints"] = []string{[]string{"192.0.2.1:41234", "192.0.2.2:41234"}[id-1]}
		} else {
			result["HomeDERP"] = region
		}
		if meshMode == "paths" {
			result["Endpoints"] = []string{[]string{"192.0.2.11:41234", "192.0.2.12:41234"}[id-1]}
			if discovery, ok := meshKeys.Load(key); ok {
				result["DiscoKey"] = discovery
			}
		}
		return result
	}
	filter := []any{map[string]any{
		"SrcIPs":   []string{"*"},
		"DstPorts": []any{map[string]any{"IP": "*", "Ports": map[string]any{"First": 18080, "Last": 18080}}},
		"IPProto":  []int{6, 17},
	}}
	send := func(value any) error {
		wire, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer(make([]byte, 0, 4+len(wire)))
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(wire)))
		buf.Write(wire)
		if err := writeAll(w, buf.Bytes()); err != nil {
			return err
		}
		w.(http.Flusher).Flush()
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	initial := map[string]any{"Node": node(index), "Peers": []any{node(remote)}, "PacketFilter": filter}
	if meshMode == "dynamic" {
		initial["DERPMap"] = meshDerpMap(region)
	}
	if err := send(initial); err != nil {
		return err
	}
	check := time.NewTicker(20 * time.Millisecond)
	defer check.Stop()
	withdrawn := false
	var lastDiscovery any
	for {
		select {
		case <-r.Context().Done():
			return nil
		case <-check.C:
			if meshMode == "paths" {
				peer := node(remote)
				discovery := peer["DiscoKey"]
				if discovery != lastDiscovery {
					lastDiscovery = discovery
					if err := send(map[string]any{"PeersChanged": []any{peer}}); err != nil {
						return err
					}
				}
				continue
			}
			if meshMode == "dynamic" {
				if next := meshRegion(); next != region {
					region = next
					if err := send(map[string]any{"Node": node(index), "Peers": []any{node(remote)}, "DERPMap": meshDerpMap(region)}); err != nil {
						return err
					}
				}
				continue
			}
			_, err := os.Stat(os.Getenv("NEXUS_TS_MESH_WITHDRAW"))
			if err == nil && !withdrawn {
				withdrawn = true
				if err := send(map[string]any{"PeersRemoved": []int{remote}}); err != nil {
					return err
				}
			} else if errors.Is(err, os.ErrNotExist) && withdrawn {
				return nil // A fresh connection must request a fresh Map.
			}
		}
	}
}
