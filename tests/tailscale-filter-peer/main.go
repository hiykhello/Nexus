// Compare rule conversion and named update semantics with fixed Tailscale.
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"

	"go4.org/netipx"

	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

type query struct {
	source, destination netip.Addr
	protocol            ipproto.Proto
	port                uint16
}

func main() {
	updates := []string{
		`{"PacketFilter":[{"SrcIPs":["100.64.0.0/10"],"DstPorts":[{"IP":"100.65.2.3","Ports":{"First":80,"Last":90}}]}]}`,
		`{"PacketFilters":{"v6":[{"SrcIPs":["2001:db8::1-2001:db8::5"],"DstPorts":[{"IP":"2001:db8:1::/48","Ports":{"First":443,"Last":443}}],"IPProto":[6]}]}}`,
		`{"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}],"IPProto":[-1,999,132]}],"PacketFilters":{"v6":null}}`,
		`{"PacketFilters":{"*":null,"empty":[]}}`,
		`{"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}],"PacketFilters":{"base":[]}}`,
	}
	addr := netip.MustParseAddr
	queries := []query{{addr("100.64.1.2"), addr("100.65.2.3"), 6, 80},
		{addr("100.64.1.2"), addr("100.65.2.3"), 17, 90},
		{addr("100.64.1.2"), addr("100.65.2.3"), 132, 80},
		{addr("2001:db8::3"), addr("2001:db8:1::1"), 6, 443},
		{addr("2001:db8::3"), addr("2001:db8:1::1"), 132, 443}}
	chunks := map[string][]tailcfg.FilterRule{}
	for _, wire := range updates {
		var response tailcfg.MapResponse
		if err := json.Unmarshal([]byte(wire), &response); err != nil {
			panic(err)
		}
		if response.PacketFilter != nil {
			chunks["base"] = response.PacketFilter
		}
		if response.PacketFilters != nil {
			if value, ok := response.PacketFilters["*"]; ok && value == nil {
				clear(chunks)
			}
			for key, value := range response.PacketFilters {
				if key == "*" {
					continue
				}
				if value == nil {
					delete(chunks, key)
				} else {
					chunks[key] = value
				}
			}
		}
		var names []string
		for key := range chunks {
			names = append(names, key)
		}
		slices.Sort(names)
		var all []tailcfg.FilterRule
		for _, key := range names {
			all = append(all, chunks[key]...)
		}
		matches, err := filter.MatchesFromFilterRules(all)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, q := range queries {
			allowed := false
			for _, match := range matches {
				if !match.SrcsContains(q.source) {
					continue
				}
				var protocol bool
				for i := 0; i < match.IPProto.Len(); i++ {
					if match.IPProto.At(i) == q.protocol {
						protocol = true
					}
				}
				if !protocol {
					continue
				}
				for _, dst := range match.Dsts {
					if dst.Net.Contains(q.destination) && dst.Ports.Contains(q.port) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				fmt.Print("1")
			} else {
				fmt.Print("0")
			}
		}
		fmt.Println()
	}
	var local netipx.IPSetBuilder
	local.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	local.AddPrefix(netip.MustParsePrefix("::/0"))
	localSet, err := local.IPSet()
	if err != nil {
		panic(err)
	}
	var wildcard tailcfg.MapResponse
	if err := json.Unmarshal([]byte(`{"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]}`), &wildcard); err != nil {
		panic(err)
	}
	matches, err := filter.MatchesFromFilterRules(wildcard.PacketFilter)
	if err != nil {
		panic(err)
	}
	f := filter.New(matches, nil, localSet, nil, nil, func(string, ...any) {})
	for _, q := range []query{{addr("100.64.1.2"), addr("100.65.2.3"), 6, 80},
		{addr("2001:db8::3"), addr("2001:db8:1::1"), 6, 80},
		{addr("100.64.1.2"), addr("2001:db8:1::1"), 6, 80},
		{addr("2001:db8::3"), addr("100.65.2.3"), 6, 80}} {
		if f.Check(q.source, q.destination, q.port, q.protocol) == filter.Accept {
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}
	}
	fmt.Println()
}
