package main

import (
    "context"
    "encoding/hex"
    "fmt"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/proxy"
    "github.com/xtls/xray-core/proxy/vless/encoding"
)
func main() {
    id := make([]byte,16)
    for i := range id { id[i] = byte(i) }
    seed := []uint32{0,1,0,1}
    first := proxy.XtlsPadding(buf.FromBytes([]byte("hello")), proxy.CommandPaddingContinue, &id, false, context.Background(), seed)
    last := proxy.XtlsPadding(buf.FromBytes([]byte("world")), proxy.CommandPaddingEnd, nil, false, context.Background(), seed)
    fmt.Println(hex.EncodeToString(append(first.Bytes(),last.Bytes()...)))
    addon := buf.New()
    if err := encoding.EncodeHeaderAddons(addon, &encoding.Addons{Flow:"xtls-rprx-vision"}); err != nil { panic(err) }
    fmt.Println(hex.EncodeToString(addon.Bytes()))
    hello := make([]byte, 79)
    copy(hello, []byte{0x16,3,3,0,74,2})
    hello[43] = 32
    hello[76] = 0x13
    hello[77] = 0x01
    hello = append(hello, []byte{0,0x2b,0,2,3,4}...)
    hello[4] = 80
    state := proxy.NewTrafficState(make([]byte,16))
    proxy.XtlsFilterTls(buf.MultiBuffer{buf.FromBytes(hello)}, state, context.Background())
    fmt.Printf("filter %v %v %v %04x %d\n", state.IsTLS, state.IsTLS12orAbove, state.EnableXtls, state.Cipher, state.NumberOfPacketToFilter)
    for _, sample := range [][]byte{{0x17,3,3,0,1,42},{0x17,3,3,0,0},{0x17,3,3,0,2,42},{}} {
        fmt.Printf("record %v\n", proxy.IsCompleteRecord(buf.MultiBuffer{buf.FromBytes(sample)}))
    }
}
