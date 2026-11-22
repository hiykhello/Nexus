package main

import (
    "context"
    "fmt"
    "os"
    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/proxy"
)

type collector struct { bytes []byte }
func (c *collector) WriteMultiBuffer(blocks buf.MultiBuffer) error {
    defer buf.ReleaseMulti(blocks)
    for _, b := range blocks { if b != nil { c.bytes = append(c.bytes, b.Bytes()...) } }
    return nil
}
func main() {
    if len(os.Args)!=2 { panic("expected direct, end, plain, or records") }
    mode:=os.Args[1]; id:=make([]byte,16); for i:=range id { id[i]=byte(i) }
    data:=make([]byte,8192); for i:=range data { data[i]=0x55 }
    state:=proxy.NewTrafficState(id)
    switch mode {
    case "direct", "end", "records":
        copy(data,[]byte{0x17,3,3,0x1f,0xfb})
        if mode=="records" { copy(data,[]byte{0x17,3,3,0x1f,0x9f}); copy(data[8100:],[]byte{0x17,3,3,0,87}) }
        state.IsTLS=true; state.IsTLS12orAbove=true; state.EnableXtls=mode!="end"; state.NumberOfPacketToFilter=0
    case "plain": state.NumberOfPacketToFilter=2
    default: panic("bad mode")
    }
    output:=new(collector)
    writer:=proxy.NewVisionWriter(output,state,true,context.Background(),nil,nil,[]uint32{900,1,900,1})
    if err:=writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(data)}); err!=nil { panic(err) }
    if _,err:=os.Stdout.Write(output.bytes); err!=nil { panic(fmt.Sprint(err)) }
}
