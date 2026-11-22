// Reproduce a permitted schedule of the pinned Xray VisionWriter sharing one
// output between two Mux sessions. This is a controlled writer, not a server.
package main

import (
    "bytes"
    "context"
    "fmt"
    "sync"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/proxy"
)

type delayedWriter struct {
    firstEntered chan struct{}
    release chan struct{}
    mu sync.Mutex
    calls int
    output []byte
}
func (w *delayedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
    defer buf.ReleaseMulti(mb)
    w.mu.Lock(); w.calls++; call := w.calls; w.mu.Unlock()
    if call == 1 { close(w.firstEntered); <-w.release }
    w.mu.Lock(); defer w.mu.Unlock()
    for _, b := range mb { w.output = append(w.output, b.Bytes()...) }
    return nil
}
func main() {
    id := make([]byte,16); for i := range id { id[i]=byte(i) }
    state := proxy.NewTrafficState(id)
    // Earlier traffic in either direction has consumed six of eight probes.
    state.NumberOfPacketToFilter=2
    sink := &delayedWriter{firstEntered:make(chan struct{}),release:make(chan struct{})}
    writer := proxy.NewVisionWriter(sink,state,false,context.Background(),nil,nil,[]uint32{0,1,0,1})
    done := make(chan error,1)
    go func(){ done <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("first"))}) }()
    <-sink.firstEntered
    if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("second"))}); err != nil { panic(err) }
    close(sink.release); if err := <-done; err != nil { panic(err) }
    if !bytes.HasPrefix(sink.output,[]byte("second")) || !bytes.Equal(sink.output[len("second"):len("second")+16],id) { panic(fmt.Sprintf("unexpected output %x",sink.output)) }
    fmt.Println("pinned Xray VisionWriter can emit plain data before its delayed initial UUID block")
}
