# UoT reference vectors

`go run .` generates request and data-frame samples using
`github.com/sagernet/sing` v0.5.1. The pinned module and `go.sum` make this
independent reference reproducible; it is not a substitute for a live
sing-box client/server interoperability test. `tests/uot.cpp` checks the
samples for IPv4, IPv6 and domains and exercises stream boundaries.
