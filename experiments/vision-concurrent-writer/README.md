# Xray VisionWriter concurrent output experiment

Run `go run .` in this directory. The Go module pins Xray v1.260327.0.

Two calls share the upstream `VisionWriter`, as Mux responses can share the
server link. The fake underlying writer suspends the first call after its
padded initial block is prepared; a second call emits ordinary bytes before
the first is released. The assertion checks the resulting order: ordinary
bytes precede the UUID and first padded block.

This establishes that this schedule is possible with the upstream writer. It
does not reproduce a complete TLS connection or establish that it caused a
particular network failure; actual transport scheduling and upstream client
behavior need independent testing.
