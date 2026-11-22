# Vision padding reference vector

`GOWORK=off go run .` calls the actual `XtlsPadding` function from Xray-core
v1.260327.0 (commit d2758a023cd7f4174a5a5fa4ff66e487d4342ba0). The seed
forces zero-length random padding so the output is deterministic. The result
covers a UUID-prefixed continue block, an end block with `hello` and `world`,
and the canonical Vision VLESS addon encoded by `EncodeHeaderAddons`.
It does not cover TLS detection, Vision's writer policy, direct transport
switching, or the other padding distributions.

The program also executes Xray's traffic filter on a synthetic ServerHello
and checks complete application-record boundaries. These examples are not
TLS authentication and do not establish behavior for every chunking pattern.
