# TLS trust test certificates

These DER certificates are test-only. A root signs an intermediate, which signs
three leaves sharing a public key: `server` has DNS and IP subject alternative
names and serverAuth, `client` has clientAuth only, and `cn` has only a common
name. No private keys are retained. The leaves are valid from 2026-10-27 to
2027-10-27 UTC; tests use the fixed time 2027-01-01 and also test times outside
that interval. They do not depend on the machine clock or system trust store.

`certificate.bin` contains the TLS Certificate message for the server and
intermediate. `signature.bin` is an RSA-PSS SHA-256 signature by the leaf key
for the synthetic transcript in `tls_client_auth.cpp`; its preceding handshake
messages are test framing only and are not valid negotiated TLS messages.

`client_wire.bin` and `server_wire.bin` are RFC 8448 Hello messages. The
`flight-signature.bin` signature covers those messages, an empty
EncryptedExtensions, and `certificate.bin`; it uses the same test leaf key.
