# XUDP writer reference

`go run .` invokes `common/xudp.PacketWriter` from the pinned Xray v1.260327.0 module. It emits one UDP open frame with a global ID, an IPv6 per-packet destination, and a keep frame with an implicit destination. `tests/xudp_xray_vector.py` compares the actual output against the Nexus encoder. The reference does not exercise Xray's reader, mux session lifecycle, UDP transport, or all destination and payload sizes.
