"""Independent NETLINK_NETFILTER table probe for the TUN fixture."""
import os
import socket
import struct

UNRELATED = "fixture_inet"


def attribute(kind, data):
    length = len(data) + 4
    return struct.pack("=HH", length, kind) + data + bytes(-length % 4)


def netlink(kind, flags, seq, family=1, subsystem=0, attrs=b""):
    return struct.pack("=IHHII", 20+len(attrs), kind, flags, seq, 0) + struct.pack("!BBH", family, 0, subsystem) + attrs


def tables(create=False):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as nl:
        nl.settimeout(2)
        nl.bind((0, 0))
        if create:
            transaction = netlink(16, 1, 1, 0, 10)
            transaction += netlink(0xA00, 0x605, 2, attrs=attribute(1, UNRELATED.encode()+b"\0") +
                                   attribute(6, b"foreign table marker"))
            transaction += netlink(17, 1, 3, 0, 10)
            nl.sendto(transaction, (0, 0))
            ack = nl.recv(65536)
            assert struct.unpack_from("=i", ack, 16)[0] == 0, ack.hex()
        nl.sendto(netlink(0xA01, 0x301, 7), (0, 0))
        result = {}
        while True:
            data = nl.recv(65536)
            offset = 0
            while offset < len(data):
                length, kind = struct.unpack_from("=IH", data, offset)
                if kind == 3:
                    return result
                if kind == 2:
                    code, = struct.unpack_from("=i", data, offset+16)
                    raise OSError(-code, os.strerror(-code))
                assert kind == 0xA00, data.hex()
                fields = {}
                pos = offset+20
                while pos < offset+length:
                    size, field = struct.unpack_from("=HH", data, pos)
                    assert size >= 4
                    fields[field] = data[pos+4:pos+size]
                    pos += (size+3) & ~3
                # Kernel-managed use count and socket owner's port ID can vary.
                result[fields[1].rstrip(b"\0").decode()] = (fields.get(2), fields.get(6))
                offset += (length+3) & ~3


