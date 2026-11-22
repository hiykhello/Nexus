import Foundation

public enum class UtunAddressFamily: UInt32, Sendable, Equatable {
    case ipv4 = 2   // AF_INET
    case ipv6 = 30  // AF_INET6 on Darwin
}

/// Framed L3 packet converter for Darwin `utun` sockets (4-byte big-endian AF header)
/// and `NEPacketTunnelFlow` batch passthrough, clamped to `AppleTunnelProfile.maxSafeMtu`.
public struct UtunPassthroughAdapter: Sendable, Equatable {
    public let maxMtu: Int

    public init(maxMtu: Int = AppleTunnelProfile.maxSafeMtu) {
        self.maxMtu = min(max(maxMtu, 1280), AppleTunnelProfile.maxSafeMtu)
    }

    public func detectFamily(_ ipPacket: Data) -> UtunAddressFamily? {
        guard let firstByte = ipPacket.first else { return nil }
        switch firstByte >> 4 {
        case 4: return ipPacket.count >= 20 ? .ipv4 : nil
        case 6: return ipPacket.count >= 40 ? .ipv6 : nil
        default: return nil
        }
    }

    public func framePacket(_ ipPacket: Data) -> Data? {
        guard ipPacket.count <= maxMtu, let family = detectFamily(ipPacket) else { return nil }
        var out = Data(capacity: 4 + ipPacket.count)
        var be = family.rawValue.bigEndian
        withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
        out.append(ipPacket)
        return out
    }

    public func unframePacket(_ utunPacket: Data) -> (family: UtunAddressFamily, payload: Data)? {
        guard utunPacket.count > 4 else { return nil }
        let rawFamily = (UInt32(utunPacket[utunPacket.startIndex]) << 24)
            | (UInt32(utunPacket[utunPacket.startIndex + 1]) << 16)
            | (UInt32(utunPacket[utunPacket.startIndex + 2]) << 8)
            | UInt32(utunPacket[utunPacket.startIndex + 3])
        guard let family = UtunAddressFamily(rawValue: rawFamily) else { return nil }
        let payload = utunPacket.dropFirst(4)
        guard payload.count <= maxMtu, detectFamily(payload) == family else { return nil }
        return (family, Data(payload))
    }

    public func frameBatch(_ packets: [Data]) -> [Data] {
        packets.compactMap { framePacket($0) }
    }
}
