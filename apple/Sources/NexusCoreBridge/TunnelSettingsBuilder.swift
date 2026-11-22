import Foundation
#if canImport(NetworkExtension)
import NetworkExtension
#endif

public struct AppleTunnelProfile: Sendable, Equatable {
    /// Apple utun headroom ceiling (4096 - UTUN_IF_HEADROOM_SIZE = 4064); exceeding this triggers a severe NE throughput cliff.
    public static let maxSafeMtu = 4064

    public let tunnelRemoteAddress: String
    public let ipv4Address: String
    public let ipv4SubnetMask: String
    public let ipv6Address: String
    public let ipv6PrefixLength: Int
    public let dnsServers: [String]
    public let mtu: Int
    public let excludePrivateNetworks: Bool
    public let preserveMdnsBonjour: Bool

    public init(
        tunnelRemoteAddress: String = "127.0.0.1",
        ipv4Address: String = "172.19.0.1",
        ipv4SubnetMask: String = "255.255.255.252",
        ipv6Address: String = "fdfe:dcba:9876::1",
        ipv6PrefixLength: Int = 126,
        dnsServers: [String] = ["172.19.0.2", "fdfe:dcba:9876::2"],
        mtu: Int = AppleTunnelProfile.maxSafeMtu,
        excludePrivateNetworks: Bool = true,
        preserveMdnsBonjour: Bool = true
    ) {
        self.tunnelRemoteAddress = tunnelRemoteAddress
        self.ipv4Address = ipv4Address
        self.ipv4SubnetMask = ipv4SubnetMask
        self.ipv6Address = ipv6Address
        self.ipv6PrefixLength = ipv6PrefixLength
        self.dnsServers = dnsServers
        self.mtu = min(max(mtu, 1280), AppleTunnelProfile.maxSafeMtu)
        self.excludePrivateNetworks = excludePrivateNetworks
        self.preserveMdnsBonjour = preserveMdnsBonjour
    }

    /// Standard IPv4 exclusions that keep LAN, AirDrop/Bonjour (224.0.0.251), and link-local working.
    public func ipv4ExcludedRoutes() -> [(address: String, mask: String)] {
        var routes: [(String, String)] = []
        if excludePrivateNetworks {
            routes.append(contentsOf: [
                ("10.0.0.0", "255.0.0.0"),
                ("100.64.0.0", "255.192.0.0"),
                ("127.0.0.0", "255.0.0.0"),
                ("169.254.0.0", "255.255.0.0"),
                ("172.16.0.0", "255.240.0.0"),
                ("192.168.0.0", "255.255.0.0"),
            ])
        }
        if preserveMdnsBonjour {
            routes.append(("224.0.0.251", "255.255.255.255"))
        }
        return routes
    }

    public func ipv6ExcludedRoutes() -> [(address: String, prefix: Int)] {
        var routes: [(String, Int)] = []
        if excludePrivateNetworks {
            routes.append(contentsOf: [
                ("::1", 128),
                ("fc00::", 7),
                ("fe80::", 10),
            ])
        }
        if preserveMdnsBonjour {
            routes.append(("ff02::fb", 128))
        }
        return routes
    }
}

#if canImport(NetworkExtension)
public enum TunnelSettingsBuilder {
    /// Produces NEPacketTunnelNetworkSettings for macOS/iOS NEPacketTunnelProvider (Stage B).
    public static func build(from profile: AppleTunnelProfile) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.tunnelRemoteAddress)
        settings.mtu = NSNumber(value: profile.mtu)

        let v4 = NEIPv4Settings(addresses: [profile.ipv4Address], subnetMasks: [profile.ipv4SubnetMask])
        v4.includedRoutes = [NEIPv4Route.default()]
        v4.excludedRoutes = profile.ipv4ExcludedRoutes().map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask)
        }
        settings.ipv4Settings = v4

        let v6 = NEIPv6Settings(
            addresses: [profile.ipv6Address],
            networkPrefixLengths: [NSNumber(value: profile.ipv6PrefixLength)]
        )
        v6.includedRoutes = [NEIPv6Route.default()]
        v6.excludedRoutes = profile.ipv6ExcludedRoutes().map {
            NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix))
        }
        settings.ipv6Settings = v6

        let dns = NEDNSSettings(servers: profile.dnsServers)
        // Empty string captures all DNS domains into the tunnel and auto-restores on teardown.
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        return settings
    }
}
#endif
