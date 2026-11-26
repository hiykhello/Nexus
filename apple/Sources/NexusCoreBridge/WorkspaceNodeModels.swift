import Foundation

/// Canonical Layer 1 TLS settings matching `src/provider/workspace_types.cppm::WorkspaceTls`.
public struct WorkspaceTlsConfig: Codable, Sendable, Equatable {
    public var enabled: Bool
    public var sni: String
    public var fingerprint: String
    public var keyExchange: String
    public var caPem: String
    public var certSha256: [String]
    public var realityPublicKey: String
    public var realityShortId: String
    public var echMode: String
    public var echConfig: String
    public var echQueryServerName: String
    public var fragment: Bool
    public var recordFragment: Bool

    enum CodingKeys: String, CodingKey {
        case enabled, sni, fingerprint, fragment
        case keyExchange = "key_exchange"
        case caPem = "ca_pem"
        case certSha256 = "cert_sha256"
        case realityPublicKey = "reality_public_key"
        case realityShortId = "reality_short_id"
        case echMode = "ech_mode"
        case echConfig = "ech_config"
        case echQueryServerName = "ech_query_server_name"
        case recordFragment = "record_fragment"
    }

    public init(
        enabled: Bool = true,
        sni: String = "",
        fingerprint: String = "",
        keyExchange: String = "",
        caPem: String = "",
        certSha256: [String] = [],
        realityPublicKey: String = "",
        realityShortId: String = "",
        echMode: String = "",
        echConfig: String = "",
        echQueryServerName: String = "",
        fragment: Bool = false,
        recordFragment: Bool = false
    ) {
        self.enabled = enabled
        self.sni = sni
        self.fingerprint = fingerprint
        self.keyExchange = keyExchange
        self.caPem = caPem
        self.certSha256 = certSha256
        self.realityPublicKey = realityPublicKey
        self.realityShortId = realityShortId
        self.echMode = echMode
        self.echConfig = echConfig
        self.echQueryServerName = echQueryServerName
        self.fragment = fragment
        self.recordFragment = recordFragment
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        self.sni = try c.decodeIfPresent(String.self, forKey: .sni) ?? ""
        self.fingerprint = try c.decodeIfPresent(String.self, forKey: .fingerprint) ?? ""
        self.keyExchange = try c.decodeIfPresent(String.self, forKey: .keyExchange) ?? ""
        self.caPem = try c.decodeIfPresent(String.self, forKey: .caPem) ?? ""
        self.certSha256 = try c.decodeIfPresent([String].self, forKey: .certSha256) ?? []
        self.realityPublicKey = try c.decodeIfPresent(String.self, forKey: .realityPublicKey) ?? ""
        self.realityShortId = try c.decodeIfPresent(String.self, forKey: .realityShortId) ?? ""
        self.echMode = try c.decodeIfPresent(String.self, forKey: .echMode) ?? ""
        self.echConfig = try c.decodeIfPresent(String.self, forKey: .echConfig) ?? ""
        self.echQueryServerName = try c.decodeIfPresent(String.self, forKey: .echQueryServerName) ?? ""
        self.fragment = try c.decodeIfPresent(Bool.self, forKey: .fragment) ?? false
        self.recordFragment = try c.decodeIfPresent(Bool.self, forKey: .recordFragment) ?? false
    }
}

/// Canonical Layer 1 transport settings; normalizes `"tcp"` and `"raw"` to `""`.
public struct WorkspaceTransportConfig: Codable, Sendable, Equatable {
    public var type: String
    public var host: String
    public var path: String
    public var serviceName: String
    public var authority: String
    public var xhttpMode: String
    public var xhttpProtocol: String
    public var headers: [String: String]
    public var maxEarlyData: Int
    public var earlyDataHeaderName: String
    public var grpcIdleTimeoutMs: Int
    public var grpcPingTimeoutMs: Int
    public var grpcPermitWithoutStream: Bool

    enum CodingKeys: String, CodingKey {
        case type, host, path, authority, headers
        case serviceName = "service_name"
        case xhttpMode = "xhttp_mode"
        case xhttpProtocol = "xhttp_protocol"
        case maxEarlyData = "max_early_data"
        case earlyDataHeaderName = "early_data_header_name"
        case grpcIdleTimeoutMs = "grpc_idle_timeout_ms"
        case grpcPingTimeoutMs = "grpc_ping_timeout_ms"
        case grpcPermitWithoutStream = "grpc_permit_without_stream"
    }

    public static func normalizeType(_ raw: String) -> String {
        let lower = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return (lower == "tcp" || lower == "raw" || lower == "none") ? "" : lower
    }

    public init(
        type: String = "",
        host: String = "",
        path: String = "",
        serviceName: String = "",
        authority: String = "",
        xhttpMode: String = "",
        xhttpProtocol: String = "",
        headers: [String: String] = [:],
        maxEarlyData: Int = 0,
        earlyDataHeaderName: String = "",
        grpcIdleTimeoutMs: Int = 0,
        grpcPingTimeoutMs: Int = 0,
        grpcPermitWithoutStream: Bool = false
    ) {
        self.type = Self.normalizeType(type)
        self.host = host
        self.path = path
        self.serviceName = serviceName
        self.authority = authority
        self.xhttpMode = xhttpMode
        self.xhttpProtocol = xhttpProtocol
        self.headers = headers
        self.maxEarlyData = max(0, min(8192, maxEarlyData))
        self.earlyDataHeaderName = earlyDataHeaderName
        self.grpcIdleTimeoutMs = max(0, grpcIdleTimeoutMs)
        self.grpcPingTimeoutMs = max(0, grpcPingTimeoutMs)
        self.grpcPermitWithoutStream = grpcPermitWithoutStream
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.type = Self.normalizeType(try c.decodeIfPresent(String.self, forKey: .type) ?? "")
        self.host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        self.path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
        self.serviceName = try c.decodeIfPresent(String.self, forKey: .serviceName) ?? ""
        self.authority = try c.decodeIfPresent(String.self, forKey: .authority) ?? ""
        self.xhttpMode = try c.decodeIfPresent(String.self, forKey: .xhttpMode) ?? ""
        self.xhttpProtocol = try c.decodeIfPresent(String.self, forKey: .xhttpProtocol) ?? ""
        self.headers = try c.decodeIfPresent([String: String].self, forKey: .headers) ?? [:]
        self.maxEarlyData = max(0, min(8192, try c.decodeIfPresent(Int.self, forKey: .maxEarlyData) ?? 0))
        self.earlyDataHeaderName = try c.decodeIfPresent(String.self, forKey: .earlyDataHeaderName) ?? ""
        self.grpcIdleTimeoutMs = max(0, try c.decodeIfPresent(Int.self, forKey: .grpcIdleTimeoutMs) ?? 0)
        self.grpcPingTimeoutMs = max(0, try c.decodeIfPresent(Int.self, forKey: .grpcPingTimeoutMs) ?? 0)
        self.grpcPermitWithoutStream = try c.decodeIfPresent(Bool.self, forKey: .grpcPermitWithoutStream) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Self.normalizeType(type), forKey: .type)
        try c.encode(host, forKey: .host)
        try c.encode(path, forKey: .path)
        try c.encode(serviceName, forKey: .serviceName)
        try c.encode(authority, forKey: .authority)
        try c.encode(xhttpMode, forKey: .xhttpMode)
        try c.encode(xhttpProtocol, forKey: .xhttpProtocol)
        try c.encode(headers, forKey: .headers)
        if maxEarlyData > 0 { try c.encode(maxEarlyData, forKey: .maxEarlyData) }
        if !earlyDataHeaderName.isEmpty { try c.encode(earlyDataHeaderName, forKey: .earlyDataHeaderName) }
        if grpcIdleTimeoutMs > 0 { try c.encode(grpcIdleTimeoutMs, forKey: .grpcIdleTimeoutMs) }
        if grpcPingTimeoutMs > 0 { try c.encode(grpcPingTimeoutMs, forKey: .grpcPingTimeoutMs) }
        if grpcPermitWithoutStream { try c.encode(grpcPermitWithoutStream, forKey: .grpcPermitWithoutStream) }
    }
}

public struct WorkspaceMultiplexConfig: Codable, Sendable, Equatable {
    public var enabled: Bool
    public var protocolName: String
    public var maxConnections: Int
    public var padding: Bool

    enum CodingKeys: String, CodingKey {
        case enabled
        case protocolName = "protocol"
        case maxConnections = "max_connections"
        case padding
    }

    public init(
        enabled: Bool = false,
        protocolName: String = "",
        maxConnections: Int = 0,
        padding: Bool = false
    ) {
        self.enabled = enabled
        self.protocolName = protocolName
        self.maxConnections = maxConnections
        self.padding = padding
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        self.protocolName = try c.decodeIfPresent(String.self, forKey: .protocolName) ?? ""
        self.maxConnections = try c.decodeIfPresent(Int.self, forKey: .maxConnections) ?? 0
        self.padding = try c.decodeIfPresent(Bool.self, forKey: .padding) ?? false
    }
}

public struct WorkspaceNodeExtraConfig: Codable, Sendable, Equatable {
    public var hy2Ports: String
    public var hy2HopIntervalMs: Int
    public var hy2UpMbps: Int
    public var hy2DownMbps: Int
    public var hy2SalamanderPassword: String
    public var tuicCongestionControl: String
    public var tuicUdpOverStream: Bool
    public var wgPeerPublicKey: String
    public var wgPresharedKey: String
    public var wgLocalAddresses: [String]
    public var wgReserved: String
    public var wgMtu: Int
    public var masqueMode: String
    public var masquePath: String
    public var masqueLocalAddresses: [String]
    public var naiveProtocol: String
    public var snellVersion: Int
    public var snellObfs: String
    public var snellObfsHost: String
    public var sshHostKeySha256: [String]

    enum CodingKeys: String, CodingKey {
        case hy2Ports = "hy2_ports"
        case hy2HopIntervalMs = "hy2_hop_interval_ms"
        case hy2UpMbps = "hy2_up_mbps"
        case hy2DownMbps = "hy2_down_mbps"
        case hy2SalamanderPassword = "hy2_salamander_password"
        case tuicCongestionControl = "tuic_congestion_control"
        case tuicUdpOverStream = "tuic_udp_over_stream"
        case wgPeerPublicKey = "wg_peer_public_key"
        case wgPresharedKey = "wg_preshared_key"
        case wgLocalAddresses = "wg_local_addresses"
        case wgReserved = "wg_reserved"
        case wgMtu = "wg_mtu"
        case masqueMode = "masque_mode"
        case masquePath = "masque_path"
        case masqueLocalAddresses = "masque_local_addresses"
        case naiveProtocol = "naive_protocol"
        case snellVersion = "snell_version"
        case snellObfs = "snell_obfs"
        case snellObfsHost = "snell_obfs_host"
        case sshHostKeySha256 = "ssh_host_key_sha256"
    }

    public init(
        hy2Ports: String = "",
        hy2HopIntervalMs: Int = 0,
        hy2UpMbps: Int = 0,
        hy2DownMbps: Int = 0,
        hy2SalamanderPassword: String = "",
        tuicCongestionControl: String = "",
        tuicUdpOverStream: Bool = false,
        wgPeerPublicKey: String = "",
        wgPresharedKey: String = "",
        wgLocalAddresses: [String] = [],
        wgReserved: String = "",
        wgMtu: Int = 0,
        masqueMode: String = "",
        masquePath: String = "",
        masqueLocalAddresses: [String] = [],
        naiveProtocol: String = "",
        snellVersion: Int = 0,
        snellObfs: String = "",
        snellObfsHost: String = "",
        sshHostKeySha256: [String] = []
    ) {
        self.hy2Ports = hy2Ports
        self.hy2HopIntervalMs = hy2HopIntervalMs
        self.hy2UpMbps = hy2UpMbps
        self.hy2DownMbps = hy2DownMbps
        self.hy2SalamanderPassword = hy2SalamanderPassword
        self.tuicCongestionControl = tuicCongestionControl
        self.tuicUdpOverStream = tuicUdpOverStream
        self.wgPeerPublicKey = wgPeerPublicKey
        self.wgPresharedKey = wgPresharedKey
        self.wgLocalAddresses = wgLocalAddresses
        self.wgReserved = wgReserved
        self.wgMtu = wgMtu
        self.masqueMode = masqueMode
        self.masquePath = masquePath
        self.masqueLocalAddresses = masqueLocalAddresses
        self.naiveProtocol = naiveProtocol
        self.snellVersion = snellVersion
        self.snellObfs = snellObfs
        self.snellObfsHost = snellObfsHost
        self.sshHostKeySha256 = sshHostKeySha256
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.hy2Ports = try c.decodeIfPresent(String.self, forKey: .hy2Ports) ?? ""
        self.hy2HopIntervalMs = try c.decodeIfPresent(Int.self, forKey: .hy2HopIntervalMs) ?? 0
        self.hy2UpMbps = try c.decodeIfPresent(Int.self, forKey: .hy2UpMbps) ?? 0
        self.hy2DownMbps = try c.decodeIfPresent(Int.self, forKey: .hy2DownMbps) ?? 0
        self.hy2SalamanderPassword = try c.decodeIfPresent(String.self, forKey: .hy2SalamanderPassword) ?? ""
        self.tuicCongestionControl = try c.decodeIfPresent(String.self, forKey: .tuicCongestionControl) ?? ""
        self.tuicUdpOverStream = try c.decodeIfPresent(Bool.self, forKey: .tuicUdpOverStream) ?? false
        self.wgPeerPublicKey = try c.decodeIfPresent(String.self, forKey: .wgPeerPublicKey) ?? ""
        self.wgPresharedKey = try c.decodeIfPresent(String.self, forKey: .wgPresharedKey) ?? ""
        self.wgLocalAddresses = try c.decodeIfPresent([String].self, forKey: .wgLocalAddresses) ?? []
        self.wgReserved = try c.decodeIfPresent(String.self, forKey: .wgReserved) ?? ""
        self.wgMtu = try c.decodeIfPresent(Int.self, forKey: .wgMtu) ?? 0
        self.masqueMode = try c.decodeIfPresent(String.self, forKey: .masqueMode) ?? ""
        self.masquePath = try c.decodeIfPresent(String.self, forKey: .masquePath) ?? ""
        self.masqueLocalAddresses = try c.decodeIfPresent([String].self, forKey: .masqueLocalAddresses) ?? []
        self.naiveProtocol = try c.decodeIfPresent(String.self, forKey: .naiveProtocol) ?? ""
        self.snellVersion = try c.decodeIfPresent(Int.self, forKey: .snellVersion) ?? 0
        self.snellObfs = try c.decodeIfPresent(String.self, forKey: .snellObfs) ?? ""
        self.snellObfsHost = try c.decodeIfPresent(String.self, forKey: .snellObfsHost) ?? ""
        self.sshHostKeySha256 = try c.decodeIfPresent([String].self, forKey: .sshHostKeySha256) ?? []
    }
}

public struct WorkspaceNodeConfig: Codable, Sendable, Equatable {
    public var protocolName: String
    public var server: String
    public var port: Int
    public var username: String
    public var password: String
    public var method: String
    public var flow: String
    public var packetEncoding: String
    public var tls: WorkspaceTlsConfig
    public var transport: WorkspaceTransportConfig
    public var multiplex: WorkspaceMultiplexConfig
    public var extra: WorkspaceNodeExtraConfig

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case server
        case port
        case username
        case password
        case method
        case flow
        case packetEncoding = "packet_encoding"
        case tls
        case transport
        case multiplex
        case extra
    }

    public init(
        protocolName: String = "vless",
        server: String = "",
        port: Int = 443,
        username: String = "",
        password: String = "",
        method: String = "",
        flow: String = "",
        packetEncoding: String = "",
        tls: WorkspaceTlsConfig = WorkspaceTlsConfig(),
        transport: WorkspaceTransportConfig = WorkspaceTransportConfig(),
        multiplex: WorkspaceMultiplexConfig = WorkspaceMultiplexConfig(),
        extra: WorkspaceNodeExtraConfig = WorkspaceNodeExtraConfig()
    ) {
        self.protocolName = protocolName
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.method = method
        self.flow = flow
        self.packetEncoding = packetEncoding
        self.tls = tls
        self.transport = transport
        self.multiplex = multiplex
        self.extra = extra
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.protocolName = try c.decodeIfPresent(String.self, forKey: .protocolName) ?? "vless"
        self.server = try c.decodeIfPresent(String.self, forKey: .server) ?? ""
        self.port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 443
        self.username = try c.decodeIfPresent(String.self, forKey: .username) ?? ""
        self.password = try c.decodeIfPresent(String.self, forKey: .password) ?? ""
        self.method = try c.decodeIfPresent(String.self, forKey: .method) ?? ""
        self.flow = try c.decodeIfPresent(String.self, forKey: .flow) ?? ""
        self.packetEncoding = try c.decodeIfPresent(String.self, forKey: .packetEncoding) ?? ""
        self.tls = try c.decodeIfPresent(WorkspaceTlsConfig.self, forKey: .tls) ?? WorkspaceTlsConfig()
        self.transport = try c.decodeIfPresent(WorkspaceTransportConfig.self, forKey: .transport) ?? WorkspaceTransportConfig()
        self.multiplex = try c.decodeIfPresent(WorkspaceMultiplexConfig.self, forKey: .multiplex) ?? WorkspaceMultiplexConfig()
        self.extra = try c.decodeIfPresent(WorkspaceNodeExtraConfig.self, forKey: .extra) ?? WorkspaceNodeExtraConfig()
    }
}

public struct WorkspacePolicyGroupConfig: Codable, Sendable, Equatable {
    public var strategy: String
    public var memberIds: [String]
    public var dynamicSubId: String
    public var includeRegex: String
    public var excludeRegex: String
    public var probeUrl: String
    public var probeIntervalMs: Int64
    public var toleranceMs: Int
    public var interruptExistConnections: Bool

    enum CodingKeys: String, CodingKey {
        case strategy
        case memberIds = "member_ids"
        case dynamicSubId = "dynamic_sub_id"
        case includeRegex = "include_regex"
        case excludeRegex = "exclude_regex"
        case probeUrl = "probe_url"
        case probeIntervalMs = "probe_interval_ms"
        case toleranceMs = "tolerance_ms"
        case interruptExistConnections = "interrupt_exist_connections"
    }

    public init(
        strategy: String = "selector",
        memberIds: [String] = [],
        dynamicSubId: String = "",
        includeRegex: String = "",
        excludeRegex: String = "",
        probeUrl: String = "https://www.gstatic.com/generate_204",
        probeIntervalMs: Int64 = 300_000,
        toleranceMs: Int = 50,
        interruptExistConnections: Bool = false
    ) {
        self.strategy = strategy
        self.memberIds = memberIds
        self.dynamicSubId = dynamicSubId
        self.includeRegex = includeRegex
        self.excludeRegex = excludeRegex
        self.probeUrl = probeUrl
        self.probeIntervalMs = probeIntervalMs
        self.toleranceMs = toleranceMs
        self.interruptExistConnections = interruptExistConnections
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.strategy = try c.decodeIfPresent(String.self, forKey: .strategy) ?? "selector"
        self.memberIds = try c.decodeIfPresent([String].self, forKey: .memberIds) ?? []
        self.dynamicSubId = try c.decodeIfPresent(String.self, forKey: .dynamicSubId) ?? ""
        self.includeRegex = try c.decodeIfPresent(String.self, forKey: .includeRegex) ?? ""
        self.excludeRegex = try c.decodeIfPresent(String.self, forKey: .excludeRegex) ?? ""
        self.probeUrl = try c.decodeIfPresent(String.self, forKey: .probeUrl) ?? "https://www.gstatic.com/generate_204"
        self.probeIntervalMs = try c.decodeIfPresent(Int64.self, forKey: .probeIntervalMs) ?? 300_000
        self.toleranceMs = try c.decodeIfPresent(Int.self, forKey: .toleranceMs) ?? 50
        self.interruptExistConnections = try c.decodeIfPresent(Bool.self, forKey: .interruptExistConnections) ?? false
    }
}

public struct WorkspaceProxyChainConfig: Codable, Sendable, Equatable {
    public var hopIds: [String]

    enum CodingKeys: String, CodingKey {
        case hopIds = "hop_ids"
    }

    public init(hopIds: [String] = []) {
        self.hopIds = hopIds
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.hopIds = try c.decodeIfPresent([String].self, forKey: .hopIds) ?? []
    }
}
