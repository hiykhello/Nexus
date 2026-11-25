import Foundation

public struct WorkspaceRoutingRule: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var enabled: Bool
    public var locked: Bool
    public var scope: String
    public var targetType: String
    public var targetProfileId: String
    public var domains: [String]
    public var ips: [String]
    public var ruleSets: [String]
    public var ports: [String]
    public var networks: [String]
    public var protocols: [String]
    public var desktopProcess: [String]
    public var androidPackages: [String]
    public var tlsFragment: Bool

    enum CodingKeys: String, CodingKey {
        case id, enabled, locked, scope, domains, ips, ports, networks, protocols
        case targetType = "target_type"
        case targetProfileId = "target_profile_id"
        case ruleSets = "rule_sets"
        case desktopProcess = "desktop_process"
        case androidPackages = "android_packages"
        case tlsFragment = "tls_fragment"
    }

    public init(
        id: String,
        enabled: Bool = true,
        locked: Bool = false,
        scope: String = "both",
        targetType: String = "proxy",
        targetProfileId: String = "",
        domains: [String] = [],
        ips: [String] = [],
        ruleSets: [String] = [],
        ports: [String] = [],
        networks: [String] = [],
        protocols: [String] = [],
        desktopProcess: [String] = [],
        androidPackages: [String] = [],
        tlsFragment: Bool = false
    ) {
        self.id = id
        self.enabled = enabled
        self.locked = locked
        self.scope = scope
        self.targetType = targetType
        self.targetProfileId = targetProfileId
        self.domains = domains
        self.ips = ips
        self.ruleSets = ruleSets
        self.ports = ports
        self.networks = networks
        self.protocols = protocols
        self.desktopProcess = desktopProcess
        self.androidPackages = androidPackages
        self.tlsFragment = tlsFragment
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        self.locked = try c.decodeIfPresent(Bool.self, forKey: .locked) ?? false
        self.scope = try c.decodeIfPresent(String.self, forKey: .scope) ?? "both"
        self.targetType = try c.decodeIfPresent(String.self, forKey: .targetType) ?? "proxy"
        self.targetProfileId = try c.decodeIfPresent(String.self, forKey: .targetProfileId) ?? ""
        self.domains = try c.decodeIfPresent([String].self, forKey: .domains) ?? []
        self.ips = try c.decodeIfPresent([String].self, forKey: .ips) ?? []
        self.ruleSets = try c.decodeIfPresent([String].self, forKey: .ruleSets) ?? []
        self.ports = try c.decodeIfPresent([String].self, forKey: .ports) ?? []
        self.networks = try c.decodeIfPresent([String].self, forKey: .networks) ?? []
        self.protocols = try c.decodeIfPresent([String].self, forKey: .protocols) ?? []
        self.desktopProcess = try c.decodeIfPresent([String].self, forKey: .desktopProcess) ?? []
        self.androidPackages = try c.decodeIfPresent([String].self, forKey: .androidPackages) ?? []
        self.tlsFragment = try c.decodeIfPresent(Bool.self, forKey: .tlsFragment) ?? false
    }
}

public struct WorkspaceRoutingProfile: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var isActive: Bool
    public var domainStrategy: String
    public var defaultOutbound: String
    public var rules: [WorkspaceRoutingRule]

    enum CodingKeys: String, CodingKey {
        case id, name, rules
        case isActive = "is_active"
        case domainStrategy = "domain_strategy"
        case defaultOutbound = "default_outbound"
    }

    public init(
        id: String,
        name: String,
        isActive: Bool = false,
        domainStrategy: String = "as-is",
        defaultOutbound: String = "proxy",
        rules: [WorkspaceRoutingRule] = []
    ) {
        self.id = id
        self.name = name
        self.isActive = isActive
        self.domainStrategy = domainStrategy
        self.defaultOutbound = defaultOutbound
        self.rules = rules
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decodeIfPresent(String.self, forKey: .id) ?? "default"
        self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? "Default"
        self.isActive = try c.decodeIfPresent(Bool.self, forKey: .isActive) ?? false
        self.domainStrategy = try c.decodeIfPresent(String.self, forKey: .domainStrategy) ?? "as-is"
        self.defaultOutbound = try c.decodeIfPresent(String.self, forKey: .defaultOutbound) ?? "proxy"
        self.rules = try c.decodeIfPresent([WorkspaceRoutingRule].self, forKey: .rules) ?? []
    }
}

private enum FlexibleDnsHostValue: Decodable {
    case single(String)
    case list([String])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) {
            self = .single(s)
        } else if let arr = try? c.decode([String].self) {
            self = .list(arr)
        } else {
            self = .single("")
        }
    }

    var primaryAddress: String {
        switch self {
        case .single(let s): return s.trimmingCharacters(in: .whitespacesAndNewlines)
        case .list(let arr): return arr.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        }
    }
}

public struct WorkspaceSimpleDnsConfig: Codable, Sendable, Equatable {
    public var bootstrapDns: String
    public var directDns: [String]
    public var remoteDns: [String]
    public var parallelQuery: Bool
    public var directExpectedRuleSets: [String]
    public var fakeIpEnabled: Bool
    public var fakeIpV4Pool: String
    public var fakeIpV6Pool: String
    public var fakeIpGlobal: Bool
    public var blockAaaa: Bool
    public var blockSvcbHttps: Bool
    public var serveStaleSeconds: Int
    public var useSystemHosts: Bool
    public var hosts: [String: String]
    public var strategy: String

    enum CodingKeys: String, CodingKey {
        case hosts, strategy
        case bootstrapDns = "bootstrap_dns"
        case directDns = "direct_dns"
        case remoteDns = "remote_dns"
        case parallelQuery = "parallel_query"
        case directExpectedRuleSets = "direct_expected_rule_sets"
        case fakeIpEnabled = "fake_ip_enabled"
        case fakeIpV4Pool = "fake_ip_v4_pool"
        case fakeIpV6Pool = "fake_ip_v6_pool"
        case fakeIpGlobal = "fake_ip_global"
        case blockAaaa = "block_aaaa"
        case blockSvcbHttps = "block_svcb_https"
        case serveStaleSeconds = "serve_stale_seconds"
        case useSystemHosts = "use_system_hosts"
    }

    public init(
        bootstrapDns: String = "223.5.5.5",
        directDns: [String] = ["local", "223.5.5.5"],
        remoteDns: [String] = ["https://1.1.1.1/dns-query"],
        parallelQuery: Bool = false,
        directExpectedRuleSets: [String] = [],
        fakeIpEnabled: Bool = false,
        fakeIpV4Pool: String = "198.18.0.0/16",
        fakeIpV6Pool: String = "fc00::/18",
        fakeIpGlobal: Bool = false,
        blockAaaa: Bool = false,
        blockSvcbHttps: Bool = false,
        serveStaleSeconds: Int = 0,
        useSystemHosts: Bool = true,
        hosts: [String: String] = [:],
        strategy: String = "prefer_ipv4"
    ) {
        self.bootstrapDns = bootstrapDns
        self.directDns = directDns
        self.remoteDns = remoteDns
        self.parallelQuery = parallelQuery
        self.directExpectedRuleSets = directExpectedRuleSets
        self.fakeIpEnabled = fakeIpEnabled
        self.fakeIpV4Pool = fakeIpV4Pool
        self.fakeIpV6Pool = fakeIpV6Pool
        self.fakeIpGlobal = fakeIpGlobal
        self.blockAaaa = blockAaaa
        self.blockSvcbHttps = blockSvcbHttps
        self.serveStaleSeconds = serveStaleSeconds
        self.useSystemHosts = useSystemHosts
        self.hosts = hosts
        self.strategy = strategy
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.bootstrapDns = try c.decodeIfPresent(String.self, forKey: .bootstrapDns) ?? "223.5.5.5"
        let direct = try c.decodeIfPresent([String].self, forKey: .directDns) ?? []
        self.directDns = direct.isEmpty ? ["local", "223.5.5.5"] : direct
        let remote = try c.decodeIfPresent([String].self, forKey: .remoteDns) ?? []
        self.remoteDns = remote.isEmpty ? ["https://1.1.1.1/dns-query"] : remote
        self.parallelQuery = try c.decodeIfPresent(Bool.self, forKey: .parallelQuery) ?? false
        self.directExpectedRuleSets = try c.decodeIfPresent([String].self, forKey: .directExpectedRuleSets) ?? []
        self.fakeIpEnabled = try c.decodeIfPresent(Bool.self, forKey: .fakeIpEnabled) ?? false
        self.fakeIpV4Pool = try c.decodeIfPresent(String.self, forKey: .fakeIpV4Pool) ?? "198.18.0.0/16"
        self.fakeIpV6Pool = try c.decodeIfPresent(String.self, forKey: .fakeIpV6Pool) ?? "fc00::/18"
        self.fakeIpGlobal = try c.decodeIfPresent(Bool.self, forKey: .fakeIpGlobal) ?? false
        self.blockAaaa = try c.decodeIfPresent(Bool.self, forKey: .blockAaaa) ?? false
        self.blockSvcbHttps = try c.decodeIfPresent(Bool.self, forKey: .blockSvcbHttps) ?? false
        self.serveStaleSeconds = try c.decodeIfPresent(Int.self, forKey: .serveStaleSeconds) ?? 0
        self.useSystemHosts = try c.decodeIfPresent(Bool.self, forKey: .useSystemHosts) ?? true
        let rawHosts = try c.decodeIfPresent([String: FlexibleDnsHostValue].self, forKey: .hosts) ?? [:]
        var resolved: [String: String] = [:]
        for (host, val) in rawHosts {
            let trimmedKey = host.trimmingCharacters(in: .whitespacesAndNewlines)
            let addr = val.primaryAddress
            if !trimmedKey.isEmpty && !addr.isEmpty { resolved[trimmedKey] = addr }
        }
        self.hosts = resolved
        self.strategy = try c.decodeIfPresent(String.self, forKey: .strategy) ?? "prefer_ipv4"
    }
}

public struct WorkspaceDnsConfig: Codable, Sendable, Equatable {
    public var mode: String
    public var simple: WorkspaceSimpleDnsConfig
    public var rawKdl: String

    enum CodingKeys: String, CodingKey {
        case mode, simple
        case rawKdl = "raw_kdl"
    }

    public init(mode: String = "simple", simple: WorkspaceSimpleDnsConfig = WorkspaceSimpleDnsConfig(), rawKdl: String = "") {
        self.mode = mode
        self.simple = simple
        self.rawKdl = rawKdl
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? "simple"
        self.simple = try c.decodeIfPresent(WorkspaceSimpleDnsConfig.self, forKey: .simple) ?? WorkspaceSimpleDnsConfig()
        self.rawKdl = try c.decodeIfPresent(String.self, forKey: .rawKdl) ?? ""
    }
}

public struct WorkspaceRuleSetAsset: Codable, Sendable, Equatable {
    public var tag: String
    public var sourceType: String
    public var format: String
    public var path: String
    public var url: String
    public var sha256: String
    public var updateIntervalMs: Int64

    enum CodingKeys: String, CodingKey {
        case tag, format, path, url, sha256
        case sourceType = "source_type"
        case updateIntervalMs = "update_interval_ms"
    }

    public init(
        tag: String,
        sourceType: String = "local",
        format: String = "nxmm",
        path: String = "",
        url: String = "",
        sha256: String = "",
        updateIntervalMs: Int64 = 3_600_000
    ) {
        self.tag = tag
        self.sourceType = sourceType
        self.format = format
        self.path = path
        self.url = url
        self.sha256 = sha256
        self.updateIntervalMs = updateIntervalMs
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.tag = try c.decodeIfPresent(String.self, forKey: .tag) ?? ""
        self.sourceType = try c.decodeIfPresent(String.self, forKey: .sourceType) ?? "local"
        self.format = try c.decodeIfPresent(String.self, forKey: .format) ?? "nxmm"
        self.path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
        self.url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        self.sha256 = try c.decodeIfPresent(String.self, forKey: .sha256) ?? ""
        self.updateIntervalMs = try c.decodeIfPresent(Int64.self, forKey: .updateIntervalMs) ?? 0
    }
}

public struct WorkspaceFullTemplateConfig: Codable, Sendable, Equatable {
    public var enabled: Bool
    public var templateKdl: String
    public var appendProxiesOnly: Bool
    public var proxyDetour: String

    enum CodingKeys: String, CodingKey {
        case enabled
        case templateKdl = "template_kdl"
        case appendProxiesOnly = "append_proxies_only"
        case proxyDetour = "proxy_detour"
    }

    public init(enabled: Bool = false, templateKdl: String = "", appendProxiesOnly: Bool = false, proxyDetour: String = "") {
        self.enabled = enabled
        self.templateKdl = templateKdl
        self.appendProxiesOnly = appendProxiesOnly
        self.proxyDetour = proxyDetour
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        self.templateKdl = try c.decodeIfPresent(String.self, forKey: .templateKdl) ?? ""
        self.appendProxiesOnly = try c.decodeIfPresent(Bool.self, forKey: .appendProxiesOnly) ?? false
        self.proxyDetour = try c.decodeIfPresent(String.self, forKey: .proxyDetour) ?? ""
    }
}
