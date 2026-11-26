import Foundation

public enum WorkspaceSchemaError: Error, LocalizedError, Equatable, Sendable {
    case unsupportedSchemaVersion(Int)
    case invalidJSON

    public var errorDescription: String? {
        switch self {
        case .unsupportedSchemaVersion(let v): return "Unsupported workspace schema_version: \(v)"
        case .invalidJSON: return "Invalid UTF-8 JSON workspace payload"
        }
    }
}

/// Polymorphic 5-kind profile discriminator matching canonical Layer 1 `workspace.json` v1.
public enum WorkspaceProfileKind: String, Codable, Sendable, Equatable, Hashable, CaseIterable {
    case node = "node"
    case customOutbound = "custom_outbound"
    case policyGroup = "policy_group"
    case proxyChain = "proxy_chain"
    case fullCustomKdl = "full_custom_kdl"

    public static func fromWire(_ raw: String) -> WorkspaceProfileKind {
        WorkspaceProfileKind(rawValue: raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) ?? .node
    }

    public var badgeTitle: String {
        switch self {
        case .node: return "节点"
        case .customOutbound: return "自定义出站"
        case .policyGroup: return "策略组"
        case .proxyChain: return "代理链"
        case .fullCustomKdl: return "高级自定义配置"
        }
    }
}

public struct WorkspaceProfileItem: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var remarks: String
    public var subscriptionId: String
    public var isFromSub: Bool
    public var kind: WorkspaceProfileKind
    public var node: WorkspaceNodeConfig?
    public var customOutboundKdl: String
    public var policyGroup: WorkspacePolicyGroupConfig?
    public var proxyChain: WorkspaceProxyChainConfig?
    public var fullCustomKdl: String

    enum CodingKeys: String, CodingKey {
        case id, remarks, kind, node
        case subscriptionId = "subscription_id"
        case isFromSub = "is_from_sub"
        case customOutboundKdl = "custom_outbound_kdl"
        case policyGroup = "policy_group"
        case proxyChain = "proxy_chain"
        case fullCustomKdl = "full_custom_kdl"
    }

    public init(
        id: String,
        remarks: String = "",
        subscriptionId: String = "",
        isFromSub: Bool = false,
        kind: WorkspaceProfileKind = .node,
        node: WorkspaceNodeConfig? = nil,
        customOutboundKdl: String = "",
        policyGroup: WorkspacePolicyGroupConfig? = nil,
        proxyChain: WorkspaceProxyChainConfig? = nil,
        fullCustomKdl: String = ""
    ) {
        self.id = id
        self.remarks = remarks
        self.subscriptionId = subscriptionId
        self.isFromSub = isFromSub
        self.kind = kind
        self.node = node
        self.customOutboundKdl = customOutboundKdl
        self.policyGroup = policyGroup
        self.proxyChain = proxyChain
        self.fullCustomKdl = fullCustomKdl
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = (try c.decodeIfPresent(String.self, forKey: .id) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        self.remarks = try c.decodeIfPresent(String.self, forKey: .remarks) ?? ""
        self.subscriptionId = try c.decodeIfPresent(String.self, forKey: .subscriptionId) ?? ""
        self.isFromSub = try c.decodeIfPresent(Bool.self, forKey: .isFromSub) ?? false
        let rawKind = try c.decodeIfPresent(String.self, forKey: .kind) ?? WorkspaceProfileKind.node.rawValue
        self.kind = WorkspaceProfileKind.fromWire(rawKind)
        self.node = try c.decodeIfPresent(WorkspaceNodeConfig.self, forKey: .node)
        self.customOutboundKdl = try c.decodeIfPresent(String.self, forKey: .customOutboundKdl) ?? ""
        self.policyGroup = try c.decodeIfPresent(WorkspacePolicyGroupConfig.self, forKey: .policyGroup)
        self.proxyChain = try c.decodeIfPresent(WorkspaceProxyChainConfig.self, forKey: .proxyChain)
        self.fullCustomKdl = try c.decodeIfPresent(String.self, forKey: .fullCustomKdl) ?? ""
    }
}

public struct WorkspaceSubscriptionUsage: Codable, Sendable, Equatable {
    public var uploadBytes: Int64
    public var downloadBytes: Int64
    public var totalBytes: Int64
    public var expireUnixSec: Int64
    public var profileTitle: String
    public var webPageUrl: String
    public var supportUrl: String

    enum CodingKeys: String, CodingKey {
        case uploadBytes = "upload_bytes"
        case downloadBytes = "download_bytes"
        case totalBytes = "total_bytes"
        case expireUnixSec = "expire_unix_sec"
        case profileTitle = "profile_title"
        case webPageUrl = "web_page_url"
        case supportUrl = "support_url"
    }

    public init(
        uploadBytes: Int64 = -1,
        downloadBytes: Int64 = -1,
        totalBytes: Int64 = -1,
        expireUnixSec: Int64 = -1,
        profileTitle: String = "",
        webPageUrl: String = "",
        supportUrl: String = ""
    ) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.totalBytes = totalBytes
        self.expireUnixSec = expireUnixSec
        self.profileTitle = profileTitle
        self.webPageUrl = webPageUrl
        self.supportUrl = supportUrl
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.uploadBytes = try c.decodeIfPresent(Int64.self, forKey: .uploadBytes) ?? -1
        self.downloadBytes = try c.decodeIfPresent(Int64.self, forKey: .downloadBytes) ?? -1
        self.totalBytes = try c.decodeIfPresent(Int64.self, forKey: .totalBytes) ?? -1
        self.expireUnixSec = try c.decodeIfPresent(Int64.self, forKey: .expireUnixSec) ?? -1
        self.profileTitle = try c.decodeIfPresent(String.self, forKey: .profileTitle) ?? ""
        self.webPageUrl = SubscriptionInfoParser.sanitizeSafeURL(try c.decodeIfPresent(String.self, forKey: .webPageUrl) ?? "")
        self.supportUrl = SubscriptionInfoParser.sanitizeSafeURL(try c.decodeIfPresent(String.self, forKey: .supportUrl) ?? "")
    }

    public var hasQuota: Bool { totalBytes > 0 }
    public var usedBytes: Int64 { max(0, uploadBytes) + max(0, downloadBytes) }
}

public struct WorkspaceSubscriptionItem: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var remarks: String
    public var url: String
    public var moreUrls: [String]
    public var enabled: Bool
    public var autoUpdateMinutes: Int
    public var userAgent: String
    public var requestHeaders: [String: String]
    public var includeRegex: String
    public var excludeRegex: String
    public var prevProfileId: String
    public var nextProfileId: String
    public var updatedAtMs: Int64
    public var usage: WorkspaceSubscriptionUsage

    enum CodingKeys: String, CodingKey {
        case id, remarks, url, enabled, usage
        case moreUrls = "more_urls"
        case autoUpdateMinutes = "auto_update_minutes"
        case userAgent = "user_agent"
        case requestHeaders = "request_headers"
        case includeRegex = "include_regex"
        case excludeRegex = "exclude_regex"
        case prevProfileId = "prev_profile_id"
        case nextProfileId = "next_profile_id"
        case updatedAtMs = "updated_at_ms"
    }

    public init(
        id: String,
        remarks: String = "",
        url: String = "",
        moreUrls: [String] = [],
        enabled: Bool = true,
        autoUpdateMinutes: Int = 0,
        userAgent: String = "",
        requestHeaders: [String: String] = [:],
        includeRegex: String = "",
        excludeRegex: String = "",
        prevProfileId: String = "",
        nextProfileId: String = "",
        updatedAtMs: Int64 = 0,
        usage: WorkspaceSubscriptionUsage = WorkspaceSubscriptionUsage()
    ) {
        self.id = id
        self.remarks = remarks
        self.url = url
        self.moreUrls = moreUrls
        self.enabled = enabled
        self.autoUpdateMinutes = autoUpdateMinutes
        self.userAgent = userAgent
        self.requestHeaders = requestHeaders
        self.includeRegex = includeRegex
        self.excludeRegex = excludeRegex
        self.prevProfileId = prevProfileId
        self.nextProfileId = nextProfileId
        self.updatedAtMs = updatedAtMs
        self.usage = usage
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        self.remarks = try c.decodeIfPresent(String.self, forKey: .remarks) ?? ""
        self.url = SubscriptionInfoParser.sanitizeSafeURL(try c.decodeIfPresent(String.self, forKey: .url) ?? "")
        let rawMore = try c.decodeIfPresent([String].self, forKey: .moreUrls) ?? []
        self.moreUrls = rawMore.map(SubscriptionInfoParser.sanitizeSafeURL).filter { !$0.isEmpty }
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        self.autoUpdateMinutes = try c.decodeIfPresent(Int.self, forKey: .autoUpdateMinutes) ?? 0
        self.userAgent = try c.decodeIfPresent(String.self, forKey: .userAgent) ?? ""
        self.requestHeaders = try c.decodeIfPresent([String: String].self, forKey: .requestHeaders) ?? [:]
        self.includeRegex = try c.decodeIfPresent(String.self, forKey: .includeRegex) ?? ""
        self.excludeRegex = try c.decodeIfPresent(String.self, forKey: .excludeRegex) ?? ""
        self.prevProfileId = try c.decodeIfPresent(String.self, forKey: .prevProfileId) ?? ""
        self.nextProfileId = try c.decodeIfPresent(String.self, forKey: .nextProfileId) ?? ""
        self.updatedAtMs = try c.decodeIfPresent(Int64.self, forKey: .updatedAtMs) ?? 0
        self.usage = try c.decodeIfPresent(WorkspaceSubscriptionUsage.self, forKey: .usage) ?? WorkspaceSubscriptionUsage()
    }
}

/// Canonical Layer 1 portable `workspace.json` (v1). Contains ZERO host, telemetry, or WebDAV credential fields.
public struct WorkspaceDocument: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1

    public var schemaVersion: Int
    public var revision: Int64
    public var updatedAtMs: Int64
    public var profiles: [WorkspaceProfileItem]
    public var subscriptions: [WorkspaceSubscriptionItem]
    public var routingProfiles: [WorkspaceRoutingProfile]
    public var dns: WorkspaceDnsConfig
    public var ruleSetAssets: [WorkspaceRuleSetAsset]
    public var fullTemplate: WorkspaceFullTemplateConfig

    enum CodingKeys: String, CodingKey {
        case revision, profiles, subscriptions, dns
        case schemaVersion = "schema_version"
        case updatedAtMs = "updated_at_ms"
        case routingProfiles = "routing_profiles"
        case ruleSetAssets = "rule_set_assets"
        case fullTemplate = "full_template"
    }

    public init(
        schemaVersion: Int = WorkspaceDocument.currentSchemaVersion,
        revision: Int64 = 1,
        updatedAtMs: Int64 = 0,
        profiles: [WorkspaceProfileItem] = [],
        subscriptions: [WorkspaceSubscriptionItem] = [],
        routingProfiles: [WorkspaceRoutingProfile] = WorkspaceDocument.defaultRoutingProfiles(),
        dns: WorkspaceDnsConfig = WorkspaceDnsConfig(),
        ruleSetAssets: [WorkspaceRuleSetAsset] = [],
        fullTemplate: WorkspaceFullTemplateConfig = WorkspaceFullTemplateConfig()
    ) {
        self.schemaVersion = schemaVersion
        self.revision = max(1, revision)
        self.updatedAtMs = max(0, updatedAtMs)
        self.profiles = profiles
        self.subscriptions = subscriptions
        self.routingProfiles = routingProfiles.isEmpty ? Self.defaultRoutingProfiles() : routingProfiles
        self.dns = dns
        self.ruleSetAssets = ruleSetAssets
        self.fullTemplate = fullTemplate
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let ver = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? Self.currentSchemaVersion
        guard ver == Self.currentSchemaVersion else {
            throw WorkspaceSchemaError.unsupportedSchemaVersion(ver)
        }
        self.schemaVersion = ver
        self.revision = max(1, try c.decodeIfPresent(Int64.self, forKey: .revision) ?? 1)
        self.updatedAtMs = max(0, try c.decodeIfPresent(Int64.self, forKey: .updatedAtMs) ?? 0)
        self.profiles = try c.decodeIfPresent([WorkspaceProfileItem].self, forKey: .profiles) ?? []
        self.subscriptions = try c.decodeIfPresent([WorkspaceSubscriptionItem].self, forKey: .subscriptions) ?? []
        let parsedRoutings = try c.decodeIfPresent([WorkspaceRoutingProfile].self, forKey: .routingProfiles) ?? []
        self.routingProfiles = parsedRoutings.isEmpty ? Self.defaultRoutingProfiles() : parsedRoutings
        self.dns = try c.decodeIfPresent(WorkspaceDnsConfig.self, forKey: .dns) ?? WorkspaceDnsConfig()
        self.ruleSetAssets = try c.decodeIfPresent([WorkspaceRuleSetAsset].self, forKey: .ruleSetAssets) ?? []
        self.fullTemplate = try c.decodeIfPresent(WorkspaceFullTemplateConfig.self, forKey: .fullTemplate) ?? WorkspaceFullTemplateConfig()
    }

    public func activeRoutingProfile() -> WorkspaceRoutingProfile {
        routingProfiles.first(where: { $0.isActive }) ?? routingProfiles.first ?? Self.defaultRoutingProfiles()[0]
    }

    public static func defaultRoutingProfiles() -> [WorkspaceRoutingProfile] {
        [
            WorkspaceRoutingProfile(
                id: "bypass-lan-cn",
                name: "绕过局域网与直连",
                isActive: true,
                domainStrategy: "as-is",
                defaultOutbound: "proxy",
                rules: [
                    WorkspaceRoutingRule(
                        id: "private-lan",
                        enabled: true,
                        locked: true,
                        scope: "both",
                        targetType: "direct",
                        ips: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"]
                    ),
                ]
            ),
            WorkspaceRoutingProfile(id: "global", name: "全局代理", isActive: false, domainStrategy: "as-is", defaultOutbound: "proxy"),
            WorkspaceRoutingProfile(id: "direct", name: "全局直连", isActive: false, domainStrategy: "as-is", defaultOutbound: "direct"),
        ]
    }

    public func encodeCanonicalJSON(pretty: Bool = true) throws -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes] : [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(self)
        guard let text = String(data: data, encoding: .utf8) else { throw WorkspaceSchemaError.invalidJSON }
        return pretty ? text + "\n" : text
    }

    public static func decodeCanonicalJSON(_ rawJSON: String) throws -> WorkspaceDocument {
        guard let data = rawJSON.data(using: .utf8) else { throw WorkspaceSchemaError.invalidJSON }
        return try JSONDecoder().decode(WorkspaceDocument.self, from: data)
    }
}
