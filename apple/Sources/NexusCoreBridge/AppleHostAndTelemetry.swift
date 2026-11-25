import Foundation

/// Layer 3 Apple host platform identifier matching `src/provider/workspace_host.cpp`.
public enum AppleHostPlatform: String, Codable, Sendable, Equatable, CaseIterable {
    case desktopMacOS = "desktop-macos"
    case iOS = "ios"
}

/// Layer 3 macOS desktop host inbound/TUN adapter block matching `DesktopHostConfig` in Core.
public struct AppleDesktopHostSection: Codable, Sendable, Equatable {
    public var enableMixed: Bool
    public var mixedListen: String
    public var secondLocalListen: String
    public var lanListen: String
    public var lanUsername: String
    public var lanPassword: String
    public var enableTun: Bool
    public var tunInterfaceName: String
    public var tunMtu: Int
    public var tunInet4: String
    public var tunInet6: String
    public var tunAutoRoute: Bool
    public var tunStrictRoute: Bool
    public var tunRouteExclude: [String]
    public var tunRouteExcludePrivate: Bool
    public var bindInterface: String
    public var inet4BindAddress: String
    public var inet6BindAddress: String

    enum CodingKeys: String, CodingKey {
        case enableMixed = "enable_mixed"
        case mixedListen = "mixed_listen"
        case secondLocalListen = "second_local_listen"
        case lanListen = "lan_listen"
        case lanUsername = "lan_username"
        case lanPassword = "lan_password"
        case enableTun = "enable_tun"
        case tunInterfaceName = "tun_interface_name"
        case tunMtu = "tun_mtu"
        case tunInet4 = "tun_inet4"
        case tunInet6 = "tun_inet6"
        case tunAutoRoute = "tun_auto_route"
        case tunStrictRoute = "tun_strict_route"
        case tunRouteExclude = "tun_route_exclude"
        case tunRouteExcludePrivate = "tun_route_exclude_private"
        case bindInterface = "bind_interface"
        case inet4BindAddress = "inet4_bind_address"
        case inet6BindAddress = "inet6_bind_address"
    }

    public init(
        enableMixed: Bool = true,
        mixedListen: String = "127.0.0.1:7890",
        secondLocalListen: String = "",
        lanListen: String = "",
        lanUsername: String = "",
        lanPassword: String = "",
        enableTun: Bool = false,
        tunInterfaceName: String = "utun",
        tunMtu: Int = AppleTunnelProfile.maxSafeMtu,
        tunInet4: String = "198.18.0.1/30",
        tunInet6: String = "",
        tunAutoRoute: Bool = true,
        tunStrictRoute: Bool = false,
        tunRouteExclude: [String] = [],
        tunRouteExcludePrivate: Bool = true,
        bindInterface: String = "",
        inet4BindAddress: String = "",
        inet6BindAddress: String = ""
    ) {
        self.enableMixed = enableMixed
        self.mixedListen = mixedListen
        self.secondLocalListen = secondLocalListen
        self.lanListen = lanListen
        self.lanUsername = lanUsername
        self.lanPassword = lanPassword
        self.enableTun = enableTun
        self.tunInterfaceName = tunInterfaceName
        self.tunMtu = tunMtu
        self.tunInet4 = tunInet4
        self.tunInet6 = tunInet6
        self.tunAutoRoute = tunAutoRoute
        self.tunStrictRoute = tunStrictRoute
        self.tunRouteExclude = tunRouteExclude
        self.tunRouteExcludePrivate = tunRouteExcludePrivate
        self.bindInterface = bindInterface
        self.inet4BindAddress = inet4BindAddress
        self.inet6BindAddress = inet6BindAddress
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enableMixed = try c.decodeIfPresent(Bool.self, forKey: .enableMixed) ?? true
        self.mixedListen = try c.decodeIfPresent(String.self, forKey: .mixedListen) ?? "127.0.0.1:7890"
        self.secondLocalListen = try c.decodeIfPresent(String.self, forKey: .secondLocalListen) ?? ""
        self.lanListen = try c.decodeIfPresent(String.self, forKey: .lanListen) ?? ""
        self.lanUsername = try c.decodeIfPresent(String.self, forKey: .lanUsername) ?? ""
        self.lanPassword = try c.decodeIfPresent(String.self, forKey: .lanPassword) ?? ""
        self.enableTun = try c.decodeIfPresent(Bool.self, forKey: .enableTun) ?? false
        self.tunInterfaceName = try c.decodeIfPresent(String.self, forKey: .tunInterfaceName) ?? "utun"
        self.tunMtu = try c.decodeIfPresent(Int.self, forKey: .tunMtu) ?? AppleTunnelProfile.maxSafeMtu
        self.tunInet4 = try c.decodeIfPresent(String.self, forKey: .tunInet4) ?? "198.18.0.1/30"
        self.tunInet6 = try c.decodeIfPresent(String.self, forKey: .tunInet6) ?? ""
        self.tunAutoRoute = try c.decodeIfPresent(Bool.self, forKey: .tunAutoRoute) ?? true
        self.tunStrictRoute = try c.decodeIfPresent(Bool.self, forKey: .tunStrictRoute) ?? false
        self.tunRouteExclude = try c.decodeIfPresent([String].self, forKey: .tunRouteExclude) ?? []
        self.tunRouteExcludePrivate = try c.decodeIfPresent(Bool.self, forKey: .tunRouteExcludePrivate) ?? true
        self.bindInterface = try c.decodeIfPresent(String.self, forKey: .bindInterface) ?? ""
        self.inet4BindAddress = try c.decodeIfPresent(String.self, forKey: .inet4BindAddress) ?? ""
        self.inet6BindAddress = try c.decodeIfPresent(String.self, forKey: .inet6BindAddress) ?? ""
    }
}

/// Layer 3 Apple local host adapter configuration (`host.json`, v1, NEVER synced).
/// WebDAV passwords and E2EE sync passphrases are stored exclusively in `KeychainTokenStore`.
public struct AppleHostConfig: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1

    public var schemaVersion: Int
    public var platform: AppleHostPlatform
    public var logLevel: String
    public var logFile: String
    public var workers: Int
    public var stateDir: String
    public var cacheDir: String
    public var controlSocket: String
    public var controlHttpListen: String
    public var controlBearerFile: String
    public var caFile: String
    public var includeSiblingNodesInSelector: Bool
    public var maxSelectorMembers: Int
    public var desktop: AppleDesktopHostSection

    enum CodingKeys: String, CodingKey {
        case platform, workers, desktop
        case schemaVersion = "schema_version"
        case logLevel = "log_level"
        case logFile = "log_file"
        case stateDir = "state_dir"
        case cacheDir = "cache_dir"
        case controlSocket = "control_socket"
        case controlHttpListen = "control_http_listen"
        case controlBearerFile = "control_bearer_file"
        case caFile = "ca_file"
        case includeSiblingNodesInSelector = "include_sibling_nodes_in_selector"
        case maxSelectorMembers = "max_selector_members"
    }

    public init(
        schemaVersion: Int = AppleHostConfig.currentSchemaVersion,
        platform: AppleHostPlatform = .desktopMacOS,
        logLevel: String = "info",
        logFile: String = "",
        workers: Int = 1,
        stateDir: String = "",
        cacheDir: String = "",
        controlSocket: String = "/var/run/org.nexus.apple/c.sock",
        controlHttpListen: String = "127.0.0.1:9090",
        controlBearerFile: String = "",
        caFile: String = "",
        includeSiblingNodesInSelector: Bool = true,
        maxSelectorMembers: Int = 128,
        desktop: AppleDesktopHostSection = AppleDesktopHostSection()
    ) {
        self.schemaVersion = schemaVersion
        self.platform = platform
        self.logLevel = logLevel
        self.logFile = logFile
        self.workers = max(1, min(16, workers))
        self.stateDir = stateDir
        self.cacheDir = cacheDir
        self.controlSocket = controlSocket
        self.controlHttpListen = controlHttpListen
        self.controlBearerFile = controlBearerFile
        self.caFile = caFile
        self.includeSiblingNodesInSelector = includeSiblingNodesInSelector
        self.maxSelectorMembers = maxSelectorMembers
        self.desktop = desktop
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let ver = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? Self.currentSchemaVersion
        guard ver == Self.currentSchemaVersion else {
            throw WorkspaceSchemaError.unsupportedSchemaVersion(ver)
        }
        self.schemaVersion = ver
        self.platform = try c.decodeIfPresent(AppleHostPlatform.self, forKey: .platform) ?? .desktopMacOS
        self.logLevel = try c.decodeIfPresent(String.self, forKey: .logLevel) ?? "info"
        self.logFile = try c.decodeIfPresent(String.self, forKey: .logFile) ?? ""
        self.workers = max(1, min(16, try c.decodeIfPresent(Int.self, forKey: .workers) ?? 1))
        self.stateDir = try c.decodeIfPresent(String.self, forKey: .stateDir) ?? ""
        self.cacheDir = try c.decodeIfPresent(String.self, forKey: .cacheDir) ?? ""
        self.controlSocket = try c.decodeIfPresent(String.self, forKey: .controlSocket) ?? "/var/run/org.nexus.apple/c.sock"
        self.controlHttpListen = try c.decodeIfPresent(String.self, forKey: .controlHttpListen) ?? "127.0.0.1:9090"
        self.controlBearerFile = try c.decodeIfPresent(String.self, forKey: .controlBearerFile) ?? ""
        self.caFile = try c.decodeIfPresent(String.self, forKey: .caFile) ?? ""
        self.includeSiblingNodesInSelector = try c.decodeIfPresent(Bool.self, forKey: .includeSiblingNodesInSelector) ?? true
        self.maxSelectorMembers = try c.decodeIfPresent(Int.self, forKey: .maxSelectorMembers) ?? 128
        self.desktop = try c.decodeIfPresent(AppleDesktopHostSection.self, forKey: .desktop) ?? AppleDesktopHostSection()
    }

    public func encodeCanonicalJSON(pretty: Bool = true) throws -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes] : [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(self)
        guard let text = String(data: data, encoding: .utf8) else { throw WorkspaceSchemaError.invalidJSON }
        return pretty ? text + "\n" : text
    }
}

/// Layer 4 ephemeral local telemetry & crash-sentinel models (`telemetry.json`, NEVER synced).
public struct ProfileTelemetryEntry: Codable, Sendable, Equatable {
    public var latencyMs: Int64
    public var lastTestedMs: Int64
    public var uploadBytes: Int64
    public var downloadBytes: Int64

    enum CodingKeys: String, CodingKey {
        case latencyMs = "latency_ms"
        case lastTestedMs = "last_tested_ms"
        case uploadBytes = "upload_bytes"
        case downloadBytes = "download_bytes"
    }

    public init(latencyMs: Int64 = -1, lastTestedMs: Int64 = 0, uploadBytes: Int64 = 0, downloadBytes: Int64 = 0) {
        self.latencyMs = latencyMs
        self.lastTestedMs = lastTestedMs
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.latencyMs = try c.decodeIfPresent(Int64.self, forKey: .latencyMs) ?? -1
        self.lastTestedMs = try c.decodeIfPresent(Int64.self, forKey: .lastTestedMs) ?? 0
        self.uploadBytes = try c.decodeIfPresent(Int64.self, forKey: .uploadBytes) ?? 0
        self.downloadBytes = try c.decodeIfPresent(Int64.self, forKey: .downloadBytes) ?? 0
    }
}

public struct TelemetryDocument: Codable, Sendable, Equatable {
    public var activeProfileId: String
    public var outboundMode: String
    public var unreadUnexpectedCrash: Bool
    public var lastCrashTimestampMs: Int64
    public var lastCrashReason: String
    public var profiles: [String: ProfileTelemetryEntry]

    enum CodingKeys: String, CodingKey {
        case profiles
        case activeProfileId = "active_profile_id"
        case outboundMode = "outbound_mode"
        case unreadUnexpectedCrash = "unread_unexpected_crash"
        case lastCrashTimestampMs = "last_crash_timestamp_ms"
        case lastCrashReason = "last_crash_reason"
    }

    public init(
        activeProfileId: String = "",
        outboundMode: String = "rule",
        unreadUnexpectedCrash: Bool = false,
        lastCrashTimestampMs: Int64 = 0,
        lastCrashReason: String = "",
        profiles: [String: ProfileTelemetryEntry] = [:]
    ) {
        self.activeProfileId = activeProfileId
        self.outboundMode = outboundMode
        self.unreadUnexpectedCrash = unreadUnexpectedCrash
        self.lastCrashTimestampMs = lastCrashTimestampMs
        self.lastCrashReason = lastCrashReason
        self.profiles = profiles
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.activeProfileId = try c.decodeIfPresent(String.self, forKey: .activeProfileId) ?? ""
        let rawMode = try c.decodeIfPresent(String.self, forKey: .outboundMode) ?? "rule"
        self.outboundMode = ["rule", "global", "direct"].contains(rawMode) ? rawMode : "rule"
        self.unreadUnexpectedCrash = try c.decodeIfPresent(Bool.self, forKey: .unreadUnexpectedCrash) ?? false
        self.lastCrashTimestampMs = try c.decodeIfPresent(Int64.self, forKey: .lastCrashTimestampMs) ?? 0
        self.lastCrashReason = try c.decodeIfPresent(String.self, forKey: .lastCrashReason) ?? ""
        self.profiles = try c.decodeIfPresent([String: ProfileTelemetryEntry].self, forKey: .profiles) ?? [:]
    }
}

/// Swift 6 actor managing Layer 4 ephemeral local telemetry (`telemetry.json`, NEVER synced).
public actor TelemetryStore {
    public let fileURL: URL

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    public func load() -> TelemetryDocument {
        guard let data = try? Data(contentsOf: fileURL),
              let doc = try? JSONDecoder().decode(TelemetryDocument.self, from: data)
        else {
            return TelemetryDocument()
        }
        return doc
    }

    @discardableResult
    public func save(_ doc: TelemetryDocument) throws -> TelemetryDocument {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(doc)
        try WorkspaceStore.atomicWrite0600(data: data, to: fileURL)
        return doc
    }

    @discardableResult
    public func setActiveProfileId(_ profileId: String) throws -> TelemetryDocument {
        var doc = load()
        doc.activeProfileId = profileId
        return try save(doc)
    }

    @discardableResult
    public func setOutboundMode(_ mode: String) throws -> TelemetryDocument {
        var doc = load()
        let allowed: Set<String> = ["rule", "global", "direct"]
        doc.outboundMode = allowed.contains(mode) ? mode : "rule"
        return try save(doc)
    }

    @discardableResult
    public func recordUnexpectedCrash(reason: String, nowMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> TelemetryDocument {
        var doc = load()
        doc.unreadUnexpectedCrash = true
        doc.lastCrashTimestampMs = nowMs
        doc.lastCrashReason = String(reason.prefix(256))
        return try save(doc)
    }

    @discardableResult
    public func clearUnexpectedCrash() throws -> TelemetryDocument {
        var doc = load()
        guard doc.unreadUnexpectedCrash else { return doc }
        doc.unreadUnexpectedCrash = false
        return try save(doc)
    }

    @discardableResult
    public func updateLatency(
        profileId: String,
        latencyMs: Int64,
        nowMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
    ) throws -> TelemetryDocument {
        var doc = load()
        var entry = doc.profiles[profileId] ?? ProfileTelemetryEntry()
        entry.latencyMs = latencyMs
        entry.lastTestedMs = nowMs
        doc.profiles[profileId] = entry
        return try save(doc)
    }
}
