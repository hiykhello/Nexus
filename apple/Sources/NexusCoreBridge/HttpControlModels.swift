import Foundation

public struct OutboundMemberSnapshot: Sendable, Equatable, Codable, Identifiable {
    public var id: String { name }
    public let name: String
    public let state: String
    public let latencyMs: Int64
    public let ewmaMs: Int64?
    public let breakerOpen: Bool

    enum CodingKeys: String, CodingKey {
        case name, state
        case latencyMs = "latency_ms"
        case ewmaMs = "ewma_ms"
        case breakerOpen = "breaker_open"
    }

    public init(name: String, state: String, latencyMs: Int64 = -1, ewmaMs: Int64? = nil, breakerOpen: Bool = false) {
        self.name = name
        self.state = state
        self.latencyMs = latencyMs
        self.ewmaMs = ewmaMs
        self.breakerOpen = breakerOpen
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try c.decode(String.self, forKey: .name)
        self.state = try c.decodeIfPresent(String.self, forKey: .state) ?? "unknown"
        self.latencyMs = try c.decodeIfPresent(Int64.self, forKey: .latencyMs) ?? -1
        self.ewmaMs = try c.decodeIfPresent(Int64.self, forKey: .ewmaMs)
        self.breakerOpen = try c.decodeIfPresent(Bool.self, forKey: .breakerOpen) ?? false
    }
}

public struct OutboundGroupSnapshot: Sendable, Equatable, Codable, Identifiable {
    public var id: String { tag }
    public let tag: String
    public let mode: String
    public let active: String
    public let manualOverride: Bool
    public let members: [OutboundMemberSnapshot]

    enum CodingKeys: String, CodingKey {
        case tag = "name"
        case mode
        case active = "selected"
        case manualOverride = "override"
        case members
    }

    public var supportsManualSelection: Bool {
        let m = mode.lowercased()
        return m == "selector" || m == "select" || m == "url-test"
    }

    public init(
        tag: String,
        mode: String,
        active: String,
        manualOverride: Bool = false,
        members: [OutboundMemberSnapshot] = []
    ) {
        self.tag = tag
        self.mode = mode
        self.active = active
        self.manualOverride = manualOverride
        self.members = members
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.tag = try c.decode(String.self, forKey: .tag)
        self.mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? ""
        self.active = try c.decodeIfPresent(String.self, forKey: .active) ?? ""
        self.manualOverride = try c.decodeIfPresent(Bool.self, forKey: .manualOverride) ?? false
        self.members = try c.decodeIfPresent([OutboundMemberSnapshot].self, forKey: .members) ?? []
    }
}

public struct ActiveConnectionSnapshot: Sendable, Equatable, Codable, Identifiable {
    public let id: String
    public let listener: Int
    public let inbound: String
    public let protocolName: String
    public let path: String
    public let source: String
    public let target: String
    public let outbound: String
    public let routeMode: String
    public let routeRule: String
    public let processPath: String
    public let sourceUid: Int64?
    public let destinationPort: Int
    public let durationMs: UInt64
    public let uploadBytes: UInt64
    public let downloadBytes: UInt64
    public let canClose: Bool

    enum CodingKeys: String, CodingKey {
        case id, listener, inbound, path, source, target, outbound
        case protocolName = "protocol"
        case routeMode = "route_mode"
        case routeRule = "route_rule"
        case processPath = "process_path"
        case sourceUid = "source_uid"
        case destinationPort = "destination_port"
        case durationMs = "duration_ms"
        case uploadBytes = "upload_bytes"
        case downloadBytes = "download_bytes"
        case canClose = "can_close"
    }

    public init(
        id: String,
        listener: Int = 0,
        inbound: String = "",
        protocolName: String,
        path: String,
        source: String = "",
        target: String = "",
        outbound: String = "",
        routeMode: String = "",
        routeRule: String = "",
        processPath: String = "",
        sourceUid: Int64? = nil,
        destinationPort: Int,
        durationMs: UInt64 = 0,
        uploadBytes: UInt64 = 0,
        downloadBytes: UInt64 = 0,
        canClose: Bool = false
    ) {
        self.id = id
        self.listener = listener
        self.inbound = inbound
        self.protocolName = protocolName
        self.path = path
        self.source = source
        self.target = target
        self.outbound = outbound
        self.routeMode = routeMode
        self.routeRule = routeRule
        self.processPath = processPath
        self.sourceUid = sourceUid
        self.destinationPort = destinationPort
        self.durationMs = durationMs
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.canClose = canClose
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(String.self, forKey: .id)
        self.listener = try c.decodeIfPresent(Int.self, forKey: .listener) ?? 0
        self.inbound = try c.decodeIfPresent(String.self, forKey: .inbound) ?? ""
        self.protocolName = try c.decodeIfPresent(String.self, forKey: .protocolName) ?? "unknown"
        self.path = try c.decodeIfPresent(String.self, forKey: .path) ?? "direct"
        self.source = try c.decodeIfPresent(String.self, forKey: .source) ?? ""
        self.target = try c.decodeIfPresent(String.self, forKey: .target) ?? ""
        self.outbound = try c.decodeIfPresent(String.self, forKey: .outbound) ?? ""
        self.routeMode = try c.decodeIfPresent(String.self, forKey: .routeMode) ?? ""
        self.routeRule = try c.decodeIfPresent(String.self, forKey: .routeRule) ?? ""
        self.processPath = try c.decodeIfPresent(String.self, forKey: .processPath) ?? ""
        self.sourceUid = try c.decodeIfPresent(Int64.self, forKey: .sourceUid)
        self.destinationPort = try c.decodeIfPresent(Int.self, forKey: .destinationPort) ?? 0
        self.durationMs = HttpControlClient.decodeFlexibleUInt64(c, key: .durationMs)
        self.uploadBytes = HttpControlClient.decodeFlexibleUInt64(c, key: .uploadBytes)
        self.downloadBytes = HttpControlClient.decodeFlexibleUInt64(c, key: .downloadBytes)
        self.canClose = try c.decodeIfPresent(Bool.self, forKey: .canClose) ?? false
    }
}

public struct LogRingEntry: Sendable, Equatable, Codable, Identifiable {
    public var id: UInt64 { seq }
    public let seq: UInt64
    public let level: String
    public let domain: String
    public let eventCode: UInt32
    public let message: String

    enum CodingKeys: String, CodingKey {
        case seq, level, domain, message, event
        case eventCode = "event_code"
    }

    public init(seq: UInt64, level: String, domain: String, eventCode: UInt32 = 0, message: String) {
        self.seq = seq
        self.level = level
        self.domain = domain
        self.eventCode = eventCode
        self.message = message
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.seq = HttpControlClient.decodeFlexibleUInt64(c, key: .seq)
        self.level = try c.decodeIfPresent(String.self, forKey: .level) ?? "info"
        self.domain = try c.decodeIfPresent(String.self, forKey: .domain) ?? "core"
        self.eventCode = (try? c.decodeIfPresent(UInt32.self, forKey: .eventCode))
            ?? (try? c.decodeIfPresent(UInt32.self, forKey: .event))
            ?? 0
        self.message = try c.decodeIfPresent(String.self, forKey: .message) ?? ""
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(seq, forKey: .seq)
        try c.encode(level, forKey: .level)
        try c.encode(domain, forKey: .domain)
        try c.encode(eventCode, forKey: .eventCode)
        try c.encode(message, forKey: .message)
    }
}

public struct LogsSnapshot: Sendable, Equatable, Codable {
    public let latestSeq: UInt64
    public let evicted: UInt64
    public let entries: [LogRingEntry]

    enum CodingKeys: String, CodingKey {
        case latestSeq = "latest_seq"
        case evicted, entries
    }

    public init(latestSeq: UInt64 = 0, evicted: UInt64 = 0, entries: [LogRingEntry] = []) {
        self.latestSeq = latestSeq
        self.evicted = evicted
        self.entries = entries
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.latestSeq = HttpControlClient.decodeFlexibleUInt64(c, key: .latestSeq)
        self.evicted = HttpControlClient.decodeFlexibleUInt64(c, key: .evicted)
        self.entries = try c.decodeIfPresent([LogRingEntry].self, forKey: .entries) ?? []
    }
}

public struct MetricsSnapshot: Sendable, Equatable {
    public let controlGeneration: UInt64
    public let activeSessions: UInt64
    public let uploadBytes: UInt64
    public let downloadBytes: UInt64

    public init(
        controlGeneration: UInt64 = 0,
        activeSessions: UInt64 = 0,
        uploadBytes: UInt64 = 0,
        downloadBytes: UInt64 = 0
    ) {
        self.controlGeneration = controlGeneration
        self.activeSessions = activeSessions
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
    }
}

public struct DiagnosticsSnapshot: Sendable, Equatable, Codable {
    public let instance: String
    public let authorizedRequests: UInt64
    public let unauthorizedRequests: UInt64
    public let expiredRequests: UInt64
    public let replyFailed: UInt64
    public let listeners: Int
    public let activeConnections: Int

    enum CodingKeys: String, CodingKey {
        case instance, listeners
        case authorizedRequests = "authorized_requests"
        case unauthorizedRequests = "unauthorized_requests"
        case expiredRequests = "expired_requests"
        case replyFailed = "reply_failed"
        case activeConnections = "active_connections"
    }

    public init(
        instance: String = "",
        authorizedRequests: UInt64 = 0,
        unauthorizedRequests: UInt64 = 0,
        expiredRequests: UInt64 = 0,
        replyFailed: UInt64 = 0,
        listeners: Int = 0,
        activeConnections: Int = 0
    ) {
        self.instance = instance
        self.authorizedRequests = authorizedRequests
        self.unauthorizedRequests = unauthorizedRequests
        self.expiredRequests = expiredRequests
        self.replyFailed = replyFailed
        self.listeners = listeners
        self.activeConnections = activeConnections
    }
}

public enum HttpControlError: Error, LocalizedError, Sendable {
    case invalidURL
    case httpStatus(Int, String)
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .invalidURL: "Invalid control plane URL"
        case .httpStatus(let code, let body): "HTTP \(code): \(body)"
        case .invalidResponse: "Invalid HTTP response"
        }
    }
}
