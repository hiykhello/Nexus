import Foundation

public struct OutboundMemberSnapshot: Sendable, Equatable, Codable, Identifiable {
    public var id: String { name }
    public let name: String
    public let state: String
    public let latencyMs: Int64
    public let ewmaMs: Int64?
    public let breakerOpen: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case state
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
        case id
        case listener
        case inbound
        case protocolName = "protocol"
        case path
        case source
        case target
        case outbound
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
        let durStr = try c.decodeIfPresent(String.self, forKey: .durationMs) ?? "0"
        let upStr = try c.decodeIfPresent(String.self, forKey: .uploadBytes) ?? "0"
        let downStr = try c.decodeIfPresent(String.self, forKey: .downloadBytes) ?? "0"
        self.durationMs = UInt64(durStr) ?? 0
        self.uploadBytes = UInt64(upStr) ?? 0
        self.downloadBytes = UInt64(downStr) ?? 0
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
        case seq
        case level
        case domain
        case eventCode = "event_code"
        case message
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
        if let s = try? c.decode(String.self, forKey: .seq), let parsed = UInt64(s) {
            self.seq = parsed
        } else {
            self.seq = try c.decodeIfPresent(UInt64.self, forKey: .seq) ?? 0
        }
        self.level = try c.decodeIfPresent(String.self, forKey: .level) ?? "info"
        self.domain = try c.decodeIfPresent(String.self, forKey: .domain) ?? "core"
        self.eventCode = try c.decodeIfPresent(UInt32.self, forKey: .eventCode) ?? 0
        self.message = try c.decodeIfPresent(String.self, forKey: .message) ?? ""
    }
}

public struct LogsSnapshot: Sendable, Equatable, Codable {
    public let latestSeq: UInt64
    public let evicted: UInt64
    public let entries: [LogRingEntry]

    enum CodingKeys: String, CodingKey {
        case latestSeq = "latest_seq"
        case evicted
        case entries
    }

    public init(latestSeq: UInt64 = 0, evicted: UInt64 = 0, entries: [LogRingEntry] = []) {
        self.latestSeq = latestSeq
        self.evicted = evicted
        self.entries = entries
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let latestStr = try c.decodeIfPresent(String.self, forKey: .latestSeq) ?? "0"
        let evictedStr = try c.decodeIfPresent(String.self, forKey: .evicted) ?? "0"
        self.latestSeq = UInt64(latestStr) ?? 0
        self.evicted = UInt64(evictedStr) ?? 0
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
        case instance
        case authorizedRequests = "authorized_requests"
        case unauthorizedRequests = "unauthorized_requests"
        case expiredRequests = "expired_requests"
        case replyFailed = "reply_failed"
        case listeners
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

/// Swift 6 actor wrapping Nexus Batch 95C HTTP /v1/* & OpenMetrics /metrics endpoints.
public actor HttpControlClient {
    private let baseURL: URL
    private let bearerToken: String?
    private let session: URLSession

    public init(baseURL: URL, bearerToken: String? = nil, timeoutSeconds: TimeInterval = 2.0) {
        self.baseURL = baseURL
        self.bearerToken = bearerToken
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSeconds
        config.timeoutIntervalForResource = timeoutSeconds
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(configuration: config)
    }

    public init(host: String = "127.0.0.1", port: UInt16, bearerToken: String? = nil, timeoutSeconds: TimeInterval = 2.0) {
        let url = URL(string: "http://\(host):\(port)") ?? URL(string: "http://127.0.0.1:9090")!
        self.init(baseURL: url, bearerToken: bearerToken, timeoutSeconds: timeoutSeconds)
    }

    public func health() async throws -> Bool {
        _ = try await send(method: "GET", path: "/v1/health")
        return true
    }

    public func status() async throws -> String {
        String(decoding: try await send(method: "GET", path: "/v1/status"), as: UTF8.self)
    }

    public func outbounds() async throws -> [OutboundGroupSnapshot] {
        let data = try await send(method: "GET", path: "/v1/outbounds")
        return try Self.decodeOutbounds(data)
    }

    public func connections() async throws -> [ActiveConnectionSnapshot] {
        let data = try await send(method: "GET", path: "/v1/connections")
        return try Self.decodeConnections(data)
    }

    public func connectionDetail(id: String) async throws -> ActiveConnectionSnapshot {
        let data = try await send(method: "GET", path: "/v1/connections/\(id)")
        return try Self.decodeConnectionDetail(data)
    }

    public func logs(
        level: String = "trace",
        domain: String = "",
        search: String = "",
        since: UInt64 = 0,
        limit: Int = 128
    ) async throws -> LogsSnapshot {
        var items = ["limit=\(limit)"]
        if since > 0 { items.append("since=\(since)") }
        if !level.isEmpty && level != "all" { items.append("level=\(level)") }
        if !domain.isEmpty && domain != "all" { items.append("domain=\(domain)") }
        if !search.isEmpty {
            let encoded = search.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? search
            items.append("search=\(encoded)")
        }
        let data = try await send(method: "GET", path: "/v1/logs?\(items.joined(separator: "&"))")
        return try Self.decodeLogs(data)
    }

    public func closeConnection(id: String) async throws {
        _ = try await send(method: "DELETE", path: "/v1/connections/\(id)")
    }

    public func closeAllConnections() async throws {
        _ = try await send(method: "DELETE", path: "/v1/connections")
    }

    public func probeGroup(tag: String) async throws {
        _ = try await send(method: "POST", path: "/v1/groups/\(tag)/probe", body: Data("{}".utf8))
    }

    public func diagnostics() async throws -> DiagnosticsSnapshot {
        let data = try await send(method: "GET", path: "/v1/diagnostics")
        return try Self.decodeDiagnostics(data)
    }

    public func notifyNetworkChange(generation: UInt64) async throws {
        let body = try JSONEncoder().encode(["generation": String(generation)])
        _ = try await send(method: "POST", path: "/v1/network-change", body: body)
    }

    public func selectGroup(tag: String, member: String) async throws {
        let body = try JSONEncoder().encode(["member": member])
        _ = try await send(method: "PUT", path: "/v1/groups/\(tag)", body: body)
    }

    public func resetGroupAuto(tag: String) async throws {
        let body = Data(#"{"member":"--auto"}"#.utf8)
        _ = try await send(method: "PUT", path: "/v1/groups/\(tag)", body: body)
    }

    public func setLogLevel(_ level: String, domain: String = "global") async throws {
        let body = try JSONEncoder().encode(["level": level, "domain": domain])
        _ = try await send(method: "POST", path: "/v1/log-level", body: body)
    }

    public func reload() async throws {
        _ = try await send(method: "POST", path: "/v1/reload")
    }

    public func clearCache(target: String = "all") async throws {
        let body = try JSONEncoder().encode(["target": target])
        _ = try await send(method: "POST", path: "/v1/state/clear-cache", body: body)
    }

    public func metrics() async throws -> MetricsSnapshot {
        let data = try await send(method: "GET", path: "/metrics")
        return Self.parseOpenMetrics(String(decoding: data, as: UTF8.self))
    }

    private func send(method: String, path: String, body: Data? = nil) async throws -> Data {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw HttpControlError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let bearerToken, !bearerToken.isEmpty {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw HttpControlError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            throw HttpControlError.httpStatus(http.statusCode, String(decoding: data, as: UTF8.self))
        }
        return data
    }

    public static func decodeOutbounds(_ data: Data) throws -> [OutboundGroupSnapshot] {
        struct Envelope: Codable { let groups: [OutboundGroupSnapshot] }
        return try JSONDecoder().decode(Envelope.self, from: data).groups
    }

    public static func decodeConnections(_ data: Data) throws -> [ActiveConnectionSnapshot] {
        struct Envelope: Codable { let connections: [ActiveConnectionSnapshot] }
        return try JSONDecoder().decode(Envelope.self, from: data).connections
    }

    public static func decodeConnectionDetail(_ data: Data) throws -> ActiveConnectionSnapshot {
        try JSONDecoder().decode(ActiveConnectionSnapshot.self, from: data)
    }

    public static func decodeLogs(_ data: Data) throws -> LogsSnapshot {
        try JSONDecoder().decode(LogsSnapshot.self, from: data)
    }

    public static func decodeDiagnostics(_ data: Data) throws -> DiagnosticsSnapshot {
        try JSONDecoder().decode(DiagnosticsSnapshot.self, from: data)
    }

    public static func parseOpenMetrics(_ text: String) -> MetricsSnapshot {
        var gen: UInt64 = 0
        var active: UInt64 = 0
        var up: UInt64 = 0
        var down: UInt64 = 0
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let space = line.lastIndex(of: " ") else { continue }
            let key = line[..<space]
            guard let val = UInt64(line[line.index(after: space)...]) else { continue }
            if key == "nexus_control_generation" { gen = val }
            else if key.hasPrefix("nexus_active_sessions") { active += val }
            else if key.hasPrefix("nexus_traffic_upload_bytes_total") { up += val }
            else if key.hasPrefix("nexus_traffic_download_bytes_total") { down += val }
        }
        return MetricsSnapshot(controlGeneration: gen, activeSessions: active, uploadBytes: up, downloadBytes: down)
    }
}
