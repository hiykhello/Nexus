import Foundation

/// Swift 6 actor wrapping Nexus HTTP `/v1/*` & OpenMetrics `/metrics` endpoints.
public actor HttpControlClient {
    internal nonisolated let baseURL: URL
    internal nonisolated let bearerToken: String?
    internal nonisolated let session: URLSession
    internal nonisolated let streamSession: URLSession

    public init(
        baseURL: URL,
        bearerToken: String? = nil,
        timeoutSeconds: TimeInterval = 2.0,
        sessionConfiguration: URLSessionConfiguration? = nil
    ) {
        self.baseURL = baseURL
        self.bearerToken = bearerToken
        let baseConfig = (sessionConfiguration?.copy() as? URLSessionConfiguration) ?? URLSessionConfiguration.ephemeral
        baseConfig.timeoutIntervalForRequest = timeoutSeconds
        baseConfig.timeoutIntervalForResource = timeoutSeconds
        baseConfig.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(configuration: baseConfig)

        let longConfig = (sessionConfiguration?.copy() as? URLSessionConfiguration) ?? URLSessionConfiguration.ephemeral
        longConfig.timeoutIntervalForRequest = max(60.0, timeoutSeconds)
        longConfig.timeoutIntervalForResource = 0
        longConfig.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.streamSession = URLSession(configuration: longConfig)
    }

    deinit {
        session.finishTasksAndInvalidate()
        streamSession.finishTasksAndInvalidate()
    }

    public init(
        host: String = "127.0.0.1",
        port: UInt16,
        bearerToken: String? = nil,
        timeoutSeconds: TimeInterval = 2.0
    ) {
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
        try Self.decodeOutbounds(try await send(method: "GET", path: "/v1/outbounds"))
    }

    public func connections() async throws -> [ActiveConnectionSnapshot] {
        try Self.decodeConnections(try await send(method: "GET", path: "/v1/connections"))
    }

    public func connectionDetail(id: String) async throws -> ActiveConnectionSnapshot {
        try Self.decodeConnectionDetail(try await send(method: "GET", path: "/v1/connections/\(Self.encodePathSegment(id))"))
    }

    public func logs(
        level: String = "trace",
        domain: String = "",
        search: String = "",
        since: UInt64 = 0,
        limit: Int = 128
    ) async throws -> LogsSnapshot {
        let path = Self.buildLogsPath(level: level, domain: domain, search: search, since: since, limit: limit, stream: false)
        return try Self.decodeLogs(try await send(method: "GET", path: path))
    }

    public func closeConnection(id: String) async throws {
        _ = try await send(method: "DELETE", path: "/v1/connections/\(Self.encodePathSegment(id))")
    }

    public func closeAllConnections() async throws {
        _ = try await send(method: "DELETE", path: "/v1/connections")
    }

    public func probeGroup(tag: String) async throws {
        _ = try await send(method: "POST", path: "/v1/groups/\(Self.encodePathSegment(tag))/probe", body: Data("{}".utf8))
    }

    public func diagnostics() async throws -> DiagnosticsSnapshot {
        try Self.decodeDiagnostics(try await send(method: "GET", path: "/v1/diagnostics"))
    }

    public func notifyNetworkChange(generation: UInt64) async throws {
        let body = try JSONEncoder().encode(["generation": String(generation)])
        _ = try await send(method: "POST", path: "/v1/network-change", body: body)
    }

    public func selectGroup(tag: String, member: String) async throws {
        let body = try JSONEncoder().encode(["member": member])
        _ = try await send(method: "PUT", path: "/v1/groups/\(Self.encodePathSegment(tag))", body: body)
    }

    public func resetGroupAuto(tag: String) async throws {
        _ = try await send(method: "PUT", path: "/v1/groups/\(Self.encodePathSegment(tag))", body: Data(#"{"member":"--auto"}"#.utf8))
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
        Self.parseOpenMetrics(String(decoding: try await send(method: "GET", path: "/metrics"), as: UTF8.self))
    }

    internal nonisolated func makeRequest(
        method: String,
        path: String,
        body: Data? = nil,
        accept: String? = nil,
        timeoutOverride: TimeInterval? = nil
    ) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw HttpControlError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let timeoutOverride { request.timeoutInterval = timeoutOverride }
        if let bearerToken, !bearerToken.isEmpty {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }
        if let accept {
            request.setValue(accept, forHTTPHeaderField: "Accept")
        }
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return request
    }

    internal func send(
        method: String,
        path: String,
        body: Data? = nil,
        useLongTimeout: Bool = false,
        timeoutOverride: TimeInterval? = nil
    ) async throws -> Data {
        let request = try makeRequest(method: method, path: path, body: body, timeoutOverride: timeoutOverride)
        let targetSession = useLongTimeout ? streamSession : session
        let (data, response) = try await targetSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw HttpControlError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            throw HttpControlError.httpStatus(http.statusCode, String(decoding: data, as: UTF8.self))
        }
        return data
    }

    internal static func encodePathSegment(_ raw: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/?#%")
        return raw.addingPercentEncoding(withAllowedCharacters: allowed) ?? raw
    }

    internal static func encodeQueryValue(_ raw: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+#?")
        return raw.addingPercentEncoding(withAllowedCharacters: allowed) ?? raw
    }

    internal static func buildLogsPath(
        level: String,
        domain: String,
        search: String,
        since: UInt64,
        limit: Int,
        stream: Bool
    ) -> String {
        var items: [String] = []
        if stream { items.append("stream=1") }
        if limit > 0 { items.append("limit=\(limit)") }
        if since > 0 { items.append("since=\(since)") }
        if !level.isEmpty && level != "all" { items.append("level=\(encodeQueryValue(level))") }
        if !domain.isEmpty && domain != "all" { items.append("domain=\(encodeQueryValue(domain))") }
        if !search.isEmpty { items.append("search=\(encodeQueryValue(search))") }
        return "/v1/logs?\(items.joined(separator: "&"))"
    }

    internal static func decodeFlexibleUInt64<K: CodingKey>(_ c: KeyedDecodingContainer<K>, key: K) -> UInt64 {
        if let s = try? c.decode(String.self, forKey: key), let parsed = UInt64(s) { return parsed }
        return (try? c.decodeIfPresent(UInt64.self, forKey: key)) ?? 0
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
        var gen: UInt64 = 0, active: UInt64 = 0, up: UInt64 = 0, down: UInt64 = 0
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
