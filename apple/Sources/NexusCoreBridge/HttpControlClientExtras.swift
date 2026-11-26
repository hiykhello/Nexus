import Foundation

/// Wave 30–31 Control API endpoints (`/v1/rules`, `/v1/dns/query`, `/v1/cache/fakeip/flush`,
/// `/v1/outbounds/{tag}/probe`, `/v1/mode`, `/v1/events`) and `AsyncThrowingStream` SSE streaming.
extension HttpControlClient {
    public func fetchRules() async throws -> [RuleMetric] {
        try Self.decodeRules(try await send(method: "GET", path: "/v1/rules"))
    }

    public func queryDns(name: String, type: String = "A", server: String? = nil) async throws -> DnsQueryResponse {
        var items = [
            "name=\(Self.encodeQueryValue(name.trimmingCharacters(in: .whitespacesAndNewlines)))",
            "type=\(Self.encodeQueryValue(type.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()))",
        ]
        if let server {
            let trimmed = server.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { items.append("server=\(Self.encodeQueryValue(trimmed))") }
        }
        let data = try await send(method: "GET", path: "/v1/dns/query?\(items.joined(separator: "&"))", useLongTimeout: true, timeoutOverride: 15.0)
        return try Self.decodeDnsQuery(data)
    }

    @discardableResult
    public func flushFakeIpCache() async throws -> FakeIpFlushResult {
        try Self.decodeFakeIpFlush(try await send(method: "POST", path: "/v1/cache/fakeip/flush", body: Data("{}".utf8)))
    }

    public func clearCache(scope: String) async throws {
        let trimmed = scope.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let effective = trimmed.isEmpty ? "all" : trimmed
        let body = try JSONEncoder().encode(["target": effective])
        _ = try await send(method: "POST", path: "/v1/state/clear-cache?scope=\(Self.encodeQueryValue(effective))", body: body)
    }

    public func probeOutbound(
        tag: String,
        url: String? = nil,
        timeoutMs: UInt32? = nil,
        mode: String? = nil
    ) async throws -> OutboundProbeResult {
        struct ProbePayload: Encodable {
            let url: String?
            let timeoutMs: UInt32?
            let mode: String?
            enum CodingKeys: String, CodingKey {
                case url, mode
                case timeoutMs = "timeout_ms"
            }
        }
        let body = try JSONEncoder().encode(ProbePayload(url: url, timeoutMs: timeoutMs, mode: mode))
        let waitSec = max(12.0, Double(timeoutMs ?? 5000) / 1000.0 + 5.0)
        let data = try await send(
            method: "POST",
            path: "/v1/outbounds/\(Self.encodePathSegment(tag))/probe",
            body: body,
            useLongTimeout: true,
            timeoutOverride: waitSec
        )
        return try Self.decodeOutboundProbe(data)
    }

    public func setLogLevel(domain: String, level: String) async throws {
        try await setLogLevel(level, domain: domain)
    }

    public func fetchMode() async throws -> ControlModeSnapshot {
        try Self.decodeMode(try await send(method: "GET", path: "/v1/mode"))
    }

    @discardableResult
    public func setMode(_ mode: String, outbound: String? = nil) async throws -> ControlModeSnapshot {
        var payload = ["mode": mode]
        if let outbound, !outbound.isEmpty { payload["outbound"] = outbound }
        let body = try JSONEncoder().encode(payload)
        return try Self.decodeMode(try await send(method: "PUT", path: "/v1/mode", body: body))
    }

    public func statusSnapshot() async throws -> StatusSnapshot {
        try Self.decodeStatus(try await send(method: "GET", path: "/v1/status"))
    }

    public func fetchEvents(cursor: UInt64 = 0) async throws -> ControlEventsSnapshot {
        try Self.decodeEvents(try await send(method: "GET", path: "/v1/events?cursor=\(cursor)"))
    }

    public nonisolated func streamSse(path: String) -> AsyncThrowingStream<SseFrame, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let request = try self.makeRequest(method: "GET", path: path, accept: "text/event-stream", timeoutOverride: 60.0)
                    let (bytes, response) = try await self.streamSession.bytes(for: request)
                    guard let http = response as? HTTPURLResponse else {
                        throw HttpControlError.invalidResponse
                    }
                    guard (200..<300).contains(http.statusCode) else {
                        throw HttpControlError.httpStatus(http.statusCode, "SSE connection rejected")
                    }
                    var parser = SseLineParser()
                    var chunk: [UInt8] = []
                    chunk.reserveCapacity(512)
                    for try await byte in bytes {
                        if Task.isCancelled { break }
                        chunk.append(byte)
                        if byte == 0x0A || chunk.count >= 512 {
                            for frame in parser.feedBytes(chunk) { continuation.yield(frame) }
                            chunk.removeAll(keepingCapacity: true)
                        }
                    }
                    if !chunk.isEmpty {
                        for frame in parser.feedBytes(chunk) { continuation.yield(frame) }
                    }
                    if let tail = parser.finish() { continuation.yield(tail) }
                    continuation.finish()
                } catch is CancellationError {
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public nonisolated func streamLogs(
        level: String = "trace",
        domain: String = "",
        search: String = "",
        since: UInt64 = 0
    ) -> AsyncThrowingStream<LogRingEntry, Error> {
        let path = Self.buildLogsPath(level: level, domain: domain, search: search, since: since, limit: 0, stream: true)
        return mapSseStream(path: path) { frame in
            guard frame.event == "log" || frame.event == "message" else { return nil }
            return try JSONDecoder().decode(LogRingEntry.self, from: Data(frame.data.utf8))
        }
    }

    public nonisolated func streamStatus(intervalMs: Int = 1000) -> AsyncThrowingStream<StatusSnapshot, Error> {
        let clamped = max(200, min(10_000, intervalMs))
        return mapSseStream(path: "/v1/status?stream=1&interval_ms=\(clamped)") { frame in
            guard frame.event == "status" || frame.event == "message" else { return nil }
            return try Self.decodeStatus(Data(frame.data.utf8))
        }
    }

    public nonisolated func streamConnections(intervalMs: Int = 1000) -> AsyncThrowingStream<[ActiveConnectionSnapshot], Error> {
        let clamped = max(200, min(10_000, intervalMs))
        return mapSseStream(path: "/v1/connections?stream=1&interval_ms=\(clamped)") { frame in
            guard frame.event == "connections" || frame.event == "message" else { return nil }
            return try Self.decodeConnections(Data(frame.data.utf8))
        }
    }

    public nonisolated func streamEvents(pollIntervalMs: Int = 1000, initialCursor: UInt64 = 0) -> AsyncThrowingStream<ControlEventItem, Error> {
        let sleepMs = max(250, min(10_000, pollIntervalMs))
        return AsyncThrowingStream { continuation in
            let task = Task {
                var cursor = initialCursor
                while !Task.isCancelled {
                    do {
                        let snap = try await self.fetchEvents(cursor: cursor)
                        cursor = max(cursor, snap.next)
                        for item in snap.events { continuation.yield(item) }
                        try await Task.sleep(for: .milliseconds(sleepMs))
                    } catch is CancellationError {
                        break
                    } catch {
                        continuation.finish(throwing: error)
                        return
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    private nonisolated func mapSseStream<T: Sendable>(
        path: String,
        transform: @escaping @Sendable (SseFrame) throws -> T?
    ) -> AsyncThrowingStream<T, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    for try await frame in self.streamSse(path: path) {
                        if Task.isCancelled { break }
                        if let value = try transform(frame) { continuation.yield(value) }
                    }
                    continuation.finish()
                } catch is CancellationError {
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public static func decodeRules(_ data: Data) throws -> [RuleMetric] {
        struct Envelope: Codable { let rules: [RuleMetric] }
        return try JSONDecoder().decode(Envelope.self, from: data).rules
    }

    public static func decodeDnsQuery(_ data: Data) throws -> DnsQueryResponse {
        try JSONDecoder().decode(DnsQueryResponse.self, from: data)
    }

    public static func decodeFakeIpFlush(_ data: Data) throws -> FakeIpFlushResult {
        try JSONDecoder().decode(FakeIpFlushResult.self, from: data)
    }

    public static func decodeOutboundProbe(_ data: Data) throws -> OutboundProbeResult {
        try JSONDecoder().decode(OutboundProbeResult.self, from: data)
    }

    public static func decodeMode(_ data: Data) throws -> ControlModeSnapshot {
        try JSONDecoder().decode(ControlModeSnapshot.self, from: data)
    }

    public static func decodeStatus(_ data: Data) throws -> StatusSnapshot {
        try JSONDecoder().decode(StatusSnapshot.self, from: data)
    }

    public static func decodeEvents(_ data: Data) throws -> ControlEventsSnapshot {
        try JSONDecoder().decode(ControlEventsSnapshot.self, from: data)
    }
}
