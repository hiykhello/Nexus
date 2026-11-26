import Foundation

public struct RuleMetric: Sendable, Equatable, Codable, Identifiable {
    public var id: String { "\(index):\(type):\(target)" }
    public let index: Int
    public let type: String
    public let action: String
    public let target: String
    public let summary: String

    enum CodingKeys: String, CodingKey {
        case index, type, action, target, summary
    }

    public init(index: Int, type: String, action: String, target: String, summary: String) {
        self.index = index
        self.type = type
        self.action = action
        self.target = target
        self.summary = summary
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.index = try c.decodeIfPresent(Int.self, forKey: .index) ?? 0
        self.type = try c.decodeIfPresent(String.self, forKey: .type) ?? ""
        self.action = try c.decodeIfPresent(String.self, forKey: .action) ?? ""
        self.target = try c.decodeIfPresent(String.self, forKey: .target) ?? ""
        self.summary = try c.decodeIfPresent(String.self, forKey: .summary) ?? ""
    }
}

public struct DnsQueryAnswer: Sendable, Equatable, Codable, Identifiable {
    public var id: String { "\(name)|\(type)|\(ttl)|\(data)" }
    public let name: String
    public let type: String
    public let ttl: UInt32
    public let data: String

    enum CodingKeys: String, CodingKey {
        case name, type, ttl, data
    }

    public init(name: String, type: String, ttl: UInt32, data: String) {
        self.name = name
        self.type = type
        self.ttl = ttl
        self.data = data
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.type = try c.decodeIfPresent(String.self, forKey: .type) ?? ""
        self.ttl = try c.decodeIfPresent(UInt32.self, forKey: .ttl) ?? 0
        self.data = try c.decodeIfPresent(String.self, forKey: .data) ?? ""
    }
}

public struct DnsQueryResponse: Sendable, Equatable, Codable {
    public let name: String
    public let type: String
    public let rcode: Int
    public let rcodeName: String
    public let ttl: UInt32
    public let elapsedMs: UInt64
    public let answers: [DnsQueryAnswer]
    public let state: String

    enum CodingKeys: String, CodingKey {
        case name, type, rcode, ttl, answers, state
        case rcodeName = "rcode_name"
        case elapsedMs = "elapsed_ms"
    }

    public init(
        name: String,
        type: String,
        rcode: Int = 0,
        rcodeName: String = "NOERROR",
        ttl: UInt32 = 0,
        elapsedMs: UInt64 = 0,
        answers: [DnsQueryAnswer] = [],
        state: String = "ok"
    ) {
        self.name = name
        self.type = type
        self.rcode = rcode
        self.rcodeName = rcodeName
        self.ttl = ttl
        self.elapsedMs = elapsedMs
        self.answers = answers
        self.state = state
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.type = try c.decodeIfPresent(String.self, forKey: .type) ?? "A"
        self.rcode = try c.decodeIfPresent(Int.self, forKey: .rcode) ?? 0
        self.rcodeName = try c.decodeIfPresent(String.self, forKey: .rcodeName) ?? ""
        self.ttl = try c.decodeIfPresent(UInt32.self, forKey: .ttl) ?? 0
        self.elapsedMs = HttpControlClient.decodeFlexibleUInt64(c, key: .elapsedMs)
        self.answers = try c.decodeIfPresent([DnsQueryAnswer].self, forKey: .answers) ?? []
        self.state = try c.decodeIfPresent(String.self, forKey: .state) ?? "ok"
    }
}

public struct FakeIpFlushResult: Sendable, Equatable, Codable {
    public let flushed: UInt64
    public let fakeip: Bool

    enum CodingKeys: String, CodingKey {
        case flushed, fakeip
    }

    public init(flushed: UInt64 = 0, fakeip: Bool = true) {
        self.flushed = flushed
        self.fakeip = fakeip
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.flushed = HttpControlClient.decodeFlexibleUInt64(c, key: .flushed)
        self.fakeip = try c.decodeIfPresent(Bool.self, forKey: .fakeip) ?? true
    }
}

public struct OutboundProbeResult: Sendable, Equatable, Codable {
    public let outbound: String
    public let resolvedOutbound: String
    public let state: String
    public let latencyMs: Int64?
    public let statusCode: Int?
    public let url: String

    enum CodingKeys: String, CodingKey {
        case outbound, state, url
        case resolvedOutbound = "resolved_outbound"
        case latencyMs = "latency_ms"
        case statusCode = "status_code"
    }

    public init(
        outbound: String,
        resolvedOutbound: String = "",
        state: String,
        latencyMs: Int64? = nil,
        statusCode: Int? = nil,
        url: String = ""
    ) {
        self.outbound = outbound
        self.resolvedOutbound = resolvedOutbound
        self.state = state
        self.latencyMs = latencyMs
        self.statusCode = statusCode
        self.url = url
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.outbound = try c.decodeIfPresent(String.self, forKey: .outbound) ?? ""
        self.resolvedOutbound = try c.decodeIfPresent(String.self, forKey: .resolvedOutbound) ?? ""
        self.state = try c.decodeIfPresent(String.self, forKey: .state) ?? "unknown"
        self.latencyMs = try c.decodeIfPresent(Int64.self, forKey: .latencyMs)
        self.statusCode = try c.decodeIfPresent(Int.self, forKey: .statusCode)
        self.url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
    }
}

public struct ControlModeSnapshot: Sendable, Equatable, Codable {
    public let mode: String
    public let outbound: String

    enum CodingKeys: String, CodingKey {
        case mode, outbound
    }

    public init(mode: String = "rule", outbound: String = "") {
        self.mode = mode
        self.outbound = outbound
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? "rule"
        self.outbound = try c.decodeIfPresent(String.self, forKey: .outbound) ?? ""
    }
}

public struct StatusSnapshot: Sendable, Equatable, Codable {
    public let instance: String
    public let state: String
    public let workers: Int
    public let listeners: Int
    public let controlGeneration: UInt64
    public let activeSessions: UInt64
    public let uploadBytesTotal: UInt64
    public let downloadBytesTotal: UInt64

    enum CodingKeys: String, CodingKey {
        case instance, state, workers, listeners
        case controlGeneration = "control_generation"
        case activeSessions = "active_sessions"
        case uploadBytesTotal = "upload_bytes_total"
        case downloadBytesTotal = "download_bytes_total"
        case uploadBytes = "upload_bytes"
        case downloadBytes = "download_bytes"
    }

    public init(
        instance: String = "",
        state: String = "running",
        workers: Int = 1,
        listeners: Int = 0,
        controlGeneration: UInt64 = 0,
        activeSessions: UInt64 = 0,
        uploadBytesTotal: UInt64 = 0,
        downloadBytesTotal: UInt64 = 0
    ) {
        self.instance = instance
        self.state = state
        self.workers = workers
        self.listeners = listeners
        self.controlGeneration = controlGeneration
        self.activeSessions = activeSessions
        self.uploadBytesTotal = uploadBytesTotal
        self.downloadBytesTotal = downloadBytesTotal
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.instance = try c.decodeIfPresent(String.self, forKey: .instance) ?? ""
        self.state = try c.decodeIfPresent(String.self, forKey: .state) ?? "running"
        self.workers = try c.decodeIfPresent(Int.self, forKey: .workers) ?? 1
        self.listeners = try c.decodeIfPresent(Int.self, forKey: .listeners) ?? 0
        self.controlGeneration = HttpControlClient.decodeFlexibleUInt64(c, key: .controlGeneration)
        self.activeSessions = HttpControlClient.decodeFlexibleUInt64(c, key: .activeSessions)
        self.uploadBytesTotal = c.contains(.uploadBytesTotal)
            ? HttpControlClient.decodeFlexibleUInt64(c, key: .uploadBytesTotal)
            : HttpControlClient.decodeFlexibleUInt64(c, key: .uploadBytes)
        self.downloadBytesTotal = c.contains(.downloadBytesTotal)
            ? HttpControlClient.decodeFlexibleUInt64(c, key: .downloadBytesTotal)
            : HttpControlClient.decodeFlexibleUInt64(c, key: .downloadBytes)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(instance, forKey: .instance)
        try c.encode(state, forKey: .state)
        try c.encode(workers, forKey: .workers)
        try c.encode(listeners, forKey: .listeners)
        try c.encode(controlGeneration, forKey: .controlGeneration)
        try c.encode(activeSessions, forKey: .activeSessions)
        try c.encode(uploadBytesTotal, forKey: .uploadBytesTotal)
        try c.encode(downloadBytesTotal, forKey: .downloadBytesTotal)
    }
}

public struct ControlEventItem: Sendable, Equatable, Codable, Identifiable {
    public let id: UInt64
    public let event: String
    public let controlGeneration: UInt64
    public let operation: UInt64?

    enum CodingKeys: String, CodingKey {
        case id, event, operation
        case controlGeneration = "control_generation"
    }

    public init(id: UInt64, event: String, controlGeneration: UInt64 = 0, operation: UInt64? = nil) {
        self.id = id
        self.event = event
        self.controlGeneration = controlGeneration
        self.operation = operation
    }
}

public struct ControlEventsSnapshot: Sendable, Equatable, Codable {
    public let instance: String
    public let next: UInt64
    public let latest: UInt64
    public let gap: Bool
    public let events: [ControlEventItem]

    public init(instance: String = "", next: UInt64 = 0, latest: UInt64 = 0, gap: Bool = false, events: [ControlEventItem] = []) {
        self.instance = instance
        self.next = next
        self.latest = latest
        self.gap = gap
        self.events = events
    }
}

public struct SseFrame: Sendable, Equatable {
    public let event: String
    public let data: String
    public let id: String?

    public init(event: String, data: String, id: String? = nil) {
        self.event = event
        self.data = data
        self.id = id
    }
}

/// WHATWG Server-Sent Events incremental parser preserving blank-line frame boundaries
/// (unlike Foundation's `AsyncBytes.lines` which drops empty lines).
public struct SseLineParser: Sendable {
    private var currentEvent = ""
    private var currentData: [String] = []
    private var currentId: String?
    private var lineBuffer: [UInt8] = []

    public init() {}

    public mutating func feedLine(_ rawLine: String) -> SseFrame? {
        let line = rawLine.hasSuffix("\r") ? String(rawLine.dropLast()) : rawLine
        if line.isEmpty { return dispatchPending() }
        if line.hasPrefix(":") { return nil }
        let field: Substring
        let value: String
        if let colon = line.firstIndex(of: ":") {
            field = line[..<colon]
            var after = line[line.index(after: colon)...]
            if after.first == " " { after = after.dropFirst() }
            value = String(after)
        } else {
            field = line[...]
            value = ""
        }
        switch field {
        case "event": currentEvent = value
        case "data": currentData.append(value)
        case "id":
            if !value.contains("\0") { currentId = value }
        default: break
        }
        return nil
    }

    public mutating func feedBytes<S: Sequence>(_ bytes: S) -> [SseFrame] where S.Element == UInt8 {
        var frames: [SseFrame] = []
        for byte in bytes {
            if byte == 0x0A {
                if lineBuffer.last == 0x0D { lineBuffer.removeLast() }
                let line = String(decoding: lineBuffer, as: UTF8.self)
                lineBuffer.removeAll(keepingCapacity: true)
                if let frame = feedLine(line) { frames.append(frame) }
            } else {
                lineBuffer.append(byte)
            }
        }
        return frames
    }

    public mutating func finish() -> SseFrame? {
        if !lineBuffer.isEmpty {
            if lineBuffer.last == 0x0D { lineBuffer.removeLast() }
            let line = String(decoding: lineBuffer, as: UTF8.self)
            lineBuffer.removeAll(keepingCapacity: false)
            if let frame = feedLine(line) { return frame }
        }
        return dispatchPending()
    }

    private mutating func dispatchPending() -> SseFrame? {
        guard !currentData.isEmpty else {
            currentEvent = ""
            return nil
        }
        let frame = SseFrame(
            event: currentEvent.isEmpty ? "message" : currentEvent,
            data: currentData.joined(separator: "\n"),
            id: currentId
        )
        currentEvent = ""
        currentData.removeAll(keepingCapacity: true)
        return frame
    }
}
