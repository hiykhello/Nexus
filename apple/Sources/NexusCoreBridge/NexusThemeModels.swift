import Foundation

/// Four curated instrument appearance presets shared across Nexus clients
/// (`gui-flagship-spec.md` §1). Persisted strictly in local `NexusClientDatabase` `host_kv` (never synced, zero `UserDefaults`).
public enum NexusThemePreset: String, Codable, Sendable, Equatable, Hashable, CaseIterable, Identifiable {
    case system = "system"
    case obsidian = "obsidian"
    case paper = "paper"
    case studioAmber = "studio_amber"

    public var id: String { rawValue }

    public var displayTitle: String {
        switch self {
        case .system: return "跟随系统"
        case .obsidian: return "曜石仪表"
        case .paper: return "暖纸日光"
        case .studioAmber: return "精密琥珀"
        }
    }

    public var subtitle: String {
        switch self {
        case .system: return "自动匹配系统深浅外观"
        case .obsidian: return "深炭机箱 · 靛蓝与翡翠信号"
        case .paper: return "暖纸底板 · 高对比浅色仪表"
        case .studioAmber: return "暖石墨 · 校准琥珀低照度"
        }
    }

    /// Migrates legacy `dark`/`light`/`daylight`/`amber` preference strings losslessly.
    public static func fromStored(_ raw: String) -> NexusThemePreset {
        switch raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "obsidian", "dark":
            return .obsidian
        case "paper", "light", "daylight":
            return .paper
        case "studio_amber", "studioamber", "amber":
            return .studioAmber
        default:
            return .system
        }
    }
}

/// Local SQLite `host_kv` persistence for `NexusThemePreset` (zero `UserDefaults`).
public enum ThemePreferenceStore {
    public static let hostKVKey = "ui_theme_preset"

    public static func load(from database: NexusClientDatabase) async -> NexusThemePreset {
        guard let rawJSON = try? await database.getHostKV(hostKVKey),
              let data = rawJSON.data(using: .utf8)
        else {
            return .system
        }
        if let decoded = try? JSONDecoder().decode(String.self, from: data) {
            return NexusThemePreset.fromStored(decoded)
        }
        return NexusThemePreset.fromStored(rawJSON)
    }

    public static func save(_ preset: NexusThemePreset, to database: NexusClientDatabase) async throws {
        let data = try JSONEncoder().encode(preset.rawValue)
        guard let json = String(data: data, encoding: .utf8) else {
            throw NexusDatabaseError.invalidUTF8
        }
        try await database.setHostKV(hostKVKey, value: json)
    }
}

/// Five-tier latency spectrum & P50 median statistics for an outbound policy group (`gui-flagship-spec.md` §4.2).
public struct GroupLatencySummary: Sendable, Equatable {
    public let totalCount: Int
    public let healthyCount: Int
    public let fastCount: Int       // < 80 ms
    public let goodCount: Int       // 80...179 ms
    public let midCount: Int        // 180...349 ms
    public let slowCount: Int       // >= 350 ms
    public let timeoutCount: Int    // down / failed / error / timeout
    public let unprobedCount: Int   // unprobed / idle
    public let p50Ms: Int64?
    public let maxHealthyMs: Int64?

    public init(
        totalCount: Int = 0,
        healthyCount: Int = 0,
        fastCount: Int = 0,
        goodCount: Int = 0,
        midCount: Int = 0,
        slowCount: Int = 0,
        timeoutCount: Int = 0,
        unprobedCount: Int = 0,
        p50Ms: Int64? = nil,
        maxHealthyMs: Int64? = nil
    ) {
        self.totalCount = totalCount
        self.healthyCount = healthyCount
        self.fastCount = fastCount
        self.goodCount = goodCount
        self.midCount = midCount
        self.slowCount = slowCount
        self.timeoutCount = timeoutCount
        self.unprobedCount = unprobedCount
        self.p50Ms = p50Ms
        self.maxHealthyMs = maxHealthyMs
    }

    public static func effectiveLatency(_ member: OutboundMemberSnapshot) -> Int64? {
        let lower = member.state.lowercased()
        if lower == "down" || lower == "failed" || lower == "error" || lower == "timeout" {
            return nil
        }
        if let ewma = member.ewmaMs, ewma >= 0 { return ewma }
        return member.latencyMs >= 0 ? member.latencyMs : nil
    }

    public static func compute(members: [OutboundMemberSnapshot]) -> GroupLatencySummary {
        var healthy: [Int64] = []
        healthy.reserveCapacity(members.count)
        var fast = 0, good = 0, mid = 0, slow = 0, timeout = 0, unprobed = 0

        for member in members {
            let lower = member.state.lowercased()
            if lower == "down" || lower == "failed" || lower == "error" || lower == "timeout" {
                timeout += 1
                continue
            }
            guard let ms = effectiveLatency(member) else {
                unprobed += 1
                continue
            }
            healthy.append(ms)
            if ms < 80 { fast += 1 }
            else if ms < 180 { good += 1 }
            else if ms < 350 { mid += 1 }
            else { slow += 1 }
        }

        healthy.sort()
        let p50: Int64?
        if healthy.isEmpty {
            p50 = nil
        } else {
            let midIdx = healthy.count / 2
            if healthy.count % 2 == 1 {
                p50 = healthy[midIdx]
            } else {
                p50 = (healthy[midIdx - 1] + healthy[midIdx]) / 2
            }
        }

        return GroupLatencySummary(
            totalCount: members.count,
            healthyCount: healthy.count,
            fastCount: fast,
            goodCount: good,
            midCount: mid,
            slowCount: slow,
            timeoutCount: timeout,
            unprobedCount: unprobed,
            p50Ms: p50,
            maxHealthyMs: healthy.last
        )
    }

    /// Proportional ratio (`0.08...1.0`) for relative-latency meter background behind healthy node cards.
    public func relativeRatio(for latencyMs: Int64?) -> Double? {
        guard let ms = latencyMs, ms >= 0, let maxMs = maxHealthyMs, maxMs > 0 else {
            return nil
        }
        let raw = Double(ms) / Double(maxMs)
        return min(1.0, max(0.08, raw))
    }
}

/// Onset marker placed on the live throughput sparkline when user changes mode/node or reloads.
public struct SparklineOnsetMarker: Sendable, Equatable, Identifiable {
    public let id: UInt64
    public var sampleIndex: Int
    public let label: String

    public init(id: UInt64, sampleIndex: Int, label: String) {
        self.id = id
        self.sampleIndex = sampleIndex
        self.label = label
    }
}

/// Sliding-window tracker keeping throughput onset markers aligned with 1Hz sample history.
public struct SparklineOnsetTracker: Sendable, Equatable {
    public let capacity: Int
    public private(set) var markers: [SparklineOnsetMarker]
    private var nextID: UInt64

    public init(capacity: Int = 24) {
        self.capacity = max(2, capacity)
        self.markers = []
        self.nextID = 1
    }

    public mutating func shiftLeft() {
        var next: [SparklineOnsetMarker] = []
        next.reserveCapacity(markers.count)
        for var marker in markers {
            marker.sampleIndex -= 1
            if marker.sampleIndex >= 0 {
                next.append(marker)
            }
        }
        markers = next
    }

    public mutating func record(label: String, at sampleIndex: Int? = nil) {
        let clamped = min(capacity - 1, max(0, sampleIndex ?? (capacity - 1)))
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let compactLabel = trimmed.isEmpty ? "切换" : String(trimmed.prefix(12))
        markers.removeAll { $0.sampleIndex == clamped }
        markers.append(SparklineOnsetMarker(id: nextID, sampleIndex: clamped, label: compactLabel))
        nextID &+= 1
        if markers.count > 6 {
            markers.removeFirst(markers.count - 6)
        }
    }

    public mutating func clear() {
        markers.removeAll(keepingCapacity: true)
    }
}
