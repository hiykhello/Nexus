import Foundation
import SQLite3

public enum NexusDatabaseError: Error, LocalizedError, Equatable, Sendable {
    case sqlite(code: Int32, message: String)
    case unsupportedSchemaVersion(Int32)
    case invalidUTF8
    case encodingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .sqlite(let code, let message):
            return "SQLite error (\(code)): \(message)"
        case .unsupportedSchemaVersion(let version):
            return "Unsupported database schema version: \(version)"
        case .invalidUTF8:
            return "Failed to convert database payload to UTF-8"
        case .encodingFailed(let detail):
            return "Database payload encoding failed: \(detail)"
        }
    }
}

/// Fast index-only profile summary read from `profiles` without touching `profile_payloads`.
public struct ProfileSummaryRecord: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let kind: WorkspaceProfileKind
    public let subscriptionId: String
    public let name: String
    public let protocolName: String
    public let server: String
    public let port: Int
    public let sortOrder: Int
    public let pinned: Bool
    public let updatedAt: Int64

    public init(
        id: String,
        kind: WorkspaceProfileKind,
        subscriptionId: String = "",
        name: String,
        protocolName: String = "",
        server: String = "",
        port: Int = 0,
        sortOrder: Int = 0,
        pinned: Bool = false,
        updatedAt: Int64 = 0
    ) {
        self.id = id
        self.kind = kind
        self.subscriptionId = subscriptionId
        self.name = name
        self.protocolName = protocolName
        self.server = server
        self.port = port
        self.sortOrder = sortOrder
        self.pinned = pinned
        self.updatedAt = updatedAt
    }
}

/// Per-node probe telemetry persisted in `node_telemetry`.
public struct NodeTelemetryRecord: Codable, Sendable, Equatable, Identifiable {
    public var id: String { profileId }
    public let profileId: String
    public let latencyMs: Int64
    public let ewmaMs: Int64
    public let statusCode: Int
    public let state: String
    public let testedAt: Int64

    public init(
        profileId: String,
        latencyMs: Int64 = -1,
        ewmaMs: Int64 = -1,
        statusCode: Int = 0,
        state: String = "",
        testedAt: Int64 = 0
    ) {
        self.profileId = profileId
        self.latencyMs = latencyMs
        self.ewmaMs = ewmaMs
        self.statusCode = statusCode
        self.state = state
        self.testedAt = testedAt
    }
}

/// Hourly traffic aggregate persisted in `traffic_ledger`.
public struct TrafficLedgerRecord: Codable, Sendable, Equatable {
    public let bucketHour: Int64
    public let profileId: String
    public let uploadBytes: Int64
    public let downloadBytes: Int64

    public init(bucketHour: Int64, profileId: String, uploadBytes: Int64, downloadBytes: Int64) {
        self.bucketHour = bucketHour
        self.profileId = profileId
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
    }
}

internal struct TelemetryMetaState: Codable, Sendable, Equatable {
    var activeProfileId: String
    var outboundMode: String
    var unreadUnexpectedCrash: Bool
    var lastCrashTimestampMs: Int64
    var lastCrashReason: String

    enum CodingKeys: String, CodingKey {
        case activeProfileId = "active_profile_id"
        case outboundMode = "outbound_mode"
        case unreadUnexpectedCrash = "unread_unexpected_crash"
        case lastCrashTimestampMs = "last_crash_timestamp_ms"
        case lastCrashReason = "last_crash_reason"
    }

    init(
        activeProfileId: String = "",
        outboundMode: String = "rule",
        unreadUnexpectedCrash: Bool = false,
        lastCrashTimestampMs: Int64 = 0,
        lastCrashReason: String = ""
    ) {
        self.activeProfileId = activeProfileId
        self.outboundMode = outboundMode
        self.unreadUnexpectedCrash = unreadUnexpectedCrash
        self.lastCrashTimestampMs = lastCrashTimestampMs
        self.lastCrashReason = lastCrashReason
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.activeProfileId = try c.decodeIfPresent(String.self, forKey: .activeProfileId) ?? ""
        let rawMode = try c.decodeIfPresent(String.self, forKey: .outboundMode) ?? "rule"
        self.outboundMode = ["rule", "global", "direct"].contains(rawMode) ? rawMode : "rule"
        self.unreadUnexpectedCrash = try c.decodeIfPresent(Bool.self, forKey: .unreadUnexpectedCrash) ?? false
        self.lastCrashTimestampMs = try c.decodeIfPresent(Int64.self, forKey: .lastCrashTimestampMs) ?? 0
        self.lastCrashReason = try c.decodeIfPresent(String.self, forKey: .lastCrashReason) ?? ""
    }
}

/// Owns a raw `sqlite3*` handle; exclusively accessed while isolated to `NexusClientDatabase`
/// except during final teardown (`deinit`) after all references to the owning actor are released.
internal final class SQLiteHandleBox: @unchecked Sendable {
    var pointer: OpaquePointer?

    init(pointer: OpaquePointer? = nil) {
        self.pointer = pointer
    }

    func close() {
        if let ptr = pointer {
            sqlite3_close_v2(ptr)
            pointer = nil
        }
    }

    deinit {
        close()
    }
}

internal enum SQLiteSchemaV1 {
    static let pragmasSQL = """
    PRAGMA busy_timeout = 5000;
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA mmap_size = 0;
    PRAGMA cache_size = -2000;
    """

    static let ddlSQL = """
    CREATE TABLE IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        sort_order INTEGER NOT NULL DEFAULT 0,
        payload_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS profiles (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        subscription_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL,
        protocol TEXT NOT NULL DEFAULT '',
        server TEXT NOT NULL DEFAULT '',
        port INTEGER NOT NULL DEFAULT 0,
        sort_order INTEGER NOT NULL DEFAULT 0,
        pinned INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_profiles_sub_sort ON profiles(subscription_id, sort_order);
    CREATE INDEX IF NOT EXISTS idx_profiles_kind ON profiles(kind);
    CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON profiles(protocol);
    CREATE INDEX IF NOT EXISTS idx_profiles_pinned ON profiles(pinned);
    CREATE TABLE IF NOT EXISTS profile_payloads (
        profile_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
        payload_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS routing_profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        payload_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS workspace_meta (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS node_telemetry (
        profile_id TEXT PRIMARY KEY,
        latency_ms INTEGER NOT NULL DEFAULT -1,
        ewma_ms INTEGER NOT NULL DEFAULT -1,
        status_code INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT '',
        tested_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS traffic_ledger (
        bucket_hour INTEGER NOT NULL,
        profile_id TEXT NOT NULL,
        upload_bytes INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_hour, profile_id)
    );
    CREATE TABLE IF NOT EXISTS host_kv (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
    );
    PRAGMA user_version = 1;
    """
}
