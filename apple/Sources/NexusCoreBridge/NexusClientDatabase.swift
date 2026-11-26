import Foundation
import SQLite3

/// Swift 6 native SQLite 3 (WAL) unified client database implementing cross-platform Schema v1.
/// Zero external SwiftPM dependencies; safe for macOS 14+ / iOS 17+ App Group shared containers.
public actor NexusClientDatabase {
    public static let schemaVersion: Int32 = 1
    public static let defaultFileName = "nexus-client.db"

    public nonisolated let dbURL: URL
    private let handle = SQLiteHandleBox()

    public init(dbURL: URL) {
        self.dbURL = dbURL
    }

    public init(rootDirectory: URL, fileName: String = NexusClientDatabase.defaultFileName) {
        self.dbURL = rootDirectory.appendingPathComponent(fileName)
    }

    public func close() {
        handle.close()
    }

    public func schemaUserVersion() throws -> Int32 {
        let db = try ensureOpen()
        return try SQLiteCore.readInt32Pragma(db, sql: "PRAGMA user_version;")
    }

    public func hasWorkspaceData() throws -> Bool {
        let db = try ensureOpen()
        return try SQLiteCore.hasWorkspaceDataLocked(db)
    }

    public func hasTelemetryData() throws -> Bool {
        let db = try ensureOpen()
        return try SQLiteCore.hasTelemetryDataLocked(db)
    }

    public func loadWorkspace() throws -> WorkspaceDocument? {
        try withReadTransaction { db in
            try SQLiteCore.loadWorkspaceLocked(db)
        }
    }

    public func saveWorkspace(_ doc: WorkspaceDocument) throws {
        try withTransaction { db in
            try SQLiteCore.writeWorkspaceLocked(db, doc: doc)
        }
    }

    /// Atomically persists `doc` only when the workspace tables are still empty;
    /// if another caller/process initialized first, returns the existing workspace intact.
    public func saveWorkspaceIfEmpty(_ doc: WorkspaceDocument) throws -> WorkspaceDocument {
        try withTransaction { db in
            if let existing = try SQLiteCore.loadWorkspaceLocked(db) {
                return existing
            }
            try SQLiteCore.writeWorkspaceLocked(db, doc: doc)
            return doc
        }
    }

    public func listProfileSummaries(
        subscriptionId: String? = nil,
        kind: WorkspaceProfileKind? = nil
    ) throws -> [ProfileSummaryRecord] {
        let db = try ensureOpen()
        var clauses: [String] = []
        var bindings: [String] = []
        if let subscriptionId {
            clauses.append("subscription_id = ?")
            bindings.append(subscriptionId)
        }
        if let kind {
            clauses.append("kind = ?")
            bindings.append(kind.rawValue)
        }
        let whereClause = clauses.isEmpty ? "" : " WHERE " + clauses.joined(separator: " AND ")
        let sql = """
        SELECT id, kind, subscription_id, name, protocol, server, port, sort_order, pinned, updated_at
        FROM profiles\(whereClause)
        ORDER BY pinned DESC, sort_order ASC, id ASC;
        """
        let stmt = try SQLiteCore.prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        for (idx, val) in bindings.enumerated() {
            try SQLiteCore.bindText(stmt, index: Int32(idx + 1), value: val)
        }
        var out: [ProfileSummaryRecord] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                out.append(ProfileSummaryRecord(
                    id: SQLiteCore.columnText(stmt, index: 0),
                    kind: WorkspaceProfileKind.fromWire(SQLiteCore.columnText(stmt, index: 1)),
                    subscriptionId: SQLiteCore.columnText(stmt, index: 2),
                    name: SQLiteCore.columnText(stmt, index: 3),
                    protocolName: SQLiteCore.columnText(stmt, index: 4),
                    server: SQLiteCore.columnText(stmt, index: 5),
                    port: Int(sqlite3_column_int(stmt, 6)),
                    sortOrder: Int(sqlite3_column_int(stmt, 7)),
                    pinned: sqlite3_column_int(stmt, 8) != 0,
                    updatedAt: sqlite3_column_int64(stmt, 9)
                ))
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw NexusDatabaseError.sqlite(code: rc, message: SQLiteCore.lastErrorMessage(db))
            }
        }
        return out
    }

    public func loadProfilePayload(id: String) throws -> WorkspaceProfileItem? {
        let db = try ensureOpen()
        let stmt = try SQLiteCore.prepare(db, sql: "SELECT payload_json FROM profile_payloads WHERE profile_id = ?;")
        defer { sqlite3_finalize(stmt) }
        try SQLiteCore.bindText(stmt, index: 1, value: id)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_ROW {
            return try SQLiteCore.decodeJSON(WorkspaceProfileItem.self, from: SQLiteCore.columnText(stmt, index: 0))
        }
        if rc == SQLITE_DONE { return nil }
        throw NexusDatabaseError.sqlite(code: rc, message: SQLiteCore.lastErrorMessage(db))
    }

    public func deleteProfile(id: String) throws {
        let db = try ensureOpen()
        let stmt = try SQLiteCore.prepare(db, sql: "DELETE FROM profiles WHERE id = ?;")
        defer { sqlite3_finalize(stmt) }
        try SQLiteCore.bindText(stmt, index: 1, value: id)
        try SQLiteCore.stepDone(db, stmt: stmt)
    }

    public func loadTelemetry() throws -> TelemetryDocument {
        try withReadTransaction { db in
            let meta: TelemetryMetaState
            if let raw = try SQLiteCore.getHostKVLocked(db, key: "telemetry_state") {
                meta = (try? SQLiteCore.decodeJSON(TelemetryMetaState.self, from: raw)) ?? TelemetryMetaState()
            } else {
                meta = TelemetryMetaState()
            }
            var profiles: [String: ProfileTelemetryEntry] = [:]
            for node in try SQLiteCore.listNodeTelemetryLocked(db) {
                profiles[node.profileId] = ProfileTelemetryEntry(latencyMs: node.latencyMs, lastTestedMs: node.testedAt)
            }
            let sumStmt = try SQLiteCore.prepare(
                db,
                sql: "SELECT profile_id, SUM(upload_bytes), SUM(download_bytes) FROM traffic_ledger GROUP BY profile_id;"
            )
            defer { sqlite3_finalize(sumStmt) }
            while true {
                let rc = sqlite3_step(sumStmt)
                if rc == SQLITE_ROW {
                    let pid = SQLiteCore.columnText(sumStmt, index: 0)
                    var entry = profiles[pid] ?? ProfileTelemetryEntry()
                    entry.uploadBytes = sqlite3_column_int64(sumStmt, 1)
                    entry.downloadBytes = sqlite3_column_int64(sumStmt, 2)
                    profiles[pid] = entry
                } else if rc == SQLITE_DONE {
                    break
                } else {
                    throw NexusDatabaseError.sqlite(code: rc, message: SQLiteCore.lastErrorMessage(db))
                }
            }
            return TelemetryDocument(
                activeProfileId: meta.activeProfileId,
                outboundMode: meta.outboundMode,
                unreadUnexpectedCrash: meta.unreadUnexpectedCrash,
                lastCrashTimestampMs: meta.lastCrashTimestampMs,
                lastCrashReason: meta.lastCrashReason,
                profiles: profiles
            )
        }
    }

    public func saveTelemetry(_ doc: TelemetryDocument) throws {
        try withTransaction { db in
            try SQLiteCore.saveTelemetryLocked(db, doc: doc)
        }
    }

    @discardableResult
    public func importLegacyTelemetryIfEmpty(_ doc: TelemetryDocument) throws -> Bool {
        try withTransaction { db in
            guard try !SQLiteCore.hasTelemetryDataLocked(db) else { return false }
            try SQLiteCore.saveTelemetryLocked(db, doc: doc)
            return true
        }
    }

    public func upsertNodeTelemetry(_ record: NodeTelemetryRecord) throws {
        let db = try ensureOpen()
        let sql = """
        INSERT INTO node_telemetry(profile_id, latency_ms, ewma_ms, status_code, state, tested_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(profile_id) DO UPDATE SET
            latency_ms = excluded.latency_ms,
            ewma_ms = excluded.ewma_ms,
            status_code = excluded.status_code,
            state = excluded.state,
            tested_at = excluded.tested_at;
        """
        let stmt = try SQLiteCore.prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try SQLiteCore.bindText(stmt, index: 1, value: record.profileId)
        try SQLiteCore.bindInt64(stmt, index: 2, value: record.latencyMs)
        try SQLiteCore.bindInt64(stmt, index: 3, value: record.ewmaMs)
        try SQLiteCore.bindInt64(stmt, index: 4, value: Int64(record.statusCode))
        try SQLiteCore.bindText(stmt, index: 5, value: record.state)
        try SQLiteCore.bindInt64(stmt, index: 6, value: record.testedAt)
        try SQLiteCore.stepDone(db, stmt: stmt)
    }

    /// Updates only `latency_ms` and `tested_at` on conflict so `ewma_ms`, `status_code`, and `state` stay intact.
    public func updateNodeLatency(profileId: String, latencyMs: Int64, testedAt: Int64) throws {
        let db = try ensureOpen()
        let sql = """
        INSERT INTO node_telemetry(profile_id, latency_ms, ewma_ms, status_code, state, tested_at)
        VALUES (?, ?, -1, 0, '', ?)
        ON CONFLICT(profile_id) DO UPDATE SET
            latency_ms = excluded.latency_ms,
            tested_at = excluded.tested_at;
        """
        let stmt = try SQLiteCore.prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try SQLiteCore.bindText(stmt, index: 1, value: profileId)
        try SQLiteCore.bindInt64(stmt, index: 2, value: latencyMs)
        try SQLiteCore.bindInt64(stmt, index: 3, value: testedAt)
        try SQLiteCore.stepDone(db, stmt: stmt)
    }

    public func listNodeTelemetry() throws -> [NodeTelemetryRecord] {
        let db = try ensureOpen()
        return try SQLiteCore.listNodeTelemetryLocked(db)
    }

    public func recordTrafficDelta(bucketHour: Int64, profileId: String, uploadBytes: Int64, downloadBytes: Int64) throws {
        let db = try ensureOpen()
        try SQLiteCore.recordTrafficDeltaLocked(
            db,
            bucketHour: bucketHour,
            profileId: profileId,
            uploadBytes: max(0, uploadBytes),
            downloadBytes: max(0, downloadBytes)
        )
    }

    public func queryTrafficLedger(sinceHour: Int64 = 0, profileId: String? = nil) throws -> [TrafficLedgerRecord] {
        let db = try ensureOpen()
        let sql = profileId == nil
            ? "SELECT bucket_hour, profile_id, upload_bytes, download_bytes FROM traffic_ledger WHERE bucket_hour >= ? ORDER BY bucket_hour ASC, profile_id ASC;"
            : "SELECT bucket_hour, profile_id, upload_bytes, download_bytes FROM traffic_ledger WHERE bucket_hour >= ? AND profile_id = ? ORDER BY bucket_hour ASC;"
        let stmt = try SQLiteCore.prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try SQLiteCore.bindInt64(stmt, index: 1, value: sinceHour)
        if let profileId { try SQLiteCore.bindText(stmt, index: 2, value: profileId) }
        var out: [TrafficLedgerRecord] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                out.append(TrafficLedgerRecord(
                    bucketHour: sqlite3_column_int64(stmt, 0),
                    profileId: SQLiteCore.columnText(stmt, index: 1),
                    uploadBytes: sqlite3_column_int64(stmt, 2),
                    downloadBytes: sqlite3_column_int64(stmt, 3)
                ))
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw NexusDatabaseError.sqlite(code: rc, message: SQLiteCore.lastErrorMessage(db))
            }
        }
        return out
    }

    public func getHostKV(_ key: String) throws -> String? {
        let db = try ensureOpen()
        return try SQLiteCore.getHostKVLocked(db, key: key)
    }

    public func setHostKV(_ key: String, value: String) throws {
        let db = try ensureOpen()
        try SQLiteCore.setHostKVLocked(db, key: key, value: value)
        SQLiteCore.enforceFilePermissions0600(at: dbURL)
    }

    /// Atomically inserts `key` only when absent and returns the persisted value.
    public func setHostKVIfAbsent(_ key: String, value: String) throws -> String {
        try withTransaction { db in
            if let existing = try SQLiteCore.getHostKVLocked(db, key: key) {
                return existing
            }
            try SQLiteCore.setHostKVLocked(db, key: key, value: value)
            return value
        }
    }

    public func deleteHostKV(_ key: String) throws {
        let db = try ensureOpen()
        let stmt = try SQLiteCore.prepare(db, sql: "DELETE FROM host_kv WHERE key = ?;")
        defer { sqlite3_finalize(stmt) }
        try SQLiteCore.bindText(stmt, index: 1, value: key)
        try SQLiteCore.stepDone(db, stmt: stmt)
    }

    public func shrinkMemory() throws {
        let db = try ensureOpen()
        try SQLiteCore.executeRaw(db, sql: "PRAGMA shrink_memory; PRAGMA wal_checkpoint(PASSIVE);")
        SQLiteCore.enforceFilePermissions0600(at: dbURL)
    }

    private func ensureOpen() throws -> OpaquePointer {
        if let ptr = handle.pointer { return ptr }
        let parent = dbURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        SQLiteCore.preCreateRestrictedFile0600(at: dbURL)

        var rawPtr: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(dbURL.path, &rawPtr, flags, nil)
        guard rc == SQLITE_OK, let ptr = rawPtr else {
            let msg = SQLiteCore.lastErrorMessage(rawPtr)
            if let rawPtr { sqlite3_close_v2(rawPtr) }
            throw NexusDatabaseError.sqlite(code: rc, message: msg)
        }
        handle.pointer = ptr
        do {
            try SQLiteCore.executeRaw(ptr, sql: SQLiteSchemaV1.pragmasSQL)
            let currentVersion = try SQLiteCore.readInt32Pragma(ptr, sql: "PRAGMA user_version;")
            if currentVersion > Self.schemaVersion {
                throw NexusDatabaseError.unsupportedSchemaVersion(currentVersion)
            }
            if currentVersion < Self.schemaVersion {
                try SQLiteCore.executeRaw(ptr, sql: "BEGIN IMMEDIATE;")
                do {
                    try SQLiteCore.executeRaw(ptr, sql: SQLiteSchemaV1.ddlSQL)
                    try SQLiteCore.executeRaw(ptr, sql: "COMMIT;")
                } catch {
                    _ = sqlite3_exec(ptr, "ROLLBACK;", nil, nil, nil)
                    throw error
                }
            }
            SQLiteCore.enforceFilePermissions0600(at: dbURL)
        } catch {
            handle.close()
            throw error
        }
        return ptr
    }

    private func withReadTransaction<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        let db = try ensureOpen()
        try SQLiteCore.executeRaw(db, sql: "BEGIN DEFERRED;")
        do {
            let result = try body(db)
            try SQLiteCore.executeRaw(db, sql: "COMMIT;")
            return result
        } catch {
            _ = sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
            throw error
        }
    }

    private func withTransaction<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        let db = try ensureOpen()
        try SQLiteCore.executeRaw(db, sql: "BEGIN IMMEDIATE;")
        do {
            let result = try body(db)
            try SQLiteCore.executeRaw(db, sql: "COMMIT;")
            SQLiteCore.enforceFilePermissions0600(at: dbURL)
            return result
        } catch {
            _ = sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
            throw error
        }
    }
}
