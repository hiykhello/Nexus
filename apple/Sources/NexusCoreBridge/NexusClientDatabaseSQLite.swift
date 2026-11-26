import Foundation
import SQLite3
#if canImport(Darwin)
import Darwin
#endif

/// Low-level C-interop SQLite 3 binding, execution, JSON coding, and `0600` permission helpers
/// used exclusively by `NexusClientDatabase`.
internal enum SQLiteCore {
    static var sqliteTransient: sqlite3_destructor_type {
        unsafeBitCast(Int(-1), to: sqlite3_destructor_type.self)
    }

    static func prepare(_ db: OpaquePointer, sql: String) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
        }
        return stmt
    }

    static func executeRaw(_ db: OpaquePointer, sql: String) throws {
        var errPtr: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errPtr)
        if rc != SQLITE_OK {
            let msg = errPtr.map { String(cString: $0) } ?? lastErrorMessage(db)
            if let errPtr { sqlite3_free(errPtr) }
            throw NexusDatabaseError.sqlite(code: rc, message: msg)
        }
        if let errPtr { sqlite3_free(errPtr) }
    }

    static func readInt32Pragma(_ db: OpaquePointer, sql: String) throws -> Int32 {
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_ROW else {
            throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
        }
        return sqlite3_column_int(stmt, 0)
    }

    static func readInt64Scalar(_ db: OpaquePointer, sql: String) throws -> Int64 {
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_ROW else {
            throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
        }
        return sqlite3_column_int64(stmt, 0)
    }

    static func bindText(_ stmt: OpaquePointer, index: Int32, value: String) throws {
        let rc = value.withCString { cstr in
            sqlite3_bind_text(stmt, index, cstr, -1, sqliteTransient)
        }
        guard rc == SQLITE_OK else {
            throw NexusDatabaseError.sqlite(code: rc, message: "sqlite3_bind_text(\(index)) failed")
        }
    }

    static func bindInt64(_ stmt: OpaquePointer, index: Int32, value: Int64) throws {
        let rc = sqlite3_bind_int64(stmt, index, value)
        guard rc == SQLITE_OK else {
            throw NexusDatabaseError.sqlite(code: rc, message: "sqlite3_bind_int64(\(index)) failed")
        }
    }

    static func stepDone(_ db: OpaquePointer, stmt: OpaquePointer) throws {
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
        }
    }

    static func columnText(_ stmt: OpaquePointer, index: Int32) -> String {
        guard let ptr = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: ptr)
    }

    static func lastErrorMessage(_ db: OpaquePointer?) -> String {
        guard let db, let ptr = sqlite3_errmsg(db) else { return "unknown sqlite3 error" }
        return String(cString: ptr)
    }

    static func hasWorkspaceDataLocked(_ db: OpaquePointer) throws -> Bool {
        let sql = """
        SELECT (SELECT COUNT(*) FROM workspace_meta)
             + (SELECT COUNT(*) FROM profiles)
             + (SELECT COUNT(*) FROM subscriptions)
             + (SELECT COUNT(*) FROM routing_profiles);
        """
        return try readInt64Scalar(db, sql: sql) > 0
    }

    static func hasTelemetryDataLocked(_ db: OpaquePointer) throws -> Bool {
        let sql = """
        SELECT (SELECT COUNT(*) FROM host_kv WHERE key = 'telemetry_state')
             + (SELECT COUNT(*) FROM node_telemetry)
             + (SELECT COUNT(*) FROM traffic_ledger);
        """
        return try readInt64Scalar(db, sql: sql) > 0
    }

    static func getHostKVLocked(_ db: OpaquePointer, key: String) throws -> String? {
        let stmt = try prepare(db, sql: "SELECT value_json FROM host_kv WHERE key = ?;")
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, index: 1, value: key)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_ROW { return columnText(stmt, index: 0) }
        if rc == SQLITE_DONE { return nil }
        throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
    }

    static func readMetaMap(_ db: OpaquePointer) throws -> [String: String] {
        let stmt = try prepare(db, sql: "SELECT key, value_json FROM workspace_meta;")
        defer { sqlite3_finalize(stmt) }
        var map: [String: String] = [:]
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                map[columnText(stmt, index: 0)] = columnText(stmt, index: 1)
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
            }
        }
        return map
    }

    static func readJSONRows<T>(_ db: OpaquePointer, sql: String, decode: (String) throws -> T) throws -> [T] {
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        var rows: [T] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                rows.append(try decode(columnText(stmt, index: 0)))
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
            }
        }
        return rows
    }

    static func loadWorkspaceLocked(_ db: OpaquePointer) throws -> WorkspaceDocument? {
        guard try hasWorkspaceDataLocked(db) else { return nil }
        let meta = try readMetaMap(db)

        let schemaVer = meta["schema_version"].flatMap(Int.init) ?? WorkspaceDocument.currentSchemaVersion
        guard schemaVer == WorkspaceDocument.currentSchemaVersion else {
            throw WorkspaceSchemaError.unsupportedSchemaVersion(schemaVer)
        }
        let revision = (meta["sync_revision"] ?? meta["revision"]).flatMap(Int64.init) ?? 1
        let updatedAtMs = meta["updated_at_ms"].flatMap(Int64.init) ?? 0
        let dns = try meta["dns"].map { try decodeJSON(WorkspaceDnsConfig.self, from: $0) } ?? WorkspaceDnsConfig()
        let assets = try meta["rule_set_assets"].map { try decodeJSON([WorkspaceRuleSetAsset].self, from: $0) } ?? []
        let fullTemplate = try meta["full_template"].map { try decodeJSON(WorkspaceFullTemplateConfig.self, from: $0) } ?? WorkspaceFullTemplateConfig()

        let subs = try readJSONRows(db, sql: "SELECT payload_json FROM subscriptions ORDER BY sort_order ASC, id ASC;") {
            try decodeJSON(WorkspaceSubscriptionItem.self, from: $0)
        }
        let profiles = try readJSONRows(
            db,
            sql: "SELECT pp.payload_json FROM profiles p JOIN profile_payloads pp ON p.id = pp.profile_id ORDER BY p.sort_order ASC, p.id ASC;"
        ) {
            try decodeJSON(WorkspaceProfileItem.self, from: $0)
        }
        var routings = try readJSONRows(db, sql: "SELECT payload_json FROM routing_profiles ORDER BY sort_order ASC, id ASC;") {
            try decodeJSON(WorkspaceRoutingProfile.self, from: $0)
        }
        if routings.isEmpty {
            routings = WorkspaceDocument.defaultRoutingProfiles()
        } else if let rawActive = meta["active_routing_id"] {
            let activeId = ((try? decodeJSON(String.self, from: rawActive)) ?? rawActive)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !activeId.isEmpty && routings.contains(where: { $0.id == activeId }) {
                for idx in routings.indices {
                    routings[idx].isActive = (routings[idx].id == activeId)
                }
            }
        }

        return WorkspaceDocument(
            schemaVersion: schemaVer,
            revision: revision,
            updatedAtMs: updatedAtMs,
            profiles: profiles,
            subscriptions: subs,
            routingProfiles: routings,
            dns: dns,
            ruleSetAssets: assets,
            fullTemplate: fullTemplate
        )
    }

    static func writeWorkspaceLocked(_ db: OpaquePointer, doc: WorkspaceDocument) throws {
        let pinnedIDs = try readPinnedProfileIDs(db)
        try executeRaw(db, sql: "DELETE FROM subscriptions; DELETE FROM profiles; DELETE FROM routing_profiles;")

        let subStmt = try prepare(
            db,
            sql: "INSERT INTO subscriptions(id, name, url, enabled, sort_order, payload_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?);"
        )
        defer { sqlite3_finalize(subStmt) }
        for (idx, sub) in doc.subscriptions.enumerated() {
            sqlite3_reset(subStmt)
            sqlite3_clear_bindings(subStmt)
            try bindText(subStmt, index: 1, value: sub.id)
            try bindText(subStmt, index: 2, value: sub.remarks)
            try bindText(subStmt, index: 3, value: sub.url)
            try bindInt64(subStmt, index: 4, value: sub.enabled ? 1 : 0)
            try bindInt64(subStmt, index: 5, value: Int64(idx))
            try bindText(subStmt, index: 6, value: try encodeJSON(sub))
            try bindInt64(subStmt, index: 7, value: sub.updatedAtMs)
            try stepDone(db, stmt: subStmt)
        }

        let profStmt = try prepare(
            db,
            sql: "INSERT INTO profiles(id, kind, subscription_id, name, protocol, server, port, sort_order, pinned, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
        )
        defer { sqlite3_finalize(profStmt) }
        let payloadStmt = try prepare(
            db,
            sql: "INSERT INTO profile_payloads(profile_id, payload_json) VALUES (?, ?);"
        )
        defer { sqlite3_finalize(payloadStmt) }
        for (idx, prof) in doc.profiles.enumerated() {
            sqlite3_reset(profStmt)
            sqlite3_clear_bindings(profStmt)
            try bindText(profStmt, index: 1, value: prof.id)
            try bindText(profStmt, index: 2, value: prof.kind.rawValue)
            try bindText(profStmt, index: 3, value: prof.subscriptionId)
            try bindText(profStmt, index: 4, value: prof.remarks)
            try bindText(profStmt, index: 5, value: prof.node?.protocolName ?? "")
            try bindText(profStmt, index: 6, value: prof.node?.server ?? "")
            try bindInt64(profStmt, index: 7, value: Int64(prof.node?.port ?? 0))
            try bindInt64(profStmt, index: 8, value: Int64(idx))
            try bindInt64(profStmt, index: 9, value: pinnedIDs.contains(prof.id) ? 1 : 0)
            try bindInt64(profStmt, index: 10, value: doc.updatedAtMs)
            try stepDone(db, stmt: profStmt)

            sqlite3_reset(payloadStmt)
            sqlite3_clear_bindings(payloadStmt)
            try bindText(payloadStmt, index: 1, value: prof.id)
            try bindText(payloadStmt, index: 2, value: try encodeJSON(prof))
            try stepDone(db, stmt: payloadStmt)
        }

        let routeStmt = try prepare(
            db,
            sql: "INSERT INTO routing_profiles(id, name, sort_order, payload_json, updated_at) VALUES (?, ?, ?, ?, ?);"
        )
        defer { sqlite3_finalize(routeStmt) }
        for (idx, rp) in doc.routingProfiles.enumerated() {
            sqlite3_reset(routeStmt)
            sqlite3_clear_bindings(routeStmt)
            try bindText(routeStmt, index: 1, value: rp.id)
            try bindText(routeStmt, index: 2, value: rp.name)
            try bindInt64(routeStmt, index: 3, value: Int64(idx))
            try bindText(routeStmt, index: 4, value: try encodeJSON(rp))
            try bindInt64(routeStmt, index: 5, value: doc.updatedAtMs)
            try stepDone(db, stmt: routeStmt)
        }

        let metaEntries: [(String, String)] = [
            ("schema_version", "\(WorkspaceDocument.currentSchemaVersion)"),
            ("sync_revision", "\(max(1, doc.revision))"),
            ("updated_at_ms", "\(max(0, doc.updatedAtMs))"),
            ("dns", try encodeJSON(doc.dns)),
            ("rule_set_assets", try encodeJSON(doc.ruleSetAssets)),
            ("full_template", try encodeJSON(doc.fullTemplate)),
            ("active_routing_id", try encodeJSON(doc.activeRoutingProfile().id)),
        ]
        let metaStmt = try prepare(
            db,
            sql: "INSERT INTO workspace_meta(key, value_json) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;"
        )
        defer { sqlite3_finalize(metaStmt) }
        for (k, v) in metaEntries {
            sqlite3_reset(metaStmt)
            sqlite3_clear_bindings(metaStmt)
            try bindText(metaStmt, index: 1, value: k)
            try bindText(metaStmt, index: 2, value: v)
            try stepDone(db, stmt: metaStmt)
        }
    }

    private static func readPinnedProfileIDs(_ db: OpaquePointer) throws -> Set<String> {
        let stmt = try prepare(db, sql: "SELECT id FROM profiles WHERE pinned != 0;")
        defer { sqlite3_finalize(stmt) }
        var pinned = Set<String>()
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                pinned.insert(columnText(stmt, index: 0))
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
            }
        }
        return pinned
    }

    static func listNodeTelemetryLocked(_ db: OpaquePointer) throws -> [NodeTelemetryRecord] {
        let stmt = try prepare(
            db,
            sql: "SELECT profile_id, latency_ms, ewma_ms, status_code, state, tested_at FROM node_telemetry ORDER BY profile_id ASC;"
        )
        defer { sqlite3_finalize(stmt) }
        var rows: [NodeTelemetryRecord] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_ROW {
                rows.append(NodeTelemetryRecord(
                    profileId: columnText(stmt, index: 0),
                    latencyMs: sqlite3_column_int64(stmt, 1),
                    ewmaMs: sqlite3_column_int64(stmt, 2),
                    statusCode: Int(sqlite3_column_int(stmt, 3)),
                    state: columnText(stmt, index: 4),
                    testedAt: sqlite3_column_int64(stmt, 5)
                ))
            } else if rc == SQLITE_DONE {
                break
            } else {
                throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
            }
        }
        return rows
    }

    static func saveTelemetryLocked(_ db: OpaquePointer, doc: TelemetryDocument) throws {
        let meta = TelemetryMetaState(
            activeProfileId: doc.activeProfileId,
            outboundMode: doc.outboundMode,
            unreadUnexpectedCrash: doc.unreadUnexpectedCrash,
            lastCrashTimestampMs: doc.lastCrashTimestampMs,
            lastCrashReason: doc.lastCrashReason
        )
        try setHostKVLocked(db, key: "telemetry_state", value: try encodeJSON(meta))
        let upsertSQL = """
        INSERT INTO node_telemetry(profile_id, latency_ms, ewma_ms, status_code, state, tested_at)
        VALUES (?, ?, -1, 0, '', ?)
        ON CONFLICT(profile_id) DO UPDATE SET
            latency_ms = excluded.latency_ms,
            tested_at = excluded.tested_at;
        """
        let stmt = try prepare(db, sql: upsertSQL)
        defer { sqlite3_finalize(stmt) }
        let countStmt = try prepare(db, sql: "SELECT COUNT(*) FROM traffic_ledger WHERE profile_id = ?;")
        defer { sqlite3_finalize(countStmt) }
        for (pid, entry) in doc.profiles {
            sqlite3_reset(stmt)
            sqlite3_clear_bindings(stmt)
            try bindText(stmt, index: 1, value: pid)
            try bindInt64(stmt, index: 2, value: entry.latencyMs)
            try bindInt64(stmt, index: 3, value: entry.lastTestedMs)
            try stepDone(db, stmt: stmt)
            if entry.uploadBytes > 0 || entry.downloadBytes > 0 {
                sqlite3_reset(countStmt)
                sqlite3_clear_bindings(countStmt)
                try bindText(countStmt, index: 1, value: pid)
                let rc = sqlite3_step(countStmt)
                guard rc == SQLITE_ROW else {
                    throw NexusDatabaseError.sqlite(code: rc, message: lastErrorMessage(db))
                }
                if sqlite3_column_int64(countStmt, 0) == 0 {
                    try recordTrafficDeltaLocked(
                        db,
                        bucketHour: 0,
                        profileId: pid,
                        uploadBytes: entry.uploadBytes,
                        downloadBytes: entry.downloadBytes
                    )
                }
            }
        }
    }

    static func setHostKVLocked(_ db: OpaquePointer, key: String, value: String) throws {
        let sql = "INSERT INTO host_kv(key, value_json) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;"
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try bindText(stmt, index: 1, value: key)
        try bindText(stmt, index: 2, value: value)
        try stepDone(db, stmt: stmt)
    }

    static func recordTrafficDeltaLocked(
        _ db: OpaquePointer,
        bucketHour: Int64,
        profileId: String,
        uploadBytes: Int64,
        downloadBytes: Int64
    ) throws {
        let sql = """
        INSERT INTO traffic_ledger(bucket_hour, profile_id, upload_bytes, download_bytes)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(bucket_hour, profile_id) DO UPDATE SET
            upload_bytes = upload_bytes + excluded.upload_bytes,
            download_bytes = download_bytes + excluded.download_bytes;
        """
        let stmt = try prepare(db, sql: sql)
        defer { sqlite3_finalize(stmt) }
        try bindInt64(stmt, index: 1, value: bucketHour)
        try bindText(stmt, index: 2, value: profileId)
        try bindInt64(stmt, index: 3, value: uploadBytes)
        try bindInt64(stmt, index: 4, value: downloadBytes)
        try stepDone(db, stmt: stmt)
    }

    static func encodeJSON<T: Encodable>(_ value: T) throws -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try enc.encode(value)
        guard let text = String(data: data, encoding: .utf8) else { throw NexusDatabaseError.invalidUTF8 }
        return text
    }

    static func decodeJSON<T: Decodable>(_ type: T.Type, from text: String) throws -> T {
        guard let data = text.data(using: .utf8) else { throw NexusDatabaseError.invalidUTF8 }
        return try JSONDecoder().decode(type, from: data)
    }

    static func preCreateRestrictedFile0600(at url: URL) {
        #if canImport(Darwin)
        let fd = Darwin.open(url.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        if fd >= 0 {
            _ = Darwin.fchmod(fd, mode_t(0o600))
            _ = Darwin.close(fd)
        }
        #endif
    }

    static func enforceFilePermissions0600(at url: URL) {
        let paths = [url.path, url.path + "-wal", url.path + "-shm"]
        #if canImport(Darwin)
        for path in paths where FileManager.default.fileExists(atPath: path) {
            _ = Darwin.chmod(path, mode_t(0o600))
        }
        #else
        for path in paths where FileManager.default.fileExists(atPath: path) {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        }
        #endif
    }
}
