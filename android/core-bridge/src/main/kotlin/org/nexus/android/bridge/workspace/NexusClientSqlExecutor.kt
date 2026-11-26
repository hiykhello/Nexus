package org.nexus.android.bridge.workspace

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Build
import org.nexus.android.bridge.profile.SecretFileIO
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Production Android `SQLiteOpenHelper` / `SQLiteDatabase` implementation of [SqlExecutor].
 * Opens lazily on first I/O call (zero main-thread disk I/O in `init`), supports API 29+ (SQLite
 * 3.22+), enforces `0600` permissions on DB + WAL/SHM sidecars, rejects schema downgrades
 * (`user_version > 1`) fail-closed, and uses bound parameters on every statement.
 */
internal class AndroidSqliteExecutor(
    context: Context,
    override val dbFile: File,
) : SqlExecutor {
    private val appContext = context.applicationContext
    private val dirPrepared = AtomicBoolean(false)

    private val helper: SQLiteOpenHelper by lazy {
        object : SQLiteOpenHelper(
            appContext,
            dbFile.absolutePath,
            null,
            NexusClientSchema.SCHEMA_VERSION,
        ) {
            override fun onConfigure(db: SQLiteDatabase) {
                db.enableWriteAheadLogging()
                db.setForeignKeyConstraintsEnabled(true)
                applyTuningPragmas(db)
            }

            override fun onCreate(db: SQLiteDatabase) {
                NexusClientSchema.DDL_STATEMENTS.forEach { db.execSQL(it) }
            }

            override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
                NexusClientSchema.DDL_STATEMENTS.forEach { db.execSQL(it) }
            }

            override fun onDowngrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
                throw IllegalStateException(
                    "Unsupported Nexus client database schema version $oldVersion (expected <= $newVersion); refusing to downgrade",
                )
            }

            override fun onOpen(db: SQLiteDatabase) {
                super.onOpen(db)
                enforceDbPermissions0600()
            }
        }
    }

    private fun ensureDirPrepared() {
        if (dirPrepared.compareAndSet(false, true)) {
            dbFile.parentFile?.let { parent ->
                parent.mkdirs()
                SecretFileIO.restrictDir0700(parent)
            }
        }
    }

    private fun readableDb(): SQLiteDatabase {
        ensureDirPrepared()
        return helper.readableDatabase
    }

    private fun writableDb(): SQLiteDatabase {
        ensureDirPrepared()
        return helper.writableDatabase
    }

    private fun applyTuningPragmas(db: SQLiteDatabase) {
        NexusClientSchema.PRAGMA_STATEMENTS
            .filterNot { it.contains("journal_mode", ignoreCase = true) || it.contains("foreign_keys", ignoreCase = true) }
            .forEach { pragma -> db.rawQuery(pragma, null).use { it.moveToFirst() } }
    }

    private fun enforceDbPermissions0600() {
        SecretFileIO.restrictFile0600(dbFile)
        SecretFileIO.restrictFile0600(File("${dbFile.path}-wal"))
        SecretFileIO.restrictFile0600(File("${dbFile.path}-shm"))
    }

    override fun <T> inTransaction(block: () -> T): T {
        val db = writableDb()
        db.beginTransactionNonExclusive()
        return try {
            val result = block()
            db.setTransactionSuccessful()
            result
        } finally {
            db.endTransaction()
            enforceDbPermissions0600()
        }
    }

    override fun <T> inReadTransaction(block: () -> T): T {
        val db = readableDb()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            db.beginTransactionReadOnly()
        } else {
            db.beginTransactionNonExclusive()
        }
        return try {
            val result = block()
            db.setTransactionSuccessful()
            result
        } finally {
            db.endTransaction()
        }
    }

    private fun tableHasRow(db: SQLiteDatabase, table: String): Boolean =
        db.rawQuery("SELECT 1 FROM $table LIMIT 1", null).use { it.moveToFirst() }

    override fun hasWorkspaceData(): Boolean {
        val db = readableDb()
        return tableHasRow(db, "workspace_meta") ||
            tableHasRow(db, "profiles") ||
            tableHasRow(db, "subscriptions") ||
            tableHasRow(db, "routing_profiles")
    }

    override fun listSubscriptions(): List<SubscriptionRow> =
        readableDb().rawQuery(
            "SELECT id, name, url, enabled, sort_order, payload_json, updated_at FROM subscriptions ORDER BY sort_order ASC, id ASC",
            null,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(SubscriptionRow(c.getString(0), c.getString(1), c.getString(2), c.getInt(3) != 0, c.getInt(4), c.getString(5), c.getLong(6)))
                }
            }
        }

    override fun replaceSubscriptions(rows: List<SubscriptionRow>) {
        val db = writableDb()
        db.execSQL("DELETE FROM subscriptions")
        db.compileStatement(
            "INSERT OR REPLACE INTO subscriptions(id, name, url, enabled, sort_order, payload_json, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
        ).use { s ->
            for (r in rows) {
                s.clearBindings()
                s.bindString(1, r.id); s.bindString(2, r.name); s.bindString(3, r.url)
                s.bindLong(4, if (r.enabled) 1L else 0L); s.bindLong(5, r.sortOrder.toLong())
                s.bindString(6, r.payloadJson); s.bindLong(7, r.updatedAt)
                s.executeInsert()
            }
        }
    }

    override fun listProfileSummaries(): List<ProfileIndexRow> =
        readableDb().rawQuery(
            "SELECT id, kind, subscription_id, name, protocol, server, port, sort_order, pinned, updated_at FROM profiles ORDER BY sort_order ASC, id ASC",
            null,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        ProfileIndexRow(
                            c.getString(0), c.getString(1), c.getString(2), c.getString(3), c.getString(4),
                            c.getString(5), c.getInt(6), c.getInt(7), c.getInt(8) != 0, c.getLong(9),
                        ),
                    )
                }
            }
        }

    override fun listProfilesWithPayloads(): List<Pair<ProfileIndexRow, String>> =
        readableDb().rawQuery(
            """
            SELECT p.id, p.kind, p.subscription_id, p.name, p.protocol, p.server, p.port,
                   p.sort_order, p.pinned, p.updated_at, pp.payload_json
            FROM profiles p
            INNER JOIN profile_payloads pp ON p.id = pp.profile_id
            ORDER BY p.sort_order ASC, p.id ASC
            """.trimIndent(),
            null,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    val idx = ProfileIndexRow(
                        c.getString(0), c.getString(1), c.getString(2), c.getString(3), c.getString(4),
                        c.getString(5), c.getInt(6), c.getInt(7), c.getInt(8) != 0, c.getLong(9),
                    )
                    add(idx to c.getString(10))
                }
            }
        }

    override fun replaceProfiles(indexRows: List<ProfileIndexRow>, payloads: Map<String, String>) {
        val db = writableDb()
        val existingPinned = hashSetOf<String>()
        val existingIds = mutableListOf<String>()
        db.rawQuery("SELECT id, pinned FROM profiles", null).use { c ->
            while (c.moveToNext()) {
                val id = c.getString(0)
                existingIds.add(id)
                if (c.getInt(1) != 0) existingPinned.add(id)
            }
        }
        val keepIds = indexRows.mapTo(hashSetOf()) { it.id }
        db.compileStatement("DELETE FROM profiles WHERE id = ?").use { s ->
            for (oldId in existingIds) {
                if (oldId !in keepIds) {
                    s.clearBindings()
                    s.bindString(1, oldId)
                    s.executeUpdateDelete()
                }
            }
        }
        db.compileStatement(
            "INSERT OR REPLACE INTO profiles(id, kind, subscription_id, name, protocol, server, port, sort_order, pinned, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).use { ps ->
            db.compileStatement("INSERT OR REPLACE INTO profile_payloads(profile_id, payload_json) VALUES(?, ?)").use { pps ->
                for (r in indexRows) {
                    val pinned = if (r.pinned || r.id in existingPinned) 1L else 0L
                    ps.clearBindings()
                    ps.bindString(1, r.id); ps.bindString(2, r.kind); ps.bindString(3, r.subscriptionId)
                    ps.bindString(4, r.name); ps.bindString(5, r.protocol); ps.bindString(6, r.server)
                    ps.bindLong(7, r.port.toLong()); ps.bindLong(8, r.sortOrder.toLong())
                    ps.bindLong(9, pinned); ps.bindLong(10, r.updatedAt)
                    ps.executeInsert()

                    pps.clearBindings()
                    pps.bindString(1, r.id)
                    pps.bindString(2, payloads[r.id].orEmpty())
                    pps.executeInsert()
                }
            }
        }
    }

    override fun setProfilePinned(profileId: String, pinned: Boolean) {
        writableDb().compileStatement("UPDATE profiles SET pinned = ? WHERE id = ?").use { s ->
            s.bindLong(1, if (pinned) 1L else 0L)
            s.bindString(2, profileId)
            s.executeUpdateDelete()
        }
    }

    override fun listRoutingProfiles(): List<RoutingProfileRow> =
        readableDb().rawQuery(
            "SELECT id, name, sort_order, payload_json, updated_at FROM routing_profiles ORDER BY sort_order ASC, id ASC",
            null,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(RoutingProfileRow(c.getString(0), c.getString(1), c.getInt(2), c.getString(3), c.getLong(4)))
                }
            }
        }

    override fun replaceRoutingProfiles(rows: List<RoutingProfileRow>) {
        val db = writableDb()
        db.execSQL("DELETE FROM routing_profiles")
        db.compileStatement(
            "INSERT OR REPLACE INTO routing_profiles(id, name, sort_order, payload_json, updated_at) VALUES(?, ?, ?, ?, ?)",
        ).use { s ->
            for (r in rows) {
                s.clearBindings()
                s.bindString(1, r.id); s.bindString(2, r.name); s.bindLong(3, r.sortOrder.toLong())
                s.bindString(4, r.payloadJson); s.bindLong(5, r.updatedAt)
                s.executeInsert()
            }
        }
    }

    override fun getWorkspaceMeta(): Map<String, String> =
        readableDb().rawQuery("SELECT key, value_json FROM workspace_meta", null).use { c ->
            buildMap { while (c.moveToNext()) put(c.getString(0), c.getString(1)) }
        }

    override fun putWorkspaceMeta(entries: Map<String, String>) {
        writableDb().compileStatement("INSERT OR REPLACE INTO workspace_meta(key, value_json) VALUES(?, ?)").use { s ->
            entries.forEach { (k, v) ->
                s.clearBindings(); s.bindString(1, k); s.bindString(2, v); s.executeInsert()
            }
        }
    }

    override fun listNodeTelemetry(): List<NodeTelemetryRecord> =
        readableDb().rawQuery(
            "SELECT profile_id, latency_ms, ewma_ms, status_code, state, tested_at FROM node_telemetry",
            null,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(NodeTelemetryRecord(c.getString(0), c.getLong(1), c.getLong(2), c.getInt(3), c.getString(4), c.getLong(5)))
                }
            }
        }

    override fun replaceNodeTelemetry(rows: List<NodeTelemetryRecord>) {
        writableDb().execSQL("DELETE FROM node_telemetry")
        rows.forEach { upsertNodeTelemetry(it) }
    }

    override fun upsertNodeTelemetry(row: NodeTelemetryRecord) {
        writableDb().compileStatement(
            "INSERT OR REPLACE INTO node_telemetry(profile_id, latency_ms, ewma_ms, status_code, state, tested_at) VALUES(?, ?, ?, ?, ?, ?)",
        ).use { s ->
            s.bindString(1, row.profileId); s.bindLong(2, row.latencyMs); s.bindLong(3, row.ewmaMs)
            s.bindLong(4, row.statusCode.toLong()); s.bindString(5, row.state); s.bindLong(6, row.testedAtMs)
            s.executeInsert()
        }
    }

    override fun updateNodeLatency(profileId: String, latencyMs: Long, testedAtMs: Long) {
        val db = writableDb()
        val updated = db.compileStatement("UPDATE node_telemetry SET latency_ms = ?, tested_at = ? WHERE profile_id = ?").use { s ->
            s.bindLong(1, latencyMs); s.bindLong(2, testedAtMs); s.bindString(3, profileId)
            s.executeUpdateDelete()
        }
        if (updated == 0) {
            upsertNodeTelemetry(
                NodeTelemetryRecord(
                    profileId = profileId,
                    latencyMs = latencyMs,
                    ewmaMs = latencyMs,
                    statusCode = if (latencyMs >= 0L) 204 else 0,
                    state = if (latencyMs >= 0L) "healthy" else "timeout",
                    testedAtMs = testedAtMs,
                ),
            )
        }
    }

    override fun recordTrafficDelta(bucketHour: Long, profileId: String, uploadBytes: Long, downloadBytes: Long) {
        inTransaction {
            val db = writableDb()
            var prevUp = 0L
            var prevDown = 0L
            db.rawQuery(
                "SELECT upload_bytes, download_bytes FROM traffic_ledger WHERE bucket_hour = ? AND profile_id = ?",
                arrayOf(bucketHour.toString(), profileId),
            ).use { c ->
                if (c.moveToFirst()) {
                    prevUp = c.getLong(0); prevDown = c.getLong(1)
                }
            }
            db.compileStatement(
                "INSERT OR REPLACE INTO traffic_ledger(bucket_hour, profile_id, upload_bytes, download_bytes) VALUES(?, ?, ?, ?)",
            ).use { s ->
                s.bindLong(1, bucketHour); s.bindString(2, profileId)
                s.bindLong(3, (prevUp + uploadBytes).coerceAtLeast(0L))
                s.bindLong(4, (prevDown + downloadBytes).coerceAtLeast(0L))
                s.executeInsert()
            }
        }
    }

    override fun queryTrafficLedger(sinceHour: Long): List<TrafficLedgerEntry> =
        readableDb().rawQuery(
            "SELECT bucket_hour, profile_id, upload_bytes, download_bytes FROM traffic_ledger WHERE bucket_hour >= ? ORDER BY bucket_hour ASC, profile_id ASC",
            arrayOf(sinceHour.toString()),
        ).use { c ->
            buildList {
                while (c.moveToNext()) add(TrafficLedgerEntry(c.getLong(0), c.getString(1), c.getLong(2), c.getLong(3)))
            }
        }

    override fun getHostKv(key: String): String? =
        readableDb().rawQuery("SELECT value_json FROM host_kv WHERE key = ?", arrayOf(key)).use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }

    override fun setHostKv(key: String, valueJson: String) {
        writableDb().compileStatement("INSERT OR REPLACE INTO host_kv(key, value_json) VALUES(?, ?)").use { s ->
            s.bindString(1, key); s.bindString(2, valueJson); s.executeInsert()
        }
    }

    override fun deleteHostKv(key: String) {
        writableDb().compileStatement("DELETE FROM host_kv WHERE key = ?").use { s ->
            s.bindString(1, key); s.executeUpdateDelete()
        }
    }

    override fun shrinkMemory() {
        val db = writableDb()
        NexusClientSchema.SHRINK_STATEMENTS.forEach { pragma ->
            runCatching { db.rawQuery(pragma, null).use { it.moveToFirst() } }
        }
        enforceDbPermissions0600()
    }

    override fun close() {
        if (dirPrepared.get()) runCatching { helper.close() }
    }
}
