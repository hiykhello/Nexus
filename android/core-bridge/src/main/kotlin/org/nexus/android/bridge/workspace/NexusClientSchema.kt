package org.nexus.android.bridge.workspace

import java.io.File

/**
 * Shared cross-platform SQLite 3 (WAL) Schema v1 constants matching Desktop & Apple verbatim.
 */
object NexusClientSchema {
    const val SCHEMA_VERSION = 1
    const val DEFAULT_DB_NAME = "nexus-client.db"

    val PRAGMA_STATEMENTS: List<String> = listOf(
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA foreign_keys=ON",
        "PRAGMA busy_timeout=5000",
        "PRAGMA temp_store=MEMORY",
        "PRAGMA mmap_size=0",
        "PRAGMA cache_size=-2000",
    )

    val DDL_STATEMENTS: List<String> = listOf(
        """
        CREATE TABLE IF NOT EXISTS subscriptions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT 0
        )
        """.trimIndent(),
        """
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
        )
        """.trimIndent(),
        "CREATE INDEX IF NOT EXISTS idx_profiles_sub_order ON profiles(subscription_id, sort_order)",
        "CREATE INDEX IF NOT EXISTS idx_profiles_kind ON profiles(kind)",
        "CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON profiles(protocol)",
        "CREATE INDEX IF NOT EXISTS idx_profiles_pinned ON profiles(pinned)",
        """
        CREATE TABLE IF NOT EXISTS profile_payloads (
            profile_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
            payload_json TEXT NOT NULL
        )
        """.trimIndent(),
        """
        CREATE TABLE IF NOT EXISTS routing_profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT 0
        )
        """.trimIndent(),
        """
        CREATE TABLE IF NOT EXISTS workspace_meta (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL
        )
        """.trimIndent(),
        """
        CREATE TABLE IF NOT EXISTS node_telemetry (
            profile_id TEXT PRIMARY KEY,
            latency_ms INTEGER NOT NULL DEFAULT -1,
            ewma_ms INTEGER NOT NULL DEFAULT -1,
            status_code INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT '',
            tested_at INTEGER NOT NULL DEFAULT 0
        )
        """.trimIndent(),
        """
        CREATE TABLE IF NOT EXISTS traffic_ledger (
            bucket_hour INTEGER NOT NULL,
            profile_id TEXT NOT NULL,
            upload_bytes INTEGER NOT NULL DEFAULT 0,
            download_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_hour, profile_id)
        )
        """.trimIndent(),
        """
        CREATE TABLE IF NOT EXISTS host_kv (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL
        )
        """.trimIndent(),
    )

    val SHRINK_STATEMENTS: List<String> = listOf(
        "PRAGMA shrink_memory",
        "PRAGMA wal_checkpoint(PASSIVE)",
    )
}

internal data class SubscriptionRow(
    val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean,
    val sortOrder: Int,
    val payloadJson: String,
    val updatedAt: Long,
)

internal data class ProfileIndexRow(
    val id: String,
    val kind: String,
    val subscriptionId: String,
    val name: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val sortOrder: Int,
    val pinned: Boolean,
    val updatedAt: Long,
)

internal data class RoutingProfileRow(
    val id: String,
    val name: String,
    val sortOrder: Int,
    val payloadJson: String,
    val updatedAt: Long,
)

data class ProfileSummary(
    val id: String,
    val kind: ProfileKind,
    val subscriptionId: String,
    val name: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val sortOrder: Int,
    val pinned: Boolean,
    val updatedAtMs: Long,
)

data class NodeTelemetryRecord(
    val profileId: String,
    val latencyMs: Long = -1L,
    val ewmaMs: Long = -1L,
    val statusCode: Int = 0,
    val state: String = "",
    val testedAtMs: Long = 0L,
)

data class TrafficLedgerEntry(
    val bucketHour: Long,
    val profileId: String,
    val uploadBytes: Long,
    val downloadBytes: Long,
)

internal interface SqlExecutor : AutoCloseable {
    val dbFile: File?
    fun <T> inTransaction(block: () -> T): T
    fun <T> inReadTransaction(block: () -> T): T
    fun hasWorkspaceData(): Boolean
    fun listSubscriptions(): List<SubscriptionRow>
    fun replaceSubscriptions(rows: List<SubscriptionRow>)
    fun listProfileSummaries(): List<ProfileIndexRow>
    fun listProfilesWithPayloads(): List<Pair<ProfileIndexRow, String>>
    fun replaceProfiles(indexRows: List<ProfileIndexRow>, payloads: Map<String, String>)
    fun setProfilePinned(profileId: String, pinned: Boolean)
    fun listRoutingProfiles(): List<RoutingProfileRow>
    fun replaceRoutingProfiles(rows: List<RoutingProfileRow>)
    fun getWorkspaceMeta(): Map<String, String>
    fun putWorkspaceMeta(entries: Map<String, String>)
    fun listNodeTelemetry(): List<NodeTelemetryRecord>
    fun replaceNodeTelemetry(rows: List<NodeTelemetryRecord>)
    fun upsertNodeTelemetry(row: NodeTelemetryRecord)
    fun updateNodeLatency(profileId: String, latencyMs: Long, testedAtMs: Long)
    fun hasTrafficLedgerData(): Boolean
    fun recordTrafficDelta(bucketHour: Long, profileId: String, uploadBytes: Long, downloadBytes: Long)
    fun queryTrafficLedger(sinceHour: Long): List<TrafficLedgerEntry>
    fun getHostKv(key: String): String?
    fun setHostKv(key: String, valueJson: String)
    fun deleteHostKv(key: String)
    fun shrinkMemory()
}
