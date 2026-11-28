package org.nexus.android.bridge.workspace

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Unified Android SQLite 3 (WAL) Client Store implementing Schema v1 (`PRAGMA user_version = 1`),
 * matching Desktop and Apple tables identically:
 * - Vertical split: `profiles` (index) + `profile_payloads` (`ON DELETE CASCADE`)
 * - `subscriptions`, `routing_profiles`, `workspace_meta`
 * - `node_telemetry`, `traffic_ledger`
 * - `host_kv` (host-only, NEVER synced; WebDAV/E2EE secrets NEVER enter SQLite)
 */
class NexusClientDatabase internal constructor(
    internal val executor: SqlExecutor,
    private val registryKey: String? = null,
) : AutoCloseable {
    val dbFile: File? get() = executor.dbFile

    fun hasWorkspaceData(): Boolean = executor.inReadTransaction { executor.hasWorkspaceData() }

    fun loadWorkspace(): WorkspaceDocument? = executor.inReadTransaction {
        val meta = executor.getWorkspaceMeta()
        val subs = executor.listSubscriptions()
        val profilesWithPayloads = executor.listProfilesWithPayloads()
        val routings = executor.listRoutingProfiles()
        if (meta.isEmpty() && subs.isEmpty() && profilesWithPayloads.isEmpty() && routings.isEmpty()) {
            return@inReadTransaction null
        }

        val version = meta[META_SCHEMA_VERSION]?.trim()?.toIntOrNull() ?: WorkspaceDocument.SCHEMA_VERSION
        require(version == WorkspaceDocument.SCHEMA_VERSION) {
            "Unsupported workspace schema_version in SQLite: $version"
        }
        val revision = meta[META_SYNC_REVISION]?.trim()?.toLongOrNull()?.coerceAtLeast(1L) ?: 1L
        val updatedAtMs = meta[META_UPDATED_AT_MS]?.trim()?.toLongOrNull()?.coerceAtLeast(0L) ?: 0L
        val activeRoutingId = meta[META_ACTIVE_ROUTING_ID]?.let { decodeJsonString(it) }.orEmpty()

        val decodedSubs = subs.map { WorkspaceJsonCodec.decodeSubscription(JSONObject(it.payloadJson)) }
        val decodedProfiles = profilesWithPayloads.map { (_, payloadJson) ->
            WorkspaceJsonCodec.decodeProfile(JSONObject(payloadJson))
        }
        val rawRoutings = routings.map { WorkspaceJsonCodec.decodeRoutingProfile(JSONObject(it.payloadJson)) }
            .ifEmpty { WorkspaceDefaults.defaultRoutingProfiles() }
        val decodedRoutings = if (activeRoutingId.isNotEmpty() && rawRoutings.any { it.id == activeRoutingId }) {
            rawRoutings.map { it.copy(isActive = it.id == activeRoutingId) }
        } else {
            rawRoutings
        }
        val dns = meta[META_DNS]?.takeIf { it.isNotBlank() }
            ?.let { WorkspaceJsonCodec.decodeDns(JSONObject(it)) } ?: DnsConfig()
        val ruleSets = meta[META_RULE_SET_ASSETS]?.takeIf { it.isNotBlank() }
            ?.let { raw ->
                val arr = JSONArray(raw)
                buildList(arr.length()) {
                    for (i in 0 until arr.length()) {
                        arr.optJSONObject(i)?.let { add(WorkspaceJsonCodec.decodeRuleSetAsset(it)) }
                    }
                }
            }.orEmpty()
        val fullTemplate = meta[META_FULL_TEMPLATE]?.takeIf { it.isNotBlank() }
            ?.let { WorkspaceJsonCodec.decodeFullTemplate(JSONObject(it)) } ?: FullTemplateConfig()

        WorkspaceDocument(
            schemaVersion = WorkspaceDocument.SCHEMA_VERSION,
            revision = revision,
            updatedAtMs = updatedAtMs,
            profiles = decodedProfiles,
            subscriptions = decodedSubs,
            routingProfiles = decodedRoutings,
            dns = dns,
            ruleSetAssets = ruleSets,
            fullTemplate = fullTemplate,
        )
    }

    fun saveWorkspace(doc: WorkspaceDocument) {
        executor.inTransaction { writeWorkspaceLocked(doc) }
    }

    fun saveWorkspaceIfEmpty(doc: WorkspaceDocument): Boolean = executor.inTransaction {
        if (executor.hasWorkspaceData()) return@inTransaction false
        writeWorkspaceLocked(doc)
        true
    }

    private fun writeWorkspaceLocked(doc: WorkspaceDocument) {
        val subRows = doc.subscriptions.mapIndexed { idx, s ->
            SubscriptionRow(
                id = s.id,
                name = s.remarks,
                url = s.url,
                enabled = s.enabled,
                sortOrder = idx,
                payloadJson = WorkspaceJsonCodec.encodeSubscription(s).toString(),
                updatedAt = s.updatedAtMs,
            )
        }
        val profileIndexRows = doc.profiles.mapIndexed { idx, p ->
            ProfileIndexRow(
                id = p.id,
                kind = p.kind.wire,
                subscriptionId = p.subscriptionId,
                name = p.remarks,
                protocol = p.node?.protocol.orEmpty(),
                server = p.node?.server.orEmpty(),
                port = p.node?.port ?: 0,
                sortOrder = idx,
                pinned = false,
                updatedAt = doc.updatedAtMs,
            )
        }
        val payloads = doc.profiles.associate { p ->
            p.id to WorkspaceJsonCodec.encodeProfile(p).toString()
        }
        val routingRows = doc.routingProfiles.mapIndexed { idx, rp ->
            RoutingProfileRow(
                id = rp.id,
                name = rp.name,
                sortOrder = idx,
                payloadJson = WorkspaceJsonCodec.encodeRoutingProfile(rp).toString(),
                updatedAt = doc.updatedAtMs,
            )
        }
        val ruleSetArr = JSONArray().apply {
            doc.ruleSetAssets.forEach { put(WorkspaceJsonCodec.encodeRuleSetAsset(it)) }
        }
        val meta = linkedMapOf(
            META_SCHEMA_VERSION to WorkspaceDocument.SCHEMA_VERSION.toString(),
            META_SYNC_REVISION to doc.revision.coerceAtLeast(1L).toString(),
            META_UPDATED_AT_MS to doc.updatedAtMs.coerceAtLeast(0L).toString(),
            META_ACTIVE_ROUTING_ID to JSONObject.quote(doc.activeRoutingProfile().id),
            META_DNS to WorkspaceJsonCodec.encodeDns(doc.dns).toString(),
            META_RULE_SET_ASSETS to ruleSetArr.toString(),
            META_FULL_TEMPLATE to WorkspaceJsonCodec.encodeFullTemplate(doc.fullTemplate).toString(),
        )
        executor.replaceSubscriptions(subRows)
        executor.replaceProfiles(profileIndexRows, payloads)
        executor.replaceRoutingProfiles(routingRows)
        executor.putWorkspaceMeta(meta)
    }

    /**
     * Fast index-only listing of profile metadata from `profiles` (NEVER reads `profile_payloads`).
     */
    fun listProfileSummaries(): List<ProfileSummary> =
        executor.listProfileSummaries().map { r ->
            ProfileSummary(
                id = r.id,
                kind = ProfileKind.fromWire(r.kind),
                subscriptionId = r.subscriptionId,
                name = r.name,
                protocol = r.protocol,
                server = r.server,
                port = r.port,
                sortOrder = r.sortOrder,
                pinned = r.pinned,
                updatedAtMs = r.updatedAt,
            )
        }

    fun setProfilePinned(profileId: String, pinned: Boolean) {
        executor.inTransaction { executor.setProfilePinned(profileId, pinned) }
    }

    fun loadTelemetry(): TelemetryDocument = executor.inReadTransaction {
        val stateObj = executor.getHostKv(KV_TELEMETRY_STATE)
            ?.let { runCatching { JSONObject(it) }.getOrNull() }
        val nodeRows = executor.listNodeTelemetry().associateBy { it.profileId }
        val trafficTotals = hashMapOf<String, Pair<Long, Long>>()
        for (entry in executor.queryTrafficLedger(0L)) {
            val cur = trafficTotals[entry.profileId] ?: (0L to 0L)
            trafficTotals[entry.profileId] = (cur.first + entry.uploadBytes) to (cur.second + entry.downloadBytes)
        }
        val allIds = linkedSetOf<String>().apply {
            addAll(nodeRows.keys)
            addAll(trafficTotals.keys)
        }
        val profiles = linkedMapOf<String, ProfileTelemetryEntry>()
        for (id in allIds) {
            val n = nodeRows[id]
            val t = trafficTotals[id] ?: (0L to 0L)
            profiles[id] = ProfileTelemetryEntry(
                latencyMs = n?.latencyMs ?: -1L,
                lastTestedMs = n?.testedAtMs ?: 0L,
                uploadBytes = t.first,
                downloadBytes = t.second,
            )
        }
        TelemetryDocument(
            activeProfileId = stateObj?.optString("active_profile_id", "").orEmpty(),
            outboundMode = stateObj?.optString("outbound_mode", "rule").orEmpty().ifBlank { "rule" },
            unreadUnexpectedCrash = stateObj?.optBoolean("unread_unexpected_crash", false) ?: false,
            lastCrashTimestampMs = stateObj?.optLong("last_crash_timestamp_ms", 0L) ?: 0L,
            lastCrashReason = stateObj?.optString("last_crash_reason", "").orEmpty(),
            profiles = profiles,
        )
    }

    fun saveTelemetry(doc: TelemetryDocument) {
        executor.inTransaction { saveTelemetryLocked(doc) }
    }

    private fun saveTelemetryLocked(doc: TelemetryDocument) {
        val stateJson = JSONObject().apply {
            put("active_profile_id", doc.activeProfileId)
            put("outbound_mode", doc.outboundMode)
            put("unread_unexpected_crash", doc.unreadUnexpectedCrash)
            put("last_crash_timestamp_ms", doc.lastCrashTimestampMs)
            put("last_crash_reason", doc.lastCrashReason)
        }.toString()
        val prevNodes = executor.listNodeTelemetry().associateBy { it.profileId }
        val nodeRows = doc.profiles.map { (id, e) ->
            val prev = prevNodes[id]
            val preserveRich = prev != null && prev.latencyMs == e.latencyMs && prev.testedAtMs == e.lastTestedMs
            NodeTelemetryRecord(
                profileId = id,
                latencyMs = e.latencyMs,
                ewmaMs = if (preserveRich) prev.ewmaMs else e.latencyMs,
                statusCode = if (preserveRich) prev.statusCode else if (e.latencyMs >= 0L) 204 else 0,
                state = if (preserveRich) prev.state else if (e.latencyMs >= 0L) "healthy" else "",
                testedAtMs = e.lastTestedMs,
            )
        }
        executor.setHostKv(KV_TELEMETRY_STATE, stateJson)
        executor.replaceNodeTelemetry(nodeRows)
        val trafficByProfile = executor.queryTrafficLedger(0L).groupBy { it.profileId }
        doc.profiles.forEach { (id, e) ->
            if (e.uploadBytes > 0L || e.downloadBytes > 0L) {
                val existing = trafficByProfile[id].orEmpty()
                val curUp = existing.sumOf { it.uploadBytes }
                val curDown = existing.sumOf { it.downloadBytes }
                val dUp = (e.uploadBytes - curUp).coerceAtLeast(0L)
                val dDown = (e.downloadBytes - curDown).coerceAtLeast(0L)
                if (dUp > 0L || dDown > 0L) {
                    executor.recordTrafficDelta(0L, id, dUp, dDown)
                }
            }
        }
    }

    fun upsertNodeTelemetry(record: NodeTelemetryRecord) {
        executor.inTransaction { executor.upsertNodeTelemetry(record) }
    }

    fun updateNodeLatency(profileId: String, latencyMs: Long, testedAtMs: Long = System.currentTimeMillis()) {
        executor.inTransaction { executor.updateNodeLatency(profileId, latencyMs, testedAtMs) }
    }

    fun listNodeTelemetry(): List<NodeTelemetryRecord> = executor.listNodeTelemetry()

    fun recordTrafficDelta(bucketHour: Long, profileId: String, uploadBytes: Long, downloadBytes: Long) {
        if (profileId.isBlank()) return
        executor.recordTrafficDelta(bucketHour, profileId, uploadBytes.coerceAtLeast(0L), downloadBytes.coerceAtLeast(0L))
    }

    fun queryTrafficLedger(sinceHour: Long = 0L): List<TrafficLedgerEntry> =
        executor.queryTrafficLedger(sinceHour)

    fun getHostKv(key: String): String? = executor.getHostKv(key)

    fun setHostKv(key: String, valueJson: String) {
        require(!containsForbiddenSyncSecret(valueJson)) {
            "WebDAV password and E2EE sync passphrase must NEVER be stored in SQLite host_kv"
        }
        executor.inTransaction { executor.setHostKv(key, valueJson) }
    }

    fun setHostKvIfAbsent(key: String, valueJson: String): Boolean {
        require(!containsForbiddenSyncSecret(valueJson)) {
            "WebDAV password and E2EE sync passphrase must NEVER be stored in SQLite host_kv"
        }
        return executor.inTransaction {
            if (executor.getHostKv(key) != null) return@inTransaction false
            executor.setHostKv(key, valueJson)
            true
        }
    }

    fun deleteHostKv(key: String) {
        executor.inTransaction { executor.deleteHostKv(key) }
    }

    fun shrinkMemory() {
        executor.shrinkMemory()
    }

    override fun close() {
        registryKey?.let { processInstances.remove(it, this) }
        executor.close()
    }

    companion object {
        const val META_SCHEMA_VERSION = "schema_version"
        const val META_SYNC_REVISION = "sync_revision"
        const val META_UPDATED_AT_MS = "updated_at_ms"
        const val META_ACTIVE_ROUTING_ID = "active_routing_id"
        const val META_DNS = "dns"
        const val META_RULE_SET_ASSETS = "rule_set_assets"
        const val META_FULL_TEMPLATE = "full_template"

        const val KV_ANDROID_HOST_CONFIG = "android_host_config"
        const val KV_TELEMETRY_STATE = "telemetry_state"

        private val processInstances = ConcurrentHashMap<String, NexusClientDatabase>()

        fun open(
            context: Context,
            dbFile: File = File(context.filesDir, NexusClientSchema.DEFAULT_DB_NAME),
        ): NexusClientDatabase {
            val key = runCatching { dbFile.canonicalPath }.getOrDefault(dbFile.absolutePath)
            return processInstances.computeIfAbsent(key) {
                NexusClientDatabase(AndroidSqliteExecutor(context.applicationContext, dbFile), registryKey = key)
            }
        }

        fun inMemory(
            dbFile: File? = null,
            userVersion: Int = NexusClientSchema.SCHEMA_VERSION,
        ): NexusClientDatabase = NexusClientDatabase(InMemorySqlExecutor(dbFile, userVersion))

        internal fun containsForbiddenSyncSecret(rawJson: String): Boolean {
            val root = runCatching { JSONObject(rawJson) }.getOrNull() ?: return false
            fun scan(obj: JSONObject, depth: Int): Boolean {
                if (depth > 4) return false
                if (obj.optString("webdav_password", "").isNotEmpty() ||
                    obj.optString("sync_passphrase", "").isNotEmpty()
                ) return true
                val keys = obj.keys()
                while (keys.hasNext()) {
                    val child = obj.optJSONObject(keys.next())
                    if (child != null && scan(child, depth + 1)) return true
                }
                return false
            }
            return scan(root, 0)
        }

        private fun decodeJsonString(raw: String): String {
            val t = raw.trim()
            if (t.startsWith("\"") && t.endsWith("\"")) {
                return runCatching { JSONArray("[$t]").getString(0) }.getOrDefault(t.removeSurrounding("\""))
            }
            return t
        }
    }
}
