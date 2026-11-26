package org.nexus.android.bridge.workspace

import org.nexus.android.bridge.profile.SecretFileIO
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * Pure-Kotlin transactional in-memory [SqlExecutor] for local JVM JUnit tests (zero Robolectric):
 * preserves exact relational semantics including `ON DELETE CASCADE` on `profile_payloads`,
 * atomic transaction rollback, forward schema version rejection, and read/shrink observability.
 */
internal class InMemorySqlExecutor(
    override val dbFile: File? = null,
    userVersion: Int = NexusClientSchema.SCHEMA_VERSION,
) : SqlExecutor {
    private val lock = Any()
    private val subscriptions = linkedMapOf<String, SubscriptionRow>()
    private val profiles = linkedMapOf<String, ProfileIndexRow>()
    private val profilePayloads = linkedMapOf<String, String>()
    private val routingProfiles = linkedMapOf<String, RoutingProfileRow>()
    private val workspaceMeta = linkedMapOf<String, String>()
    private val nodeTelemetry = linkedMapOf<String, NodeTelemetryRecord>()
    private val trafficLedger = linkedMapOf<Pair<Long, String>, TrafficLedgerEntry>()
    private val hostKv = linkedMapOf<String, String>()

    internal val payloadReads = AtomicInteger(0)
    internal val readTransactions = AtomicInteger(0)
    internal val shrinkCalls = AtomicInteger(0)

    init {
        if (userVersion > NexusClientSchema.SCHEMA_VERSION) {
            throw IllegalStateException(
                "Unsupported Nexus client database schema version $userVersion (expected <= ${NexusClientSchema.SCHEMA_VERSION}); refusing to downgrade",
            )
        }
        touchDbFile0600()
    }

    private fun touchDbFile0600() {
        val f = dbFile ?: return
        f.parentFile?.let { p -> p.mkdirs(); SecretFileIO.restrictDir0700(p) }
        if (!f.exists()) SecretFileIO.atomicWriteSecret0600(f, "") else SecretFileIO.restrictFile0600(f)
    }

    override fun <T> inTransaction(block: () -> T): T = synchronized(lock) {
        val snapSubs = LinkedHashMap(subscriptions)
        val snapProfs = LinkedHashMap(profiles)
        val snapPayloads = LinkedHashMap(profilePayloads)
        val snapRoutings = LinkedHashMap(routingProfiles)
        val snapMeta = LinkedHashMap(workspaceMeta)
        val snapTel = LinkedHashMap(nodeTelemetry)
        val snapTraffic = LinkedHashMap(trafficLedger)
        val snapHost = LinkedHashMap(hostKv)
        try {
            val res = block()
            touchDbFile0600()
            res
        } catch (t: Throwable) {
            subscriptions.clear(); subscriptions.putAll(snapSubs)
            profiles.clear(); profiles.putAll(snapProfs)
            profilePayloads.clear(); profilePayloads.putAll(snapPayloads)
            routingProfiles.clear(); routingProfiles.putAll(snapRoutings)
            workspaceMeta.clear(); workspaceMeta.putAll(snapMeta)
            nodeTelemetry.clear(); nodeTelemetry.putAll(snapTel)
            trafficLedger.clear(); trafficLedger.putAll(snapTraffic)
            hostKv.clear(); hostKv.putAll(snapHost)
            throw t
        }
    }

    override fun <T> inReadTransaction(block: () -> T): T = synchronized(lock) {
        readTransactions.incrementAndGet()
        block()
    }

    override fun hasWorkspaceData(): Boolean = synchronized(lock) {
        workspaceMeta.isNotEmpty() || profiles.isNotEmpty() || subscriptions.isNotEmpty() || routingProfiles.isNotEmpty()
    }

    override fun listSubscriptions(): List<SubscriptionRow> = synchronized(lock) {
        subscriptions.values.sortedWith(compareBy<SubscriptionRow> { it.sortOrder }.thenBy { it.id })
    }

    override fun replaceSubscriptions(rows: List<SubscriptionRow>) = synchronized(lock) {
        subscriptions.clear()
        rows.forEach { subscriptions[it.id] = it }
    }

    override fun listProfileSummaries(): List<ProfileIndexRow> = synchronized(lock) {
        profiles.values.sortedWith(compareBy<ProfileIndexRow> { it.sortOrder }.thenBy { it.id })
    }

    override fun listProfilesWithPayloads(): List<Pair<ProfileIndexRow, String>> = synchronized(lock) {
        payloadReads.incrementAndGet()
        profiles.values
            .sortedWith(compareBy<ProfileIndexRow> { it.sortOrder }.thenBy { it.id })
            .mapNotNull { row -> profilePayloads[row.id]?.let { row to it } }
    }

    override fun replaceProfiles(indexRows: List<ProfileIndexRow>, payloads: Map<String, String>) = synchronized(lock) {
        val prevPinned = profiles.values.filter { it.pinned }.mapTo(hashSetOf()) { it.id }
        val keepIds = indexRows.mapTo(hashSetOf()) { it.id }
        val removed = profiles.keys.filter { it !in keepIds }
        for (id in removed) {
            profiles.remove(id)
            profilePayloads.remove(id)
        }
        for (r in indexRows) {
            profiles[r.id] = r.copy(pinned = r.pinned || r.id in prevPinned)
            profilePayloads[r.id] = payloads[r.id].orEmpty()
        }
    }

    override fun setProfilePinned(profileId: String, pinned: Boolean) = synchronized(lock) {
        profiles[profileId]?.let { profiles[profileId] = it.copy(pinned = pinned) }
        Unit
    }

    internal fun hasPayloadRow(profileId: String): Boolean = synchronized(lock) {
        profilePayloads.containsKey(profileId)
    }

    override fun listRoutingProfiles(): List<RoutingProfileRow> = synchronized(lock) {
        routingProfiles.values.sortedWith(compareBy<RoutingProfileRow> { it.sortOrder }.thenBy { it.id })
    }

    override fun replaceRoutingProfiles(rows: List<RoutingProfileRow>) = synchronized(lock) {
        routingProfiles.clear()
        rows.forEach { routingProfiles[it.id] = it }
    }

    override fun getWorkspaceMeta(): Map<String, String> = synchronized(lock) { LinkedHashMap(workspaceMeta) }

    override fun putWorkspaceMeta(entries: Map<String, String>) = synchronized(lock) {
        workspaceMeta.putAll(entries)
    }

    override fun listNodeTelemetry(): List<NodeTelemetryRecord> = synchronized(lock) {
        nodeTelemetry.values.toList()
    }

    override fun replaceNodeTelemetry(rows: List<NodeTelemetryRecord>) = synchronized(lock) {
        nodeTelemetry.clear()
        rows.forEach { nodeTelemetry[it.profileId] = it }
    }

    override fun upsertNodeTelemetry(row: NodeTelemetryRecord) = synchronized(lock) {
        nodeTelemetry[row.profileId] = row
    }

    override fun updateNodeLatency(profileId: String, latencyMs: Long, testedAtMs: Long) = synchronized(lock) {
        val existing = nodeTelemetry[profileId]
        if (existing != null) {
            nodeTelemetry[profileId] = existing.copy(latencyMs = latencyMs, testedAtMs = testedAtMs)
        } else {
            nodeTelemetry[profileId] = NodeTelemetryRecord(
                profileId = profileId,
                latencyMs = latencyMs,
                ewmaMs = latencyMs,
                statusCode = if (latencyMs >= 0L) 204 else 0,
                state = if (latencyMs >= 0L) "healthy" else "timeout",
                testedAtMs = testedAtMs,
            )
        }
    }

    override fun recordTrafficDelta(bucketHour: Long, profileId: String, uploadBytes: Long, downloadBytes: Long) = synchronized(lock) {
        val k = bucketHour to profileId
        val cur = trafficLedger[k]
        trafficLedger[k] = TrafficLedgerEntry(
            bucketHour = bucketHour,
            profileId = profileId,
            uploadBytes = ((cur?.uploadBytes ?: 0L) + uploadBytes).coerceAtLeast(0L),
            downloadBytes = ((cur?.downloadBytes ?: 0L) + downloadBytes).coerceAtLeast(0L),
        )
    }

    override fun queryTrafficLedger(sinceHour: Long): List<TrafficLedgerEntry> = synchronized(lock) {
        trafficLedger.values
            .filter { it.bucketHour >= sinceHour }
            .sortedWith(compareBy<TrafficLedgerEntry> { it.bucketHour }.thenBy { it.profileId })
    }

    override fun getHostKv(key: String): String? = synchronized(lock) { hostKv[key] }

    override fun setHostKv(key: String, valueJson: String) = synchronized(lock) {
        hostKv[key] = valueJson
    }

    override fun deleteHostKv(key: String) = synchronized(lock) {
        hostKv.remove(key)
        Unit
    }

    override fun shrinkMemory() {
        shrinkCalls.incrementAndGet()
        touchDbFile0600()
    }

    override fun close() = Unit
}
