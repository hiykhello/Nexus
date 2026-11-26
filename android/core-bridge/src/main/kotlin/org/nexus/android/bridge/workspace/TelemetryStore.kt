package org.nexus.android.bridge.workspace

data class ProfileTelemetryEntry(
    val latencyMs: Long = -1L,
    val lastTestedMs: Long = 0L,
    val uploadBytes: Long = 0L,
    val downloadBytes: Long = 0L,
)

data class TelemetryDocument(
    val activeProfileId: String = "",
    val outboundMode: String = "rule",
    val unreadUnexpectedCrash: Boolean = false,
    val lastCrashTimestampMs: Long = 0L,
    val lastCrashReason: String = "",
    val profiles: Map<String, ProfileTelemetryEntry> = emptyMap(),
)

/**
 * Layer 4 ephemeral local telemetry & crash-sentinel store backed exclusively by
 * `NexusClientDatabase` (`node_telemetry`, `traffic_ledger`, and `host_kv`).
 */
class TelemetryStore(
    val db: NexusClientDatabase = NexusClientDatabase.inMemory(),
) {
    fun load(): TelemetryDocument = db.loadTelemetry()

    fun save(doc: TelemetryDocument): TelemetryDocument {
        db.saveTelemetry(doc)
        return doc
    }

    fun recordUnexpectedCrash(reason: String): TelemetryDocument {
        val current = load()
        return save(
            current.copy(
                unreadUnexpectedCrash = true,
                lastCrashTimestampMs = System.currentTimeMillis(),
                lastCrashReason = reason.take(256),
            ),
        )
    }

    fun hasUnreadUnexpectedCrash(): Boolean = load().unreadUnexpectedCrash

    fun clearUnexpectedCrash(): TelemetryDocument {
        val current = load()
        return if (!current.unreadUnexpectedCrash) current else save(current.copy(unreadUnexpectedCrash = false))
    }

    fun setActiveProfileId(profileId: String): TelemetryDocument =
        save(load().copy(activeProfileId = profileId))

    fun setOutboundMode(mode: String): TelemetryDocument {
        val safe = if (mode in setOf("rule", "global", "direct")) mode else "rule"
        return save(load().copy(outboundMode = safe))
    }

    fun updateLatency(profileId: String, latencyMs: Long): TelemetryDocument {
        db.updateNodeLatency(profileId, latencyMs, System.currentTimeMillis())
        return load()
    }

    fun recordTrafficDelta(bucketHour: Long, profileId: String, uploadBytes: Long, downloadBytes: Long) {
        db.recordTrafficDelta(bucketHour, profileId, uploadBytes, downloadBytes)
    }

    fun queryTrafficLedger(sinceHour: Long = 0L): List<TrafficLedgerEntry> =
        db.queryTrafficLedger(sinceHour)
}
