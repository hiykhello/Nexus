package org.nexus.android.bridge.workspace

import org.json.JSONObject
import java.io.File

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
 * Layer 4 ephemeral local telemetry & crash-sentinel store (`telemetry.json`, NEVER synced).
 */
class TelemetryStore(val file: File) {
    fun load(): TelemetryDocument {
        if (!file.isFile) return TelemetryDocument()
        return runCatching { decode(file.readText(Charsets.UTF_8)) }.getOrDefault(TelemetryDocument())
    }

    fun save(doc: TelemetryDocument): TelemetryDocument {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, ".${file.name}.${System.nanoTime()}.tmp")
        try {
            tmp.writeText(encode(doc), Charsets.UTF_8)
            if (!tmp.renameTo(file)) {
                file.writeText(encode(doc), Charsets.UTF_8)
                tmp.delete()
            }
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
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
        val cur = load()
        val prev = cur.profiles[profileId] ?: ProfileTelemetryEntry()
        val nextMap = cur.profiles.toMutableMap()
        nextMap[profileId] = prev.copy(latencyMs = latencyMs, lastTestedMs = System.currentTimeMillis())
        return save(cur.copy(profiles = nextMap))
    }

    companion object {
        fun encode(doc: TelemetryDocument): String {
            val root = JSONObject().apply {
                put("active_profile_id", doc.activeProfileId)
                put("outbound_mode", doc.outboundMode)
                put("unread_unexpected_crash", doc.unreadUnexpectedCrash)
                put("last_crash_timestamp_ms", doc.lastCrashTimestampMs)
                put("last_crash_reason", doc.lastCrashReason)
                put("profiles", JSONObject().apply {
                    doc.profiles.forEach { (id, e) ->
                        put(
                            id,
                            JSONObject().apply {
                                put("latency_ms", e.latencyMs)
                                put("last_tested_ms", e.lastTestedMs)
                                put("upload_bytes", e.uploadBytes)
                                put("download_bytes", e.downloadBytes)
                            },
                        )
                    }
                })
            }
            return root.toString(2) + "\n"
        }

        fun decode(raw: String): TelemetryDocument {
            val root = JSONObject(raw)
            val profilesMap = linkedMapOf<String, ProfileTelemetryEntry>()
            root.optJSONObject("profiles")?.let { pObj ->
                val keys = pObj.keys()
                while (keys.hasNext()) {
                    val id = keys.next()
                    pObj.optJSONObject(id)?.let { e ->
                        profilesMap[id] = ProfileTelemetryEntry(
                            latencyMs = e.optLong("latency_ms", -1L),
                            lastTestedMs = e.optLong("last_tested_ms", 0L),
                            uploadBytes = e.optLong("upload_bytes", 0L),
                            downloadBytes = e.optLong("download_bytes", 0L),
                        )
                    }
                }
            }
            return TelemetryDocument(
                activeProfileId = root.optString("active_profile_id", ""),
                outboundMode = root.optString("outbound_mode", "rule"),
                unreadUnexpectedCrash = root.optBoolean("unread_unexpected_crash", false),
                lastCrashTimestampMs = root.optLong("last_crash_timestamp_ms", 0L),
                lastCrashReason = root.optString("last_crash_reason", ""),
                profiles = profilesMap,
            )
        }
    }
}
