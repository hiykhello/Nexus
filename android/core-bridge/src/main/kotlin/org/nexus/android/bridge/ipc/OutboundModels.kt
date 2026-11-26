package org.nexus.android.bridge.ipc

import org.json.JSONObject

data class OutboundMemberSnapshot(
    val name: String,
    val state: String,
    val latencyMs: Long,
    val selected: Boolean,
    val overridden: Boolean,
)

data class OutboundGroupSnapshot(
    val tag: String,
    val mode: String,
    val active: String,
    val manualOverride: Boolean,
    val members: List<OutboundMemberSnapshot>,
)

data class ActiveConnectionSnapshot(
    val id: Long,
    val listener: Int,
    val protocol: String,
    val path: String,
    val destinationPort: Int,
    val uploadBytes: Long,
    val downloadBytes: Long,
    val inbound: String = "",
    val source: String = "",
    val target: String = "",
    val outbound: String = "",
    val routeMode: String = "",
    val routeRule: String = "",
    val processPath: String = "",
    val durationMs: Long = 0L,
    val canClose: Boolean = false,
)

data class LogRingEntry(
    val seq: Long,
    val level: String,
    val domain: String,
    val eventCode: Int,
    val message: String,
)

data class LogsSnapshot(
    val latestSeq: Long = 0L,
    val evicted: Long = 0L,
    val entries: List<LogRingEntry> = emptyList(),
)

object OutboundJsonParser {
    private fun parseConnectionObject(c: JSONObject): ActiveConnectionSnapshot = ActiveConnectionSnapshot(
        id = c.optString("id").toLongOrNull() ?: c.optLong("id", 0L),
        listener = c.optInt("listener", 0),
        protocol = c.optString("protocol", "unknown"),
        path = c.optString("path", "direct"),
        destinationPort = c.optInt("destination_port", 0),
        uploadBytes = c.optString("upload_bytes").toLongOrNull() ?: c.optLong("upload_bytes", 0L),
        downloadBytes = c.optString("download_bytes").toLongOrNull() ?: c.optLong("download_bytes", 0L),
        inbound = c.optString("inbound", ""),
        source = c.optString("source", ""),
        target = c.optString("target", ""),
        outbound = c.optString("outbound", ""),
        routeMode = c.optString("route_mode", ""),
        routeRule = c.optString("route_rule", ""),
        processPath = c.optString("process_path", ""),
        durationMs = c.optString("duration_ms").toLongOrNull() ?: c.optLong("duration_ms", 0L),
        canClose = c.optBoolean("can_close", false),
    )

    fun parseConnections(jsonText: String): List<ActiveConnectionSnapshot> = runCatching {
        val root = JSONObject(jsonText)
        val arr = root.optJSONArray("connections") ?: return@runCatching emptyList()
        buildList {
            for (i in 0 until arr.length()) {
                val c = arr.optJSONObject(i) ?: continue
                add(parseConnectionObject(c))
            }
        }
    }.getOrDefault(emptyList())

    fun parseConnectionDetail(jsonText: String): ActiveConnectionSnapshot? = runCatching {
        val obj = JSONObject(jsonText)
        val parsed = parseConnectionObject(obj)
        if (parsed.id > 0L) parsed else null
    }.getOrNull()

    fun parseLogs(jsonText: String): LogsSnapshot = runCatching {
        val root = JSONObject(jsonText)
        val latest = root.optString("latest_seq").toLongOrNull() ?: root.optLong("latest_seq", 0L)
        val evicted = root.optString("evicted").toLongOrNull() ?: root.optLong("evicted", 0L)
        val arr = root.optJSONArray("entries")
        val entries = buildList {
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val e = arr.optJSONObject(i) ?: continue
                    add(
                        LogRingEntry(
                            seq = e.optString("seq").toLongOrNull() ?: e.optLong("seq", 0L),
                            level = e.optString("level", "info"),
                            domain = e.optString("domain", "core"),
                            eventCode = e.optInt("event", e.optInt("event_code", 0)),
                            message = e.optString("message", ""),
                        ),
                    )
                }
            }
        }
        LogsSnapshot(latestSeq = latest, evicted = evicted, entries = entries)
    }.getOrDefault(LogsSnapshot())

    fun parse(jsonText: String): List<OutboundGroupSnapshot> = runCatching {
        val root = JSONObject(jsonText)
        val arr = root.optJSONArray("groups") ?: return@runCatching emptyList()
        buildList {
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val tag = obj.optString("name").ifEmpty { obj.optString("tag") }
                if (tag.isEmpty()) continue
                val mode = obj.optString("mode")
                val active = obj.optString("selected").ifEmpty { obj.optString("active") }
                val manualOverride = obj.optBoolean("override", false)
                val memArr = obj.optJSONArray("members")
                val members = buildList {
                    if (memArr != null) {
                        for (j in 0 until memArr.length()) {
                            val m = memArr.optJSONObject(j) ?: continue
                            val name = m.optString("name")
                            if (name.isEmpty()) continue
                            val isSelected = active.isNotEmpty() && name == active
                            add(
                                OutboundMemberSnapshot(
                                    name = name,
                                    state = m.optString("state", "unknown"),
                                    latencyMs = m.optLong("latency_ms", -1L),
                                    selected = isSelected,
                                    overridden = isSelected && manualOverride,
                                ),
                            )
                        }
                    }
                }
                add(OutboundGroupSnapshot(tag, mode, active, manualOverride, members))
            }
        }
    }.getOrDefault(emptyList())
}
