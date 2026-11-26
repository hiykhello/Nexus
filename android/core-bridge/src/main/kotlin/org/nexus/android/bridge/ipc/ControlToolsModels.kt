package org.nexus.android.bridge.ipc

import org.json.JSONObject

data class LiveRuleSnapshot(
    val index: Int,
    val type: String,
    val action: String,
    val target: String,
    val summary: String,
)

data class DnsAnswerRecord(
    val name: String,
    val type: String,
    val ttl: Long,
    val data: String,
)

data class DnsQueryResult(
    val ok: Boolean,
    val name: String = "",
    val type: String = "A",
    val rcode: Int = -1,
    val rcodeName: String = "",
    val ttl: Long = 0L,
    val elapsedMs: Long = 0L,
    val answers: List<DnsAnswerRecord> = emptyList(),
    val errorCode: String = "",
    val errorMessage: String = "",
)

data class FakeIpFlushResult(
    val ok: Boolean,
    val flushed: Long = 0L,
    val unavailable: Boolean = false,
    val message: String = "",
)

data class OutboundProbeResult(
    val ok: Boolean,
    val outbound: String = "",
    val resolvedOutbound: String = "",
    val state: String = "unknown",
    val latencyMs: Long = -1L,
    val statusCode: Int = 0,
    val url: String = "",
    val errorMessage: String = "",
)

data class LiveStatusSnapshot(
    val instance: String = "",
    val state: String = "",
    val workers: Int = 0,
    val listeners: Int = 0,
    val controlGeneration: Long = 0L,
    val activeSessions: Long = 0L,
    val uploadBytes: Long = 0L,
    val downloadBytes: Long = 0L,
) {
    fun toMetricsSummary(): MetricsSummary = MetricsSummary(
        controlGeneration = controlGeneration,
        activeSessions = activeSessions,
        uploadBytes = uploadBytes,
        downloadBytes = downloadBytes,
    )
}

object ControlToolsJsonParser {
    fun parseRules(jsonText: String): List<LiveRuleSnapshot> = runCatching {
        val root = JSONObject(jsonText)
        val arr = root.optJSONArray("rules") ?: return@runCatching emptyList()
        buildList(arr.length()) {
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                add(
                    LiveRuleSnapshot(
                        index = obj.optInt("index", i),
                        type = obj.optString("type", ""),
                        action = obj.optString("action", ""),
                        target = obj.optString("target", ""),
                        summary = obj.optString("summary", ""),
                    ),
                )
            }
        }
    }.getOrDefault(emptyList())

    fun parseDnsQuery(reply: ControlReply): DnsQueryResult {
        if (!reply.ok) {
            val (code, msg) = extractError(reply.body, fallback = "HTTP ${reply.statusCode}")
            return DnsQueryResult(ok = false, errorCode = code, errorMessage = msg)
        }
        return runCatching {
            val root = JSONObject(reply.body)
            val arr = root.optJSONArray("answers")
            val answers = buildList {
                if (arr != null) {
                    for (i in 0 until arr.length()) {
                        val a = arr.optJSONObject(i) ?: continue
                        add(
                            DnsAnswerRecord(
                                name = a.optString("name", ""),
                                type = a.optString("type", ""),
                                ttl = a.optLong("ttl", 0L),
                                data = a.optString("data", ""),
                            ),
                        )
                    }
                }
            }
            DnsQueryResult(
                ok = true,
                name = root.optString("name", ""),
                type = root.optString("type", "A"),
                rcode = root.optInt("rcode", 0),
                rcodeName = root.optString("rcode_name", ""),
                ttl = root.optLong("ttl", 0L),
                elapsedMs = root.optLong("elapsed_ms", 0L),
                answers = answers,
            )
        }.getOrElse { err ->
            DnsQueryResult(ok = false, errorCode = "parse-error", errorMessage = err.message ?: "DNS 响应解析失败")
        }
    }

    fun parseFakeIpFlush(reply: ControlReply): FakeIpFlushResult {
        if (reply.statusCode == 409) {
            val (code, msg) = extractError(reply.body, fallback = "FakeIP 未启用")
            return FakeIpFlushResult(
                ok = false,
                unavailable = code == "fakeip-unavailable" || msg.contains("fakeip", ignoreCase = true),
                message = if (code == "fakeip-unavailable") "当前未启用 FakeIP 池" else msg,
            )
        }
        if (!reply.ok) {
            val (_, msg) = extractError(reply.body, fallback = "刷新 FakeIP 失败 (HTTP ${reply.statusCode})")
            return FakeIpFlushResult(ok = false, message = msg)
        }
        return runCatching {
            val root = JSONObject(reply.body)
            val flushed = root.optLong("flushed", 0L).coerceAtLeast(0L)
            FakeIpFlushResult(ok = true, flushed = flushed, message = "已清理 $flushed 条未固定 FakeIP 映射")
        }.getOrElse {
            FakeIpFlushResult(ok = true, flushed = 0L, message = "FakeIP 映射已刷新")
        }
    }

    fun parseOutboundProbe(reply: ControlReply): OutboundProbeResult {
        if (!reply.ok) {
            val (_, msg) = extractError(reply.body, fallback = "单节点测速失败 (HTTP ${reply.statusCode})")
            return OutboundProbeResult(ok = false, state = "error", errorMessage = msg)
        }
        return runCatching {
            val root = JSONObject(reply.body)
            val latency = if (root.isNull("latency_ms")) -1L else root.optLong("latency_ms", -1L)
            OutboundProbeResult(
                ok = true,
                outbound = root.optString("outbound", ""),
                resolvedOutbound = root.optString("resolved_outbound", ""),
                state = root.optString("state", "unknown"),
                latencyMs = latency,
                statusCode = root.optInt("status_code", 0),
                url = root.optString("url", ""),
            )
        }.getOrElse { err ->
            OutboundProbeResult(ok = false, state = "error", errorMessage = err.message ?: "测速结果解析失败")
        }
    }

    fun parseStatus(jsonText: String): LiveStatusSnapshot? = runCatching {
        val root = JSONObject(jsonText)
        LiveStatusSnapshot(
            instance = root.optString("instance", ""),
            state = root.optString("state", ""),
            workers = root.optInt("workers", 0),
            listeners = root.optInt("listeners", 0),
            controlGeneration = root.optString("control_generation").toLongOrNull()
                ?: root.optLong("control_generation", 0L),
            activeSessions = root.optString("active_sessions").toLongOrNull()
                ?: root.optLong("active_sessions", 0L),
            uploadBytes = root.optString("upload_bytes_total").toLongOrNull()
                ?: root.optLong("upload_bytes_total", 0L),
            downloadBytes = root.optString("download_bytes_total").toLongOrNull()
                ?: root.optLong("download_bytes_total", 0L),
        )
    }.getOrNull()

    fun parseSingleLogEvent(jsonText: String): LogRingEntry? = runCatching {
        val e = JSONObject(jsonText)
        LogRingEntry(
            seq = e.optString("seq").toLongOrNull() ?: e.optLong("seq", 0L),
            level = e.optString("level", "info"),
            domain = e.optString("domain", "core"),
            eventCode = e.optInt("event", e.optInt("event_code", 0)),
            message = e.optString("message", ""),
        )
    }.getOrNull()

    private fun extractError(body: String, fallback: String): Pair<String, String> = runCatching {
        val root = JSONObject(body)
        val errObj = root.optJSONObject("error")
        if (errObj != null) {
            errObj.optString("code", "") to errObj.optString("message", fallback).ifBlank { fallback }
        } else {
            "" to body.trim().ifBlank { fallback }
        }
    }.getOrDefault("" to body.trim().ifBlank { fallback })
}
