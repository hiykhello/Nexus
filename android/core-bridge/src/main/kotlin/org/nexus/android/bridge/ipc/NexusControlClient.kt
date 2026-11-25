package org.nexus.android.bridge.ipc

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Process
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

data class ControlReply(val ok: Boolean, val statusCode: Int, val body: String)

data class MetricsSummary(
    val controlGeneration: Long = 0,
    val activeSessions: Long = 0,
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
)

/**
 * Dual-transport Nexus control client:
 * 1. Local AF_UNIX SOCK_SEQPACKET NEXUS/1 NUL-delimited control socket (zero TCP footprint)
 * 2. Optional loopback HTTP /v1/ API & /metrics with per-session Bearer token auth
 */
class NexusControlClient(
    private val unixSocketPath: String,
    private val httpBaseUrl: String? = null,
    private val bearerToken: String? = null,
    private val bearerTokenProvider: (() -> String?)? = null,
    private val timeoutMs: Int = 2_000,
) {
    suspend fun status(): ControlReply = sendUnix("status")
    suspend fun reload(): ControlReply = sendUnix("reload")
    suspend fun setLogLevel(level: String): ControlReply = sendUnix("log-level", level)
    suspend fun selectOutbound(group: String, member: String): ControlReply =
        if (httpBaseUrl != null) {
            val encoded = encodePathSegment(group)
            val httpReply = sendHttp("PUT", "/v1/groups/$encoded", JSONObject().put("member", member).toString())
            if (httpReply.ok) httpReply else sendUnix("select", group, member)
        } else {
            sendUnix("select", group, member)
        }

    suspend fun getOutboundMode(): ControlReply =
        if (httpBaseUrl != null) sendHttp("GET", "/v1/mode") else sendUnix("mode")

    suspend fun setOutboundMode(mode: String, outbound: String = "proxy"): ControlReply =
        if (httpBaseUrl != null) {
            sendHttp("PUT", "/v1/mode", buildSetModeHttpJson(mode, outbound))
        } else {
            sendUnix(*buildSetModeUnixTokens(mode, outbound).toTypedArray())
        }

    suspend fun resetGroupAuto(group: String): ControlReply =
        if (httpBaseUrl != null) {
            val encoded = encodePathSegment(group)
            sendHttp("PUT", "/v1/groups/$encoded", JSONObject().put("member", "--auto").toString())
        } else {
            sendUnix("select", group, "--auto")
        }

    suspend fun setHttpLogLevel(level: String): ControlReply =
        sendHttp("POST", "/v1/log-level", JSONObject().put("level", level).toString())

    suspend fun fetchOutboundsJson(): ControlReply = sendHttp("GET", "/v1/outbounds")
    suspend fun fetchConnectionsJson(): ControlReply = sendHttp("GET", "/v1/connections")
    suspend fun fetchConnectionDetailJson(id: Long): ControlReply = sendHttp("GET", "/v1/connections/$id")
    suspend fun fetchLogsJson(
        level: String = "trace",
        domain: String = "",
        search: String = "",
        since: Long = 0L,
        limit: Int = 128,
    ): ControlReply {
        val params = buildList {
            add("limit=$limit")
            if (since > 0L) add("since=$since")
            if (level.isNotBlank() && level != "all") add("level=${encodeQueryValue(level)}")
            if (domain.isNotBlank() && domain != "all") add("domain=${encodeQueryValue(domain)}")
            if (search.isNotBlank()) add("search=${encodeQueryValue(search)}")
        }.joinToString("&")
        return sendHttp("GET", "/v1/logs?$params")
    }
    suspend fun fetchDiagnosticsJson(): ControlReply = sendHttp("GET", "/v1/diagnostics")
    suspend fun fetchEventsJson(cursor: Long = 0): ControlReply = sendHttp("GET", "/v1/events?cursor=$cursor")
    suspend fun closeConnection(id: Long): ControlReply = sendHttp("DELETE", "/v1/connections/$id")
    suspend fun closeAllConnections(): ControlReply =
        if (httpBaseUrl != null) sendHttp("DELETE", "/v1/connections") else sendUnix("close-all")
    suspend fun probeGroup(group: String): ControlReply =
        if (httpBaseUrl != null) {
            sendHttp("POST", "/v1/groups/${encodePathSegment(group)}/probe", "{}")
        } else {
            sendUnix("probe", group)
        }
    suspend fun notifyNetworkChange(generation: Long): ControlReply =
        if (httpBaseUrl != null) {
            sendHttp("POST", "/v1/network-change", JSONObject().put("generation", generation.toString()).toString())
        } else {
            sendUnix("network-change", generation.toString())
        }
    suspend fun clearCache(target: String = "all"): ControlReply =
        sendHttp("POST", "/v1/state/clear-cache", JSONObject().put("target", target).toString())
    suspend fun fetchMetrics(): MetricsSummary {
        val reply = sendHttp("GET", "/metrics")
        return if (reply.ok) parseOpenMetrics(reply.body) else MetricsSummary()
    }

    suspend fun sendUnix(vararg tokens: String): ControlReply = withContext(Dispatchers.IO) {
        val frame = buildNexus1Frame(tokens.toList())
            ?: return@withContext ControlReply(false, 0, "invalid NEXUS/1 request")
        if (!File(unixSocketPath).exists()) {
            return@withContext ControlReply(false, 0, "control socket not found")
        }
        runCatching {
            LocalSocket(LocalSocket.SOCKET_SEQPACKET).use { sock ->
                sock.connect(LocalSocketAddress(unixSocketPath, LocalSocketAddress.Namespace.FILESYSTEM))
                sock.soTimeout = timeoutMs
                if (sock.peerCredentials.uid != Process.myUid()) {
                    return@withContext ControlReply(false, 403, "control socket peer UID mismatch")
                }
                sock.outputStream.write(frame)
                sock.outputStream.flush()
                val out = ByteArrayOutputStream()
                val buf = ByteArray(MAX_REPLY_BYTES + 1)
                val input = sock.inputStream
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    if (out.size() + n > MAX_REPLY_BYTES) {
                        return@withContext ControlReply(false, 0, "reply exceeds 64 KiB limit")
                    }
                    out.write(buf, 0, n)
                    // SOCK_SEQPACKET delivers one complete reply packet per recv.
                    break
                }
                val text = String(out.toByteArray(), Charsets.UTF_8)
                decodeNexus1Reply(text)
            }
        }.getOrElse { err ->
            ControlReply(false, 0, err.message ?: "Unix IPC error")
        }
    }

    suspend fun sendHttp(method: String, path: String, body: String? = null): ControlReply =
        withContext(Dispatchers.IO) {
            val base = httpBaseUrl ?: return@withContext ControlReply(false, 0, "HTTP control disabled")
            runCatching {
                val token = bearerTokenProvider?.invoke()?.takeIf { it.isNotEmpty() } ?: bearerToken
                val conn = (URL(base.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
                    requestMethod = method
                    connectTimeout = timeoutMs
                    readTimeout = timeoutMs
                    instanceFollowRedirects = false
                    useCaches = false
                    if (!token.isNullOrEmpty()) {
                        setRequestProperty("Authorization", "Bearer $token")
                    }
                    if (body != null) {
                        doOutput = true
                        setRequestProperty("Content-Type", "application/json")
                        outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                    }
                }
                try {
                    val code = conn.responseCode
                    val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                    val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                    ControlReply(code in 200..299, code, text)
                } finally {
                    conn.disconnect()
                }
            }.getOrElse { err ->
                ControlReply(false, 0, err.message ?: "HTTP control error")
            }
        }

    companion object {
        const val MAX_REQUEST_BYTES = 1024
        const val MAX_REPLY_BYTES = 65_536

        fun encodePathSegment(segment: String): String =
            URLEncoder.encode(segment, "UTF-8").replace("+", "%20")

        internal fun encodeQueryValue(value: String): String =
            URLEncoder.encode(value, "UTF-8").replace("+", "%20")

        fun buildSetModeHttpJson(mode: String, outbound: String = ""): String =
            JSONObject().put("mode", mode).apply {
                if (outbound.isNotBlank()) put("outbound", outbound)
            }.toString()

        fun buildSetModeUnixTokens(mode: String, outbound: String = ""): List<String> =
            if (outbound.isNotBlank()) listOf("mode", mode, outbound) else listOf("mode", mode)

        fun buildNexus1Frame(tokens: List<String>): ByteArray? {
            if (tokens.isEmpty()) return null
            for (token in tokens) {
                if (token.isEmpty() || token.indexOf('\u0000') >= 0) return null
            }
            val wire = "NEXUS/1 " + tokens.joinToString("\u0000")
            val bytes = wire.toByteArray(Charsets.UTF_8)
            return if (bytes.size <= MAX_REQUEST_BYTES) bytes else null
        }

        fun decodeNexus1Reply(raw: String): ControlReply = when {
            raw.isEmpty() -> ControlReply(false, 0, "empty control reply")
            raw.startsWith("NEXUS/1 OK\n") -> ControlReply(true, 200, raw.removePrefix("NEXUS/1 OK\n"))
            raw == "NEXUS/1 OK" -> ControlReply(true, 200, "")
            raw.startsWith("NEXUS/1 ERROR\n") ->
                ControlReply(false, 400, raw.removePrefix("NEXUS/1 ERROR\n").trim())
            raw == "NEXUS/1 ERROR" -> ControlReply(false, 400, "control error")
            else -> ControlReply(false, 500, raw.trim())
        }

        fun parseOpenMetrics(text: String): MetricsSummary {
            var gen = 0L
            var active = 0L
            var up = 0L
            var down = 0L
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val braceEnd = line.indexOf('}')
                val searchFrom = if (braceEnd >= 0) braceEnd + 1 else 0
                val sep = line.indexOf(' ', searchFrom)
                if (sep <= 0) continue
                val key = line.substring(0, sep)
                val rest = line.substring(sep + 1).trimStart()
                val valueToken = rest.substringBefore(' ').substringBefore('\t')
                val value = valueToken.toLongOrNull() ?: valueToken.toDoubleOrNull()?.toLong() ?: continue
                when {
                    key == "nexus_control_generation" -> gen = value
                    key.startsWith("nexus_active_sessions") -> active += value
                    key.startsWith("nexus_traffic_upload_bytes_total") -> up += value
                    key.startsWith("nexus_traffic_download_bytes_total") -> down += value
                }
            }
            return MetricsSummary(gen, active, up, down)
        }
    }
}
