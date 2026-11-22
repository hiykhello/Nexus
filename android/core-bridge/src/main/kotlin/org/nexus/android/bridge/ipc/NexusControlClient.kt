package org.nexus.android.bridge.ipc

import android.net.LocalSocket
import android.net.LocalSocketAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class ControlReply(val ok: Boolean, val statusCode: Int, val body: String)

data class MetricsSummary(
    val controlGeneration: Long = 0,
    val activeSessions: Long = 0,
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
)

/**
 * Dual-transport Nexus control client:
 * 1. Local AF_UNIX NEXUS/1 NUL-delimited control socket (zero TCP footprint)
 * 2. Optional loopback HTTP /v1/* & /metrics with Bearer token auth (Batch 95C)
 */
class NexusControlClient(
    private val unixSocketPath: String,
    private val httpBaseUrl: String? = null,
    private val bearerToken: String? = null,
    private val timeoutMs: Int = 2_000,
) {
    suspend fun status(): ControlReply = sendUnix("status")
    suspend fun reload(): ControlReply = sendUnix("reload")
    suspend fun setLogLevel(level: String): ControlReply = sendUnix("log-level", level)
    suspend fun selectOutbound(group: String, member: String): ControlReply =
        sendUnix("select", group, member)

    suspend fun resetGroupAuto(group: String): ControlReply =
        if (httpBaseUrl != null) {
            sendHttp("PUT", "/v1/groups/$group", """{"member":"--auto"}""")
        } else {
            sendUnix("select", group, "--auto")
        }

    suspend fun setHttpLogLevel(level: String): ControlReply =
        sendHttp("POST", "/v1/log-level", """{"level":"$level"}""")

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
            if (level.isNotBlank() && level != "all") add("level=${java.net.URLEncoder.encode(level, "UTF-8")}")
            if (domain.isNotBlank() && domain != "all") add("domain=${java.net.URLEncoder.encode(domain, "UTF-8")}")
            if (search.isNotBlank()) add("search=${java.net.URLEncoder.encode(search, "UTF-8")}")
        }.joinToString("&")
        return sendHttp("GET", "/v1/logs?$params")
    }
    suspend fun fetchDiagnosticsJson(): ControlReply = sendHttp("GET", "/v1/diagnostics")
    suspend fun fetchEventsJson(cursor: Long = 0): ControlReply = sendHttp("GET", "/v1/events?cursor=$cursor")
    suspend fun closeConnection(id: Long): ControlReply = sendHttp("DELETE", "/v1/connections/$id")
    suspend fun closeAllConnections(): ControlReply =
        if (httpBaseUrl != null) sendHttp("DELETE", "/v1/connections") else sendUnix("close-all")
    suspend fun probeGroup(group: String): ControlReply =
        if (httpBaseUrl != null) sendHttp("POST", "/v1/groups/$group/probe", "{}") else sendUnix("probe", group)
    suspend fun notifyNetworkChange(generation: Long): ControlReply =
        if (httpBaseUrl != null) {
            sendHttp("POST", "/v1/network-change", """{"generation":"$generation"}""")
        } else {
            sendUnix("network-change", generation.toString())
        }
    suspend fun clearCache(target: String = "all"): ControlReply =
        sendHttp("POST", "/v1/state/clear-cache", """{"target":"$target"}""")
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
            LocalSocket(LocalSocket.SOCKET_STREAM).use { sock ->
                sock.connect(LocalSocketAddress(unixSocketPath, LocalSocketAddress.Namespace.FILESYSTEM))
                sock.soTimeout = timeoutMs
                sock.outputStream.write(frame)
                sock.outputStream.flush()
                sock.shutdownOutput()
                val out = ByteArrayOutputStream()
                val buf = ByteArray(4096)
                val input = BufferedInputStream(sock.inputStream)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    if (out.size() + n > MAX_REPLY_BYTES) {
                        return@withContext ControlReply(false, 0, "reply exceeds 64 KiB limit")
                    }
                    out.write(buf, 0, n)
                }
                val text = out.toString(Charsets.UTF_8)
                ControlReply(text.isNotEmpty(), if (text.isNotEmpty()) 200 else 0, text)
            }
        }.getOrElse { err ->
            ControlReply(false, 0, err.message ?: "Unix IPC error")
        }
    }

    suspend fun sendHttp(method: String, path: String, body: String? = null): ControlReply =
        withContext(Dispatchers.IO) {
            val base = httpBaseUrl ?: return@withContext ControlReply(false, 0, "HTTP control disabled")
            runCatching {
                val conn = (URL(base.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
                    requestMethod = method
                    connectTimeout = timeoutMs
                    readTimeout = timeoutMs
                    useCaches = false
                    if (!bearerToken.isNullOrEmpty()) {
                        setRequestProperty("Authorization", "Bearer $bearerToken")
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

        fun buildNexus1Frame(tokens: List<String>): ByteArray? {
            if (tokens.isEmpty()) return null
            for (token in tokens) {
                if (token.isEmpty() || token.indexOf('\u0000') >= 0) return null
            }
            val wire = "NEXUS/1 " + tokens.joinToString("\u0000")
            val bytes = wire.toByteArray(Charsets.UTF_8)
            return if (bytes.size <= MAX_REQUEST_BYTES) bytes else null
        }

        fun parseOpenMetrics(text: String): MetricsSummary {
            var gen = 0L
            var active = 0L
            var up = 0L
            var down = 0L
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val sep = line.lastIndexOf(' ')
                if (sep <= 0) continue
                val key = line.substring(0, sep)
                val value = line.substring(sep + 1).toLongOrNull() ?: continue
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
