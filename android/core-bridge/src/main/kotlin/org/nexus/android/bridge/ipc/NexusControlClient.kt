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
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.util.Locale

data class ControlReply(val ok: Boolean, val statusCode: Int, val body: String)

data class MetricsSummary(
    val controlGeneration: Long = 0,
    val activeSessions: Long = 0,
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
)

/**
 * Caches a bearer-token secret file by `lastModified()` + `length()` so high-frequency HTTP/SSE
 * calls avoid re-reading flash storage on every request while immediately picking up rotated tokens.
 */
class CachedTokenReader(private val tokenFile: File) {
    private val lock = Any()
    private var cachedMtime: Long = -1L
    private var cachedLen: Long = -1L
    private var cachedToken: String? = null

    fun read(): String? = synchronized(lock) {
        if (!tokenFile.isFile) {
            cachedMtime = -1L
            cachedLen = -1L
            cachedToken = null
            return null
        }
        val mtime = tokenFile.lastModified()
        val len = tokenFile.length()
        if (mtime == cachedMtime && len == cachedLen && cachedToken != null) {
            return cachedToken
        }
        val fresh = runCatching { tokenFile.readText(Charsets.UTF_8).trim() }.getOrNull()
        cachedMtime = mtime
        cachedLen = len
        cachedToken = fresh?.takeIf { it.isNotEmpty() }
        cachedToken
    }
}

/**
 * Dual-transport Nexus control client:
 * 1. Local AF_UNIX SOCK_SEQPACKET NEXUS/1 NUL-delimited control socket (zero TCP footprint)
 * 2. Optional loopback HTTP /v1/ API & /metrics with per-session Bearer token auth
 */
class NexusControlClient(
    private val unixSocketPath: String,
    private val httpBaseUrl: String? = null,
    private val httpBaseUrlProvider: (() -> String?)? = null,
    private val bearerToken: String? = null,
    private val bearerTokenProvider: (() -> String?)? = null,
    private val timeoutMs: Int = 2_000,
) {
    private fun resolvedBaseUrl(): String? =
        httpBaseUrlProvider?.invoke()?.takeIf { it.isNotBlank() } ?: httpBaseUrl?.takeIf { it.isNotBlank() }

    private fun resolvedToken(): String? =
        bearerTokenProvider?.invoke()?.takeIf { it.isNotEmpty() } ?: bearerToken?.takeIf { it.isNotEmpty() }

    fun createSseClient(readTimeoutMs: Int = NexusSseClient.DEFAULT_SSE_READ_TIMEOUT_MS): NexusSseClient =
        NexusSseClient(
            httpBaseUrlProvider = { resolvedBaseUrl() },
            bearerTokenProvider = { resolvedToken() },
            readTimeoutMs = readTimeoutMs,
        )

    suspend fun status(): ControlReply = sendUnix("status")
    suspend fun reload(): ControlReply = sendUnix("reload")

    suspend fun selectOutbound(group: String, member: String): ControlReply =
        if (resolvedBaseUrl() != null) {
            val encoded = encodePathSegment(group)
            val httpReply = sendHttp("PUT", "/v1/groups/$encoded", JSONObject().put("member", member).toString())
            if (httpReply.ok) httpReply else sendUnix("select", group, member)
        } else {
            sendUnix("select", group, member)
        }

    suspend fun setOutboundMode(mode: String, outbound: String = "proxy"): ControlReply =
        if (resolvedBaseUrl() != null) {
            sendHttp("PUT", "/v1/mode", buildSetModeHttpJson(mode, outbound))
        } else {
            sendUnix(*buildSetModeUnixTokens(mode, outbound).toTypedArray())
        }

    suspend fun resetGroupAuto(group: String): ControlReply =
        if (resolvedBaseUrl() != null) {
            val encoded = encodePathSegment(group)
            sendHttp("PUT", "/v1/groups/$encoded", JSONObject().put("member", "--auto").toString())
        } else {
            sendUnix("select", group, "--auto")
        }

    suspend fun fetchStatusJson(): ControlReply = sendHttp("GET", "/v1/status")
    suspend fun fetchOutboundsJson(): ControlReply = sendHttp("GET", "/v1/outbounds")
    suspend fun fetchRulesJson(): ControlReply = sendHttp("GET", "/v1/rules")
    suspend fun fetchRules(): List<LiveRuleSnapshot> {
        val reply = fetchRulesJson()
        return if (reply.ok) ControlToolsJsonParser.parseRules(reply.body) else emptyList()
    }

    suspend fun queryDns(
        name: String,
        type: String = "A",
        server: String = "",
    ): DnsQueryResult {
        val cleanName = name.trim()
        if (cleanName.isEmpty()) {
            return DnsQueryResult(ok = false, errorCode = "invalid-name", errorMessage = "请输入待查询的域名")
        }
        val params = buildList {
            add("name=${encodeQueryValue(cleanName)}")
            if (type.isNotBlank()) add("type=${encodeQueryValue(type.trim().uppercase())}")
            if (server.isNotBlank()) add("server=${encodeQueryValue(server.trim())}")
        }.joinToString("&")
        val reply = sendHttp("GET", "/v1/dns/query?$params", readTimeoutOverrideMs = DNS_QUERY_READ_TIMEOUT_MS)
        return ControlToolsJsonParser.parseDnsQuery(reply)
    }

    suspend fun flushFakeIp(): FakeIpFlushResult {
        val reply = sendHttp("POST", "/v1/cache/fakeip/flush", "{}")
        return ControlToolsJsonParser.parseFakeIpFlush(reply)
    }

    suspend fun probeOutbound(
        tag: String,
        url: String = DEFAULT_PROBE_URL,
        timeoutMs: Int = 5_000,
        mode: String = "http",
    ): OutboundProbeResult {
        val clampedTimeout = timeoutMs.coerceIn(500, 30_000)
        val body = JSONObject().apply {
            if (url.isNotBlank()) put("url", url)
            put("timeout_ms", clampedTimeout)
            put("mode", if (mode == "h2-ping") "h2-ping" else "http")
        }.toString()
        val reply = sendHttp(
            method = "POST",
            path = "/v1/outbounds/${encodePathSegment(tag)}/probe",
            body = body,
            readTimeoutOverrideMs = clampedTimeout + 3_000,
        )
        return ControlToolsJsonParser.parseOutboundProbe(reply)
    }

    suspend fun setLogLevel(level: String, domain: String = "global"): ControlReply {
        val body = JSONObject().apply {
            put("level", level.trim().lowercase())
            if (domain.isNotBlank()) put("domain", domain.trim())
        }.toString()
        return sendHttp("POST", "/v1/log-level", body)
    }

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

    suspend fun closeConnection(id: Long): ControlReply = sendHttp("DELETE", "/v1/connections/$id")
    suspend fun closeAllConnections(): ControlReply =
        if (resolvedBaseUrl() != null) sendHttp("DELETE", "/v1/connections") else sendUnix("close-all")

    suspend fun probeGroup(group: String): ControlReply =
        if (resolvedBaseUrl() != null) {
            sendHttp("POST", "/v1/groups/${encodePathSegment(group)}/probe", "{}")
        } else {
            sendUnix("probe", group)
        }

    suspend fun notifyNetworkChange(generation: Long): ControlReply =
        if (resolvedBaseUrl() != null) {
            sendHttp("POST", "/v1/network-change", JSONObject().put("generation", generation.toString()).toString())
        } else {
            sendUnix("network-change", generation.toString())
        }

    suspend fun clearCache(target: String = "all"): ControlReply =
        sendHttp("POST", "/v1/state/clear-cache", JSONObject().put("target", target).toString())

    suspend fun fetchMetrics(): MetricsSummary {
        val reply = sendHttp("GET", "/metrics")
        if (reply.ok) return parseOpenMetrics(reply.body)
        val statusReply = fetchStatusJson()
        if (statusReply.ok) {
            ControlToolsJsonParser.parseStatus(statusReply.body)?.let { return it.toMetricsSummary() }
        }
        return MetricsSummary()
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

    suspend fun sendHttp(
        method: String,
        path: String,
        body: String? = null,
        readTimeoutOverrideMs: Int? = null,
    ): ControlReply = withContext(Dispatchers.IO) {
        val base = resolvedBaseUrl() ?: return@withContext ControlReply(false, 0, "HTTP control disabled")
        if (!isLoopbackHttpUrl(base)) {
            return@withContext ControlReply(false, 403, "refusing non-loopback control HTTP URL")
        }
        runCatching {
            val token = resolvedToken()
            val conn = (URL(base.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = timeoutMs
                readTimeout = readTimeoutOverrideMs ?: timeoutMs
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
        const val DNS_QUERY_READ_TIMEOUT_MS = 15_000
        const val DEFAULT_PROBE_URL = "https://www.gstatic.com/generate_204"

        fun httpUrlFromListen(listen: String?, fallback: String = "http://127.0.0.1:9090"): String {
            val clean = listen?.trim().orEmpty()
            if (clean.isEmpty()) return fallback
            val candidate = when {
                clean.contains("://") -> clean
                clean == "::" || clean == "::1" -> "http://[::1]"
                else -> "http://$clean"
            }
            val uri = runCatching { URI(candidate) }.getOrNull() ?: return fallback
            if (!uri.scheme.equals("http", ignoreCase = true)) return fallback
            if (!uri.rawUserInfo.isNullOrEmpty()) return fallback
            if (uri.rawQuery != null || uri.rawFragment != null) return fallback
            if (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/") return fallback
            val rawHost = uri.host?.lowercase(Locale.ROOT) ?: return fallback
            val normalizedHost = when (rawHost) {
                "0.0.0.0" -> "127.0.0.1"
                "::", "[::]" -> "[::1]"
                "::1", "[::1]" -> "[::1]"
                "127.0.0.1", "localhost" -> rawHost
                else -> return fallback
            }
            val port = uri.port
            if (port == 0 || port > 65_535) return fallback
            return if (port > 0) "http://$normalizedHost:$port" else "http://$normalizedHost"
        }

        internal fun isLoopbackHttpUrl(url: String): Boolean {
            val uri = runCatching { URI(url.trim()) }.getOrNull() ?: return false
            if (!uri.scheme.equals("http", ignoreCase = true)) return false
            if (!uri.rawUserInfo.isNullOrEmpty()) return false
            val host = uri.host?.lowercase(Locale.ROOT) ?: return false
            return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
        }

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
