package org.nexus.android.ui

import org.nexus.android.bridge.profile.SecretFileIO
import org.nexus.android.bridge.workspace.SubscriptionItem
import java.net.HttpURLConnection
import java.net.URL

/**
 * Safe bounded HTTPS/loopback subscription fetcher with redirect-hop limits,
 * same-origin header scrubbing, and CRLF injection stripping.
 */
internal object SubscriptionHttpFetcher {
    fun fetchPayload(sub: SubscriptionItem): Pair<String, Map<String, List<String>>> {
        val initial = URL(sub.url.trim())
        val initialOrigin = urlOriginKey(initial)
        var current = initial
        repeat(4) { hop ->
            val loopback = current.host in setOf("127.0.0.1", "localhost", "::1", "[::1]")
            require(current.protocol == "https" || (current.protocol == "http" && loopback)) {
                "仅允许 HTTPS 订阅链接"
            }
            val sameOrigin = urlOriginKey(current) == initialOrigin
            val conn = (current.openConnection() as HttpURLConnection).apply {
                connectTimeout = 8_000
                readTimeout = 10_000
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", sanitizeHeaderValue(sub.userAgent).ifBlank { "Nexus-Android/1.0" })
                if (sameOrigin) {
                    sanitizeRequestHeaders(sub.requestHeaders).forEach { (k, v) -> setRequestProperty(k, v) }
                }
            }
            try {
                val code = conn.responseCode
                if (code in setOf(301, 302, 303, 307, 308)) {
                    require(hop < 3) { "重定向次数过多" }
                    val loc = conn.getHeaderField("Location")?.trim().orEmpty()
                    require(loc.isNotEmpty()) { "重定向缺少 Location" }
                    current = URL(current, loc)
                } else {
                    require(code in 200..299) { "HTTP $code" }
                    val bytes = conn.inputStream.use { SecretFileIO.readBoundedBytes(it, 2 * 1024 * 1024) }
                    val hdrs = conn.headerFields.filterKeys { it != null }
                    return String(bytes, Charsets.UTF_8) to hdrs
                }
            } finally {
                conn.disconnect()
            }
        }
        error("订阅重定向超限")
    }

    fun urlOriginKey(url: URL): String {
        val port = if (url.port != -1) url.port else url.defaultPort
        return "${url.protocol.lowercase()}://${url.host.lowercase()}:$port"
    }

    fun sanitizeHeaderValue(raw: String): String =
        raw.replace("\r", "").replace("\n", "").trim()

    fun sanitizeRequestHeaders(headers: Map<String, String>): Map<String, String> =
        buildMap {
            for ((rawKey, rawVal) in headers) {
                val key = sanitizeHeaderValue(rawKey)
                val value = sanitizeHeaderValue(rawVal)
                if (key.isNotEmpty() && !key.equals("host", ignoreCase = true)) {
                    put(key, value)
                }
            }
        }
}
