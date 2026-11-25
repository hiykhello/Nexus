package org.nexus.android.bridge.workspace

import java.net.URLDecoder
import java.util.Base64

data class ParsedSubscriptionHeaders(
    val usage: SubscriptionUsage,
    val updateIntervalMinutes: Int = 0,
)

/**
 * Parses standard subscription HTTP response headers:
 * - `Subscription-Userinfo`: `upload=...; download=...; total=...; expire=...`
 * - `Profile-Title`: `base64:<encoded>`, percent-encoded UTF-8, or plain text
 * - `Profile-Web-Page-URL` & `Support-URL`: strict safe URL scheme filter (`http`, `https`, `tg` only)
 * - `Profile-Update-Interval`: hours -> minutes
 */
object SubscriptionInfoParser {
    private val ALLOWED_URL_SCHEMES = setOf("http", "https", "tg")

    fun parseHeaders(headers: Map<String, List<String>>): ParsedSubscriptionHeaders {
        val lookup = HashMap<String, String>(headers.size)
        for ((k, values) in headers) {
            val key = k.trim().lowercase()
            val first = values.firstOrNull { it.isNotBlank() }?.trim()
            if (key.isNotEmpty() && !first.isNullOrEmpty()) {
                lookup[key] = first
            }
        }

        val (upload, download, total, expire) = parseUserinfo(lookup["subscription-userinfo"].orEmpty())
        val title = decodeProfileTitle(lookup["profile-title"].orEmpty())
        val webPage = sanitizeSafeUrl(lookup["profile-web-page-url"].orEmpty())
        val support = sanitizeSafeUrl(lookup["support-url"].orEmpty())
        val intervalHours = lookup["profile-update-interval"]?.trim()?.toIntOrNull() ?: 0
        val intervalMinutes = if (intervalHours > 0) (intervalHours * 60).coerceIn(15, 7 * 24 * 60) else 0

        return ParsedSubscriptionHeaders(
            usage = SubscriptionUsage(
                uploadBytes = upload,
                downloadBytes = download,
                totalBytes = total,
                expireUnixSec = expire,
                profileTitle = title,
                webPageUrl = webPage,
                supportUrl = support,
            ),
            updateIntervalMinutes = intervalMinutes,
        )
    }

    fun parseUserinfo(raw: String): UserinfoQuad {
        var upload = -1L
        var download = -1L
        var total = -1L
        var expire = -1L
        for (part in raw.split(';')) {
            val eq = part.indexOf('=')
            if (eq <= 0) continue
            val key = part.substring(0, eq).trim().lowercase()
            val valueStr = part.substring(eq + 1).trim()
            val parsed = parseNonNegativeLong(valueStr) ?: continue
            when (key) {
                "upload" -> upload = parsed
                "download" -> download = parsed
                "total" -> total = parsed
                "expire" -> expire = parsed
            }
        }
        return UserinfoQuad(upload, download, total, expire)
    }

    fun decodeProfileTitle(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return ""
        val decoded = when {
            trimmed.startsWith("base64:", ignoreCase = true) -> {
                val b64 = trimmed.substring(7).trim()
                decodeBase64Relaxed(b64).ifBlank { trimmed }
            }
            trimmed.contains('%') -> runCatching {
                URLDecoder.decode(trimmed, "UTF-8")
            }.getOrDefault(trimmed)
            else -> trimmed
        }
        return sanitizeControlChars(decoded).take(128)
    }

    fun sanitizeSafeUrl(raw: String): String {
        val trimmed = sanitizeControlChars(raw.trim())
        if (trimmed.isEmpty() || trimmed.any { it.isWhitespace() }) return ""
        val colon = trimmed.indexOf(':')
        if (colon <= 0) return ""
        val scheme = trimmed.substring(0, colon).lowercase()
        if (scheme !in ALLOWED_URL_SCHEMES) return ""
        if (scheme == "http" || scheme == "https") {
            if (!trimmed.startsWith("$scheme://", ignoreCase = true)) return ""
        } else if (scheme == "tg") {
            if (!trimmed.startsWith("tg://", ignoreCase = true)) return ""
        }
        return trimmed.take(512)
    }

    private fun parseNonNegativeLong(raw: String): Long? {
        if (raw.isEmpty()) return null
        val direct = raw.toLongOrNull()
        if (direct != null) return if (direct >= 0L) direct else null
        val asDouble = raw.toDoubleOrNull() ?: return null
        if (!asDouble.isFinite() || asDouble < 0.0 || asDouble > Long.MAX_VALUE.toDouble()) return null
        return asDouble.toLong()
    }

    private fun decodeBase64Relaxed(raw: String): String {
        val normalized = raw.replace('-', '+').replace('_', '/').replace(Regex("\\s+"), "")
        if (normalized.isEmpty()) return ""
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        return runCatching {
            String(Base64.getDecoder().decode(padded), Charsets.UTF_8)
        }.getOrDefault("")
    }

    private fun sanitizeControlChars(text: String): String = buildString(text.length) {
        for (ch in text) {
            if (ch.code >= 0x20 && ch.code != 0x7F) append(ch)
        }
    }

    data class UserinfoQuad(
        val uploadBytes: Long,
        val downloadBytes: Long,
        val totalBytes: Long,
        val expireUnixSec: Long,
    )
}
