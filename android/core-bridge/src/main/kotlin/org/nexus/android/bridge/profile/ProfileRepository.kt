package org.nexus.android.bridge.profile

import org.nexus.android.bridge.share.ShareLinkParser
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

data class NexusProfile(
    val id: String,
    val name: String,
    val kdlFile: File,
    val subscriptionUrl: String = "",
    val updatedAtMs: Long = 0L,
)

/**
 * Multi-profile & subscription repository with strict 0600 secret isolation
 * and atomic KDL file replacement.
 */
class ProfileRepository(private val rootDir: File) {
    private val profilesDir = File(rootDir, "profiles").apply { mkdirs() }
    private val secretsDir = File(rootDir, "secrets").apply { mkdirs() }
    private val activeMarker = File(rootDir, ".active_profile")

    fun listProfiles(): List<NexusProfile> {
        val files = profilesDir.listFiles { f -> f.isFile && f.extension == "kdl" }.orEmpty()
        return files.sortedBy { it.name }.map { file ->
            val id = file.nameWithoutExtension
            val metaFile = File(profilesDir, "$id.url")
            val subUrl = if (metaFile.isFile) metaFile.readText().trim() else ""
            NexusProfile(
                id = id,
                name = id,
                kdlFile = file,
                subscriptionUrl = subUrl,
                updatedAtMs = file.lastModified(),
            )
        }
    }

    fun activeProfileId(): String? =
        activeMarker.takeIf { it.isFile }?.readText()?.trim()?.takeIf { it.isNotEmpty() }

    fun setActiveProfile(id: String) {
        atomicWrite(activeMarker, id + "\n")
    }

    fun writeSecret(tag: String, secret: String): File {
        val safeTag = sanitizeId(tag)
        val file = File(secretsDir, "$safeTag.secret")
        atomicWrite(file, secret.trim() + "\n")
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setReadable(true, true)
        file.setWritable(true, true)
        return file
    }

    fun saveProfile(name: String, kdlContent: String, subscriptionUrl: String = ""): NexusProfile {
        val id = sanitizeId(name)
        val kdlFile = File(profilesDir, "$id.kdl")
        atomicWrite(kdlFile, kdlContent)
        val metaFile = File(profilesDir, "$id.url")
        if (subscriptionUrl.isNotBlank()) atomicWrite(metaFile, subscriptionUrl.trim() + "\n")
        else if (metaFile.exists()) metaFile.delete()
        return NexusProfile(id, id, kdlFile, subscriptionUrl.trim(), kdlFile.lastModified())
    }

    fun deleteProfile(id: String): Boolean {
        val safe = sanitizeId(id)
        val deleted = File(profilesDir, "$safe.kdl").delete()
        File(profilesDir, "$safe.url").delete()
        return deleted
    }

    /**
     * Fetches a remote HTTPS subscription (or loopback HTTP for testing), decodes Base64 or
     * newline-delimited share URIs, writes each node's credential to a 0600 private file,
     * and generates a complete zero-plaintext KDL profile.
     */
    fun importSubscription(name: String, urlString: String): Result<NexusProfile> = runCatching {
        val url = URL(urlString.trim())
        val isLoopback = url.host == "127.0.0.1" || url.host == "localhost" || url.host == "::1"
        require(url.protocol == "https" || (url.protocol == "http" && isLoopback)) {
            "仅允许 HTTPS 订阅链接（本机回环调试除外）"
        }
        val conn = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 8000
            readTimeout = 10000
            setRequestProperty("User-Agent", "Nexus-Android/1.0")
        }
        try {
            val code = conn.responseCode
            require(code in 200..299) { "订阅拉取失败: HTTP $code" }
            val rawBytes = conn.inputStream.use { it.readNBytes(MAX_SUBSCRIPTION_BYTES) }
            val kdl = buildKdlFromSubscriptionPayload(rawBytes.toString(Charsets.UTF_8))
            saveProfile(name, kdl, urlString)
        } finally {
            conn.disconnect()
        }
    }

    internal fun buildKdlFromSubscriptionPayload(payload: String): String {
        val lines = decodeSubscriptionLines(payload)
        val parsed = lines.mapNotNull { ShareLinkParser.parse(it).getOrNull() }
        require(parsed.isNotEmpty()) { "订阅内容中未找到可识别的 VLESS/Trojan/Hysteria2/SS 节点" }

        val usedTags = mutableSetOf<String>()
        val blocks = mutableListOf<String>()
        val memberTags = mutableListOf<String>()
        for (node in parsed) {
            var uniqueTag = sanitizeId(node.tag)
            var suffix = 2
            while (!usedTags.add(uniqueTag)) uniqueTag = "${sanitizeId(node.tag)}-$suffix".also { suffix++ }
            val adjusted = node.copy(tag = uniqueTag)
            val secretFile = writeSecret(uniqueTag, adjusted.secret)
            blocks += ShareLinkParser.renderKdlOutbound(adjusted, secretFile.absolutePath)
            memberTags += uniqueTag
        }
        return buildString {
            appendLine("schema-version 1")
            appendLine("role \"client\"")
            appendLine("workers 2")
            appendLine("inbound \"local\" type=\"socks5\" { listen host=\"127.0.0.1\" port=10808; authentication \"none\"; }")
            appendLine("outbound \"direct\" type=\"direct\"")
            for (b in blocks) {
                appendLine()
                append(b)
            }
            appendLine()
            appendLine("outbound \"proxy\" type=\"selector\" {")
            for (tag in memberTags) appendLine("    member \"$tag\"")
            appendLine("    member \"direct\"")
            appendLine("    selected \"${memberTags.first()}\"")
            appendLine("}")
            appendLine("routing { default-outbound \"proxy\"; }")
        }
    }

    companion object {
        private const val MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024

        fun sanitizeId(raw: String): String {
            val cleaned = raw.trim().replace(Regex("[^A-Za-z0-9._-]"), "-").trim('-')
            return cleaned.ifEmpty { "profile" }.take(64)
        }

        fun decodeSubscriptionLines(payload: String): List<String> {
            val trimmed = payload.trim()
            if (trimmed.isEmpty()) return emptyList()
            val direct = trimmed.lines().map { it.trim() }.filter { it.contains("://") }
            if (direct.isNotEmpty()) return direct
            val decoded = runCatching {
                val normalized = trimmed.replace('-', '+').replace('_', '/').replace(Regex("\\s+"), "")
                val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
                String(Base64.getDecoder().decode(padded), Charsets.UTF_8)
            }.getOrDefault("")
            return decoded.lines().map { it.trim() }.filter { it.contains("://") }
        }

        private fun atomicWrite(target: File, content: String) {
            val tmp = File(target.parentFile, ".${target.name}.tmp")
            tmp.writeText(content)
            if (!tmp.renameTo(target)) {
                target.writeText(content)
                tmp.delete()
            }
        }
    }
}
