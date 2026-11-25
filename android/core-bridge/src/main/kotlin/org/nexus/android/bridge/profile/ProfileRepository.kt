package org.nexus.android.bridge.profile

import org.nexus.android.bridge.model.ShareLinkParser
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
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
    private val secretsDir = File(rootDir, "secrets").apply {
        mkdirs()
        restrictDir0700(this)
    }
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
        atomicWriteSecret0600(file, secret.trim() + "\n")
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
        val kdlFile = File(profilesDir, "$safe.kdl")
        val deleted = kdlFile.delete()
        File(profilesDir, "$safe.url").delete()
        // Clean up profile-namespaced secret files (written with "$safe--*.secret").
        val prefix = "$safe--"
        secretsDir.listFiles { f -> f.isFile && f.name.startsWith(prefix) && f.extension == "secret" }
            ?.forEach { runCatching { it.delete() } }
        if (activeProfileId() == safe) {
            runCatching { activeMarker.delete() }
        }
        return deleted
    }

    /**
     * Fetches a remote HTTPS subscription (or loopback HTTP for testing), decodes Base64 or
     * newline-delimited share URIs, writes each node's credential to a 0600 private file,
     * and generates a complete zero-plaintext KDL profile.
     */
    fun importSubscription(
        name: String,
        urlString: String,
        controlDirective: String = "",
    ): Result<NexusProfile> = runCatching {
        val rawBytes = fetchSubscriptionBytes(urlString.trim())
        val profileId = sanitizeId(name)
        val kdl = buildKdlFromSubscriptionPayload(
            payload = String(rawBytes, Charsets.UTF_8),
            profileId = profileId,
            controlDirective = controlDirective,
        )
        saveProfile(name, kdl, urlString)
    }

    private fun validateSubscriptionUrl(url: URL) {
        val isLoopback = url.host == "127.0.0.1" || url.host == "localhost" || url.host == "::1" || url.host == "[::1]"
        require(url.protocol == "https" || (url.protocol == "http" && isLoopback)) {
            "仅允许 HTTPS 订阅链接（本机回环调试除外）"
        }
    }

    private fun fetchSubscriptionBytes(initialUrl: String): ByteArray {
        var current = URL(initialUrl)
        repeat(MAX_REDIRECTS + 1) { hop ->
            validateSubscriptionUrl(current)
            val conn = (current.openConnection() as HttpURLConnection).apply {
                connectTimeout = 8000
                readTimeout = 10000
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", "Nexus-Android/1.0")
            }
            try {
                val code = conn.responseCode
                if (code in setOf(301, 302, 303, 307, 308)) {
                    require(hop < MAX_REDIRECTS) { "订阅重定向次数过多" }
                    val location = conn.getHeaderField("Location")?.trim()
                    require(!location.isNullOrEmpty()) { "订阅重定向缺少目标地址" }
                    current = URL(current, location)
                } else {
                    require(code in 200..299) { "订阅拉取失败: HTTP $code" }
                    return conn.inputStream.use { readBoundedBytes(it, MAX_SUBSCRIPTION_BYTES) }
                }
            } finally {
                conn.disconnect()
            }
        }
        error("订阅重定向次数过多")
    }

    internal fun buildKdlFromSubscriptionPayload(
        payload: String,
        profileId: String = "",
        controlDirective: String = "",
    ): String {
        val lines = decodeSubscriptionLines(payload)
        val parsed = lines.mapNotNull { ShareLinkParser.parse(it).getOrNull() }
        require(parsed.isNotEmpty()) { "订阅内容中未找到可识别的 VLESS/Trojan/Hysteria2/SS 节点" }

        val safeProfile = if (profileId.isNotBlank()) sanitizeId(profileId) else ""
        val usedTags = mutableSetOf<String>()
        val blocks = mutableListOf<String>()
        val memberTags = mutableListOf<String>()
        for (node in parsed) {
            var uniqueTag = sanitizeId(node.tag)
            var suffix = 2
            while (!usedTags.add(uniqueTag)) uniqueTag = "${sanitizeId(node.tag)}-$suffix".also { suffix++ }
            val adjusted = node.copy(tag = uniqueTag)
            val secretKey = if (safeProfile.isNotEmpty()) "$safeProfile--$uniqueTag" else uniqueTag
            val secretPath = if (adjusted.secret.isNotEmpty()) writeSecret(secretKey, adjusted.secret).absolutePath else ""
            blocks += ShareLinkParser.renderKdlOutbound(adjusted, secretPath)
            memberTags += uniqueTag
        }
        val trimmedControl = controlDirective.trim()
        return buildString {
            appendLine("schema-version 1")
            appendLine("role \"client\"")
            appendLine("workers 2")
            if (trimmedControl.isNotEmpty()) {
                appendLine(trimmedControl)
            }
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
        private const val MAX_REDIRECTS = 3

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

        fun readBoundedBytes(input: InputStream, maxBytes: Int): ByteArray {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var total = 0
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                require(total <= maxBytes) { "订阅内容超过 ${maxBytes / (1024 * 1024)} MiB 上限" }
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }

        internal fun restrictDir0700(dir: File) {
            runCatching {
                Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwx------"))
            }.onFailure {
                dir.setReadable(false, false)
                dir.setWritable(false, false)
                dir.setExecutable(false, false)
                dir.setReadable(true, true)
                dir.setWritable(true, true)
                dir.setExecutable(true, true)
            }
        }

        fun atomicWriteSecret0600(target: File, content: String) {
            val parent = target.parentFile ?: error("Missing parent directory for ${target.path}")
            parent.mkdirs()
            val tmp = File(parent, ".${target.name}.${System.nanoTime()}.tmp")
            try {
                if (tmp.exists()) tmp.delete()
                val createdPosix = runCatching {
                    Files.createFile(
                        tmp.toPath(),
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
                    )
                    true
                }.getOrDefault(false)
                if (!createdPosix) {
                    tmp.createNewFile()
                    tmp.setReadable(false, false)
                    tmp.setWritable(false, false)
                    tmp.setReadable(true, true)
                    tmp.setWritable(true, true)
                }
                tmp.writeText(content, Charsets.UTF_8)
                if (!tmp.renameTo(target)) {
                    throw java.io.IOException("Atomic rename failed for ${target.name}")
                }
                runCatching {
                    Files.setPosixFilePermissions(target.toPath(), PosixFilePermissions.fromString("rw-------"))
                }
            } catch (t: Throwable) {
                runCatching { tmp.delete() }
                throw t
            }
        }

        private fun atomicWrite(target: File, content: String) {
            val tmp = File(target.parentFile, ".${target.name}.${System.nanoTime()}.tmp")
            try {
                tmp.writeText(content, Charsets.UTF_8)
                if (!tmp.renameTo(target)) {
                    target.writeText(content, Charsets.UTF_8)
                    tmp.delete()
                }
            } catch (t: Throwable) {
                runCatching { tmp.delete() }
                throw t
            }
        }
    }
}
