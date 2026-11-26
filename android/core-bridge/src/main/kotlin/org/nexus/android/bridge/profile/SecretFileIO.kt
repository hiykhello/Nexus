package org.nexus.android.bridge.profile

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64

/**
 * Focused POSIX 0600/0700 secret file I/O, bounded stream reader, ID sanitizer,
 * and Base64/plain subscription line decoder.
 */
object SecretFileIO {
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
            require(total <= maxBytes) { "内容超过 ${maxBytes / (1024 * 1024)} MiB 上限" }
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    fun restrictDir0700(dir: File) {
        if (!dir.exists()) return
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

    fun restrictFile0600(file: File) {
        if (!file.exists()) return
        runCatching {
            Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------"))
        }.onFailure {
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
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
                restrictFile0600(tmp)
            }
            tmp.writeText(content, Charsets.UTF_8)
            if (!tmp.renameTo(target)) {
                throw java.io.IOException("Atomic rename failed for ${target.name}")
            }
            restrictFile0600(target)
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
    }
}
