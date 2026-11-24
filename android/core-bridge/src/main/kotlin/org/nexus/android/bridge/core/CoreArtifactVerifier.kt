package org.nexus.android.bridge.core

import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest

data class ArtifactVerificationResult(
    val valid: Boolean,
    val sha256Hex: String,
    val byteSize: Long,
    val isAarch64Elf: Boolean,
    val reason: String,
)

data class OfflineRulesetSummary(
    val totalFiles: Int,
    val freshFiles: Int,
    val staleFiles: Int,
    val totalBytes: Long,
)

object CoreArtifactVerifier {
    private const val EM_AARCH64 = 183
    private const val BUFFER_BYTES = 16384

    fun computeSha256Hex(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER_BYTES)
        file.inputStream().use { input ->
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString(separator = "") { "%02x".format(it) }
    }

    fun isLittleEndianArm64Elf(file: File): Boolean {
        if (!file.isFile || file.length() < 20) return false
        val header = ByteArray(20)
        RandomAccessFile(file, "r").use { raf ->
            raf.readFully(header)
        }
        if (header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() ||
            header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte()
        ) {
            return false
        }
        val elfClass = header[4].toInt() and 0xff // 2 = ELFCLASS64
        val endian = header[5].toInt() and 0xff // 1 = ELFDATA2LSB
        val machine = (header[18].toInt() and 0xff) or ((header[19].toInt() and 0xff) shl 8)
        return elfClass == 2 && endian == 1 && machine == EM_AARCH64
    }

    fun verifyCoreBinary(
        file: File,
        expectedSha256Hex: String? = null,
        requireArm64Elf: Boolean = true,
    ): ArtifactVerificationResult {
        if (!file.isFile) {
            return ArtifactVerificationResult(false, "", 0L, false, "missing binary: ${file.name}")
        }
        val arm64 = isLittleEndianArm64Elf(file)
        if (requireArm64Elf && !arm64) {
            return ArtifactVerificationResult(false, "", file.length(), false, "expected aarch64 ELF64 binary")
        }
        val digestHex = computeSha256Hex(file)
        if (expectedSha256Hex != null) {
            val expected = expectedSha256Hex
                .trim()
                .substringBefore(' ')
                .substringBefore('\t')
                .substringBefore('\n')
                .substringBefore('\r')
                .lowercase()
            if (!isValidSha256Hex(expected)) {
                return ArtifactVerificationResult(false, digestHex, file.length(), arm64, "invalid expected sha256")
            }
            if (digestHex != expected) {
                return ArtifactVerificationResult(false, digestHex, file.length(), arm64, "sha256 mismatch")
            }
        }
        return ArtifactVerificationResult(true, digestHex, file.length(), arm64, "verified")
    }

    private fun isValidSha256Hex(hex: String): Boolean =
        hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }

    fun evaluateOfflineRulesets(
        cacheDir: File,
        staleAfterMillis: Long = 7L * 24 * 3600 * 1000,
        nowMillis: Long = System.currentTimeMillis(),
    ): OfflineRulesetSummary {
        if (!cacheDir.isDirectory) {
            return OfflineRulesetSummary(0, 0, 0, 0L)
        }
        var total = 0
        var fresh = 0
        var stale = 0
        var totalBytes = 0L
        cacheDir.walkTopDown()
            .filter { it.isFile && (it.extension == "srs" || it.extension == "kdl" || it.extension == "beve") }
            .forEach { entry ->
                total += 1
                totalBytes += entry.length()
                val age = nowMillis - entry.lastModified()
                if (age <= staleAfterMillis) fresh += 1 else stale += 1
            }
        return OfflineRulesetSummary(total, fresh, stale, totalBytes)
    }
}
