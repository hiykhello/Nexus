package org.nexus.android.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.core.CoreArtifactVerifier
import java.io.File
import kotlin.io.path.createTempDirectory

class CoreArtifactVerifierTest {
    private fun makeFakeElf(machine: Int): ByteArray {
        val bytes = ByteArray(64)
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2 // ELFCLASS64
        bytes[5] = 1 // ELFDATA2LSB
        bytes[18] = (machine and 0xff).toByte()
        bytes[19] = ((machine ushr 8) and 0xff).toByte()
        return bytes
    }

    @Test
    fun verifiesAarch64ElfAndSha256() {
        val dir = createTempDirectory("nexus-art-").toFile()
        try {
            val bin = File(dir, "libnexus.so")
            bin.writeBytes(makeFakeElf(183))
            val sha = CoreArtifactVerifier.computeSha256Hex(bin)
            val ok = CoreArtifactVerifier.verifyCoreBinary(bin, sha, requireArm64Elf = true)
            assertTrue(ok.valid)
            assertTrue(ok.isAarch64Elf)

            val badSha = CoreArtifactVerifier.verifyCoreBinary(bin, "0".repeat(64), requireArm64Elf = true)
            assertFalse(badSha.valid)
            assertEquals("sha256 mismatch", badSha.reason)

            val x86 = File(dir, "x86.so")
            x86.writeBytes(makeFakeElf(62))
            val badArch = CoreArtifactVerifier.verifyCoreBinary(x86, null, requireArm64Elf = true)
            assertFalse(badArch.valid)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun evaluatesOfflineRulesetsFreshAndStale() {
        val dir = createTempDirectory("nexus-rs-").toFile()
        try {
            val now = 1_000_000_000L
            val freshFile = File(dir, "geoip.srs").apply {
                writeBytes(ByteArray(128))
                setLastModified(now - 1000L)
            }
            val staleFile = File(dir, "legacy.kdl").apply {
                writeText("schema-version 1\n")
                setLastModified(now - 20_000_000L)
            }
            assertTrue(freshFile.exists() && staleFile.exists())
            val summary = CoreArtifactVerifier.evaluateOfflineRulesets(
                cacheDir = dir,
                staleAfterMillis = 60_000L,
                nowMillis = now,
            )
            assertEquals(2, summary.totalFiles)
            assertEquals(1, summary.freshFiles)
            assertEquals(1, summary.staleFiles)
            assertEquals(128L + staleFile.length(), summary.totalBytes)
        } finally {
            dir.deleteRecursively()
        }
    }
}
