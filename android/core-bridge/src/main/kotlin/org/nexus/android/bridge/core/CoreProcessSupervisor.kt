package org.nexus.android.bridge.core

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.TimeUnit

data class CoreValidationResult(val ok: Boolean, val output: String)

/**
 * Manages the native aarch64-linux-musl Nexus sidecar binary packaged in nativeLibraryDir/libnexus.so.
 * Android 10+ W^X requires execution directly from nativeLibraryDir with useLegacyPackaging = true.
 */
class CoreProcessSupervisor(private val context: Context) {
    @Volatile private var process: Process? = null

    fun binaryFile(): File = File(context.applicationInfo.nativeLibraryDir, "libnexus.so")

    fun isRunning(): Boolean = process?.isAlive == true

    private fun verifyCoreBinary(bin: File): CoreValidationResult? {
        if (!bin.isFile || !bin.canExecute()) {
            return CoreValidationResult(false, "Missing executable core binary: ${bin.absolutePath}")
        }
        val expectedSha = try {
            context.assets.open(SHA256_ASSET_NAME).bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (_: FileNotFoundException) {
            null
        } catch (err: Throwable) {
            return CoreValidationResult(
                false,
                "Failed to read core checksum asset: ${err.message ?: err.javaClass.simpleName}",
            )
        }
        val check = CoreArtifactVerifier.verifyCoreBinary(bin, expectedSha, requireArm64Elf = true)
        return if (check.valid) null else CoreValidationResult(false, "Core integrity check failed: ${check.reason}")
    }

    suspend fun validateConfig(configFile: File): CoreValidationResult = withContext(Dispatchers.IO) {
        val bin = binaryFile()
        verifyCoreBinary(bin)?.let { return@withContext it }
        runCatching {
            val proc = ProcessBuilder(bin.absolutePath, "check", "--config", configFile.absolutePath)
                .redirectErrorStream(true)
                .start()
            val captured = ByteArrayOutputStream()
            val reader = Thread({
                runCatching {
                    val buf = ByteArray(1024)
                    proc.inputStream.use { input ->
                        while (true) {
                            val n = input.read(buf)
                            if (n <= 0) break
                            val remaining = MAX_VALIDATION_OUTPUT_BYTES - captured.size()
                            if (remaining > 0) {
                                captured.write(buf, 0, minOf(n, remaining))
                            }
                        }
                    }
                }
            }, "nexus-check-drain").apply {
                isDaemon = true
                start()
            }
            val finished = proc.waitFor(5, TimeUnit.SECONDS)
            if (!finished) {
                proc.destroyForcibly()
                proc.waitFor(500, TimeUnit.MILLISECONDS)
                reader.join(250)
                CoreValidationResult(false, "nexus check timed out")
            } else {
                reader.join(500)
                val text = String(captured.toByteArray(), Charsets.UTF_8).trim()
                CoreValidationResult(
                    proc.exitValue() == 0,
                    text.ifBlank {
                        if (proc.exitValue() == 0) "configuration valid" else "exit ${proc.exitValue()}"
                    },
                )
            }
        }.getOrElse { err ->
            CoreValidationResult(false, err.message ?: "failed to run nexus check")
        }
    }

    @Synchronized
    fun start(
        configFile: File,
        tunFdSocket: File? = null,
        onLogLine: ((String) -> Unit)? = null,
        onExit: ((Int) -> Unit)? = null,
    ): Boolean {
        if (isRunning()) return true
        val bin = binaryFile()
        val verifyErr = verifyCoreBinary(bin)
        if (verifyErr != null) {
            onLogLine?.invoke("[error] core: ${verifyErr.output}")
            return false
        }

        val builder = ProcessBuilder(bin.absolutePath, "run", "--config", configFile.absolutePath)
            .directory(context.filesDir)
            .redirectErrorStream(true)
        if (tunFdSocket != null) {
            builder.environment()["NEXUS_TUN_FD_SOCK"] = tunFdSocket.absolutePath
        }
        val proc = runCatching { builder.start() }.getOrNull() ?: return false
        process = proc

        // Always drain stdout/stderr so the sidecar pipe never fills and deadlocks; also observe unexpected exit.
        Thread({
            runCatching {
                proc.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        onLogLine?.invoke(line)
                    }
                }
            }
            val exitCode = runCatching { proc.waitFor() }.getOrDefault(-1)
            val unexpected = synchronized(this@CoreProcessSupervisor) {
                if (process === proc) {
                    process = null
                    true
                } else {
                    false
                }
            }
            if (unexpected) {
                onExit?.invoke(exitCode)
            }
        }, "nexus-core-log").apply {
            isDaemon = true
            start()
        }
        return true
    }

    @Synchronized
    fun stop() {
        val proc = process ?: return
        process = null
        proc.destroy()
        if (!proc.waitFor(1500, TimeUnit.MILLISECONDS)) {
            proc.destroyForcibly()
            proc.waitFor(1000, TimeUnit.MILLISECONDS)
        }
    }

    companion object {
        private const val SHA256_ASSET_NAME = "nexus-core.sha256"
        private const val MAX_VALIDATION_OUTPUT_BYTES = 4096
    }
}
