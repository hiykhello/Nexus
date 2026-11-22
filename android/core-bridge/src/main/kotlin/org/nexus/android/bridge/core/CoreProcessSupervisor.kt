package org.nexus.android.bridge.core

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
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

    suspend fun validateConfig(configFile: File): CoreValidationResult = withContext(Dispatchers.IO) {
        val bin = binaryFile()
        if (!bin.isFile || !bin.canExecute()) {
            return@withContext CoreValidationResult(false, "Missing executable core binary: ${bin.absolutePath}")
        }
        runCatching {
            val proc = ProcessBuilder(bin.absolutePath, "check", "--config", configFile.absolutePath)
                .redirectErrorStream(true)
                .start()
            val text = proc.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }.take(4096)
            val finished = proc.waitFor(5, TimeUnit.SECONDS)
            if (!finished) {
                proc.destroyForcibly()
                CoreValidationResult(false, "nexus check timed out")
            } else {
                CoreValidationResult(proc.exitValue() == 0, text.ifBlank {
                    if (proc.exitValue() == 0) "configuration valid" else "exit ${proc.exitValue()}"
                })
            }
        }.getOrElse { err ->
            CoreValidationResult(false, err.message ?: "failed to run nexus check")
        }
    }

    @Synchronized
    fun start(
        configFile: File,
        tunFd: Int? = null,
        onLogLine: ((String) -> Unit)? = null,
    ): Boolean {
        if (isRunning()) return true
        val bin = binaryFile()
        if (!bin.isFile || !bin.canExecute()) return false

        val builder = ProcessBuilder(bin.absolutePath, "run", "--config", configFile.absolutePath)
            .directory(context.filesDir)
            .redirectErrorStream(true)
        if (tunFd != null && tunFd >= 0) {
            builder.environment()["NEXUS_TUN_FD"] = tunFd.toString()
        }
        val proc = runCatching { builder.start() }.getOrNull() ?: return false
        process = proc

        if (onLogLine != null) {
            Thread({
                runCatching {
                    proc.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                        for (line in lines) onLogLine(line)
                    }
                }
            }, "nexus-core-log").apply {
                isDaemon = true
                start()
            }
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
}
