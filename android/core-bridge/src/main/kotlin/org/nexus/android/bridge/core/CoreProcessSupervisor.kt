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

    suspend fun validateConfig(
        configFile: File,
        isConfigDir: Boolean = false,
        hostOverrideFile: File? = null,
    ): CoreValidationResult = withContext(Dispatchers.IO) {
        val bin = binaryFile()
        verifyCoreBinary(bin)?.let { return@withContext it }
        val args = buildList {
            add(bin.absolutePath)
            add("check")
            add(if (isConfigDir) "--config-dir" else "--config")
            add(configFile.absolutePath)
            if (hostOverrideFile != null) {
                add("--host-override")
                add(hostOverrideFile.absolutePath)
            }
        }
        runBoundedCommand(args, timeoutSeconds = 5L, maxBytes = MAX_VALIDATION_OUTPUT_BYTES, emptyOkMsg = "configuration valid")
    }

    suspend fun composeWorkspace(
        workspaceFile: File,
        hostFile: File,
        secretsDir: File,
        activeProfileId: String,
        emitKdlFile: File,
    ): CoreValidationResult = withContext(Dispatchers.IO) {
        val bin = binaryFile()
        verifyCoreBinary(bin)?.let { return@withContext it }
        val args = buildList {
            add(bin.absolutePath)
            add("workspace")
            add("compose")
            add("--workspace")
            add(workspaceFile.absolutePath)
            add("--host")
            add(hostFile.absolutePath)
            add("--secrets-dir")
            add(secretsDir.absolutePath)
            if (activeProfileId.isNotBlank()) {
                add("--active")
                add(activeProfileId)
            }
            add("--emit-kdl")
            add(emitKdlFile.absolutePath)
            add("--json-result")
        }
        runBoundedCommand(args, timeoutSeconds = 10L, maxBytes = MAX_COMPOSE_OUTPUT_BYTES, emptyOkMsg = "")
    }

    private fun runBoundedCommand(
        command: List<String>,
        timeoutSeconds: Long,
        maxBytes: Int,
        emptyOkMsg: String,
    ): CoreValidationResult = runCatching {
        val proc = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()
        val captured = ByteArrayOutputStream()
        val reader = Thread({
            runCatching {
                val buf = ByteArray(4096)
                proc.inputStream.use { input ->
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        val remaining = maxBytes - captured.size()
                        if (remaining > 0) {
                            captured.write(buf, 0, minOf(n, remaining))
                        }
                    }
                }
            }
        }, "nexus-cli-drain").apply {
            isDaemon = true
            start()
        }
        val finished = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!finished) {
            proc.destroyForcibly()
            proc.waitFor(500, TimeUnit.MILLISECONDS)
            reader.join(250)
            CoreValidationResult(false, "nexus command timed out")
        } else {
            reader.join(500)
            val text = String(captured.toByteArray(), Charsets.UTF_8).trim()
            CoreValidationResult(
                proc.exitValue() == 0,
                text.ifBlank {
                    if (proc.exitValue() == 0) emptyOkMsg else "exit ${proc.exitValue()}"
                },
            )
        }
    }.getOrElse { err ->
        CoreValidationResult(false, err.message ?: "failed to run nexus core command")
    }

    @Synchronized
    fun start(
        configFile: File,
        tunFdSocket: File? = null,
        isConfigDir: Boolean = false,
        hostOverrideFile: File? = null,
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

        val cmd = buildList {
            add(bin.absolutePath)
            add("run")
            add(if (isConfigDir) "--config-dir" else "--config")
            add(configFile.absolutePath)
            if (hostOverrideFile != null) {
                add("--host-override")
                add(hostOverrideFile.absolutePath)
            }
        }
        val builder = ProcessBuilder(cmd)
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
        private const val MAX_COMPOSE_OUTPUT_BYTES = 4 * 1024 * 1024
    }
}
