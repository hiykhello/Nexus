package org.nexus.android.bridge.process

import java.io.Closeable
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Supervises the static aarch64-linux-musl Nexus binary extracted to nativeLibraryDir/libnexus.so.
 * Maintains a bounded 8 KiB rolling stderr ring for crash diagnostics and enforces graceful SIGTERM
 * shutdown so state snapshots/FakeIP WAL flush cleanly before exit.
 */
class NexusCoreProcess(
    private val executable: File,
    private val workDir: File,
    private val onUnexpectedExit: (exitCode: Int, lastStderr: String) -> Unit,
) : Closeable {
    private val stopping = AtomicBoolean(false)
    private val stderrLock = Any()
    private val stderrRing = ArrayDeque<String>(MAX_STDERR_LINES)
    private var stderrBytes = 0

    @Volatile
    private var process: Process? = null
    private var stderrThread: Thread? = null
    private var watcherThread: Thread? = null

    fun start(configFile: File, extraArgs: List<String> = emptyList()) {
        require(executable.isFile && executable.canExecute()) {
            "Nexus executable missing or not executable: ${executable.absolutePath}"
        }
        stopping.set(false)
        val cmd = buildList {
            add(executable.absolutePath)
            add("run")
            add("--config")
            add(configFile.absolutePath)
            addAll(extraArgs)
        }
        val proc = ProcessBuilder(cmd)
            .directory(workDir)
            .redirectErrorStream(true)
            .start()
        process = proc

        stderrThread = Thread({
            proc.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    recordLine(line!!)
                }
            }
        }, "nexus-core-log").apply {
            isDaemon = true
            start()
        }

        watcherThread = Thread({
            val code = runCatching { proc.waitFor() }.getOrDefault(-1)
            if (!stopping.get()) {
                onUnexpectedExit(code, recentStderr())
            }
        }, "nexus-core-watch").apply {
            isDaemon = true
            start()
        }
    }

    fun recentStderr(): String = synchronized(stderrLock) {
        stderrRing.joinToString("\n")
    }

    override fun close() {
        stopping.set(true)
        val proc = process ?: return
        process = null
        runCatching { proc.destroy() } // SIGTERM for clean state flush
        val exited = runCatching { proc.waitFor(GRACEFUL_STOP_MS, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        if (!exited) {
            runCatching { proc.destroyForcibly() }
            runCatching { proc.waitFor(500, TimeUnit.MILLISECONDS) }
        }
        runCatching { stderrThread?.interrupt() }
        runCatching { watcherThread?.interrupt() }
    }

    private fun recordLine(line: String) {
        synchronized(stderrLock) {
            val truncated = if (line.length > 512) line.substring(0, 512) else line
            stderrRing.addLast(truncated)
            stderrBytes += truncated.length + 1
            while (stderrRing.size > MAX_STDERR_LINES || stderrBytes > MAX_STDERR_BYTES) {
                val dropped = stderrRing.removeFirstOrNull() ?: break
                stderrBytes -= dropped.length + 1
            }
        }
    }

    companion object {
        private const val GRACEFUL_STOP_MS = 1_500L
        private const val MAX_STDERR_LINES = 64
        private const val MAX_STDERR_BYTES = 8 * 1024
    }
}
