package org.nexus.android.bridge.uds

import android.net.LocalSocket
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Serves Nexus platform::protect_socket() requests over p.sock via SCM_RIGHTS.
 * Every received FileDescriptor is unconditionally closed after VpnService.protect(fd)
 * to prevent FD leaks in the :bg process.
 */
class ProtectSocketServer(
    private val socketFile: File,
    private val protectFd: (Int) -> Boolean,
) : Closeable {
    private val running = AtomicBoolean(false)
    private var server: UdsServerSocket? = null
    private var acceptThread: Thread? = null
    private var workers: ExecutorService? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val bound = UdsServerSocket.bind(socketFile)
        server = bound
        val pool = Executors.newFixedThreadPool(2) { r ->
            Thread(r, "nexus-protect-worker").apply { isDaemon = true }
        }
        workers = pool
        acceptThread = Thread({
            while (running.get()) {
                val client = try {
                    bound.accept()
                } catch (_: Throwable) {
                    if (!running.get()) break
                    continue
                }
                pool.execute { handleClient(client) }
            }
        }, "nexus-protect-accept").apply {
            isDaemon = true
            start()
        }
    }

    private fun handleClient(client: LocalSocket) {
        client.use { sock ->
            runCatching {
                sock.soTimeout = CLIENT_TIMEOUT_MS
                val input = sock.inputStream
                val output = sock.outputStream
                val marker = ByteArray(1)
                while (running.get()) {
                    val read = input.read(marker)
                    if (read <= 0) break
                    val fds = sock.ancillaryFileDescriptors
                    if (fds.isNullOrEmpty()) {
                        output.write(STATUS_ERROR)
                        output.flush()
                        continue
                    }
                    var ok = false
                    try {
                        val pfd = ParcelFileDescriptor.dup(fds[0])
                        try {
                            ok = protectFd(pfd.fd)
                        } finally {
                            runCatching { pfd.close() }
                        }
                    } finally {
                        // Crucial: close every received SCM_RIGHTS descriptor in this process.
                        for (fd in fds) {
                            UdsServerSocket.closeFdQuietly(fd)
                        }
                    }
                    output.write(if (ok) STATUS_OK else STATUS_ERROR)
                    output.flush()
                }
            }
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        runCatching { server?.close() }
        server = null
        runCatching { workers?.shutdownNow() }
        workers = null
        runCatching { acceptThread?.interrupt() }
        acceptThread = null
    }

    companion object {
        private const val CLIENT_TIMEOUT_MS = 3_000
        private const val STATUS_OK = 0
        private const val STATUS_ERROR = 1
    }
}
