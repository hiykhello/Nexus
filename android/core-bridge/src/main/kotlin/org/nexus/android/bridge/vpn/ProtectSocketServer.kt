package org.nexus.android.bridge.vpn

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Filesystem AF_UNIX SCM_RIGHTS protect-socket server matching src/platform/socket_namespace.cpp.
 *
 * Wire protocol:
 *  1. Nexus core connects to protectSocketPath and sends 1 byte + SCM_RIGHTS fd.
 *  2. Server verifies SO_PEERCRED uid == Process.myUid() (strict same-UID boundary).
 *  3. Server calls VpnService.protect(fd), closes its duplicated fd, and replies 1 byte (0x00).
 */
class ProtectSocketServer(
    private val socketPath: File,
    private val protectFd: (Int) -> Boolean,
) : Closeable {
    private val running = AtomicBoolean(false)
    @Volatile private var boundSocket: LocalSocket? = null
    @Volatile private var serverSocket: LocalServerSocket? = null
    @Volatile private var acceptThread: Thread? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        socketPath.parentFile?.mkdirs()
        if (socketPath.exists()) socketPath.delete()

        val local = LocalSocket(LocalSocket.SOCKET_STREAM)
        local.bind(LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
        // Restrict socket permissions to owner only (0600).
        socketPath.setReadable(false, false)
        socketPath.setWritable(false, false)
        socketPath.setReadable(true, true)
        socketPath.setWritable(true, true)

        boundSocket = local
        serverSocket = LocalServerSocket(local.fileDescriptor)
        acceptThread = Thread({ acceptLoop() }, "nexus-protect-srv").apply {
            isDaemon = true
            start()
        }
    }

    private fun acceptLoop() {
        val srv = serverSocket ?: return
        val expectedUid = Process.myUid()
        while (running.get()) {
            val client = try {
                srv.accept()
            } catch (_: IOException) {
                break
            }
            handleClient(client, expectedUid)
        }
    }

    private fun handleClient(client: LocalSocket, expectedUid: Int) {
        try {
            client.soTimeout = 250
            val cred = client.peerCredentials
            if (cred.uid != expectedUid) return

            val marker = client.inputStream.read()
            if (marker < 0) return

            val fds = client.ancillaryFileDescriptors
            if (fds.isNullOrEmpty()) return

            var allProtected = true
            for (rawFd in fds) {
                val pfd = ParcelFileDescriptor.dup(rawFd)
                try {
                    if (!protectFd(pfd.fd)) allProtected = false
                } finally {
                    pfd.close()
                }
            }
            if (allProtected) {
                client.outputStream.write(0)
                client.outputStream.flush()
            }
        } catch (_: IOException) {
            // Best-effort peer teardown; core handles timeout/EOF cleanly.
        } finally {
            runCatching { client.close() }
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        runCatching { serverSocket?.close() }
        runCatching { boundSocket?.close() }
        serverSocket = null
        boundSocket = null
        acceptThread?.interrupt()
        acceptThread = null
        socketPath.delete()
    }
}
