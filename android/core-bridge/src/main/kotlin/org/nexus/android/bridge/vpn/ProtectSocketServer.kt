package org.nexus.android.bridge.vpn

import android.net.LocalSocket
import android.os.ParcelFileDescriptor
import android.os.Process
import org.nexus.android.bridge.uds.UdsServerSocket
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
 *  3. Server calls VpnService.protect(fd), closes all received & duplicated fds, and replies 1 byte (0x00).
 */
class ProtectSocketServer(
    private val socketPath: File,
    private val protectFd: (Int) -> Boolean,
) : Closeable {
    private val running = AtomicBoolean(false)
    @Volatile private var server: UdsServerSocket? = null
    @Volatile private var acceptThread: Thread? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val bound = try {
            UdsServerSocket.bind(socketPath)
        } catch (t: Throwable) {
            running.set(false)
            throw t
        }
        server = bound
        acceptThread = Thread({ acceptLoop(bound) }, "nexus-protect-srv").apply {
            isDaemon = true
            start()
        }
    }

    private fun acceptLoop(srv: UdsServerSocket) {
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
            try {
                for (rawFd in fds) {
                    val pfd = ParcelFileDescriptor.dup(rawFd)
                    try {
                        if (!protectFd(pfd.fd)) allProtected = false
                    } finally {
                        pfd.close()
                    }
                }
            } finally {
                for (rawFd in fds) {
                    UdsServerSocket.closeFdQuietly(rawFd)
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
        runCatching { server?.close() }
        server = null
        acceptThread?.interrupt()
        acceptThread = null
    }
}
