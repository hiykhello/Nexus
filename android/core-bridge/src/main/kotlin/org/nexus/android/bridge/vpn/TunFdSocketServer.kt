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
 * Filesystem AF_UNIX SCM_RIGHTS server handing the VpnService TUN descriptor
 * to the child libnexus.so process (because fork/exec strips inherited FDs > 2).
 */
class TunFdSocketServer(
    private val socketPath: File,
    private val tunInterface: ParcelFileDescriptor,
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
        acceptThread = Thread({ acceptLoop(bound) }, "nexus-tun-fd-srv").apply {
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
            client.soTimeout = 500
            val cred = client.peerCredentials
            if (cred.uid != expectedUid) return
            val marker = client.inputStream.read()
            if (marker < 0) return
            client.setFileDescriptorsForSend(arrayOf(tunInterface.fileDescriptor))
            client.outputStream.write(0)
            client.outputStream.flush()
        } catch (_: IOException) {
            // Best-effort handoff; core handles timeout/EOF cleanly.
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
