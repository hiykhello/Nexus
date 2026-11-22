package org.nexus.android.bridge.uds

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.system.Os
import android.system.OsConstants
import java.io.Closeable
import java.io.File
import java.io.IOException
import org.nexus.android.bridge.model.RuntimeSocketPaths

/**
 * Pure Android SDK filesystem Unix Domain Socket server (zero JNI).
 * Never uses abstract namespace so kernel DAC (0700 app dir / 0600 socket) + SELinux app_data_file
 * isolate Nexus IPC strictly to this app's UID.
 */
class UdsServerSocket private constructor(
    private val socketFile: File,
    private val localServer: LocalServerSocket,
    private val boundClientSocket: LocalSocket,
) : Closeable {

    fun accept(): LocalSocket = localServer.accept()

    override fun close() {
        runCatching { localServer.close() }
        runCatching { boundClientSocket.close() }
        runCatching { socketFile.delete() }
    }

    companion object {
        fun bind(file: File): UdsServerSocket {
            val path = file.absolutePath
            require(path.startsWith("/")) { "UDS path must be absolute: $path" }
            require(path.toByteArray(Charsets.UTF_8).size < RuntimeSocketPaths.MAX_UNIX_PATH_BYTES) {
                "UDS path exceeds 108-byte sun_path limit: $path"
            }

            file.parentFile?.mkdirs()
            if (file.exists() && !file.delete()) {
                throw IOException("Failed to remove stale socket file: $path")
            }

            val socket = LocalSocket(LocalSocket.SOCKET_STREAM)
            try {
                socket.bind(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
                Os.chmod(path, 0b110_000_000) // 0600 owner-only
                val server = LocalServerSocket(socket.fileDescriptor)
                return UdsServerSocket(file, server, socket)
            } catch (t: Throwable) {
                runCatching { socket.close() }
                runCatching { file.delete() }
                throw IOException("Failed to bind filesystem UDS at $path", t)
            }
        }

        fun closeFdQuietly(fd: java.io.FileDescriptor?) {
            if (fd == null || !fd.valid()) return
            runCatching { Os.close(fd) }
        }
    }
}
