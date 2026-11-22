package org.nexus.android.bridge.uds

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.File
import java.io.IOException

/**
 * Client for Nexus LocalControl Unix socket (c.sock) speaking the NEXUS/1 NUL-delimited protocol.
 */
class ControlSocketClient(
    private val socketFile: File,
    private val timeoutMs: Int = 2_000,
) {
    fun request(vararg args: String): Result<String> = runCatching {
        require(args.isNotEmpty()) { "Control request requires at least one token" }
        val wire = buildWireFrame(args.toList())
        LocalSocket(LocalSocket.SOCKET_STREAM).use { sock ->
            sock.soTimeout = timeoutMs
            sock.connect(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            sock.outputStream.write(wire)
            sock.outputStream.flush()
            sock.shutdownOutput()
            val reply = sock.inputStream.readBytes()
            if (reply.isEmpty()) throw IOException("Empty control reply")
            reply.toString(Charsets.UTF_8)
        }
    }

    fun status(): Result<String> = request("status")
    fun reload(): Result<String> = request("reload")
    fun setLogLevel(level: String): Result<String> = request("log-level", level)
    fun selectOutbound(group: String, member: String): Result<String> = request("select", group, member)
    fun notifyNetworkChange(generation: Long): Result<String> = request("network-change", generation.toString())

    companion object {
        const val PROTOCOL_VERSION = "NEXUS/1"
        const val MAX_REQUEST_BYTES = 1024

        fun buildWireFrame(args: List<String>): ByteArray {
            require(args.isNotEmpty()) { "Control request requires at least one token" }
            for (token in args) {
                require(token.isNotEmpty() && !token.contains('\u0000')) {
                    "Invalid control token"
                }
            }
            val payload = "$PROTOCOL_VERSION ${args.joinToString("\u0000")}"
            val bytes = payload.toByteArray(Charsets.UTF_8)
            require(bytes.size <= MAX_REQUEST_BYTES) {
                "Control request exceeds $MAX_REQUEST_BYTES bytes"
            }
            return bytes
        }
    }
}
