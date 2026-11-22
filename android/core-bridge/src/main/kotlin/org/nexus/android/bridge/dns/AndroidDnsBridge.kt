package org.nexus.android.bridge.dns

import android.net.DnsResolver
import android.net.Network
import android.os.CancellationSignal
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.nexus.android.bridge.uds.UdsServerSocket

data class DnsBridgeRequest(
    val requestId: Int,
    val timeoutMs: Int,
    val wireQuery: ByteArray,
)

data class DnsBridgeResponse(
    val requestId: Int,
    val status: Byte,
    val errorCode: Int,
    val wireAnswer: ByteArray,
)

object DnsBridgeCodec {
    const val STATUS_OK: Byte = 0
    const val STATUS_NO_NETWORK: Byte = 1
    const val STATUS_TIMEOUT: Byte = 2
    const val STATUS_DNS_ERROR: Byte = 3
    const val MAX_WIRE_BYTES = 4096

    fun readRequest(input: DataInputStream): DnsBridgeRequest? {
        val header = ByteArray(10)
        try {
            input.readFully(header)
        } catch (_: EOFException) {
            return null
        }
        val buf = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val reqId = buf.int
        val timeoutMs = buf.int.coerceIn(200, 15_000)
        val len = buf.short.toInt() and 0xFFFF
        require(len in 12..MAX_WIRE_BYTES) { "Invalid DNS wire query length: $len" }
        val wire = ByteArray(len)
        input.readFully(wire)
        return DnsBridgeRequest(reqId, timeoutMs, wire)
    }

    fun writeResponse(output: DataOutputStream, response: DnsBridgeResponse) {
        val header = ByteBuffer.allocate(11).order(ByteOrder.BIG_ENDIAN)
            .putInt(response.requestId)
            .put(response.status)
            .putInt(response.errorCode)
            .putShort(response.wireAnswer.size.toShort())
            .array()
        output.write(header)
        if (response.wireAnswer.isNotEmpty()) {
            output.write(response.wireAnswer)
        }
        output.flush()
    }
}

/**
 * Bridges Nexus `local` DNS queries to Android's native DnsResolver.rawQuery(underlyingNetwork, ...).
 * Preserves Captive Portal resolution, enterprise search domains, DNS64/NAT64, and full RR types
 * (A/AAAA/HTTPS/SVCB/TXT/SRV) while staying strictly pinned to the non-VPN physical network.
 */
class AndroidDnsBridge(
    private val socketFile: File,
    private val physicalNetworkProvider: () -> Network?,
) : Closeable {
    private val running = AtomicBoolean(false)
    private var server: UdsServerSocket? = null
    private var acceptThread: Thread? = null
    private var workers: ExecutorService? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val bound = UdsServerSocket.bind(socketFile)
        server = bound
        val pool = Executors.newCachedThreadPool { r ->
            Thread(r, "nexus-dns-bridge").apply { isDaemon = true }
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
                pool.execute { handleClient(client, pool) }
            }
        }, "nexus-dns-bridge-accept").apply {
            isDaemon = true
            start()
        }
    }

    private fun handleClient(client: android.net.LocalSocket, executor: ExecutorService) {
        client.use { sock ->
            runCatching {
                val input = DataInputStream(sock.inputStream)
                val output = DataOutputStream(sock.outputStream)
                while (running.get()) {
                    val req = DnsBridgeCodec.readRequest(input) ?: break
                    val resp = resolveRaw(req, executor)
                    synchronized(output) {
                        DnsBridgeCodec.writeResponse(output, resp)
                    }
                }
            }
        }
    }

    private fun resolveRaw(req: DnsBridgeRequest, executor: ExecutorService): DnsBridgeResponse {
        val network = physicalNetworkProvider()
            ?: return DnsBridgeResponse(req.requestId, DnsBridgeCodec.STATUS_NO_NETWORK, 0, ByteArray(0))

        val latch = CountDownLatch(1)
        val answerRef = AtomicReference<ByteArray?>(null)
        val errCodeRef = AtomicReference(0)
        val signal = CancellationSignal()

        DnsResolver.getInstance().rawQuery(
            network,
            req.wireQuery,
            DnsResolver.FLAG_EMPTY,
            executor,
            signal,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(answer: ByteArray, rcode: Int) {
                    answerRef.set(answer)
                    latch.countDown()
                }

                override fun onError(error: DnsResolver.DnsException) {
                    errCodeRef.set(error.code)
                    latch.countDown()
                }
            },
        )

        val completed = latch.await(req.timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        if (!completed) {
            signal.cancel()
            return DnsBridgeResponse(req.requestId, DnsBridgeCodec.STATUS_TIMEOUT, 0, ByteArray(0))
        }
        val answer = answerRef.get()
        return if (answer != null && answer.size <= DnsBridgeCodec.MAX_WIRE_BYTES) {
            DnsBridgeResponse(req.requestId, DnsBridgeCodec.STATUS_OK, 0, answer)
        } else {
            DnsBridgeResponse(req.requestId, DnsBridgeCodec.STATUS_DNS_ERROR, errCodeRef.get(), ByteArray(0))
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
}
