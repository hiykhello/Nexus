package org.nexus.android.bridge.ipc

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.Locale

sealed class WsEvent {
    data class Connected(val channels: List<String> = emptyList()) : WsEvent()
    data class Log(val entry: LogRingEntry) : WsEvent()
    data class Connections(val connections: List<ActiveConnectionSnapshot>) : WsEvent()
    data class Metrics(val status: LiveStatusSnapshot) : WsEvent()
}

class WsUpgradeRejectedException(val statusCode: Int, message: String) : Exception(message)

class WsFrameTooLargeException(message: String) : Exception(message)

/**
 * Pure JDK RFC 6455 multiplexed Control WebSocket client (`GET /v1/ws`):
 * - Zero external dependencies (`Socket` + `MessageDigest("SHA-1")` + `SecureRandom` + `Base64`)
 * - Strict loopback guard + `Authorization: Bearer` header ONLY (never URL token)
 * - Client-masked framing, Ping->Pong echo, fragmented text reassembly, 256 KiB cap
 * - Immediate coroutine cancellation unblock via `awaitCancellation()` socket closer
 */
class NexusWsClient(
    private val httpBaseUrlProvider: () -> String?,
    private val bearerTokenProvider: () -> String? = { null },
    private val connectTimeoutMs: Int = 3_000,
    private val readTimeoutMs: Int = DEFAULT_WS_READ_TIMEOUT_MS,
    private val maxFrameBytes: Int = MAX_FRAME_BYTES,
) {
    private val random = SecureRandom()

    fun stream(
        channels: List<String>,
        since: Long = 0L,
        intervalMs: Int = 1_000,
        reconnect: Boolean = true,
    ): Flow<WsEvent> = flow {
        val cleanChannels = channels.map { it.trim().lowercase(Locale.ROOT) }.filter { it.isNotEmpty() }.distinct()
        var backoffMs = INITIAL_BACKOFF_MS
        var lastLogSeq = since.coerceAtLeast(0L)

        while (currentCoroutineContext().isActive) {
            val base = httpBaseUrlProvider()?.trimEnd('/')
            if (base.isNullOrBlank()) {
                if (!reconnect) throw WsUpgradeRejectedException(0, "control HTTP URL unavailable")
                delay(backoffMs)
                backoffMs = (backoffMs * 2L).coerceAtMost(MAX_BACKOFF_MS)
                continue
            }
            if (!NexusControlClient.isLoopbackHttpUrl(base)) {
                throw WsUpgradeRejectedException(403, "refusing non-loopback control WebSocket URL")
            }
            val endpoint = NexusWsCodec.parseLoopbackEndpoint(base)
                ?: throw WsUpgradeRejectedException(403, "invalid loopback control WebSocket URL")

            var receivedAny = false
            try {
                coroutineScope {
                    val sock = Socket()
                    val cancelCloser = launch(Dispatchers.Unconfined, start = CoroutineStart.UNDISPATCHED) {
                        try {
                            awaitCancellation()
                        } finally {
                            runCatching { sock.close() }
                        }
                    }
                    try {
                        sock.tcpNoDelay = true
                        sock.soTimeout = readTimeoutMs
                        sock.connect(InetSocketAddress(endpoint.first, endpoint.second), connectTimeoutMs)

                        val input = BufferedInputStream(sock.getInputStream(), 8_192)
                        val output = sock.getOutputStream()
                        val wsKey = NexusWsCodec.generateSecWebSocketKey(random)
                        val token = bearerTokenProvider()?.takeIf { it.isNotEmpty() }

                        output.write(NexusWsCodec.buildUpgradeRequest(endpoint.third, wsKey, token).toByteArray(Charsets.US_ASCII))
                        output.flush()
                        NexusWsCodec.verifyUpgradeResponse(input, wsKey)

                        val subJson = NexusWsCodec.buildSubscribePayload(cleanChannels, lastLogSeq, intervalMs)
                        NexusWsCodec.writeClientFrame(output, NexusWsCodec.OP_TEXT, subJson.toByteArray(Charsets.UTF_8), random)
                        receivedAny = true
                        backoffMs = INITIAL_BACKOFF_MS
                        emit(WsEvent.Connected(cleanChannels))

                        val textBuffer = ByteArrayOutputStream()
                        var assemblingText = false
                        var awaitingPong = false

                        while (currentCoroutineContext().isActive) {
                            val frame = try {
                                NexusWsCodec.readServerFrame(input, maxFrameBytes)
                            } catch (te: SocketTimeoutException) {
                                if (!awaitingPong) {
                                    awaitingPong = true
                                    NexusWsCodec.writeClientFrame(output, NexusWsCodec.OP_PING, ByteArray(0), random)
                                    continue
                                }
                                throw te
                            } catch (tooBig: WsFrameTooLargeException) {
                                runCatching { NexusWsCodec.writeCloseFrame(output, NexusWsCodec.CLOSE_MESSAGE_TOO_BIG, random) }
                                throw tooBig
                            }
                            awaitingPong = false
                            when (frame.opcode) {
                                NexusWsCodec.OP_PING -> NexusWsCodec.writeClientFrame(output, NexusWsCodec.OP_PONG, frame.payload, random)
                                NexusWsCodec.OP_PONG -> Unit
                                NexusWsCodec.OP_CLOSE -> {
                                    val code = if (frame.payload.size >= 2) {
                                        ((frame.payload[0].toInt() and 0xFF) shl 8) or (frame.payload[1].toInt() and 0xFF)
                                    } else NexusWsCodec.CLOSE_NORMAL
                                    runCatching { NexusWsCodec.writeCloseFrame(output, code, random) }
                                    break
                                }
                                NexusWsCodec.OP_TEXT -> {
                                    textBuffer.reset()
                                    if (frame.fin) {
                                        assemblingText = false
                                        NexusWsCodec.parseServerMessage(String(frame.payload, Charsets.UTF_8))?.let { ev ->
                                            if (ev is WsEvent.Log && ev.entry.seq > lastLogSeq) lastLogSeq = ev.entry.seq
                                            emit(ev)
                                        }
                                    } else {
                                        assemblingText = true
                                        textBuffer.write(frame.payload)
                                    }
                                }
                                NexusWsCodec.OP_CONTINUATION -> if (assemblingText) {
                                    if (textBuffer.size() + frame.payload.size > maxFrameBytes) {
                                        runCatching { NexusWsCodec.writeCloseFrame(output, NexusWsCodec.CLOSE_MESSAGE_TOO_BIG, random) }
                                        throw WsFrameTooLargeException("fragmented WS message exceeds $maxFrameBytes bytes")
                                    }
                                    textBuffer.write(frame.payload)
                                    if (frame.fin) {
                                        assemblingText = false
                                        val full = String(textBuffer.toByteArray(), Charsets.UTF_8)
                                        textBuffer.reset()
                                        NexusWsCodec.parseServerMessage(full)?.let { ev ->
                                            if (ev is WsEvent.Log && ev.entry.seq > lastLogSeq) lastLogSeq = ev.entry.seq
                                            emit(ev)
                                        }
                                    }
                                }
                            }
                        }
                    } finally {
                        cancelCloser.cancel()
                        runCatching { sock.close() }
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (rej: WsUpgradeRejectedException) {
                throw rej
            } catch (tooBig: WsFrameTooLargeException) {
                if (!reconnect) throw tooBig
            } catch (err: Throwable) {
                if (!currentCoroutineContext().isActive) throw CancellationException("WS stream cancelled")
                if (!reconnect) throw err
            }

            if (!reconnect || !currentCoroutineContext().isActive) break
            if (receivedAny) backoffMs = INITIAL_BACKOFF_MS
            delay(backoffMs)
            backoffMs = (backoffMs * 2L).coerceAtMost(MAX_BACKOFF_MS)
        }
    }.flowOn(Dispatchers.IO)

    companion object {
        const val DEFAULT_WS_READ_TIMEOUT_MS = 25_000
        const val MAX_FRAME_BYTES = 256 * 1024
        const val WS_PATH = NexusWsCodec.WS_PATH
        internal const val OP_CONTINUATION = NexusWsCodec.OP_CONTINUATION
        internal const val OP_TEXT = NexusWsCodec.OP_TEXT
        internal const val OP_CLOSE = NexusWsCodec.OP_CLOSE
        internal const val OP_PING = NexusWsCodec.OP_PING
        internal const val OP_PONG = NexusWsCodec.OP_PONG
        internal const val CLOSE_MESSAGE_TOO_BIG = NexusWsCodec.CLOSE_MESSAGE_TOO_BIG
        private const val INITIAL_BACKOFF_MS = 500L
        private const val MAX_BACKOFF_MS = 8_000L

        fun computeAcceptKey(secWebSocketKey: String): String = NexusWsCodec.computeAcceptKey(secWebSocketKey)
        fun buildSubscribePayload(channels: List<String>, since: Long = 0L, intervalMs: Int = 1_000): String =
            NexusWsCodec.buildSubscribePayload(channels, since, intervalMs)
        fun parseServerMessage(jsonText: String): WsEvent? = NexusWsCodec.parseServerMessage(jsonText)
    }
}
