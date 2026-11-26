package org.nexus.android.bridge.ipc

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.DisposableHandle
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

data class SseEvent(
    val event: String = "message",
    val data: String = "",
    val id: String = "",
)

/**
 * Pure Kotlin Server-Sent Events (`text/event-stream`) client built on `HttpURLConnection`.
 * - Zero external dependencies.
 * - `readTimeoutMs = 25_000` cleanly survives Core's 15s `: keepalive` heartbeats.
 * - Exponential backoff reconnect (`500ms` -> `8s`) with clean disconnect on coroutine cancellation.
 */
class NexusSseClient(
    private val httpBaseUrlProvider: () -> String?,
    private val bearerTokenProvider: () -> String? = { null },
    private val connectTimeoutMs: Int = 3_000,
    private val readTimeoutMs: Int = DEFAULT_SSE_READ_TIMEOUT_MS,
) {
    fun streamEvents(path: String): Flow<SseEvent> = flow {
        var backoffMs = INITIAL_BACKOFF_MS
        while (currentCoroutineContext().isActive) {
            val base = httpBaseUrlProvider()?.trimEnd('/')
            if (base.isNullOrBlank() || !NexusControlClient.isLoopbackHttpUrl(base)) {
                delay(backoffMs)
                backoffMs = (backoffMs * 2L).coerceAtMost(MAX_BACKOFF_MS)
                continue
            }
            var conn: HttpURLConnection? = null
            var cancelHandle: DisposableHandle? = null
            var receivedAnyFrame = false
            try {
                val token = bearerTokenProvider()?.takeIf { it.isNotEmpty() }
                val opened = (URL(base + path).openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = connectTimeoutMs
                    readTimeout = readTimeoutMs
                    instanceFollowRedirects = false
                    useCaches = false
                    setRequestProperty("Accept", "text/event-stream")
                    setRequestProperty("Cache-Control", "no-cache")
                    if (!token.isNullOrEmpty()) {
                        setRequestProperty("Authorization", "Bearer $token")
                    }
                }
                conn = opened
                cancelHandle = currentCoroutineContext()[Job]?.invokeOnCompletion {
                    runCatching { opened.disconnect() }
                }
                if (!currentCoroutineContext().isActive) {
                    throw CancellationException("SSE stream cancelled")
                }
                val code = opened.responseCode
                if (code !in 200..299) {
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2L).coerceAtMost(MAX_BACKOFF_MS)
                    continue
                }
                BufferedReader(InputStreamReader(opened.inputStream, Charsets.UTF_8)).use { reader ->
                    val parser = SseFrameAccumulator()
                    while (currentCoroutineContext().isActive) {
                        val line = reader.readLine() ?: break
                        val emitted = parser.feedLine(line)
                        if (emitted != null) {
                            receivedAnyFrame = true
                            backoffMs = INITIAL_BACKOFF_MS
                            emit(emitted)
                        }
                    }
                    parser.flushPending()?.let {
                        receivedAnyFrame = true
                        emit(it)
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                if (!currentCoroutineContext().isActive) {
                    throw CancellationException("SSE stream cancelled")
                }
                // Transient stream drop or core reload; reconnect with bounded backoff.
            } finally {
                cancelHandle?.dispose()
                runCatching { conn?.disconnect() }
            }
            if (!currentCoroutineContext().isActive) break
            if (receivedAnyFrame) backoffMs = INITIAL_BACKOFF_MS
            delay(backoffMs)
            backoffMs = (backoffMs * 2L).coerceAtMost(MAX_BACKOFF_MS)
        }
    }.flowOn(Dispatchers.IO)

    fun streamStatus(intervalMs: Int = 1_000): Flow<LiveStatusSnapshot> = flow {
        val clamped = intervalMs.coerceIn(200, 10_000)
        streamEvents("/v1/status?stream=1&interval_ms=$clamped").collect { ev ->
            if (ev.data.isNotEmpty()) {
                ControlToolsJsonParser.parseStatus(ev.data)?.let { emit(it) }
            }
        }
    }

    fun streamConnections(intervalMs: Int = 1_500): Flow<List<ActiveConnectionSnapshot>> = flow {
        val clamped = intervalMs.coerceIn(200, 10_000)
        streamEvents("/v1/connections?stream=1&interval_ms=$clamped").collect { ev ->
            if (ev.data.isNotEmpty()) {
                emit(OutboundJsonParser.parseConnections(ev.data))
            }
        }
    }

    fun streamLogs(
        since: Long = 0L,
        level: String = "",
        domain: String = "",
        search: String = "",
    ): Flow<LogRingEntry> = flow {
        val query = buildLogsStreamPath(since, level, domain, search)
        streamEvents(query).collect { ev ->
            if (ev.data.isNotEmpty()) {
                ControlToolsJsonParser.parseSingleLogEvent(ev.data)?.let { emit(it) }
            }
        }
    }

    companion object {
        const val DEFAULT_SSE_READ_TIMEOUT_MS = 25_000
        const val MAX_FRAME_BYTES = 256 * 1024
        private const val INITIAL_BACKOFF_MS = 500L
        private const val MAX_BACKOFF_MS = 8_000L

        fun buildLogsStreamPath(
            since: Long = 0L,
            level: String = "",
            domain: String = "",
            search: String = "",
        ): String {
            val params = buildList {
                add("stream=1")
                if (since > 0L) add("since=$since")
                if (level.isNotBlank() && level != "all" && level != "trace") {
                    add("level=${NexusControlClient.encodeQueryValue(level)}")
                }
                if (domain.isNotBlank() && domain != "all") {
                    add("domain=${NexusControlClient.encodeQueryValue(domain)}")
                }
                if (search.isNotBlank()) {
                    add("search=${NexusControlClient.encodeQueryValue(search)}")
                }
            }.joinToString("&")
            return "/v1/logs?$params"
        }

        fun parseSseLines(lines: Sequence<String>): List<SseEvent> {
            val acc = SseFrameAccumulator()
            val out = mutableListOf<SseEvent>()
            for (line in lines) {
                acc.feedLine(line)?.let { out.add(it) }
            }
            acc.flushPending()?.let { out.add(it) }
            return out
        }
    }
}

/**
 * Spec-compliant incremental SSE frame accumulator:
 * - Ignores `: comment` keepalive lines
 * - Joins multiline `data:` payloads with `\n`
 * - Dispatches on blank line
 */
internal class SseFrameAccumulator(
    private val maxFrameBytes: Int = NexusSseClient.MAX_FRAME_BYTES,
) {
    private var eventType: String = ""
    private var eventId: String = ""
    private val dataLines = mutableListOf<String>()
    private var accumulatedBytes: Int = 0
    private var oversized: Boolean = false

    fun feedLine(rawLine: String): SseEvent? {
        val line = rawLine.trimEnd('\r')
        if (line.isEmpty()) {
            return flushPending()
        }
        if (line.startsWith(':')) {
            return null
        }
        val colon = line.indexOf(':')
        val field = if (colon >= 0) line.substring(0, colon) else line
        val rawVal = if (colon >= 0) line.substring(colon + 1) else ""
        val value = if (rawVal.startsWith(' ')) rawVal.substring(1) else rawVal
        when (field) {
            "event" -> if (value.length <= 256) eventType = value
            "data" -> {
                if (!oversized) {
                    val addBytes = value.toByteArray(Charsets.UTF_8).size + if (dataLines.isEmpty()) 0 else 1
                    if (accumulatedBytes + addBytes > maxFrameBytes) {
                        oversized = true
                        dataLines.clear()
                        accumulatedBytes = 0
                    } else {
                        dataLines.add(value)
                        accumulatedBytes += addBytes
                    }
                }
            }
            "id" -> if (!value.contains('\u0000') && value.length <= 256) eventId = value
        }
        return null
    }

    fun flushPending(): SseEvent? {
        if (oversized) {
            oversized = false
            eventType = ""
            dataLines.clear()
            accumulatedBytes = 0
            return null
        }
        if (dataLines.isEmpty()) {
            eventType = ""
            accumulatedBytes = 0
            return null
        }
        val event = SseEvent(
            event = eventType.ifBlank { "message" },
            data = dataLines.joinToString("\n"),
            id = eventId,
        )
        eventType = ""
        dataLines.clear()
        accumulatedBytes = 0
        return event
    }
}
