package org.nexus.android.bridge.ipc

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale

internal data class WsRawFrame(
    val fin: Boolean,
    val opcode: Int,
    val payload: ByteArray,
)

/**
 * Pure JDK RFC 6455 handshake, framing, and `/v1/ws` JSON pub/sub codec helpers.
 */
internal object NexusWsCodec {
    const val WS_PATH = "/v1/ws"
    const val OP_CONTINUATION = 0x0
    const val OP_TEXT = 0x1
    const val OP_CLOSE = 0x8
    const val OP_PING = 0x9
    const val OP_PONG = 0xA
    const val CLOSE_NORMAL = 1000
    const val CLOSE_MESSAGE_TOO_BIG = 1009

    // RFC 6455 §1.3 canonical WebSocket GUID
    private const val WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    private const val MAX_HEADER_BYTES = 8 * 1024
    private const val MAX_HEADER_COUNT = 64

    fun generateSecWebSocketKey(rng: SecureRandom = SecureRandom()): String {
        val nonce = ByteArray(16)
        rng.nextBytes(nonce)
        return Base64.getEncoder().encodeToString(nonce)
    }

    fun computeAcceptKey(secWebSocketKey: String): String {
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest((secWebSocketKey.trim() + WS_GUID).toByteArray(Charsets.US_ASCII))
        return Base64.getEncoder().encodeToString(sha1)
    }

    fun parseLoopbackEndpoint(baseUrl: String): Triple<String, Int, String>? {
        val uri = runCatching { URI(baseUrl.trim()) }.getOrNull() ?: return null
        val rawHost = uri.host?.lowercase(Locale.ROOT) ?: return null
        val connectHost = rawHost.removePrefix("[").removeSuffix("]")
        val port = if (uri.port > 0) uri.port else 80
        val hostHeader = if (connectHost.contains(':')) "[$connectHost]:$port" else "$connectHost:$port"
        return Triple(connectHost, port, hostHeader)
    }

    fun buildUpgradeRequest(hostHeader: String, wsKey: String, bearerToken: String?): String =
        buildString {
            append("GET ").append(WS_PATH).append(" HTTP/1.1\r\n")
            append("Host: ").append(hostHeader).append("\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: ").append(wsKey).append("\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            if (!bearerToken.isNullOrEmpty()) {
                val clean = bearerToken.replace("\r", "").replace("\n", "")
                append("Authorization: Bearer ").append(clean).append("\r\n")
            }
            append("\r\n")
        }

    fun buildSubscribePayload(channels: List<String>, since: Long = 0L, intervalMs: Int = 1_000): String {
        val arr = JSONArray()
        channels.forEach { arr.put(it) }
        return JSONObject().apply {
            put("type", "subscribe")
            put("channels", arr)
            put("since", since.coerceAtLeast(0L))
            put("interval_ms", intervalMs.coerceIn(200, 10_000))
        }.toString()
    }

    fun verifyUpgradeResponse(input: InputStream, wsKey: String) {
        val statusLine = readAsciiLine(input, MAX_HEADER_BYTES)
            ?: throw WsUpgradeRejectedException(0, "EOF during WebSocket handshake")
        val statusCode = statusLine.split(' ', limit = 3).getOrNull(1)?.toIntOrNull() ?: 0
        val headers = HashMap<String, String>()
        var totalBytes = statusLine.length
        var count = 0
        while (true) {
            val line = readAsciiLine(input, MAX_HEADER_BYTES - totalBytes)
                ?: throw WsUpgradeRejectedException(statusCode, "EOF in WebSocket response headers")
            if (line.isEmpty()) break
            totalBytes += line.length + 2
            if (++count > MAX_HEADER_COUNT || totalBytes > MAX_HEADER_BYTES) {
                throw WsUpgradeRejectedException(statusCode, "WebSocket handshake headers too large")
            }
            val colon = line.indexOf(':')
            if (colon > 0) {
                val k = line.substring(0, colon).trim().lowercase(Locale.ROOT)
                val v = line.substring(colon + 1).trim()
                headers[k] = headers[k]?.let { "$it, $v" } ?: v
            }
        }
        if (statusCode != 101) {
            throw WsUpgradeRejectedException(statusCode, "WebSocket upgrade rejected: HTTP $statusCode")
        }
        val upgrade = headers["upgrade"].orEmpty()
        val connection = headers["connection"].orEmpty()
        val accept = headers["sec-websocket-accept"].orEmpty()
        if (!upgrade.equals("websocket", ignoreCase = true) ||
            !connection.contains("upgrade", ignoreCase = true)
        ) {
            throw WsUpgradeRejectedException(101, "Missing WebSocket Upgrade/Connection headers")
        }
        val expected = computeAcceptKey(wsKey)
        if (!MessageDigest.isEqual(accept.toByteArray(Charsets.US_ASCII), expected.toByteArray(Charsets.US_ASCII))) {
            throw WsUpgradeRejectedException(101, "Sec-WebSocket-Accept mismatch")
        }
    }

    fun writeClientFrame(out: OutputStream, opcode: Int, payload: ByteArray, rng: SecureRandom) {
        val len = payload.size
        val header = ByteArrayOutputStream(14)
        header.write(0x80 or (opcode and 0x0F))
        when {
            len < 126 -> header.write(0x80 or len)
            len <= 65_535 -> {
                header.write(0x80 or 126)
                header.write((len ushr 8) and 0xFF)
                header.write(len and 0xFF)
            }
            else -> {
                header.write(0x80 or 127)
                val lenLong = len.toLong()
                for (shift in 56 downTo 0 step 8) {
                    header.write(((lenLong ushr shift) and 0xFFL).toInt())
                }
            }
        }
        val mask = ByteArray(4)
        rng.nextBytes(mask)
        header.write(mask)
        val masked = ByteArray(len)
        for (i in 0 until len) masked[i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
        out.write(header.toByteArray())
        if (masked.isNotEmpty()) out.write(masked)
        out.flush()
    }

    fun writeCloseFrame(out: OutputStream, code: Int, rng: SecureRandom) {
        val payload = byteArrayOf(((code ushr 8) and 0xFF).toByte(), (code and 0xFF).toByte())
        writeClientFrame(out, OP_CLOSE, payload, rng)
    }

    fun readServerFrame(input: InputStream, maxFrameBytes: Int): WsRawFrame {
        val b0 = input.read()
        if (b0 < 0) throw EOFException("WS stream closed")
        val b1 = input.read()
        if (b1 < 0) throw EOFException("WS stream truncated")
        val fin = (b0 and 0x80) != 0
        if ((b0 and 0x70) != 0) throw WsFrameTooLargeException("non-zero RSV bits in WS frame")
        val opcode = b0 and 0x0F
        val masked = (b1 and 0x80) != 0
        var payloadLen = (b1 and 0x7F).toLong()
        if (payloadLen == 126L) {
            val ext = readExact(input, 2)
            payloadLen = (((ext[0].toInt() and 0xFF) shl 8) or (ext[1].toInt() and 0xFF)).toLong()
        } else if (payloadLen == 127L) {
            val ext = readExact(input, 8)
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (ext[i].toLong() and 0xFFL)
            if (v < 0L) throw WsFrameTooLargeException("invalid 64-bit WS frame length")
            payloadLen = v
        }
        if (opcode >= 0x8 && (!fin || payloadLen > 125L)) {
            throw WsFrameTooLargeException("invalid WS control frame")
        }
        if (payloadLen > maxFrameBytes.toLong()) {
            throw WsFrameTooLargeException("WS frame size $payloadLen exceeds $maxFrameBytes byte cap")
        }
        val mask = if (masked) readExact(input, 4) else null
        val payload = if (payloadLen > 0L) readExact(input, payloadLen.toInt()) else ByteArray(0)
        if (mask != null) {
            for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
        }
        return WsRawFrame(fin = fin, opcode = opcode, payload = payload)
    }

    fun parseServerMessage(jsonText: String): WsEvent? = runCatching {
        val root = JSONObject(jsonText)
        when (root.optString("type", "").lowercase(Locale.ROOT)) {
            "subscribed" -> {
                val arr = root.optJSONArray("channels")
                val ch = buildList {
                    if (arr != null) for (i in 0 until arr.length()) add(arr.optString(i, ""))
                }.filter { it.isNotEmpty() }
                WsEvent.Connected(ch)
            }
            "log" -> root.optJSONObject("data")?.let {
                ControlToolsJsonParser.parseSingleLogEvent(it.toString())?.let { e -> WsEvent.Log(e) }
            }
            "connections" -> {
                val rawData = root.opt("data") ?: return@runCatching null
                val body = when (rawData) {
                    is JSONObject -> rawData.toString()
                    is JSONArray -> JSONObject().put("connections", rawData).toString()
                    else -> return@runCatching null
                }
                WsEvent.Connections(OutboundJsonParser.parseConnections(body))
            }
            "metrics" -> root.optJSONObject("data")?.let {
                ControlToolsJsonParser.parseStatus(it.toString())?.let { s -> WsEvent.Metrics(s) }
            }
            else -> null
        }
    }.getOrNull()

    private fun readExact(input: InputStream, count: Int): ByteArray {
        val buf = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val n = input.read(buf, offset, count - offset)
            if (n < 0) throw EOFException("unexpected EOF reading $count bytes")
            offset += n
        }
        return buf
    }

    private fun readAsciiLine(input: InputStream, maxBytes: Int): String? {
        val out = ByteArrayOutputStream(64)
        while (true) {
            val b = input.read()
            if (b < 0) return if (out.size() == 0) null else String(out.toByteArray(), Charsets.US_ASCII)
            if (b == '\n'.code) break
            if (b != '\r'.code) {
                if (out.size() >= maxBytes) throw WsUpgradeRejectedException(431, "header line exceeds limit")
                out.write(b)
            }
        }
        return String(out.toByteArray(), Charsets.US_ASCII)
    }
}
