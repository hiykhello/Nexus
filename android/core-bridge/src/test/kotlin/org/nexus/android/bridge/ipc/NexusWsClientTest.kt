package org.nexus.android.bridge.ipc

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class NexusWsClientTest {
    @Test
    fun handshakeHeaderAuthMaskedSubscribePingPongFragmentedEventsAndClose() = runBlocking {
        // Verify RFC 6455 §1.3 official Sec-WebSocket-Accept test vector (47DA GUID)
        assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", NexusWsClient.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="))

        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val capturedRequestLine = AtomicReference("")
        val capturedAuthHeader = AtomicReference("")
        val capturedSubscribe = AtomicReference("")
        val capturedPongPayload = AtomicReference<ByteArray>()
        val serverDone = CountDownLatch(1)

        val serverThread = Thread {
            try {
                server.accept().use { sock ->
                    val input = BufferedInputStream(sock.getInputStream())
                    val output = sock.getOutputStream()
                    val (reqLine, headers) = readHttpRequest(input)
                    capturedRequestLine.set(reqLine)
                    capturedAuthHeader.set(headers["authorization"].orEmpty())

                    val wsKey = headers["sec-websocket-key"].orEmpty()
                    val accept = NexusWsClient.computeAcceptKey(wsKey)
                    val upgradeResp = "HTTP/1.1 101 Switching Protocols\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Accept: $accept\r\n\r\n"
                    output.write(upgradeResp.toByteArray(Charsets.US_ASCII))
                    output.flush()

                    // Client must send masked subscribe frame
                    val subFrame = readMaskedClientFrame(input)
                    assertTrue(subFrame.masked)
                    assertEquals(NexusWsClient.OP_TEXT, subFrame.opcode)
                    capturedSubscribe.set(String(subFrame.payload, Charsets.UTF_8))

                    // Send Ping -> expect masked Pong echoing exact bytes
                    val pingBytes = "hb-42".toByteArray(Charsets.US_ASCII)
                    writeUnmaskedServerFrame(output, fin = true, opcode = NexusWsClient.OP_PING, payload = pingBytes)
                    val pongFrame = readMaskedClientFrame(input)
                    assertTrue(pongFrame.masked)
                    assertEquals(NexusWsClient.OP_PONG, pongFrame.opcode)
                    capturedPongPayload.set(pongFrame.payload)

                    // Emit metrics, log, and fragmented connections message
                    val metricsMsg = """{"type":"metrics","data":{"instance":"android","state":"running","active_sessions":9,"upload_bytes_total":512,"download_bytes_total":4096}}"""
                    writeUnmaskedServerFrame(output, fin = true, opcode = NexusWsClient.OP_TEXT, payload = metricsMsg.toByteArray(Charsets.UTF_8))

                    val logMsg = """{"type":"log","data":{"seq":15,"level":"warn","domain":"quic","event":3,"message":"jitter"}}"""
                    writeUnmaskedServerFrame(output, fin = true, opcode = NexusWsClient.OP_TEXT, payload = logMsg.toByteArray(Charsets.UTF_8))

                    val connMsg = """{"type":"connections","data":{"connections":[{"id":7,"inbound":"tun","protocol":"tcp","target":"example.com:443","outbound":"HK-01","upload_bytes":100,"download_bytes":200}]}}"""
                    val connBytes = connMsg.toByteArray(Charsets.UTF_8)
                    val mid = connBytes.size / 2
                    writeUnmaskedServerFrame(output, fin = false, opcode = NexusWsClient.OP_TEXT, payload = connBytes.copyOfRange(0, mid))
                    writeUnmaskedServerFrame(output, fin = true, opcode = NexusWsClient.OP_CONTINUATION, payload = connBytes.copyOfRange(mid, connBytes.size))

                    // Clean Close frame
                    writeUnmaskedServerFrame(output, fin = true, opcode = NexusWsClient.OP_CLOSE, payload = byteArrayOf(0x03, 0xE8.toByte()))
                }
            } finally {
                serverDone.countDown()
            }
        }
        serverThread.start()

        try {
            val client = NexusWsClient(
                httpBaseUrlProvider = { "http://127.0.0.1:${server.localPort}" },
                bearerTokenProvider = { "secret-ws-token-99" },
                readTimeoutMs = 5_000,
            )
            val events = mutableListOf<WsEvent>()
            withTimeout(5_000L) {
                client.stream(
                    channels = listOf("metrics", "logs", "connections"),
                    since = 10L,
                    intervalMs = 1_000,
                    reconnect = false,
                ).collect { events.add(it) }
            }
            assertTrue(serverDone.await(3, TimeUnit.SECONDS))

            // Verify zero URL token and strict Bearer header
            assertEquals("GET /v1/ws HTTP/1.1", capturedRequestLine.get())
            assertFalse(capturedRequestLine.get().contains("token"))
            assertEquals("Bearer secret-ws-token-99", capturedAuthHeader.get())

            // Verify subscribe JSON contract
            val subObj = JSONObject(capturedSubscribe.get())
            assertEquals("subscribe", subObj.getString("type"))
            assertEquals(10L, subObj.getLong("since"))
            assertEquals(1_000, subObj.getInt("interval_ms"))
            assertEquals(3, subObj.getJSONArray("channels").length())

            // Verify Pong echo
            assertArrayEquals("hb-42".toByteArray(Charsets.US_ASCII), capturedPongPayload.get())

            // Verify all decoded events
            assertTrue(events[0] is WsEvent.Connected)
            val m = events.filterIsInstance<WsEvent.Metrics>().single()
            assertEquals(9L, m.status.activeSessions)
            assertEquals(4096L, m.status.downloadBytes)
            val l = events.filterIsInstance<WsEvent.Log>().single()
            assertEquals(15L, l.entry.seq)
            assertEquals("warn", l.entry.level)
            assertEquals("jitter", l.entry.message)
            val c = events.filterIsInstance<WsEvent.Connections>().single()
            assertEquals(1, c.connections.size)
            assertEquals("example.com:443", c.connections[0].target)
        } finally {
            server.close()
        }
    }

    @Test
    fun rejectsNonLoopbackUrlAndPropagates404UpgradeRejection() = runBlocking {
        val externalClient = NexusWsClient(httpBaseUrlProvider = { "https://evil.example:443" })
        try {
            externalClient.stream(listOf("metrics"), reconnect = false).collect {}
            fail("Expected WsUpgradeRejectedException for external host")
        } catch (ex: WsUpgradeRejectedException) {
            assertEquals(403, ex.statusCode)
        }

        val lanClient = NexusWsClient(httpBaseUrlProvider = { "http://192.168.1.50:9090" })
        try {
            lanClient.stream(listOf("metrics"), reconnect = false).collect {}
            fail("Expected WsUpgradeRejectedException for non-loopback LAN host")
        } catch (ex: WsUpgradeRejectedException) {
            assertEquals(403, ex.statusCode)
        }

        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val t = Thread {
            runCatching {
                server.accept().use { sock ->
                    readHttpRequest(BufferedInputStream(sock.getInputStream()))
                    sock.getOutputStream().write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    sock.getOutputStream().flush()
                }
            }
        }
        t.start()
        try {
            val client = NexusWsClient(httpBaseUrlProvider = { "http://127.0.0.1:${server.localPort}" })
            try {
                client.stream(listOf("metrics"), reconnect = true).collect {}
                fail("Expected WsUpgradeRejectedException(404) so caller falls back to SSE")
            } catch (ex: WsUpgradeRejectedException) {
                assertEquals(404, ex.statusCode)
            }
        } finally {
            server.close()
            t.join(2_000)
        }
    }

    @Test
    fun enforces256KiBFrameCapAndUnblocksImmediatelyOnCancellation() = runBlocking {
        assertEquals(256 * 1024, NexusWsClient.MAX_FRAME_BYTES)

        // 1. Oversized frame (> 256 KiB) sends Close 1009 and throws WsFrameTooLargeException
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val closeCodeRef = AtomicReference(-1)
        val serverThread = Thread {
            runCatching {
                server.accept().use { sock ->
                    val input = BufferedInputStream(sock.getInputStream())
                    val output = sock.getOutputStream()
                    val (_, headers) = readHttpRequest(input)
                    val accept = NexusWsClient.computeAcceptKey(headers["sec-websocket-key"].orEmpty())
                    output.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    readMaskedClientFrame(input) // subscribe
                    // Announce 300 KiB frame header (> 256 KiB cap)
                    val bigLen = 300 * 1024L
                    val hdr = ByteArray(10)
                    hdr[0] = (0x80 or NexusWsClient.OP_TEXT).toByte()
                    hdr[1] = 127.toByte()
                    for (i in 0 until 8) hdr[2 + i] = ((bigLen ushr (56 - i * 8)) and 0xFFL).toByte()
                    output.write(hdr)
                    output.flush()
                    val closeFrame = readMaskedClientFrame(input)
                    if (closeFrame.opcode == NexusWsClient.OP_CLOSE && closeFrame.payload.size >= 2) {
                        closeCodeRef.set(((closeFrame.payload[0].toInt() and 0xFF) shl 8) or (closeFrame.payload[1].toInt() and 0xFF))
                    }
                }
            }
        }
        serverThread.start()
        try {
            val client = NexusWsClient(httpBaseUrlProvider = { "http://127.0.0.1:${server.localPort}" })
            try {
                client.stream(listOf("metrics"), reconnect = false).collect {}
                fail("Expected WsFrameTooLargeException")
            } catch (_: WsFrameTooLargeException) {
                // expected
            }
            serverThread.join(2_000)
            assertEquals(NexusWsClient.CLOSE_MESSAGE_TOO_BIG, closeCodeRef.get())
        } finally {
            server.close()
        }

        // 2. Cancellation immediately closes blocking socket (< 1s despite 25s readTimeout)
        val idleServer = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val connectedLatch = CountDownLatch(1)
        val holdLatch = CountDownLatch(1)
        val idleThread = Thread {
            runCatching {
                idleServer.accept().use { sock ->
                    val input = BufferedInputStream(sock.getInputStream())
                    val output = sock.getOutputStream()
                    val (_, headers) = readHttpRequest(input)
                    val accept = NexusWsClient.computeAcceptKey(headers["sec-websocket-key"].orEmpty())
                    output.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    readMaskedClientFrame(input)
                    connectedLatch.countDown()
                    holdLatch.await(5, TimeUnit.SECONDS)
                }
            }
        }
        idleThread.start()
        try {
            val client = NexusWsClient(
                httpBaseUrlProvider = { "http://127.0.0.1:${idleServer.localPort}" },
                readTimeoutMs = 25_000,
            )
            val job = launch(Dispatchers.IO) {
                try {
                    client.stream(listOf("metrics"), reconnect = true).collect {}
                } catch (_: CancellationException) {
                    // expected
                }
            }
            assertTrue(connectedLatch.await(3, TimeUnit.SECONDS))
            delay(50L)
            val t0 = System.nanoTime()
            job.cancel()
            withTimeout(1_500L) { job.join() }
            val elapsedMs = (System.nanoTime() - t0) / 1_000_000L
            assertTrue("Expected immediate cancel unblock, took ${elapsedMs}ms", elapsedMs < 1_000L)
        } finally {
            holdLatch.countDown()
            idleServer.close()
            idleThread.join(2_000)
        }
    }

    private data class DecodedFrame(val fin: Boolean, val opcode: Int, val masked: Boolean, val payload: ByteArray)

    private fun readHttpRequest(input: InputStream): Pair<String, Map<String, String>> {
        val reqLine = readLine(input)
        val headers = HashMap<String, String>()
        while (true) {
            val line = readLine(input)
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx > 0) headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
        }
        return reqLine to headers
    }

    private fun readLine(input: InputStream): String {
        val buf = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0 || b == '\n'.code) break
            if (b != '\r'.code) buf.write(b)
        }
        return String(buf.toByteArray(), Charsets.US_ASCII)
    }

    private fun readMaskedClientFrame(input: InputStream): DecodedFrame {
        val b0 = input.read()
        val b1 = input.read()
        val fin = (b0 and 0x80) != 0
        val opcode = b0 and 0x0F
        val masked = (b1 and 0x80) != 0
        var len = (b1 and 0x7F).toLong()
        if (len == 126L) {
            len = (((input.read() and 0xFF) shl 8) or (input.read() and 0xFF)).toLong()
        } else if (len == 127L) {
            var v = 0L
            repeat(8) { v = (v shl 8) or (input.read().toLong() and 0xFFL) }
            len = v
        }
        val mask = if (masked) ByteArray(4) { input.read().toByte() } else null
        val payload = ByteArray(len.toInt()) { input.read().toByte() }
        if (mask != null) {
            for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
        }
        return DecodedFrame(fin, opcode, masked, payload)
    }

    private fun writeUnmaskedServerFrame(out: OutputStream, fin: Boolean, opcode: Int, payload: ByteArray) {
        out.write((if (fin) 0x80 else 0x00) or (opcode and 0x0F))
        when {
            payload.size < 126 -> out.write(payload.size)
            payload.size <= 65_535 -> {
                out.write(126)
                out.write((payload.size ushr 8) and 0xFF)
                out.write(payload.size and 0xFF)
            }
            else -> {
                out.write(127)
                val lenL = payload.size.toLong()
                for (shift in 56 downTo 0 step 8) out.write(((lenL ushr shift) and 0xFFL).toInt())
            }
        }
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }
}
