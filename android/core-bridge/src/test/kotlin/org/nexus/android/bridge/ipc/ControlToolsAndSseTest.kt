package org.nexus.android.bridge.ipc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class ControlToolsAndSseTest {
    @Test
    fun sseParserHandlesMultilineDataKeepaliveCommentsAndCrLf() {
        val rawLines = sequenceOf(
            ": keepalive",
            "",
            "event: status\r",
            "id: 42\r",
            "data: {\"state\":\"running\",\"active_sessions\":7}\r",
            "\r",
            ": another keepalive comment",
            "event: log",
            "data: line-one",
            "data: line-two",
            "",
        )
        val events = NexusSseClient.parseSseLines(rawLines)
        assertEquals(2, events.size)
        assertEquals("status", events[0].event)
        assertEquals("42", events[0].id)
        assertEquals("{\"state\":\"running\",\"active_sessions\":7}", events[0].data)
        assertEquals("log", events[1].event)
        assertEquals("line-one\nline-two", events[1].data)

        val streamPath = NexusSseClient.buildLogsStreamPath(since = 99L, level = "warn", search = "quic timeout")
        assertTrue(streamPath.startsWith("/v1/logs?stream=1"))
        assertTrue(streamPath.contains("since=99"))
        assertTrue(streamPath.contains("level=warn"))
        assertTrue(streamPath.contains("search=quic%20timeout"))
    }

    @Test
    fun controlToolsParsersHandleRulesDnsQueryFakeIp409AndOutboundProbe() {
        val rules = ControlToolsJsonParser.parseRules(
            """{"rules":[{"index":0,"type":"domain-suffix","action":"route","target":"Auto","summary":"openai.com"}]}""",
        )
        assertEquals(1, rules.size)
        assertEquals("domain-suffix", rules[0].type)
        assertEquals("Auto", rules[0].target)
        assertEquals("openai.com", rules[0].summary)

        val dnsOk = ControlToolsJsonParser.parseDnsQuery(
            ControlReply(
                ok = true,
                statusCode = 200,
                body = """{"name":"example.com","type":"A","rcode":0,"rcode_name":"NOERROR","ttl":120,"elapsed_ms":14,"answers":[{"name":"example.com","type":"A","ttl":120,"data":"93.184.216.34"}]}""",
            ),
        )
        assertTrue(dnsOk.ok)
        assertEquals("NOERROR", dnsOk.rcodeName)
        assertEquals(14L, dnsOk.elapsedMs)
        assertEquals(1, dnsOk.answers.size)
        assertEquals("93.184.216.34", dnsOk.answers[0].data)

        val dnsTimeout = ControlToolsJsonParser.parseDnsQuery(
            ControlReply(ok = false, statusCode = 504, body = """{"error":{"code":"dns-timeout","message":"DNS query timed out"}}"""),
        )
        assertFalse(dnsTimeout.ok)
        assertEquals("dns-timeout", dnsTimeout.errorCode)

        val fakeIpOk = ControlToolsJsonParser.parseFakeIpFlush(
            ControlReply(ok = true, statusCode = 200, body = """{"flushed":23,"fakeip":true}"""),
        )
        assertTrue(fakeIpOk.ok)
        assertEquals(23L, fakeIpOk.flushed)

        val fakeIp409 = ControlToolsJsonParser.parseFakeIpFlush(
            ControlReply(ok = false, statusCode = 409, body = """{"error":{"code":"fakeip-unavailable","message":"fakeip-unavailable"}}"""),
        )
        assertFalse(fakeIp409.ok)
        assertTrue(fakeIp409.unavailable)

        val probeOk = ControlToolsJsonParser.parseOutboundProbe(
            ControlReply(
                ok = true,
                statusCode = 200,
                body = """{"outbound":"HK-01","resolved_outbound":"HK-01","state":"healthy","latency_ms":42,"status_code":204,"url":"https://www.gstatic.com/generate_204"}""",
            ),
        )
        assertTrue(probeOk.ok)
        assertEquals("healthy", probeOk.state)
        assertEquals(42L, probeOk.latencyMs)
        assertEquals(204, probeOk.statusCode)

        val probeNullLatency = ControlToolsJsonParser.parseOutboundProbe(
            ControlReply(
                ok = true,
                statusCode = 200,
                body = """{"outbound":"US-04","resolved_outbound":"US-04","state":"timeout","latency_ms":null,"url":"https://www.gstatic.com/generate_204"}""",
            ),
        )
        assertTrue(probeNullLatency.ok)
        assertEquals("timeout", probeNullLatency.state)
        assertEquals(-1L, probeNullLatency.latencyMs)

        val status = ControlToolsJsonParser.parseStatus(
            """{"instance":"android","state":"running","workers":1,"listeners":2,"control_generation":"5","active_sessions":11,"upload_bytes_total":"1024","download_bytes_total":"8192"}""",
        )
        assertNotNull(status)
        assertEquals(11L, status!!.activeSessions)
        assertEquals(8192L, status.toMetricsSummary().downloadBytes)

        val logEntry = ControlToolsJsonParser.parseSingleLogEvent(
            """{"seq":77,"timestamp_ns":1000,"level":"warn","domain":"quic","event":3,"session":9,"message":"retransmit"}""",
        )
        assertNotNull(logEntry)
        assertEquals(77L, logEntry!!.seq)
        assertEquals("warn", logEntry.level)
        assertEquals("retransmit", logEntry.message)
    }

    @Test
    fun cachedTokenReaderPicksUpRotationsAndHttpUrlHelperNormalizesListen() {
        val dir = Files.createTempDirectory("nexus-token-cache").toFile()
        try {
            val f = File(dir, "control.token")
            val reader = CachedTokenReader(f)
            assertNull(reader.read())

            f.writeText("token-alpha-123456\n", Charsets.UTF_8)
            assertEquals("token-alpha-123456", reader.read())
            assertEquals("token-alpha-123456", reader.read())

            // Rotate with different length / mtime
            f.writeText("token-beta-rotated-987654321\n", Charsets.UTF_8)
            f.setLastModified(System.currentTimeMillis() + 5_000L)
            assertEquals("token-beta-rotated-987654321", reader.read())
        } finally {
            dir.deleteRecursively()
        }

        assertEquals("http://127.0.0.1:9095", NexusControlClient.httpUrlFromListen("127.0.0.1:9095"))
        assertEquals("http://127.0.0.1:9090", NexusControlClient.httpUrlFromListen("  "))
        assertEquals("http://[::1]:9091", NexusControlClient.httpUrlFromListen("http://[::1]:9091"))
        // Loopback normalization & external-host rejection (Bearer token exfiltration guard)
        assertEquals("http://127.0.0.1:9090", NexusControlClient.httpUrlFromListen("0.0.0.0:9090"))
        assertEquals("http://127.0.0.1:9095", NexusControlClient.httpUrlFromListen("http://0.0.0.0:9095"))
        assertEquals("http://[::1]:9090", NexusControlClient.httpUrlFromListen("[::]:9090"))
        assertEquals("http://[::1]:9091", NexusControlClient.httpUrlFromListen("http://[::]:9091"))
        assertEquals("http://localhost:9092", NexusControlClient.httpUrlFromListen("localhost:9092"))
        assertEquals("http://127.0.0.1:9090", NexusControlClient.httpUrlFromListen("https://evil.example"))
        assertEquals("http://127.0.0.1:9090", NexusControlClient.httpUrlFromListen("https://127.0.0.1:9090"))
        assertEquals("http://127.0.0.1:9090", NexusControlClient.httpUrlFromListen("http://192.168.1.10:9090"))
        assertEquals("http://127.0.0.1:9090", NexusControlClient.httpUrlFromListen("http://127.0.0.1@evil.example:9090"))
    }

    @Test
    fun sseAccumulatorCapsOversizedFrameAndRecoversForSubsequentEvents() {
        val chunk = "x".repeat(70 * 1024)
        val rawLines = sequenceOf(
            "event: oversized",
            "data: $chunk",
            "data: $chunk",
            "data: $chunk",
            "data: $chunk", // 280 KiB > 256 KiB cap
            "",
            "event: status",
            "data: {\"state\":\"running\"}",
            "",
        )
        val events = NexusSseClient.parseSseLines(rawLines)
        assertEquals(256 * 1024, NexusSseClient.MAX_FRAME_BYTES)
        assertEquals(1, events.size)
        assertEquals("status", events[0].event)
        assertEquals("{\"state\":\"running\"}", events[0].data)
    }
}
