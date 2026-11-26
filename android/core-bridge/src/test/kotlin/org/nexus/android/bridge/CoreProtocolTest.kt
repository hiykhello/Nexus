package org.nexus.android.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.ipc.OutboundJsonParser
import org.nexus.android.bridge.model.OutboundScheme
import org.nexus.android.bridge.model.ShareLinkParser
import org.nexus.android.bridge.profile.SecretFileIO
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64

class CoreProtocolTest {
    @Test
    fun buildsValidNexus1Frames() {
        val single = NexusControlClient.buildNexus1Frame(listOf("status"))
        assertNotNull(single)
        assertEquals("NEXUS/1 status", single!!.toString(Charsets.UTF_8))

        val multi = NexusControlClient.buildNexus1Frame(listOf("select", "proxy", "--auto"))
        assertNotNull(multi)
        assertEquals("NEXUS/1 select\u0000proxy\u0000--auto", multi!!.toString(Charsets.UTF_8))

        val netChange = NexusControlClient.buildNexus1Frame(listOf("network-change", "4"))
        assertNotNull(netChange)
        assertEquals("NEXUS/1 network-change\u00004", netChange!!.toString(Charsets.UTF_8))

        val closeAny = NexusControlClient.buildNexus1Frame(listOf("close-any", "42"))
        assertNotNull(closeAny)
        assertEquals("NEXUS/1 close-any\u000042", closeAny!!.toString(Charsets.UTF_8))

        val closeAll = NexusControlClient.buildNexus1Frame(listOf("close-all"))
        assertNotNull(closeAll)
        assertEquals("NEXUS/1 close-all", closeAll!!.toString(Charsets.UTF_8))

        val probe = NexusControlClient.buildNexus1Frame(listOf("probe", "auto"))
        assertNotNull(probe)
        assertEquals("NEXUS/1 probe\u0000auto", probe!!.toString(Charsets.UTF_8))

        val logs = OutboundJsonParser.parseLogs(
            """{"latest_seq":"5","evicted":"1","entries":[{"seq":"5","level":"trace","domain":"route","event_code":102,"message":"matched"}]}""",
        )
        assertEquals(5L, logs.latestSeq)
        assertEquals(1L, logs.evicted)
        assertEquals(1, logs.entries.size)
        assertEquals("trace", logs.entries[0].level)

        val detail = OutboundJsonParser.parseConnectionDetail(
            """{"id":"42","listener":0,"inbound":"socks","protocol":"socks5","path":"direct","outbound":"direct","target":"1.1.1.1:443","destination_port":443,"duration_ms":"90","upload_bytes":"100","download_bytes":"200","can_close":true}""",
        )
        assertNotNull(detail)
        assertEquals(42L, detail!!.id)
        assertEquals("socks", detail.inbound)
        assertEquals("direct", detail.outbound)
    }

    @Test
    fun rejectsMalformedNexus1Frames() {
        assertNull(NexusControlClient.buildNexus1Frame(emptyList()))
        assertNull(NexusControlClient.buildNexus1Frame(listOf("select", "")))
        assertNull(NexusControlClient.buildNexus1Frame(listOf("a\u0000b")))

        val okReply = NexusControlClient.decodeNexus1Reply("NEXUS/1 OK\nrunning\n")
        assertTrue(okReply.ok)
        assertEquals(200, okReply.statusCode)
        assertEquals("running\n", okReply.body)

        val errReply = NexusControlClient.decodeNexus1Reply("NEXUS/1 ERROR\npermission-denied\n")
        assertFalse(errReply.ok)
        assertEquals(400, errReply.statusCode)
        assertEquals("permission-denied", errReply.body)

        assertFalse(NexusControlClient.decodeNexus1Reply("").ok)
        assertEquals("HK%20Group%2F1", NexusControlClient.encodePathSegment("HK Group/1"))
        assertEquals("dns%20timeout%20%2B%20err", NexusControlClient.encodeQueryValue("dns timeout + err"))
    }

    @Test
    fun parsesOpenMetricsSummary() {
        val sample = """
            # HELP nexus_control_generation gen
            nexus_control_generation 7 1700000000
            nexus_active_sessions{listener="0"} 5
            nexus_active_sessions{listener="1"} 2 1700000000
            nexus_traffic_upload_bytes_total{listener="0"} 1000
            nexus_traffic_download_bytes_total{listener="0"} 4096
        """.trimIndent()
        val m = NexusControlClient.parseOpenMetrics(sample)
        assertEquals(7L, m.controlGeneration)
        assertEquals(7L, m.activeSessions)
        assertEquals(1000L, m.uploadBytes)
        assertEquals(4096L, m.downloadBytes)
    }

    @Test
    fun parsesShareLinksAndNeverEmbedsPlaintextSecrets() {
        val vless = ShareLinkParser.parse(
            "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443" +
                "?security=reality&sni=www.example.com&fp=chrome&pbk=0123abcd&sid=cafe&type=xhttp&path=%2Fapi&mode=stream-one#HK%20Edge",
        ).getOrThrow()
        assertEquals(OutboundScheme.VLESS, vless.scheme)
        assertEquals("HK-Edge", vless.tag)
        assertEquals("xhttp", vless.transport)
        assertEquals("/api", vless.path)

        val kdl = ShareLinkParser.renderKdlOutbound(vless, "/data/user/0/org.nexus.android/files/secrets/HK-Edge.secret")
        assertTrue(kdl.contains("uuid-file"))
        assertFalse(kdl.contains("11111111-2222"))
        assertTrue(kdl.contains("""public-key "0123abcd""""))
        assertTrue(kdl.contains("""transport "xhttp""""))

        val ss = ShareLinkParser.parse("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206c2VjcmV0a2V5@[2001:db8::1]:8443#JP_SS").getOrThrow()
        assertEquals(OutboundScheme.SHADOWSOCKS, ss.scheme)
        assertEquals("2022-blake3-aes-128-gcm", ss.method)
        assertEquals("secretkey", ss.secret)
        assertEquals("2001:db8::1", ss.host)
        assertEquals(8443, ss.port)

        assertTrue(ShareLinkParser.parse("http://example.com").isFailure)
    }

    @Test
    fun decodesBase64SubscriptionAndWritesStrict0600Secrets() {
        val raw = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@node1.example.com:443?security=reality&pbk=abcd#Node%201\n" +
            "trojan://topsecretpass@node2.example.com:443?sni=node2.example.com#Node%202\n"
        val encoded = Base64.getEncoder().encodeToString(raw.toByteArray(Charsets.UTF_8))
        val lines = SecretFileIO.decodeSubscriptionLines(encoded)
        assertEquals(2, lines.size)
        assertEquals("Node-1", SecretFileIO.sanitizeId("Node 1"))

        val tmpRoot = File(System.getProperty("java.io.tmpdir"), "nexus-sub-test-${System.nanoTime()}").apply { mkdirs() }
        try {
            val secret = File(tmpRoot, "node1.secret")
            SecretFileIO.atomicWriteSecret0600(secret, "topsecretpass")
            assertEquals("topsecretpass", secret.readText(Charsets.UTF_8))
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(secret.toPath()))
        } finally {
            tmpRoot.deleteRecursively()
        }
    }
}
