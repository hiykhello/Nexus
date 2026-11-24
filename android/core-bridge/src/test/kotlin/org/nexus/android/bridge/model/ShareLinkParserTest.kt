package org.nexus.android.bridge.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ShareLinkParserTest {
    @Test
    fun parsesVlessRealityXhttpAndRendersPrivateSecretFile() {
        val uri = "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443" +
            "?security=reality&sni=www.example.com&fp=chrome-133&pbk=0123abcd&sid=cafe&type=xhttp&path=%2Fapi&mode=stream-one#HK%20Edge"
        val parsed = ShareLinkParser.parse(uri).getOrThrow()
        assertEquals(OutboundScheme.VLESS, parsed.scheme)
        assertEquals("HK-Edge", parsed.tag)
        assertEquals("edge.example.com", parsed.host)
        assertEquals(443, parsed.port)
        assertEquals("xhttp", parsed.transport)
        assertEquals("/api", parsed.path)

        val kdl = ShareLinkParser.renderKdlOutbound(parsed, "/data/user/0/org.nexus.android/no_backup/hk.uuid")
        assertTrue(kdl.contains("""outbound "HK-Edge" type="vless""""))
        assertTrue(kdl.contains("uuid-file \"/data/user/0/org.nexus.android/no_backup/hk.uuid\""))
        assertFalse(kdl.contains("11111111-2222"))
        assertTrue(kdl.contains("public-key \"0123abcd\""))
        assertTrue(kdl.contains("mode \"stream-one\""))
    }

    @Test
    fun parsesShadowsocksSip002Ipv6() {
        val parsed = ShareLinkParser.parse(
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206c2VjcmV0a2V5@[2001:db8::1]:8443#JP_SS"
        ).getOrThrow()
        assertEquals(OutboundScheme.SHADOWSOCKS, parsed.scheme)
        assertEquals("2022-blake3-aes-128-gcm", parsed.method)
        assertEquals("secretkey", parsed.secret)
        assertEquals("2001:db8::1", parsed.host)
        assertEquals(8443, parsed.port)
    }

    @Test
    fun parsesTrojanWsPinAnytlsGrpcTuicAndSnell5() {
        val trojan = ShareLinkParser.parse(
            "trojan://pass123@tr.example.com:443?sni=tr.example.com&type=ws&path=%2Fws&host=cdn.example.com&certificate-sha256=deadbeef#TR-WS"
        ).getOrThrow()
        val trojanKdl = ShareLinkParser.renderKdlOutbound(trojan, "/sec/tr.pass")
        assertTrue(trojanKdl.contains("""outbound "TR-WS" type="trojan""""))
        assertTrue(trojanKdl.contains("""certificate-sha256 "deadbeef""""))
        assertTrue(trojanKdl.contains("""transport "websocket""""))

        val anytls = ShareLinkParser.parse(
            "anytls://anypass@any.example.com:443?sni=any.example.com&type=grpc&serviceName=tun&authority=any.example.com#AnyNode"
        ).getOrThrow()
        val anyKdl = ShareLinkParser.renderKdlOutbound(anytls, "/sec/any.pass")
        assertTrue(anyKdl.contains("""outbound "AnyNode" type="anytls""""))
        assertTrue(anyKdl.contains("""transport "grpc""""))
        assertTrue(anyKdl.contains("""service-name "tun""""))

        val tuic = ShareLinkParser.parse(
            "tuic://11111111-2222-3333-4444-555555555555:tuicpass@t.example.com:8443?sni=t.example.com&congestion_control=bbr#TUIC"
        ).getOrThrow()
        val tuicKdl = ShareLinkParser.renderKdlOutbound(tuic, "/sec/tuic.pass")
        assertTrue(tuicKdl.contains("""outbound "TUIC" type="tuic""""))
        assertTrue(tuicKdl.contains("""uuid "11111111-2222-3333-4444-555555555555""""))
        assertTrue(tuicKdl.contains("""congestion-control "bbr""""))

        val snell = ShareLinkParser.parse(
            "snell://pskvalue@sn.example.com:6160?version=5&obfs=http&obfs-host=bing.com#Snell5"
        ).getOrThrow()
        val snellKdl = ShareLinkParser.renderKdlOutbound(snell, "/sec/sn.psk")
        assertTrue(snellKdl.contains("""outbound "Snell5" type="snell""""))
        assertTrue(snellKdl.contains("version 5"))
        assertTrue(snellKdl.contains("""psk-file "/sec/sn.psk""""))
        assertTrue(snellKdl.contains("""obfs "http""""))

        val ssh = ShareLinkParser.parse(
            "ssh://alice:s3cr3t@bastion.example.com:2222?host-key-sha256=SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU&cipher=aes256-gcm@openssh.com#Bastion"
        ).getOrThrow()
        val sshKdl = ShareLinkParser.renderKdlOutbound(ssh, "/sec/ssh.pass")
        assertTrue(sshKdl.contains("""outbound "Bastion" type="ssh""""))
        assertTrue(sshKdl.contains("""user "alice""""))
        assertTrue(sshKdl.contains("""password-file "/sec/ssh.pass""""))
        assertTrue(sshKdl.contains("""host-key-sha256 "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU""""))
        assertTrue(sshKdl.contains("""cipher "aes256-gcm@openssh.com""""))
        assertFalse(sshKdl.contains("s3cr3t"))

        val nh2 = ShareLinkParser.parse(
            "naive+https://alice:pw@naive.example.com:443?sni=naive.example.com&fp=chrome#NaiveH2"
        ).getOrThrow()
        assertEquals(OutboundScheme.NAIVE, nh2.scheme)
        assertEquals("h2", nh2.protocolName)
        assertTrue(nh2.padding)
        val nh2Kdl = ShareLinkParser.renderKdlOutbound(nh2, "/sec/n2.pass")
        assertTrue(nh2Kdl.contains("""outbound "NaiveH2" type="naive""""))
        assertTrue(nh2Kdl.contains("""protocol "h2""""))
        assertTrue(nh2Kdl.contains("verify #true"))

        val nh3 = ShareLinkParser.parse(
            "naive+quic://bob:pw@nq.example.com:8443?padding=0#NaiveH3"
        ).getOrThrow()
        assertEquals("h3", nh3.protocolName)
        assertFalse(nh3.padding)

        val h3Proxy = ShareLinkParser.parse(
            "https://u:p@h3p.example.com:443?h3=1&udp=1&fp=chrome#H3Proxy"
        ).getOrThrow()
        assertEquals(OutboundScheme.HTTP_CONNECT, h3Proxy.scheme)
        assertEquals("h3", h3Proxy.httpVersion)
        assertTrue(h3Proxy.udp)
        val h3Kdl = ShareLinkParser.renderKdlOutbound(h3Proxy, "/sec/h3.pass")
        assertTrue(h3Kdl.contains("""type="http-connect""""))
        assertTrue(h3Kdl.contains("""http-version "h3""""))
        assertTrue(h3Kdl.contains("udp #true"))
        assertTrue(h3Kdl.contains("verify #true"))
    }

    @Test
    fun rejectsUnsupportedSchemeAndHandlesSlashOrSnellVersion() {
        val slashPort = ShareLinkParser.parse(
            "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443/?security=tls&sni=edge.example.com#SlashPort"
        ).getOrThrow()
        assertEquals("edge.example.com", slashPort.host)
        assertEquals(443, slashPort.port)

        val slashV6 = ShareLinkParser.parse(
            "vless://11111111-2222-3333-4444-555555555555@[2001:db8::1]:443/?security=tls&sni=edge.example.com#SlashV6"
        ).getOrThrow()
        assertEquals("2001:db8::1", slashV6.host)
        assertEquals(443, slashV6.port)

        val ssSlash = ShareLinkParser.parse(
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206YT8/@1.2.3.4:8388/?plugin=none#SlashB64"
        ).getOrThrow()
        assertEquals("2022-blake3-aes-128-gcm", ssSlash.method)
        assertEquals("a??", ssSlash.secret)
        assertEquals("1.2.3.4", ssSlash.host)
        assertEquals(8388, ssSlash.port)

        assertTrue(ShareLinkParser.parse("snell://pskvalue@sn.example.com:6160?version=3#Snell3").isFailure)
        assertTrue(ShareLinkParser.parse("http://example.com").isFailure)

        // Security: untrusted ssh:// URIs must never inject local filesystem private-key-file paths.
        val sshInjected = ShareLinkParser.parse(
            "ssh://alice@bastion.example.com:22?private-key-file=%2Fetc%2Fpasswd#SafeSSH"
        ).getOrThrow()
        assertEquals("", sshInjected.privateKeyFile)
        val sshKdl = ShareLinkParser.renderKdlOutbound(sshInjected, "")
        assertFalse(sshKdl.contains("/etc/passwd"))

        // Security: KDL escaping must strip control chars and Unicode line terminators.
        val ctrlNode = ShareLinkParser.parse(
            "trojan://pass@edge.example.com:443?sni=a%0Ab%E2%80%A8c#Tag"
        ).getOrThrow()
        val ctrlKdl = ShareLinkParser.renderKdlOutbound(ctrlNode, "/sec/t.pass")
        assertTrue(ctrlKdl.contains("""server-name "abc""""))
    }
}
