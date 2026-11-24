package org.nexus.android.bridge.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRuleOpsTest {
    private val sampleKdl = """
        schema-version 1
        role "client"
        outbound "direct" type="direct"
        outbound "hk-01" type="vless" { server host="hk.example.com" port=443; }
        outbound "Auto" type="selector" {
            member "hk-01"
            member "direct"
            selected "hk-01"
        }
        dns {
            server "local" address="223.5.5.5:53"
            server "remote" address="1.1.1.1:53"
        }
        routing {
            default-outbound "Auto"
        }
    """.trimIndent() + "\n"

    @Test
    fun buildCustomRouteRuleHandlesDomainIpAndReject() {
        val (okDomain, domainRule) = AndroidRuleOps.buildCustomRouteRule(
            matchType = "domain-suffix",
            pattern = ".openai.com ",
            action = "route",
            outbound = "Auto",
        )
        assertTrue(okDomain)
        assertTrue(domainRule.contains("rule action=\"route\" outbound=\"Auto\""))
        assertTrue(domainRule.contains("domain-suffix \"openai.com\""))

        val (okIp, ipRule) = AndroidRuleOps.buildCustomRouteRule(
            matchType = "ip-cidr",
            pattern = "8.8.8.8",
            action = "reject",
        )
        assertTrue(okIp)
        assertTrue(ipRule.contains("rule action=\"reject\""))
        assertTrue(ipRule.contains("ip-cidr \"8.8.8.8/32\""))

        val (okEmpty, _) = AndroidRuleOps.buildCustomRouteRule("domain", "   ", "route")
        assertFalse(okEmpty)
    }

    @Test
    fun buildAndInsertDnsRuleAppendsIntoExistingDnsBlock() {
        val (okRule, dnsLine) = AndroidRuleOps.buildDnsRule(
            matchType = "domain-suffix",
            pattern = "internal.corp",
            action = "route",
            server = "local",
        )
        assertTrue(okRule)
        assertEquals(
            "rule domain-suffix=\"internal.corp\" action=\"route\" server=\"local\"",
            dnsLine,
        )

        val (okInsert, updated) = AndroidRuleOps.insertDnsRule(sampleKdl, dnsLine)
        assertTrue(okInsert)
        assertEquals(1, Regex("(?m)^dns\\s*\\{").findAll(updated).count())
        assertTrue(updated.contains("    rule domain-suffix=\"internal.corp\" action=\"route\" server=\"local\""))
    }

    @Test
    fun insertDnsRuleCreatesDnsBlockWithDefaultServersWhenAbsent() {
        val minimal = "schema-version 1\noutbound \"direct\" type=\"direct\"\n"
        val (okRule, rejectLine) = AndroidRuleOps.buildDnsRule(
            matchType = "domain",
            pattern = "ads.example.com",
            action = "reject",
        )
        assertTrue(okRule)
        assertTrue(rejectLine.contains("action=\"reject\" reject-method=\"reply\""))

        val (okInsert, updated) = AndroidRuleOps.insertDnsRule(minimal, rejectLine)
        assertTrue(okInsert)
        assertTrue(updated.contains("    server \"local\" type=\"local\""))
        assertTrue(updated.contains("    server \"remote\" type=\"udp\" host=\"1.1.1.1\" port=53"))
        assertTrue(updated.contains("    rule domain=\"ads.example.com\""))

        val (okRemote, remoteLine) = AndroidRuleOps.buildDnsRule(
            matchType = "domain-suffix",
            pattern = "openai.com",
            action = "route",
            server = "remote",
        )
        assertTrue(okRemote)
        val (okSecond, afterSecond) = AndroidRuleOps.insertDnsRule(updated, remoteLine)
        assertTrue(okSecond)
        assertEquals(1, Regex("server \"local\"").findAll(afterSecond).count())
        assertTrue(afterSecond.contains("    rule domain-suffix=\"openai.com\" action=\"route\" server=\"remote\""))
    }

    @Test
    fun extractorsDiscoverOutboundsAndDnsServers() {
        val outbounds = AndroidRuleOps.extractOutboundTargets(sampleKdl)
        assertTrue("Auto" in outbounds)
        assertTrue("direct" in outbounds)

        val servers = AndroidRuleOps.extractDnsServers(sampleKdl)
        assertEquals(listOf("local", "remote"), servers)
    }
}
