package org.nexus.android.bridge.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidKdlOpsTest {
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
        // routing { default-outbound "commented" }
        routing {
            default-outbound "Auto"
        }
    """.trimIndent() + "\n"

    @Test
    fun outboundModeRoundTripPreservesOriginalDefault() {
        assertEquals("rule", AndroidKdlOps.detectOutboundMode(sampleKdl))
        val (okDirect, directKdl) = AndroidKdlOps.applyOutboundMode(sampleKdl, "direct")
        assertTrue(okDirect)
        assertEquals("direct", AndroidKdlOps.detectOutboundMode(directKdl))
        assertTrue(directKdl.contains("default-outbound \"direct\""))

        val (okRule, restoredKdl) = AndroidKdlOps.applyOutboundMode(directKdl, "rule")
        assertTrue(okRule)
        assertEquals("rule", AndroidKdlOps.detectOutboundMode(restoredKdl))
        assertTrue(restoredKdl.contains("default-outbound \"Auto\""))
    }

    @Test
    fun quickRouteRuleCreatesValidTcpProgramAndAppendsIntoExistingBlock() {
        val firstRule = AndroidKdlOps.buildQuickRouteRule("api.github.com:443", action = "route", outbound = "direct")
        assertTrue(firstRule.contains("domain-suffix \"api.github.com\""))
        val (ok1, afterFirst) = AndroidKdlOps.insertRouteRule(sampleKdl, firstRule)
        assertTrue(ok1)
        assertTrue(afterFirst.contains("tcp-program sniff-timeout-ms=300 unknown=\"skip\" {"))
        assertTrue(afterFirst.contains("outbound=\"direct\""))

        val secondRule = AndroidKdlOps.buildQuickRouteRule("1.1.1.1:443", action = "reject", outbound = "")
        assertTrue(secondRule.contains("ip-cidr \"1.1.1.1/32\""))
        assertTrue(secondRule.contains("action=\"reject\""))
        val (ok2, afterSecond) = AndroidKdlOps.insertRouteRule(afterFirst, secondRule)
        assertTrue(ok2)
        // Must append into the existing tcp-program block without creating a duplicate block
        assertEquals(1, Regex("tcp-program\\s+sniff-timeout-ms=").findAll(afterSecond).count())
        assertTrue(afterSecond.contains("domain-suffix \"api.github.com\""))
        assertTrue(afterSecond.contains("ip-cidr \"1.1.1.1/32\""))
    }

    @Test
    fun insertRouteRuleCreatesValidRoutingBlockWhenAbsent() {
        val minimalKdl = "schema-version 1\noutbound \"direct\" type=\"direct\"\n"
        val rule = AndroidKdlOps.buildQuickRouteRule("example.com", action = "route", outbound = "direct")
        val (ok, updated) = AndroidKdlOps.insertRouteRule(minimalKdl, rule)
        assertTrue(ok)
        assertTrue(updated.contains("default-outbound \"direct\""))
        assertTrue(updated.contains("tcp-program sniff-timeout-ms=300 unknown=\"skip\" {"))
    }

    @Test
    fun remoteOutboundAndGroupExtractionWorkWithCustomNames() {
        assertTrue(AndroidKdlOps.hasRemoteOutbound(sampleKdl))
        assertEquals("Auto", AndroidKdlOps.extractProxyGroupName(sampleKdl))
        assertFalse(AndroidKdlOps.hasRemoteOutbound("outbound \"direct\" type=\"direct\""))
    }

    @Test
    fun formatKdlNormalizesIndentationWithoutCorruptingStringsOrComments() {
        val messy = "  schema-version 1  \n\n\nrouting {\n// ignore { brace in comment\ndefault-outbound \"proxy{1}\"\n  tcp-program {\nrule action=\"route\" outbound=\"direct\" {\n  domain-suffix \"example.com\"\n}\n  }\n}\n\n"
        val expected = """
            schema-version 1

            routing {
                // ignore { brace in comment
                default-outbound "proxy{1}"
                tcp-program {
                    rule action="route" outbound="direct" {
                        domain-suffix "example.com"
                    }
                }
            }
        """.trimIndent() + "\n"
        assertEquals(expected, AndroidKdlOps.formatKdl(messy))
        assertEquals(expected, AndroidKdlOps.formatKdl(expected))
    }
}
