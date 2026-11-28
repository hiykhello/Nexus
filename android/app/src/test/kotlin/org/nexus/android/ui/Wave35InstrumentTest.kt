package org.nexus.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidThemePreset
import org.nexus.android.ui.theme.resolveEffectiveDarkTheme

class Wave35InstrumentTest {

    @Test
    fun themePresetPersistenceAndLegacyMigration() {
        assertEquals(AndroidThemePreset.OBSIDIAN, AndroidThemePreset.fromWire("dark"))
        assertEquals(AndroidThemePreset.OBSIDIAN, AndroidThemePreset.fromWire("obsidian"))
        assertEquals(AndroidThemePreset.PAPER, AndroidThemePreset.fromWire("light"))
        assertEquals(AndroidThemePreset.PAPER, AndroidThemePreset.fromWire("daylight"))
        assertEquals(AndroidThemePreset.PAPER, AndroidThemePreset.fromWire("paper"))
        assertEquals(AndroidThemePreset.STUDIO_AMBER, AndroidThemePreset.fromWire("amber"))
        assertEquals(AndroidThemePreset.STUDIO_AMBER, AndroidThemePreset.fromWire("studio_amber"))
        assertEquals(AndroidThemePreset.SYSTEM, AndroidThemePreset.fromWire("unknown"))

        val cfg = AndroidHostConfig(
            android = AndroidHostSection(
                themePreset = AndroidThemePreset.STUDIO_AMBER,
                dynamicColor = true,
                surfaceAlpha = 0.80f,
            ),
        )
        val roundTrip = AndroidHostConfig.fromJson(cfg.toJson())
        assertEquals(AndroidThemePreset.STUDIO_AMBER, roundTrip.android.themePreset)
        assertTrue(roundTrip.android.dynamicColor)
        assertEquals(0.80f, roundTrip.android.surfaceAlpha, 0.01f)
    }

    @Test
    fun effectiveDarkThemeMatrix() {
        assertTrue(resolveEffectiveDarkTheme(AndroidThemePreset.SYSTEM, systemDark = true))
        assertFalse(resolveEffectiveDarkTheme(AndroidThemePreset.SYSTEM, systemDark = false))
        assertTrue(resolveEffectiveDarkTheme(AndroidThemePreset.OBSIDIAN, systemDark = false))
        assertTrue(resolveEffectiveDarkTheme(AndroidThemePreset.STUDIO_AMBER, systemDark = false))
        assertFalse(resolveEffectiveDarkTheme(AndroidThemePreset.PAPER, systemDark = true))
    }

    @Test
    fun groupLatencySpectrumComputesMedianTiersAndRelativeMeter() {
        val members = listOf(
            OutboundMemberSnapshot("HK-01", "healthy", 40L, selected = true, overridden = false),
            OutboundMemberSnapshot("SG-02", "healthy", 120L, selected = false, overridden = false),
            OutboundMemberSnapshot("JP-03", "healthy", 240L, selected = false, overridden = false),
            OutboundMemberSnapshot("UK-06", "degraded", 400L, selected = false, overridden = false),
            OutboundMemberSnapshot("US-04", "timeout", 0L, selected = false, overridden = false),
            OutboundMemberSnapshot("DE-05", "unknown", -1L, selected = false, overridden = false),
        )
        val stats = computeGroupLatencyStats(members)
        assertEquals(6, stats.total)
        assertEquals(4, stats.healthyCount)
        assertEquals(180L, stats.p50Ms) // median of [40, 120, 240, 400] = (120 + 240)/2
        assertEquals(400L, stats.maxHealthyMs)
        assertEquals(1, stats.fastCount)
        assertEquals(1, stats.goodCount)
        assertEquals(1, stats.slowCount)
        assertEquals(2, stats.badCount) // >=350ms + timeout
        assertEquals(1, stats.unprobedCount)

        assertEquals(0.10f, computeMemberRelativeFraction(40L, "healthy", 400L), 0.001f)
        assertEquals(1.0f, computeMemberRelativeFraction(400L, "degraded", 400L), 0.001f)
        assertEquals(0f, computeMemberRelativeFraction(0L, "timeout", 400L), 0.001f)
        assertEquals(0f, computeMemberRelativeFraction(-1L, "unknown", 400L), 0.001f)
    }

    @Test
    fun sparklineOnsetShiftAppendDedupAndCap() {
        var markers = emptyList<SparklineOnset>()
        markers = appendOnsetMarker(markers, sampleCount = 24, label = "HK-01")
        assertEquals(listOf(SparklineOnset(23, "HK-01")), markers)
        // Duplicate at same slot replaces label cleanly
        markers = appendOnsetMarker(markers, sampleCount = 24, label = "全局")
        assertEquals(listOf(SparklineOnset(23, "全局")), markers)
        // Shift left on tick
        markers = shiftOnsetMarkers(markers)
        assertEquals(listOf(SparklineOnset(22, "全局")), markers)
        // Evict marker scrolling off left edge
        val evicted = shiftOnsetMarkers(listOf(SparklineOnset(0, "OLD"), SparklineOnset(5, "NEW")))
        assertEquals(listOf(SparklineOnset(4, "NEW")), evicted)
        // Cap at MAX_SPARKLINE_ONSETS = 3
        val capped = appendOnsetMarker(
            listOf(SparklineOnset(2, "A"), SparklineOnset(6, "B"), SparklineOnset(10, "C")),
            sampleCount = 24,
            label = "D",
        )
        assertEquals(3, capped.size)
        assertEquals("D", capped.last().label)
    }

    @Test
    fun quickCommandDomainDetectionExplainParserAndFakeIp() {
        assertTrue(looksLikeDomainOrHost("github.com"))
        assertTrue(looksLikeDomainOrHost("https://api.openai.com:443/v1"))
        assertTrue(looksLikeDomainOrHost("1.1.1.1"))
        assertFalse(looksLikeDomainOrHost("> probe"))
        assertFalse(looksLikeDomainOrHost("HK-01"))
        assertFalse(looksLikeDomainOrHost("two words.com"))

        assertEquals("api.openai.com", extractDiagnosticHost("https://api.openai.com:443/v1"))
        assertEquals("github.com:443", normalizeExplainTarget("github.com"))
        assertEquals("api.github.com:8443", normalizeExplainTarget("api.github.com:8443"))
        assertEquals("[2606:4700:4700::1111]:443", normalizeExplainTarget("2606:4700:4700::1111"))

        val parsed = parseExplainOneline("dns=remote-doh route=geosite-dev action=route outbound=proxy", running = true)
        assertNotNull(parsed)
        assertEquals("remote-doh", parsed!!.dnsPolicy)
        assertEquals("geosite-dev", parsed.routeRule)
        assertEquals("代理分流", parsed.action)
        assertEquals("proxy", parsed.outbound)
        assertFalse(parsed.isOffline)

        val offlineReject = parseExplainOneline("dns=reject:rcode=3 route=ads action=reject outbound=block", running = false)
        assertNotNull(offlineReject)
        assertEquals("DNS 拦截", offlineReject!!.dnsPolicy)
        assertEquals("拦截", offlineReject.action)
        assertTrue(offlineReject.isOffline)

        assertNull(parseExplainOneline("rule explain: invalid config"))

        assertTrue(isFakeIpAddress("198.18.0.42"))
        assertTrue(isFakeIpAddress("198.19.255.1"))
        assertTrue(isFakeIpAddress("fc00::1a2b"))
        assertFalse(isFakeIpAddress("140.82.114.6"))
        assertFalse(isFakeIpAddress("fd00::1"))
    }

    @Test
    fun quickCommandNodeSearchAndLogDomainParsing() {
        val groups = listOf(
            OutboundGroupSnapshot(
                tag = "Auto",
                mode = "url-test",
                active = "HK-01",
                manualOverride = false,
                members = listOf(
                    OutboundMemberSnapshot("HK-01 香港", "healthy", 42L, selected = true, overridden = false),
                    OutboundMemberSnapshot("JP-03 东京", "healthy", 110L, selected = false, overridden = false),
                ),
            ),
        )
        assertEquals(2, filterCommandNodes(groups, "").size)
        assertEquals(0, filterCommandNodes(groups, "> mode").size)
        val jp = filterCommandNodes(groups, "东京")
        assertEquals(1, jp.size)
        assertEquals("JP-03 东京", jp.first().member.name)

        assertEquals("dns", parseLogDomain("09:41:04 [debug] dns: cache hit api.github.com"))
        assertEquals("route", parseLogDomain("[info] route: quic api.github.com:443 -> Auto/HK-01"))
        assertEquals("control", parseLogDomain("09:41:15 [info] control: hot-reloaded profile"))
        assertEquals("tun", parseLogDomain("[info] vpn: interface ready"))
        assertEquals("proxy", parseLogDomain("09:41:09 [warn] probe: UK-06 latency elevated"))
    }

    @Test
    fun quickCommandActionFilteringRuleLocalizationAndProbeableGroup() {
        // rule:<N> localization
        val indexedRule = parseExplainOneline("dns=remote route=rule:3 action=route outbound=proxy", running = true)
        assertNotNull(indexedRule)
        assertEquals("规则 #3", indexedRule!!.routeRule)

        // > command filtering (running vs stopped)
        assertEquals(7, filterQuickCommandActions("", running = true, outboundMode = "rule").size)
        assertEquals(4, filterQuickCommandActions("", running = false, outboundMode = "rule").size)
        assertEquals(7, filterQuickCommandActions(">", running = true, outboundMode = "rule").size)
        val probeMatch = filterQuickCommandActions("> 测速", running = true, outboundMode = "rule")
        assertEquals(listOf(QuickCommandActionId.PROBE_ALL), probeMatch.map { it.id })
        val fakeIpMatch = filterQuickCommandActions("> fakeip", running = true, outboundMode = "rule")
        assertEquals(listOf(QuickCommandActionId.FLUSH_FAKEIP), fakeIpMatch.map { it.id })
        val directMatch = filterQuickCommandActions("> direct", running = false, outboundMode = "direct")
        assertEquals(listOf(QuickCommandActionId.MODE_DIRECT), directMatch.map { it.id })
        assertTrue(directMatch.first().selected)
        assertTrue(filterQuickCommandActions("> nonexistent_cmd", running = true, outboundMode = "rule").isEmpty())

        // Probeable group selection skips selector/select groups (prevents HTTP 409)
        val selectorOnly = listOf(
            OutboundGroupSnapshot("Manual", "selector", "HK-01", manualOverride = false, members = emptyList()),
            OutboundGroupSnapshot("Select2", "select", "SG-02", manualOverride = false, members = emptyList()),
        )
        assertNull(findProbeableGroupTag(selectorOnly, preferredTag = "Manual"))

        val mixedGroups = selectorOnly + OutboundGroupSnapshot("Auto", "url-test", "HK-01", manualOverride = false, members = emptyList())
        assertEquals("Auto", findProbeableGroupTag(mixedGroups, preferredTag = "Manual"))
        assertEquals("Auto", findProbeableGroupTag(mixedGroups, preferredTag = "Auto"))
    }
}
