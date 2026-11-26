package org.nexus.android.bridge.workspace

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.vpn.ScreenStateMonitor
import java.io.File
import java.nio.file.Files

class AndroidHostConfigAndComposerTest {
    @Test
    fun hostConfigJsonRoundTripStaysIsolatedFromWorkspace() {
        val dir = Files.createTempDirectory("nexus-host-test").toFile()
        try {
            val db = NexusClientDatabase.inMemory(File(dir, NexusClientSchema.DEFAULT_DB_NAME))
            val store = AndroidHostConfigStore(File(dir, "host.json"), db)
            val cfg = AndroidHostConfig(
                common = HostCommonConfig(workers = 20, workersSpec = "max-2", workersMax = 12, logLevel = "debug", maxSelectorMembers = 64),
                android = AndroidHostSection(
                    runMode = AndroidRunMode.PROXY_ONLY,
                    localListen = "127.0.0.1:10809",
                    tunMtu = 1500,
                    perAppMode = AndroidPerAppMode.INCLUDE,
                    perAppPackages = listOf("com.android.chrome"),
                    excludeSelfFromVpn = false,
                    allowBypass = true,
                    bypassLan = true,
                    appendHttpProxy = true,
                    enableIpv6 = true,
                    autoStartOnBoot = true,
                    dozePauseEnabled = true,
                    oomSoftLimitMb = 64,
                ),
            )
            store.save(cfg)
            val loaded = store.load()
            assertEquals(cfg, loaded)
            assertEquals(20, loaded.common.workers)
            assertEquals("max-2", loaded.common.workersSpec)
            assertEquals(12, loaded.common.workersMax)
            val raw = db.getHostKv(NexusClientDatabase.KV_ANDROID_HOST_CONFIG) ?: ""
            assertTrue(raw.contains("\"workers\":20") || raw.contains("\"workers\": 20"))
            assertTrue(raw.contains("\"workers_spec\":\"max-2\"") || raw.contains("\"workers_spec\": \"max-2\""))
            assertTrue(raw.contains("\"workers_max\":12") || raw.contains("\"workers_max\": 12"))
            assertTrue(raw.contains("\"run_mode\":\"proxy_only\"") || raw.contains("\"run_mode\": \"proxy_only\""))
            assertTrue(raw.contains("\"exclude_self_from_vpn\":false") || raw.contains("\"exclude_self_from_vpn\": false"))
            assertFalse(raw.contains("\"profiles\""))

            // Default workers == 1 and compact JSON omits empty workers_spec / zero workers_max
            val defaultCfg = AndroidHostConfig()
            assertEquals(1, defaultCfg.common.workers)
            assertEquals(1, AndroidHostConfig.fromJson("{}").common.workers)
            val defaultJson = defaultCfg.toJson()
            assertFalse(defaultJson.contains("workers_spec"))
            assertFalse(defaultJson.contains("workers_max"))

            // Strict workers_spec validation parity with Core
            listOf("", "auto", "max", "max-0", "max-2", "auto-4").forEach { spec ->
                assertTrue("Expected valid spec: '$spec'", HostCommonConfig.isValidWorkersSpec(spec))
            }
            listOf("max-", "auto-", "max-abc", "max--1", "foo", "2", "AUTO", "max-99999999999999999999").forEach { spec ->
                assertFalse("Expected invalid spec: '$spec'", HostCommonConfig.isValidWorkersSpec(spec))
            }
            assertEquals("", AndroidHostConfig.fromJson("""{"workers_spec":"max-bad","workers_max":-5}""").common.workersSpec)
            assertEquals(0, AndroidHostConfig.fromJson("""{"workers_spec":"max-bad","workers_max":-5}""").common.workersMax)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun perAppPlanEnforcesSelfInsideVpnDefaultAcrossAllThreeModes() {
        val self = "org.nexus.android"
        val userPkgs = listOf("com.android.chrome", "org.mozilla.firefox")

        // OFF + default excludeSelfFromVpn=false: self stays INSIDE VPN; captive portals excluded
        val offDefault = AndroidHostConfig.computePerAppPlan(
            self,
            AndroidHostSection(perAppMode = AndroidPerAppMode.OFF, excludeSelfFromVpn = false),
        )
        assertTrue(offDefault.allowedPackages.isEmpty())
        assertFalse(self in offDefault.disallowedPackages)
        assertTrue("com.android.captiveportallogin" in offDefault.disallowedPackages)

        // EXCLUDE + default excludeSelfFromVpn=false: even if userPkgs contained self, self stays inside VPN
        val excludeDefault = AndroidHostConfig.computePerAppPlan(
            self,
            AndroidHostSection(perAppMode = AndroidPerAppMode.EXCLUDE, perAppPackages = userPkgs + self, excludeSelfFromVpn = false),
        )
        assertTrue(excludeDefault.allowedPackages.isEmpty())
        assertFalse(self in excludeDefault.disallowedPackages)
        assertTrue("com.android.chrome" in excludeDefault.disallowedPackages)
        assertTrue("com.android.captiveportallogin" in excludeDefault.disallowedPackages)

        // EXCLUDE + excludeSelfFromVpn=true: self is explicitly disallowed
        val excludeSelf = AndroidHostConfig.computePerAppPlan(
            self,
            AndroidHostSection(perAppMode = AndroidPerAppMode.EXCLUDE, perAppPackages = userPkgs, excludeSelfFromVpn = true),
        )
        assertTrue(self in excludeSelf.disallowedPackages)

        // INCLUDE + default excludeSelfFromVpn=false: self IS included in allowed list; disallowed empty
        val includeDefault = AndroidHostConfig.computePerAppPlan(
            self,
            AndroidHostSection(perAppMode = AndroidPerAppMode.INCLUDE, perAppPackages = userPkgs, excludeSelfFromVpn = false),
        )
        assertTrue(includeDefault.disallowedPackages.isEmpty())
        assertTrue(self in includeDefault.allowedPackages)
        assertTrue("com.android.chrome" in includeDefault.allowedPackages)

        // INCLUDE + excludeSelfFromVpn=true: self omitted from allowed list
        val includeNoSelf = AndroidHostConfig.computePerAppPlan(
            self,
            AndroidHostSection(perAppMode = AndroidPerAppMode.INCLUDE, perAppPackages = userPkgs + self, excludeSelfFromVpn = true),
        )
        assertFalse(self in includeNoSelf.allowedPackages)
        assertTrue("com.android.chrome" in includeNoSelf.allowedPackages)

        // INCLUDE + empty perAppPackages + excludeSelfFromVpn=true: fallback disallows self & captive portals
        val includeEmptyNoSelf = AndroidHostConfig.computePerAppPlan(
            self,
            AndroidHostSection(perAppMode = AndroidPerAppMode.INCLUDE, perAppPackages = emptyList(), excludeSelfFromVpn = true),
        )
        assertTrue(includeEmptyNoSelf.allowedPackages.isEmpty())
        assertTrue(self in includeEmptyNoSelf.disallowedPackages)
        assertTrue("com.android.captiveportallogin" in includeEmptyNoSelf.disallowedPackages)
    }

    @Test
    fun fakeIpv6RouteAndPowerSavePolicyWorkCorrectly() {
        val fakeWs = WorkspaceDocument(
            dns = DnsConfig(mode = "simple", simple = SimpleDnsConfig(fakeIpEnabled = true, fakeIpV6Pool = "fc00::/18")),
        )
        assertTrue(AndroidHostConfig.needsFakeIpv6Route(fakeWs, AndroidHostSection(enableIpv6 = true)))
        assertFalse(AndroidHostConfig.needsFakeIpv6Route(fakeWs, AndroidHostSection(enableIpv6 = false)))

        assertFalse(ScreenStateMonitor.shouldPausePolling(interactive = true, deviceIdle = false, screenOffPauseStats = true, dozePauseEnabled = true))
        assertTrue(ScreenStateMonitor.shouldPausePolling(interactive = false, deviceIdle = false, screenOffPauseStats = true, dozePauseEnabled = true))
        assertTrue(ScreenStateMonitor.shouldPausePolling(interactive = true, deviceIdle = true, screenOffPauseStats = true, dozePauseEnabled = true))
        assertFalse(ScreenStateMonitor.shouldPausePolling(interactive = true, deviceIdle = true, screenOffPauseStats = true, dozePauseEnabled = false))
    }

    @Test
    fun workspaceComposerParsesJsonAndEvaluatesLiveTunHotSwitch() {
        val sampleJson = """
            {
              "ok": true,
              "active_tag": "hk-01",
              "selector_tag": "proxy",
              "selector_members": ["hk-01", "sg-02", "jp-03"],
              "warnings": ["fake-ip coerced"],
              "errors": [],
              "secret_files": ["/data/secrets/hk-01.secret"],
              "kdl": "schema-version 1\n"
            }
        """.trimIndent()
        val parsed = WorkspaceComposer.parseComposeResultJson(sampleJson)
        assertTrue(parsed.ok)
        assertEquals("hk-01", parsed.activeTag)
        assertEquals("proxy", parsed.selectorTag)
        assertEquals(listOf("hk-01", "sg-02", "jp-03"), parsed.selectorMembers)
        assertEquals(listOf("fake-ip coerced"), parsed.warnings)
        assertEquals(listOf("/data/secrets/hk-01.secret"), parsed.secretFiles)

        assertTrue(WorkspaceComposer.canHotSwitchViaSelector(running = true, targetTag = "sg-02", selectorTag = parsed.selectorTag, selectorMembers = parsed.selectorMembers))
        assertFalse(WorkspaceComposer.canHotSwitchViaSelector(running = true, targetTag = "us-99", selectorTag = parsed.selectorTag, selectorMembers = parsed.selectorMembers))
        assertFalse(WorkspaceComposer.canHotSwitchViaSelector(running = false, targetTag = "sg-02", selectorTag = parsed.selectorTag, selectorMembers = parsed.selectorMembers))

        val bad = WorkspaceComposer.parseComposeResultJson("fatal: invalid KDL")
        assertFalse(bad.ok)
        assertEquals(1, bad.errors.size)

        // Core sanitizeTag parity & unambiguous tag resolution
        assertEquals("HK-01", WorkspaceComposer.sanitizeTag("HK-01 香港高速"))
        assertEquals("direct-node", WorkspaceComposer.sanitizeTag("direct"))
        assertEquals("edge-a-b-c", WorkspaceComposer.sanitizeTag("edge.a/b+c"))
        val p1 = ProfileItem(id = "id1", remarks = "HK-01 香港")
        val p2 = ProfileItem(id = "id2", remarks = "SG-02 狮城")
        val p3 = ProfileItem(id = "id3", remarks = "HK-01 备用")
        assertEquals("HK-01", WorkspaceComposer.resolveUnambiguousTag(p1, listOf(p1, p2)))
        assertEquals("", WorkspaceComposer.resolveUnambiguousTag(p1, listOf(p1, p3)))

        // Control API mode payload uses "outbound" (Core contract) + UDS tokens preserve outbound
        val modeJson = NexusControlClient.buildSetModeHttpJson("global", "Auto")
        assertTrue(modeJson.contains("\"outbound\":\"Auto\""))
        assertFalse(modeJson.contains("proxy_group"))
        assertEquals(listOf("mode", "global", "Auto"), NexusControlClient.buildSetModeUnixTokens("global", "Auto"))
        assertEquals(listOf("mode", "rule"), NexusControlClient.buildSetModeUnixTokens("rule", ""))
    }

    @Test
    fun telemetryStoreTracksCrashSentinelAndActiveProfile() {
        val store = TelemetryStore(NexusClientDatabase.inMemory())
        assertFalse(store.hasUnreadUnexpectedCrash())
        store.setActiveProfileId("hk-01")
        store.setOutboundMode("global")
        store.recordUnexpectedCrash("exit=139")
        val loaded = store.load()
        assertEquals("hk-01", loaded.activeProfileId)
        assertEquals("global", loaded.outboundMode)
        assertTrue(loaded.unreadUnexpectedCrash)
        assertEquals("exit=139", loaded.lastCrashReason)

        store.clearUnexpectedCrash()
        assertFalse(store.hasUnreadUnexpectedCrash())
    }
}
