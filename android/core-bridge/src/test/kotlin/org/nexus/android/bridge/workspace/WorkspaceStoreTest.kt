package org.nexus.android.bridge.workspace

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.model.ShareLinkParser
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

class WorkspaceStoreTest {
    @Test
    fun fullWorkspaceJsonRoundTripCoversAllFiveProfileKindsAndPortableBoundary() {
        val doc = WorkspaceDocument(
            schemaVersion = 1,
            revision = 7L,
            updatedAtMs = 1_700_000_000_000L,
            profiles = listOf(
                ProfileItem(
                    id = "n1",
                    remarks = "HK-Edge",
                    subscriptionId = "sub1",
                    isFromSub = true,
                    kind = ProfileKind.NODE,
                    node = NodeConfig(
                        protocol = "vless",
                        server = "hk.example.com",
                        port = 443,
                        password = "uuid-secret-value",
                        flow = "xtls-rprx-vision",
                        tls = NodeTlsConfig(
                            enabled = true,
                            sni = "cdn.example.com",
                            fingerprint = "chrome",
                            certSha256 = listOf("ab:cd:ef"),
                            realityPublicKey = "pubKey123",
                            realityShortId = "0102",
                            echMode = "auto",
                        ),
                        transport = NodeTransportConfig(
                            type = "xhttp",
                            host = "cdn.example.com",
                            path = "/stream",
                            xhttpMode = "auto",
                            xhttpProtocol = "h2",
                            headers = mapOf("X-Test" to "1"),
                        ),
                        multiplex = NodeMultiplexConfig(enabled = true, protocol = "smux", maxConnections = 4, padding = true),
                        extra = NodeExtraConfig(hy2Ports = "20000-20100", hy2UpMbps = 100, tuicUdpOverStream = true),
                    ),
                ),
                ProfileItem(
                    id = "c1",
                    remarks = "Custom-Out",
                    kind = ProfileKind.CUSTOM_OUTBOUND,
                    customOutboundKdl = """outbound "{{tag}}" type="direct"""",
                ),
                ProfileItem(
                    id = "g1",
                    remarks = "Auto-Group",
                    kind = ProfileKind.POLICY_GROUP,
                    policyGroup = PolicyGroupConfig(strategy = "url-test", memberIds = listOf("n1"), toleranceMs = 45),
                ),
                ProfileItem(
                    id = "ch1",
                    remarks = "Two-Hop",
                    kind = ProfileKind.PROXY_CHAIN,
                    proxyChain = ProxyChainConfig(hopIds = listOf("n1", "c1")),
                ),
                ProfileItem(
                    id = "fk1",
                    remarks = "Legacy-Full",
                    kind = ProfileKind.FULL_CUSTOM_KDL,
                    fullCustomKdl = "schema-version 1\nrole \"client\"\n",
                ),
            ),
            subscriptions = listOf(
                SubscriptionItem(
                    id = "sub1",
                    remarks = "MainSub",
                    url = "https://sub.example.com/feed",
                    moreUrls = listOf("https://backup.example.com/feed"),
                    autoUpdateMinutes = 60,
                    prevProfileId = "c1",
                    nextProfileId = "g1",
                    usage = SubscriptionUsage(
                        uploadBytes = 1024L,
                        downloadBytes = 4096L,
                        totalBytes = 100_000L,
                        expireUnixSec = 1_900_000_000L,
                        profileTitle = "Main Edge",
                        webPageUrl = "https://sub.example.com",
                        supportUrl = "tg://resolve?domain=nexus",
                    ),
                ),
            ),
            routingProfiles = listOf(
                RoutingProfileItem(
                    id = "rp1",
                    name = "Split",
                    isActive = true,
                    domainStrategy = "ip-if-non-match",
                    defaultOutbound = "proxy",
                    rules = listOf(
                        RoutingRuleItem(
                            id = "r1",
                            scope = "both",
                            targetType = "profile_id",
                            targetProfileId = "ch1",
                            domains = listOf("domain:openai.com"),
                            desktopProcess = listOf("curl"),
                            androidPackages = listOf("com.android.chrome"),
                            tlsFragment = true,
                        ),
                    ),
                ),
            ),
            dns = DnsConfig(
                mode = "simple",
                simple = SimpleDnsConfig(
                    fakeIpEnabled = true,
                    fakeIpV4Pool = "198.18.0.0/16",
                    fakeIpV6Pool = "fc00::/18",
                    strategy = "prefer_ipv4",
                    hosts = mapOf("router.lan" to "192.168.1.1"),
                ),
                rawKdl = "",
            ),
            ruleSetAssets = listOf(RuleSetAsset(tag = "cn", sourceType = "local", format = "nxmm", path = "cn.nxmm")),
            fullTemplate = FullTemplateConfig(enabled = false, templateKdl = "", appendProxiesOnly = true, proxyDetour = "proxy"),
        )

        val encoded = WorkspaceJsonCodec.encode(doc)
        // Strict Layer 1 portability: zero host/per-app/telemetry/allowInsecure fields
        assertFalse(encoded.contains("per_app_mode"))
        assertFalse(encoded.contains("mixed_listen"))
        assertFalse(encoded.contains("allowInsecure"))
        assertFalse(encoded.contains("unread_unexpected_crash"))
        assertTrue(encoded.contains("\"strategy\": \"prefer_ipv4\""))
        assertTrue(encoded.contains("\"fake_ip_v4_pool\": \"198.18.0.0/16\""))
        assertTrue(encoded.contains("\"fake_ip_v6_pool\": \"fc00::/18\""))
        assertTrue(encoded.contains("\"router.lan\": \"192.168.1.1\""))

        val decoded = WorkspaceJsonCodec.decode(encoded)
        assertEquals(doc, decoded)
    }

    @Test
    fun vlessRealityVisionTransportNormalizesTcpToEmptyAndLegacyArrayHostsDecodes() {
        val uri = "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=abc123&sid=0102&flow=xtls-rprx-vision#VLESS-Reality"
        val parsed = ShareLinkParser.parse(uri).getOrThrow()
        val item = WorkspaceDefaults.fromParsedOutbound("n-reality", parsed)
        assertEquals("", item.node?.transport?.type)
        assertEquals("xtls-rprx-vision", item.node?.flow)
        assertEquals("abc123", item.node?.tls?.realityPublicKey)

        // Legacy workspace JSON with "type": "tcp" and array hosts normalizes cleanly
        val legacyJson = """
            {
              "schema_version": 1,
              "profiles": [{
                "id": "p1",
                "kind": "node",
                "node": {
                  "protocol": "vless",
                  "server": "edge.example.com",
                  "port": 443,
                  "transport": { "type": "tcp" }
                }
              }],
              "dns": {
                "mode": "simple",
                "simple": { "hosts": { "nas.lan": ["192.168.1.50"] } }
              }
            }
        """.trimIndent()
        val decoded = WorkspaceJsonCodec.decode(legacyJson)
        assertEquals("", decoded.profiles.first().node?.transport?.type)
        assertEquals("192.168.1.50", decoded.dns.simple.hosts["nas.lan"])
    }

    @Test
    fun storeWrites0600AndMigratesLegacyProfilesOnce() {
        val dir = Files.createTempDirectory("nexus-ws-test").toFile()
        try {
            val legacyDir = File(dir, "profiles").apply { mkdirs() }
            File(legacyDir, "Tokyo-Core.kdl").writeText("schema-version 1\nrole \"client\"\n", Charsets.UTF_8)
            File(legacyDir, "HK-Gaming.kdl").writeText("schema-version 1\nrole \"client\"\n", Charsets.UTF_8)

            val store = WorkspaceStore(dir)
            val first = store.migrateLegacyProfilesIfNeeded(dir)
            assertFalse(first.skippedAlreadyMigrated)
            assertEquals(2, first.migratedProfileIds.size)

            val loaded = store.loadOrInit()
            assertEquals(2, loaded.profiles.size)
            assertTrue(loaded.profiles.all { it.kind == ProfileKind.FULL_CUSTOM_KDL })

            val perms = Files.getPosixFilePermissions(store.workspaceFile.toPath())
            assertEquals(PosixFilePermissions.fromString("rw-------"), perms)

            // Second run must be an idempotent no-op
            val second = store.migrateLegacyProfilesIfNeeded(dir)
            assertTrue(second.skippedAlreadyMigrated)
            assertEquals(2, store.loadOrInit().profiles.size)
        } finally {
            dir.deleteRecursively()
        }
    }
}
