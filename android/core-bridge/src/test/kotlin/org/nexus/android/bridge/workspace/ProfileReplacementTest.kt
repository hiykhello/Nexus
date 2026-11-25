package org.nexus.android.bridge.workspace

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class ProfileReplacementTest {
    private fun subNode(
        id: String,
        remarks: String,
        host: String,
        port: Int = 443,
        password: String = "pw-1",
        transport: String = "tcp",
        subId: String = "sub1",
    ) = ProfileItem(
        id = id,
        remarks = remarks,
        subscriptionId = subId,
        isFromSub = true,
        kind = ProfileKind.NODE,
        node = NodeConfig(
            protocol = "vless",
            server = host,
            port = port,
            password = password,
            tls = NodeTlsConfig(sni = host),
            transport = NodeTransportConfig(type = transport, path = "/ws"),
        ),
    )

    @Test
    fun fiveTierMatchingPreservesIdsManualGroupsAndChains() {
        val manualNode = subNode("manual-1", "MyManual", "manual.example.com").copy(isFromSub = false, subscriptionId = "")
        val manualGroup = ProfileItem(
            id = "grp-manual",
            remarks = "ManualGroup",
            kind = ProfileKind.POLICY_GROUP,
            policyGroup = PolicyGroupConfig(strategy = "selector", memberIds = listOf("old-t1", "old-t2")),
        )
        val brokenChain = ProfileItem(
            id = "chain-1",
            remarks = "KeepFailClosed",
            kind = ProfileKind.PROXY_CHAIN,
            proxyChain = ProxyChainConfig(hopIds = listOf("old-t1", "old-removed")),
        )
        val workspace = WorkspaceDocument(
            profiles = listOf(
                manualNode,
                manualGroup,
                brokenChain,
                subNode("old-t1", "HK-01", "hk1.example.com"), // Tier 1 exact
                subNode("old-t2", "SG-OldName", "sg1.example.com"), // Tier 2 renamed remarks
                subNode("old-t3", "JP-01", "jp1.example.com", password = "old-secret"), // Tier 3 rotated secret
                subNode("old-t4", "US-Old", "us1.example.com", password = "old-pw", transport = "ws"), // Tier 4 unique endpoint
                subNode("old-t5", "DE-Edge", "de-old.example.com", password = "pw-x"), // Tier 5 host migrated
                subNode("old-removed", "Gone-Node", "gone.example.com"), // removed
            ),
        )

        val incoming = listOf(
            subNode("new-1", "HK-01", "hk1.example.com"),
            subNode("new-2", "SG-Renamed", "sg1.example.com"),
            subNode("new-3", "JP-01", "jp1.example.com", password = "rotated-secret"),
            subNode("new-4", "US-NewName", "us1.example.com", password = "new-pw", transport = "grpc"),
            subNode("new-5", "DE-Edge", "de-new.example.com", password = "pw-y"),
            subNode("new-6", "Brand-New", "fresh.example.com"),
        )

        val res = ProfileReplacement.replaceSubscriptionNodes(
            workspace = workspace,
            subscriptionId = "sub1",
            incomingNodes = incoming,
            activeProfileId = "old-t2",
        )

        assertFalse(res.abortedEmpty)
        assertEquals(5, res.matchedCount)
        assertEquals(1, res.addedCount)
        assertEquals("old-t2", res.activeProfileId)
        assertEquals(listOf("old-removed"), res.removedIds)

        val ids = res.workspace.profiles.map { it.id }.toSet()
        assertTrue(setOf("manual-1", "grp-manual", "chain-1", "old-t1", "old-t2", "old-t3", "old-t4", "old-t5").all { it in ids })
        // Fail-closed: chain hop list must NEVER be silently shortened; broken ref is reported explicitly
        val survivingChain = res.workspace.profiles.first { it.id == "chain-1" }
        assertEquals(listOf("old-t1", "old-removed"), survivingChain.proxyChain?.hopIds)
        assertEquals(listOf("chain-1->old-removed"), res.orphanedChainRefs)
    }

    @Test
    fun emptyIncomingAbortsFailClosedWithoutWipingExistingNodes() {
        val ws = WorkspaceDocument(profiles = listOf(subNode("n1", "HK-01", "hk.example.com")))
        val res = ProfileReplacement.replaceSubscriptionNodes(ws, "sub1", emptyList(), activeProfileId = "n1")
        assertTrue(res.abortedEmpty)
        assertEquals(1, res.workspace.profiles.size)
        assertEquals("n1", res.activeProfileId)
    }

    @Test
    fun multiPassTierOrderingPreventsEarlyWeakMatchStealingLaterExactMatch() {
        val existing = subNode("orig-hk", "HK-01", "hk1.example.com", password = "pw-1", transport = "ws")
        val ws = WorkspaceDocument(profiles = listOf(existing))
        val incoming = listOf(
            // Earlier node only matches via Tier 4 (same host/port, different remarks & password & transport)
            subNode("weak-first", "HK-Alt", "hk1.example.com", password = "pw-other", transport = "grpc"),
            // Later node is an exact Tier 1 match for orig-hk
            subNode("exact-second", "HK-01", "hk1.example.com", password = "pw-1", transport = "ws"),
        )
        val res = ProfileReplacement.replaceSubscriptionNodes(ws, "sub1", incoming, activeProfileId = "orig-hk")
        assertEquals(1, res.matchedCount)
        assertEquals(1, res.addedCount)
        val exact = res.workspace.profiles.first { it.remarks == "HK-01" }
        val alt = res.workspace.profiles.first { it.remarks == "HK-Alt" }
        assertEquals("orig-hk", exact.id)
        assertTrue(alt.id != "orig-hk")
    }

    @Test
    fun regexFilterAppliesIncludeExcludeAndIgnoresMalformedPatterns() {
        val nodes = listOf(
            subNode("1", "HK-01", "hk.example.com"),
            subNode("2", "SG-02", "sg.example.com"),
            subNode("3", "HK-Expired", "hk2.example.com"),
        )
        val filtered = ProfileReplacement.filterNodesByRegex(nodes, includeRegex = "^HK-", excludeRegex = "Expired")
        assertEquals(listOf("1"), filtered.map { it.id })

        // Invalid regex must not throw
        val safe = ProfileReplacement.filterNodesByRegex(nodes, includeRegex = "[unclosed", excludeRegex = "*bad")
        assertEquals(3, safe.size)
    }

    @Test
    fun failClosedOrphanSecretGcDeletesSecretPemAndEchOnlyWhenComposeSucceeded() {
        val dir = Files.createTempDirectory("nexus-sec-gc").toFile()
        try {
            val active = File(dir, "keep.secret").apply { writeText("a") }
            val orphanSecret = File(dir, "stale.secret").apply { writeText("b") }
            val orphanPem = File(dir, "stale-ca.pem").apply { writeText("c") }
            val orphanEch = File(dir, "stale.ech").apply { writeText("d") }
            val nonSecret = File(dir, "readme.txt").apply { writeText("e") }

            // composeOk = false -> fail-closed: delete nothing
            val skipped = ProfileReplacement.gcOrphanSecretFiles(dir, listOf(active.absolutePath), composeOk = false)
            assertTrue(skipped.isEmpty())
            assertTrue(orphanSecret.isFile && orphanPem.isFile && orphanEch.isFile)

            // composeOk = true -> delete unreferenced .secret, .pem, and .ech
            val deleted = ProfileReplacement.gcOrphanSecretFiles(dir, listOf(active.absolutePath), composeOk = true)
            assertEquals(setOf(orphanSecret, orphanPem, orphanEch), deleted.toSet())
            assertTrue(active.isFile)
            assertFalse(orphanSecret.exists() || orphanPem.exists() || orphanEch.exists())
            assertTrue(nonSecret.isFile)
        } finally {
            dir.deleteRecursively()
        }
    }
}
