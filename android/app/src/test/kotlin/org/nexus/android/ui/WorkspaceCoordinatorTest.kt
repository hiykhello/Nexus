package org.nexus.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.WorkspaceDefaults
import org.nexus.android.bridge.workspace.WorkspaceDocument
import java.net.URL

class WorkspaceCoordinatorTest {
    @Test
    fun buildRuleFromConnectionHandlesDirectDomainIpv4AndBracketedIpv6() {
        val directDomain = WorkspaceCoordinator.buildRuleFromConnection(
            targetHost = "api.github.com:443",
            action = "route",
            outbound = "direct",
        )
        assertEquals("direct", directDomain.targetType)
        assertEquals("both", directDomain.scope)
        assertEquals(listOf("domain:api.github.com"), directDomain.domains)
        assertTrue(directDomain.ips.isEmpty())

        val rejectIpv4 = WorkspaceCoordinator.buildRuleFromConnection(
            targetHost = "1.1.1.1:443",
            action = "reject",
            outbound = "",
        )
        assertEquals("block", rejectIpv4.targetType)
        assertEquals("routing_only", rejectIpv4.scope)
        assertEquals(listOf("1.1.1.1/32"), rejectIpv4.ips)
        assertTrue(rejectIpv4.domains.isEmpty())

        val proxyIpv6 = WorkspaceCoordinator.buildRuleFromConnection(
            targetHost = "[2001:db8::1]:443",
            action = "route",
            outbound = "proxy",
        )
        assertEquals("proxy", proxyIpv6.targetType)
        assertEquals("routing_only", proxyIpv6.scope)
        assertEquals(listOf("2001:db8::1/128"), proxyIpv6.ips)
        assertTrue(proxyIpv6.domains.isEmpty())
    }

    @Test
    fun originKeyAndHeaderSanitizerPreventCrossOriginAndCrlfLeaks() {
        val orig = WorkspaceCoordinator.urlOriginKey(URL("https://sub.example.com/a"))
        val same = WorkspaceCoordinator.urlOriginKey(URL("https://sub.example.com:443/b"))
        val cross = WorkspaceCoordinator.urlOriginKey(URL("https://cdn.other.example/b"))
        assertEquals(orig, same)
        assertFalse(orig == cross)

        val cleaned = WorkspaceCoordinator.sanitizeRequestHeaders(
            mapOf(
                "Host" to "evil.example",
                "X-Auth\r\nInjected" to "secret\r\nX-Bad: 1",
                "Accept" to "text/plain",
            ),
        )
        assertFalse(cleaned.keys.any { it.equals("host", ignoreCase = true) })
        assertEquals("text/plain", cleaned["Accept"])
        assertFalse(cleaned.values.any { it.contains('\r') || it.contains('\n') })
    }

    @Test
    fun defaultDirectSeedAllowsWorkspaceLaunchWhileShowingOnboardingUntilRemoteNodeAdded() {
        val seed = WorkspaceDefaults.defaultDirectProfile()
        assertEquals(WorkspaceDefaults.DEFAULT_DIRECT_PROFILE_ID, seed.id)
        assertEquals(ProfileKind.CUSTOM_OUTBOUND, seed.kind)

        val seededState = WorkspaceUiState(
            document = WorkspaceDocument(profiles = listOf(seed)),
            activeProfileId = seed.id,
        )
        assertEquals("默认直连", seededState.activeProfileTitle)
        assertFalse(seededState.hasAnyRemoteProfile)

        val remote = ProfileItem(
            id = "hk-1",
            remarks = "HK-01",
            kind = ProfileKind.NODE,
            node = NodeConfig(protocol = "vless", server = "hk.example.com", port = 443),
        )
        val withRemote = seededState.copy(
            document = WorkspaceDocument(profiles = listOf(seed, remote)),
            activeProfileId = remote.id,
        )
        assertEquals("HK-01", withRemote.activeProfileTitle)
        assertTrue(withRemote.hasAnyRemoteProfile)
    }
}
