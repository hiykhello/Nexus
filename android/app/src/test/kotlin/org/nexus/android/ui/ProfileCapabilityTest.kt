package org.nexus.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind

class ProfileCapabilityTest {

    @Test
    fun allThirteenNexusProtocolsRegisteredAndBadged() {
        assertEquals(13, ALL_NEXUS_PROTOCOLS.size)
        val keys = ALL_NEXUS_PROTOCOLS.map { it.first }.toSet()
        assertTrue(keys.containsAll(setOf("vless", "trojan", "hysteria2", "tuic", "wireguard", "masque", "shadowsocks", "anytls", "naive", "snell", "ssh", "socks5", "http-connect")))

        val wg = ProfileItem("wg-1", "Tokyo WG", kind = ProfileKind.NODE, node = NodeConfig(protocol = "wireguard", server = "jp.example.com", port = 51820))
        val hy2 = ProfileItem("hy2-1", "SG HY2", kind = ProfileKind.NODE, node = NodeConfig(protocol = "hysteria2", server = "sg.example.com", port = 443))
        assertEquals("WG", shortProtocolBadge(wg))
        assertEquals("HY2", shortProtocolBadge(hy2))
    }

    @Test
    fun subscriptionFilterAndSortWorkAcrossManualAndSubGroups() {
        val items = listOf(
            ProfileItem("p1", "Beta VLESS", subscriptionId = "sub-a", kind = ProfileKind.NODE, node = NodeConfig(protocol = "vless", server = "b.example.com", port = 443)),
            ProfileItem("p2", "Alpha WireGuard", subscriptionId = "", kind = ProfileKind.NODE, node = NodeConfig(protocol = "wireguard", server = "a.example.com", port = 51820)),
            ProfileItem("p3", "Gamma Trojan", subscriptionId = "sub-a", kind = ProfileKind.NODE, node = NodeConfig(protocol = "trojan", server = "c.example.com", port = 443)),
        )
        val known = setOf("sub-a")
        assertEquals(3, filterAndSortProfiles(items, "all", known, "", "default").size)
        assertEquals(listOf("p2"), filterAndSortProfiles(items, "manual", known, "", "default").map { it.id })
        assertEquals(listOf("p1", "p3"), filterAndSortProfiles(items, "sub-a", known, "", "default").map { it.id })
        assertEquals(listOf("p2", "p1", "p3"), filterAndSortProfiles(items, "all", known, "", "name").map { it.id })
        assertEquals(listOf("p2"), filterAndSortProfiles(items, "all", known, "51820", "default").map { it.id })
    }

    @Test
    fun hostsPairsRoundTripCleanly() {
        val raw = "router.local=192.168.1.1, nas.lan = 10.0.0.2, invalid"
        val parsed = parseHostsPairs(raw)
        assertEquals(mapOf("router.local" to "192.168.1.1", "nas.lan" to "10.0.0.2"), parsed)
        assertEquals(parsed, parseHostsPairs(formatHostsPairs(parsed)))
    }
}
