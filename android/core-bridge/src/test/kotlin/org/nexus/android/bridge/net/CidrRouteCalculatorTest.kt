package org.nexus.android.bridge.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.net.InetAddress

class CidrRouteCalculatorTest {
    @Test
    fun noExcludesReturnsFullIpv4AndIpv6() {
        val v4 = CidrRouteCalculator.computeAllowedRoutes(
            ipv6 = false,
            excludePrivate = false,
            extraExcludes = emptyList(),
        )
        assertEquals(listOf("0.0.0.0/0"), v4.map(CidrPrefix::toString))

        val v6 = CidrRouteCalculator.computeAllowedRoutes(
            ipv6 = true,
            excludePrivate = false,
            extraExcludes = emptyList(),
        )
        assertEquals(listOf("0:0:0:0:0:0:0:0/0"), v6.map(CidrPrefix::toString))
    }

    @Test
    fun privateExcludeRemovesRfc1918AndKeepsSentinelDns() {
        val sentinel = InetAddress.getByName("172.19.0.2")
        val routes = CidrRouteCalculator.computeAllowedRoutes(
            ipv6 = false,
            excludePrivate = true,
            extraExcludes = emptyList(),
            mustIncludeAddresses = listOf(sentinel),
        )
        assertTrue(containsIp(routes, "1.1.1.1"))
        assertTrue(containsIp(routes, "8.8.8.8"))
        assertTrue(containsIp(routes, "172.19.0.2")) // sentinel DNS pinned inside 172.16.0.0/12
        assertFalse(containsIp(routes, "192.168.1.1"))
        assertFalse(containsIp(routes, "10.0.0.1"))
        assertFalse(containsIp(routes, "172.19.0.3"))
        assertFalse(containsIp(routes, "127.0.0.1"))
    }

    @Test
    fun ipv6PrivateExcludeRemovesUlaAndLinkLocal() {
        val sentinel = InetAddress.getByName("fdfe:dcba:9876::2")
        val routes = CidrRouteCalculator.computeAllowedRoutes(
            ipv6 = true,
            excludePrivate = true,
            extraExcludes = emptyList(),
            mustIncludeAddresses = listOf(sentinel),
        )
        assertTrue(containsIp(routes, "2606:4700:4700::1111"))
        assertTrue(containsIp(routes, "fdfe:dcba:9876::2"))
        assertFalse(containsIp(routes, "fe80::1"))
        assertFalse(containsIp(routes, "::1"))
        assertFalse(containsIp(routes, "fd00::1"))
    }

    private fun containsIp(cidrs: List<CidrPrefix>, ipText: String): Boolean {
        val ip = CidrPrefix.toUnsignedBigInt(InetAddress.getByName(ipText).address)
        return cidrs.any { cidr ->
            val start = CidrPrefix.toUnsignedBigInt(cidr.address.address)
            val size = BigInteger.ONE.shiftLeft(cidr.bitWidth - cidr.prefixLength)
            ip >= start && ip < start.add(size)
        }
    }
}
