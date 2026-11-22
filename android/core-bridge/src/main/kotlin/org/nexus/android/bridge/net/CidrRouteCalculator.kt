package org.nexus.android.bridge.net

import java.math.BigInteger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

data class CidrPrefix(
    val address: InetAddress,
    val prefixLength: Int,
) {
    val isIpv6: Boolean get() = address is Inet6Address
    val bitWidth: Int get() = if (isIpv6) 128 else 32

    fun normalized(): CidrPrefix {
        val raw = toUnsignedBigInt(address.address)
        val hostBits = bitWidth - prefixLength
        val masked = if (hostBits == bitWidth) BigInteger.ZERO else raw.shiftRight(hostBits).shiftLeft(hostBits)
        return CidrPrefix(fromUnsignedBigInt(masked, bitWidth / 8), prefixLength)
    }

    override fun toString(): String = "${address.hostAddress}/$prefixLength"

    companion object {
        fun parse(cidr: String): CidrPrefix {
            val parts = cidr.trim().split('/')
            require(parts.size == 2) { "Invalid CIDR: $cidr" }
            val addr = InetAddress.getByName(parts[0])
            val len = parts[1].toInt()
            val max = if (addr is Inet6Address) 128 else 32
            require(len in 0..max) { "Prefix length out of range ($len) for $cidr" }
            return CidrPrefix(addr, len).normalized()
        }

        internal fun toUnsignedBigInt(bytes: ByteArray): BigInteger = BigInteger(1, bytes)

        internal fun fromUnsignedBigInt(value: BigInteger, byteLen: Int): InetAddress {
            val raw = value.toByteArray()
            val out = ByteArray(byteLen)
            val srcPos = maxOf(0, raw.size - byteLen)
            val copyLen = minOf(raw.size, byteLen)
            System.arraycopy(raw, srcPos, out, byteLen - copyLen, copyLen)
            return InetAddress.getByAddress(out)
        }
    }
}

/**
 * Pure-Kotlin IPv4/IPv6 CIDR subtraction engine.
 * Used on Android API <= 32 where VpnService.Builder.excludeRoute(IpPrefix) is unavailable,
 * computing minimal non-overlapping auto-route CIDR ranges.
 */
object CidrRouteCalculator {
    val PRIVATE_IPV4_CIDRS: List<CidrPrefix> = listOf(
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
    ).map(CidrPrefix::parse)

    val PRIVATE_IPV6_CIDRS: List<CidrPrefix> = listOf(
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ).map(CidrPrefix::parse)

    private data class Range(val start: BigInteger, val end: BigInteger)

    fun computeAllowedRoutes(
        ipv6: Boolean,
        excludePrivate: Boolean,
        extraExcludes: List<CidrPrefix>,
        mustIncludeAddresses: List<InetAddress> = emptyList(),
    ): List<CidrPrefix> {
        val bits = if (ipv6) 128 else 32
        val maxVal = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE)

        val excludes = buildList {
            if (excludePrivate) addAll(if (ipv6) PRIVATE_IPV6_CIDRS else PRIVATE_IPV4_CIDRS)
            addAll(extraExcludes.filter { it.isIpv6 == ipv6 })
        }.map { toRange(it) }

        var remaining = subtractRanges(listOf(Range(BigInteger.ZERO, maxVal)), excludes)

        // Ensure sentinel TUN DNS addresses are always routed into the TUN even if inside a private block.
        val pinned = mustIncludeAddresses
            .filter { (it is Inet6Address) == ipv6 }
            .map { CidrPrefix(it, bits) }
            .map { toRange(it) }
        if (pinned.isNotEmpty()) {
            remaining = mergeRanges(remaining + pinned)
        }

        return remaining.flatMap { rangeToCidrs(it.start, it.end, bits) }
    }

    private fun toRange(prefix: CidrPrefix): Range {
        val norm = prefix.normalized()
        val start = CidrPrefix.toUnsignedBigInt(norm.address.address)
        val hostBits = norm.bitWidth - norm.prefixLength
        val size = BigInteger.ONE.shiftLeft(hostBits)
        return Range(start, start.add(size).subtract(BigInteger.ONE))
    }

    private fun mergeRanges(ranges: List<Range>): List<Range> {
        if (ranges.isEmpty()) return emptyList()
        val sorted = ranges.sortedBy { it.start }
        val merged = mutableListOf(sorted.first())
        for (i in 1 until sorted.size) {
            val cur = sorted[i]
            val last = merged.last()
            if (cur.start <= last.end.add(BigInteger.ONE)) {
                merged[merged.lastIndex] = Range(last.start, maxOf(last.end, cur.end))
            } else {
                merged.add(cur)
            }
        }
        return merged
    }

    private fun subtractRanges(base: List<Range>, excludes: List<Range>): List<Range> {
        val mergedExcludes = mergeRanges(excludes)
        var current = base
        for (ex in mergedExcludes) {
            val next = mutableListOf<Range>()
            for (r in current) {
                if (ex.end < r.start || ex.start > r.end) {
                    next.add(r)
                } else {
                    if (ex.start > r.start) {
                        next.add(Range(r.start, ex.start.subtract(BigInteger.ONE)))
                    }
                    if (ex.end < r.end) {
                        next.add(Range(ex.end.add(BigInteger.ONE), r.end))
                    }
                }
            }
            current = next
        }
        return current
    }

    private fun rangeToCidrs(start: BigInteger, end: BigInteger, bits: Int): List<CidrPrefix> {
        val out = mutableListOf<CidrPrefix>()
        var cur = start
        val byteLen = bits / 8
        while (cur <= end) {
            val remaining = end.subtract(cur).add(BigInteger.ONE)
            val maxSizeBits = remaining.bitLength() - 1
            val trailingZeros = if (cur == BigInteger.ZERO) bits else cur.lowestSetBit
            val blockBits = minOf(maxSizeBits, trailingZeros)
            val prefixLen = bits - blockBits
            val addr = CidrPrefix.fromUnsignedBigInt(cur, byteLen)
            require(if (bits == 128) addr is Inet6Address else addr is Inet4Address)
            out.add(CidrPrefix(addr, prefixLen))
            cur = cur.add(BigInteger.ONE.shiftLeft(blockBits))
        }
        return out
    }
}
