package org.nexus.android.bridge.workspace

import org.nexus.android.bridge.model.ParsedOutbound

enum class ProfileKind(val wire: String) {
    NODE("node"),
    CUSTOM_OUTBOUND("custom_outbound"),
    POLICY_GROUP("policy_group"),
    PROXY_CHAIN("proxy_chain"),
    FULL_CUSTOM_KDL("full_custom_kdl");

    companion object {
        fun fromWire(raw: String?): ProfileKind =
            entries.firstOrNull { it.wire == raw?.trim()?.lowercase() } ?: NODE
    }
}

data class NodeTlsConfig(
    val enabled: Boolean = true,
    val sni: String = "",
    val fingerprint: String = "",
    val keyExchange: String = "",
    val caPem: String = "",
    val certSha256: List<String> = emptyList(),
    val realityPublicKey: String = "",
    val realityShortId: String = "",
    val echMode: String = "",
    val echConfig: String = "",
)

data class NodeTransportConfig(
    val type: String = "",
    val host: String = "",
    val path: String = "",
    val serviceName: String = "",
    val authority: String = "",
    val xhttpMode: String = "",
    val xhttpProtocol: String = "",
    val headers: Map<String, String> = emptyMap(),
) {
    companion object {
        fun normalizeType(raw: String?): String {
            val lower = raw?.trim()?.lowercase().orEmpty()
            return if (lower == "tcp" || lower == "raw") "" else lower
        }
    }
}

data class NodeMultiplexConfig(
    val enabled: Boolean = false,
    val protocol: String = "",
    val maxConnections: Int = 0,
    val padding: Boolean = false,
)

data class NodeExtraConfig(
    val hy2Ports: String = "",
    val hy2HopIntervalMs: Int = 0,
    val hy2UpMbps: Int = 0,
    val hy2DownMbps: Int = 0,
    val hy2SalamanderPassword: String = "",
    val tuicCongestionControl: String = "",
    val tuicUdpOverStream: Boolean = false,
    val wgPeerPublicKey: String = "",
    val wgPresharedKey: String = "",
    val wgLocalAddresses: List<String> = emptyList(),
    val wgReserved: String = "",
    val wgMtu: Int = 0,
    val masqueMode: String = "",
    val masquePath: String = "",
    val masqueLocalAddresses: List<String> = emptyList(),
    val naiveProtocol: String = "",
    val snellVersion: Int = 0,
    val snellObfs: String = "",
    val snellObfsHost: String = "",
    val sshHostKeySha256: List<String> = emptyList(),
)

data class NodeConfig(
    val protocol: String = "vless",
    val server: String = "",
    val port: Int = 443,
    val username: String = "",
    val password: String = "",
    val method: String = "",
    val flow: String = "",
    val packetEncoding: String = "",
    val tls: NodeTlsConfig = NodeTlsConfig(),
    val transport: NodeTransportConfig = NodeTransportConfig(),
    val multiplex: NodeMultiplexConfig = NodeMultiplexConfig(),
    val extra: NodeExtraConfig = NodeExtraConfig(),
)

data class PolicyGroupConfig(
    val strategy: String = "selector",
    val memberIds: List<String> = emptyList(),
    val dynamicSubId: String = "",
    val includeRegex: String = "",
    val excludeRegex: String = "",
    val probeUrl: String = "https://www.gstatic.com/generate_204",
    val probeIntervalMs: Long = 300_000L,
    val toleranceMs: Int = 50,
)

data class ProxyChainConfig(
    val hopIds: List<String> = emptyList(),
)

data class ProfileItem(
    val id: String,
    val remarks: String = "",
    val subscriptionId: String = "",
    val isFromSub: Boolean = false,
    val kind: ProfileKind = ProfileKind.NODE,
    val node: NodeConfig? = null,
    val customOutboundKdl: String = "",
    val policyGroup: PolicyGroupConfig? = null,
    val proxyChain: ProxyChainConfig? = null,
    val fullCustomKdl: String = "",
)

data class SubscriptionUsage(
    val uploadBytes: Long = -1L,
    val downloadBytes: Long = -1L,
    val totalBytes: Long = -1L,
    val expireUnixSec: Long = -1L,
    val profileTitle: String = "",
    val webPageUrl: String = "",
    val supportUrl: String = "",
) {
    val hasQuota: Boolean get() = totalBytes > 0L
    val usedBytes: Long get() = (uploadBytes.coerceAtLeast(0L) + downloadBytes.coerceAtLeast(0L))
}

data class SubscriptionItem(
    val id: String,
    val remarks: String = "",
    val url: String = "",
    val moreUrls: List<String> = emptyList(),
    val enabled: Boolean = true,
    val autoUpdateMinutes: Int = 0,
    val userAgent: String = "",
    val requestHeaders: Map<String, String> = emptyMap(),
    val includeRegex: String = "",
    val excludeRegex: String = "",
    val prevProfileId: String = "",
    val nextProfileId: String = "",
    val updatedAtMs: Long = 0L,
    val usage: SubscriptionUsage = SubscriptionUsage(),
)

data class RoutingRuleItem(
    val id: String,
    val enabled: Boolean = true,
    val locked: Boolean = false,
    val scope: String = "both",
    val targetType: String = "proxy",
    val targetProfileId: String = "",
    val domains: List<String> = emptyList(),
    val ips: List<String> = emptyList(),
    val ruleSets: List<String> = emptyList(),
    val ports: List<String> = emptyList(),
    val networks: List<String> = emptyList(),
    val protocols: List<String> = emptyList(),
    val desktopProcess: List<String> = emptyList(),
    val androidPackages: List<String> = emptyList(),
    val tlsFragment: Boolean = false,
)

data class RoutingProfileItem(
    val id: String,
    val name: String,
    val isActive: Boolean = false,
    val domainStrategy: String = "as-is",
    val defaultOutbound: String = "proxy",
    val rules: List<RoutingRuleItem> = emptyList(),
)

data class SimpleDnsConfig(
    val bootstrapDns: String = "223.5.5.5",
    val directDns: List<String> = listOf("local", "223.5.5.5"),
    val remoteDns: List<String> = listOf("https://1.1.1.1/dns-query"),
    val parallelQuery: Boolean = false,
    val directExpectedRuleSets: List<String> = emptyList(),
    val fakeIpEnabled: Boolean = false,
    val fakeIpV4Pool: String = "198.18.0.0/16",
    val fakeIpV6Pool: String = "fc00::/18",
    val fakeIpGlobal: Boolean = false,
    val blockAaaa: Boolean = false,
    val blockSvcbHttps: Boolean = false,
    val serveStaleSeconds: Int = 0,
    val useSystemHosts: Boolean = true,
    val hosts: Map<String, String> = emptyMap(),
    val strategy: String = "prefer_ipv4",
)

data class DnsConfig(
    val mode: String = "simple",
    val simple: SimpleDnsConfig = SimpleDnsConfig(),
    val rawKdl: String = "",
)

data class RuleSetAsset(
    val tag: String,
    val sourceType: String = "local",
    val format: String = "nxmm",
    val path: String = "",
    val url: String = "",
    val sha256: String = "",
    val updateIntervalMs: Long = 0L,
)

data class FullTemplateConfig(
    val enabled: Boolean = false,
    val templateKdl: String = "",
    val appendProxiesOnly: Boolean = false,
    val proxyDetour: String = "",
)

data class WorkspaceDocument(
    val schemaVersion: Int = SCHEMA_VERSION,
    val revision: Long = 1L,
    val updatedAtMs: Long = 0L,
    val profiles: List<ProfileItem> = emptyList(),
    val subscriptions: List<SubscriptionItem> = emptyList(),
    val routingProfiles: List<RoutingProfileItem> = WorkspaceDefaults.defaultRoutingProfiles(),
    val dns: DnsConfig = DnsConfig(),
    val ruleSetAssets: List<RuleSetAsset> = emptyList(),
    val fullTemplate: FullTemplateConfig = FullTemplateConfig(),
) {
    fun activeRoutingProfile(): RoutingProfileItem =
        routingProfiles.firstOrNull { it.isActive }
            ?: routingProfiles.firstOrNull()
            ?: WorkspaceDefaults.defaultRoutingProfiles().first()

    companion object {
        const val SCHEMA_VERSION = 1
    }
}

object WorkspaceDefaults {
    fun defaultRoutingProfiles(): List<RoutingProfileItem> = listOf(
        RoutingProfileItem(
            id = "bypass-lan-cn",
            name = "绕过局域网与直连",
            isActive = true,
            domainStrategy = "as-is",
            defaultOutbound = "proxy",
            rules = listOf(
                RoutingRuleItem(
                    id = "private-lan",
                    enabled = true,
                    locked = true,
                    scope = "both",
                    targetType = "direct",
                    ips = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"),
                ),
            ),
        ),
        RoutingProfileItem(
            id = "global",
            name = "全局代理",
            isActive = false,
            domainStrategy = "as-is",
            defaultOutbound = "proxy",
            rules = emptyList(),
        ),
        RoutingProfileItem(
            id = "direct",
            name = "全局直连",
            isActive = false,
            domainStrategy = "as-is",
            defaultOutbound = "direct",
            rules = emptyList(),
        ),
    )

    fun fromParsedOutbound(
        id: String,
        parsed: ParsedOutbound,
        subscriptionId: String = "",
        isFromSub: Boolean = false,
    ): ProfileItem = ProfileItem(
        id = id,
        remarks = parsed.tag,
        subscriptionId = subscriptionId,
        isFromSub = isFromSub,
        kind = ProfileKind.NODE,
        node = NodeConfig(
            protocol = parsed.scheme.kdlType,
            server = parsed.host,
            port = parsed.port,
            username = parsed.username,
            password = parsed.secret,
            method = parsed.method,
            flow = parsed.flow,
            tls = NodeTlsConfig(
                enabled = parsed.sni.isNotEmpty() || parsed.realityPublicKey.isNotEmpty() ||
                    parsed.scheme.kdlType in setOf("vless", "trojan", "anytls", "hysteria2", "tuic", "naive", "http-connect"),
                sni = parsed.sni,
                fingerprint = parsed.fingerprint,
                certSha256 = listOfNotNull(parsed.certificateSha256.takeIf { it.isNotEmpty() }),
                realityPublicKey = parsed.realityPublicKey,
                realityShortId = parsed.realityShortId,
            ),
            transport = NodeTransportConfig(
                type = NodeTransportConfig.normalizeType(parsed.transport),
                host = parsed.hostHeader,
                path = parsed.path,
                serviceName = if (parsed.transport == "grpc") parsed.path else "",
                authority = if (parsed.transport == "grpc") parsed.hostHeader else "",
                xhttpMode = parsed.xhttpMode,
            ),
            extra = NodeExtraConfig(
                tuicCongestionControl = parsed.congestionControl,
                tuicUdpOverStream = parsed.udpRelayMode.equals("quic", ignoreCase = true),
                naiveProtocol = parsed.protocolName,
                snellVersion = parsed.snellVersion,
                snellObfs = parsed.obfs,
                snellObfsHost = parsed.obfsHost,
                sshHostKeySha256 = if (parsed.scheme.kdlType == "ssh" && parsed.certificateSha256.isNotEmpty()) {
                    listOf(parsed.certificateSha256)
                } else {
                    emptyList()
                },
            ),
        ),
    )
}
