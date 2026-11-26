package org.nexus.android.bridge.workspace

import org.json.JSONArray
import org.json.JSONObject

/**
 * Canonical v1 JSON codec for Layer 1 portable `workspace.json`.
 * Strictly emits ONLY portable Layer 1 keys (zero host ports, zero per-app OS keys, zero telemetry).
 */
object WorkspaceJsonCodec {
    fun encode(doc: WorkspaceDocument, indentSpaces: Int = 2): String {
        val root = JSONObject()
        root.put("schema_version", WorkspaceDocument.SCHEMA_VERSION)
        root.put("revision", doc.revision)
        root.put("updated_at_ms", doc.updatedAtMs)
        root.put("profiles", JSONArray().apply { doc.profiles.forEach { put(encodeProfile(it)) } })
        root.put("subscriptions", JSONArray().apply { doc.subscriptions.forEach { put(encodeSubscription(it)) } })
        root.put("routing_profiles", JSONArray().apply { doc.routingProfiles.forEach { put(encodeRoutingProfile(it)) } })
        root.put("dns", encodeDns(doc.dns))
        root.put("rule_set_assets", JSONArray().apply { doc.ruleSetAssets.forEach { put(encodeRuleSetAsset(it)) } })
        root.put("full_template", encodeFullTemplate(doc.fullTemplate))
        return if (indentSpaces > 0) root.toString(indentSpaces) + "\n" else root.toString()
    }

    fun decode(rawJson: String): WorkspaceDocument {
        val root = JSONObject(rawJson)
        val version = root.optInt("schema_version", WorkspaceDocument.SCHEMA_VERSION)
        require(version == WorkspaceDocument.SCHEMA_VERSION) {
            "Unsupported workspace schema_version: $version"
        }
        val profiles = decodeArray(root.optJSONArray("profiles")) { decodeProfile(it) }
        val subscriptions = decodeArray(root.optJSONArray("subscriptions")) { decodeSubscription(it) }
        val parsedRoutings = decodeArray(root.optJSONArray("routing_profiles")) { decodeRoutingProfile(it) }
        val routings = parsedRoutings.ifEmpty { WorkspaceDefaults.defaultRoutingProfiles() }
        val dns = root.optJSONObject("dns")?.let { decodeDns(it) } ?: DnsConfig()
        val ruleSetAssets = decodeArray(root.optJSONArray("rule_set_assets")) { decodeRuleSetAsset(it) }
        val fullTemplate = root.optJSONObject("full_template")?.let { decodeFullTemplate(it) } ?: FullTemplateConfig()
        return WorkspaceDocument(
            schemaVersion = WorkspaceDocument.SCHEMA_VERSION,
            revision = root.optLong("revision", 1L).coerceAtLeast(1L),
            updatedAtMs = root.optLong("updated_at_ms", 0L).coerceAtLeast(0L),
            profiles = profiles,
            subscriptions = subscriptions,
            routingProfiles = routings,
            dns = dns,
            ruleSetAssets = ruleSetAssets,
            fullTemplate = fullTemplate,
        )
    }

    internal fun encodeProfile(p: ProfileItem): JSONObject = JSONObject().apply {
        put("id", p.id)
        put("remarks", p.remarks)
        put("subscription_id", p.subscriptionId)
        put("is_from_sub", p.isFromSub)
        put("kind", p.kind.wire)
        p.node?.let { put("node", encodeNode(it)) }
        if (p.customOutboundKdl.isNotEmpty() || p.kind == ProfileKind.CUSTOM_OUTBOUND) {
            put("custom_outbound_kdl", p.customOutboundKdl)
        }
        p.policyGroup?.let { put("policy_group", encodePolicyGroup(it)) }
        p.proxyChain?.let { put("proxy_chain", JSONObject().put("hop_ids", toJsonStringArray(it.hopIds))) }
        if (p.fullCustomKdl.isNotEmpty() || p.kind == ProfileKind.FULL_CUSTOM_KDL) {
            put("full_custom_kdl", p.fullCustomKdl)
        }
    }

    internal fun decodeProfile(obj: JSONObject): ProfileItem {
        val kind = ProfileKind.fromWire(obj.optString("kind", ProfileKind.NODE.wire))
        return ProfileItem(
            id = obj.optString("id", "").trim(),
            remarks = obj.optString("remarks", ""),
            subscriptionId = obj.optString("subscription_id", ""),
            isFromSub = obj.optBoolean("is_from_sub", false),
            kind = kind,
            node = obj.optJSONObject("node")?.let { decodeNode(it) },
            customOutboundKdl = obj.optString("custom_outbound_kdl", ""),
            policyGroup = obj.optJSONObject("policy_group")?.let { decodePolicyGroup(it) },
            proxyChain = obj.optJSONObject("proxy_chain")?.let { ProxyChainConfig(readStringList(it.optJSONArray("hop_ids"))) },
            fullCustomKdl = obj.optString("full_custom_kdl", ""),
        )
    }

    private fun encodeNode(n: NodeConfig): JSONObject = JSONObject().apply {
        put("protocol", n.protocol)
        put("server", n.server)
        put("port", n.port)
        put("username", n.username)
        put("password", n.password)
        put("method", n.method)
        put("flow", n.flow)
        put("packet_encoding", n.packetEncoding)
        put("tls", JSONObject().apply {
            put("enabled", n.tls.enabled)
            put("sni", n.tls.sni)
            put("fingerprint", n.tls.fingerprint)
            put("key_exchange", n.tls.keyExchange)
            put("ca_pem", n.tls.caPem)
            put("cert_sha256", toJsonStringArray(n.tls.certSha256))
            put("reality_public_key", n.tls.realityPublicKey)
            put("reality_short_id", n.tls.realityShortId)
            put("ech_mode", n.tls.echMode)
            put("ech_config", n.tls.echConfig)
        })
        put("transport", JSONObject().apply {
            put("type", NodeTransportConfig.normalizeType(n.transport.type))
            put("host", n.transport.host)
            put("path", n.transport.path)
            put("service_name", n.transport.serviceName)
            put("authority", n.transport.authority)
            put("xhttp_mode", n.transport.xhttpMode)
            put("xhttp_protocol", n.transport.xhttpProtocol)
            put("headers", toJsonStringMap(n.transport.headers))
        })
        put("multiplex", JSONObject().apply {
            put("enabled", n.multiplex.enabled)
            put("protocol", n.multiplex.protocol)
            put("max_connections", n.multiplex.maxConnections)
            put("padding", n.multiplex.padding)
        })
        put("extra", encodeNodeExtra(n.extra))
    }

    private fun decodeNode(obj: JSONObject): NodeConfig {
        val tlsObj = obj.optJSONObject("tls")
        val trObj = obj.optJSONObject("transport")
        val muxObj = obj.optJSONObject("multiplex")
        val exObj = obj.optJSONObject("extra")
        return NodeConfig(
            protocol = obj.optString("protocol", "vless"),
            server = obj.optString("server", ""),
            port = obj.optInt("port", 443),
            username = obj.optString("username", ""),
            password = obj.optString("password", ""),
            method = obj.optString("method", ""),
            flow = obj.optString("flow", ""),
            packetEncoding = obj.optString("packet_encoding", ""),
            tls = if (tlsObj != null) {
                NodeTlsConfig(
                    enabled = tlsObj.optBoolean("enabled", true),
                    sni = tlsObj.optString("sni", ""),
                    fingerprint = tlsObj.optString("fingerprint", ""),
                    keyExchange = tlsObj.optString("key_exchange", ""),
                    caPem = tlsObj.optString("ca_pem", ""),
                    certSha256 = readStringList(tlsObj.optJSONArray("cert_sha256")),
                    realityPublicKey = tlsObj.optString("reality_public_key", ""),
                    realityShortId = tlsObj.optString("reality_short_id", ""),
                    echMode = tlsObj.optString("ech_mode", ""),
                    echConfig = tlsObj.optString("ech_config", ""),
                )
            } else NodeTlsConfig(),
            transport = if (trObj != null) {
                NodeTransportConfig(
                    type = NodeTransportConfig.normalizeType(trObj.optString("type", "")),
                    host = trObj.optString("host", ""),
                    path = trObj.optString("path", ""),
                    serviceName = trObj.optString("service_name", ""),
                    authority = trObj.optString("authority", ""),
                    xhttpMode = trObj.optString("xhttp_mode", ""),
                    xhttpProtocol = trObj.optString("xhttp_protocol", ""),
                    headers = readStringMap(trObj.optJSONObject("headers")),
                )
            } else NodeTransportConfig(),
            multiplex = if (muxObj != null) {
                NodeMultiplexConfig(
                    enabled = muxObj.optBoolean("enabled", false),
                    protocol = muxObj.optString("protocol", ""),
                    maxConnections = muxObj.optInt("max_connections", 0),
                    padding = muxObj.optBoolean("padding", false),
                )
            } else NodeMultiplexConfig(),
            extra = if (exObj != null) decodeNodeExtra(exObj) else NodeExtraConfig(),
        )
    }

    private fun encodeNodeExtra(e: NodeExtraConfig): JSONObject = JSONObject().apply {
        put("hy2_ports", e.hy2Ports)
        put("hy2_hop_interval_ms", e.hy2HopIntervalMs)
        put("hy2_up_mbps", e.hy2UpMbps)
        put("hy2_down_mbps", e.hy2DownMbps)
        put("hy2_salamander_password", e.hy2SalamanderPassword)
        put("tuic_congestion_control", e.tuicCongestionControl)
        put("tuic_udp_over_stream", e.tuicUdpOverStream)
        put("wg_peer_public_key", e.wgPeerPublicKey)
        put("wg_preshared_key", e.wgPresharedKey)
        put("wg_local_addresses", toJsonStringArray(e.wgLocalAddresses))
        put("wg_reserved", e.wgReserved)
        put("wg_mtu", e.wgMtu)
        put("masque_mode", e.masqueMode)
        put("masque_path", e.masquePath)
        put("masque_local_addresses", toJsonStringArray(e.masqueLocalAddresses))
        put("naive_protocol", e.naiveProtocol)
        put("snell_version", e.snellVersion)
        put("snell_obfs", e.snellObfs)
        put("snell_obfs_host", e.snellObfsHost)
        put("ssh_host_key_sha256", toJsonStringArray(e.sshHostKeySha256))
    }

    private fun decodeNodeExtra(obj: JSONObject): NodeExtraConfig = NodeExtraConfig(
        hy2Ports = obj.optString("hy2_ports", ""),
        hy2HopIntervalMs = obj.optInt("hy2_hop_interval_ms", 0),
        hy2UpMbps = obj.optInt("hy2_up_mbps", 0),
        hy2DownMbps = obj.optInt("hy2_down_mbps", 0),
        hy2SalamanderPassword = obj.optString("hy2_salamander_password", ""),
        tuicCongestionControl = obj.optString("tuic_congestion_control", ""),
        tuicUdpOverStream = obj.optBoolean("tuic_udp_over_stream", false),
        wgPeerPublicKey = obj.optString("wg_peer_public_key", ""),
        wgPresharedKey = obj.optString("wg_preshared_key", ""),
        wgLocalAddresses = readStringList(obj.optJSONArray("wg_local_addresses")),
        wgReserved = obj.optString("wg_reserved", ""),
        wgMtu = obj.optInt("wg_mtu", 0),
        masqueMode = obj.optString("masque_mode", ""),
        masquePath = obj.optString("masque_path", ""),
        masqueLocalAddresses = readStringList(obj.optJSONArray("masque_local_addresses")),
        naiveProtocol = obj.optString("naive_protocol", ""),
        snellVersion = obj.optInt("snell_version", 0),
        snellObfs = obj.optString("snell_obfs", ""),
        snellObfsHost = obj.optString("snell_obfs_host", ""),
        sshHostKeySha256 = readStringList(obj.optJSONArray("ssh_host_key_sha256")),
    )

    private fun encodePolicyGroup(g: PolicyGroupConfig): JSONObject = JSONObject().apply {
        put("strategy", g.strategy)
        put("member_ids", toJsonStringArray(g.memberIds))
        put("dynamic_sub_id", g.dynamicSubId)
        put("include_regex", g.includeRegex)
        put("exclude_regex", g.excludeRegex)
        put("probe_url", g.probeUrl)
        put("probe_interval_ms", g.probeIntervalMs)
        put("tolerance_ms", g.toleranceMs)
    }

    private fun decodePolicyGroup(obj: JSONObject): PolicyGroupConfig = PolicyGroupConfig(
        strategy = obj.optString("strategy", "selector"),
        memberIds = readStringList(obj.optJSONArray("member_ids")),
        dynamicSubId = obj.optString("dynamic_sub_id", ""),
        includeRegex = obj.optString("include_regex", ""),
        excludeRegex = obj.optString("exclude_regex", ""),
        probeUrl = obj.optString("probe_url", "https://www.gstatic.com/generate_204"),
        probeIntervalMs = obj.optLong("probe_interval_ms", 300_000L),
        toleranceMs = obj.optInt("tolerance_ms", 50),
    )

    internal fun encodeSubscription(s: SubscriptionItem): JSONObject = JSONObject().apply {
        put("id", s.id)
        put("remarks", s.remarks)
        put("url", s.url)
        put("more_urls", toJsonStringArray(s.moreUrls))
        put("enabled", s.enabled)
        put("auto_update_minutes", s.autoUpdateMinutes)
        put("user_agent", s.userAgent)
        put("request_headers", toJsonStringMap(s.requestHeaders))
        put("include_regex", s.includeRegex)
        put("exclude_regex", s.excludeRegex)
        put("prev_profile_id", s.prevProfileId)
        put("next_profile_id", s.nextProfileId)
        put("updated_at_ms", s.updatedAtMs)
        put("usage", JSONObject().apply {
            put("upload_bytes", s.usage.uploadBytes)
            put("download_bytes", s.usage.downloadBytes)
            put("total_bytes", s.usage.totalBytes)
            put("expire_unix_sec", s.usage.expireUnixSec)
            put("profile_title", s.usage.profileTitle)
            put("web_page_url", s.usage.webPageUrl)
            put("support_url", s.usage.supportUrl)
        })
    }

    internal fun decodeSubscription(obj: JSONObject): SubscriptionItem {
        val uObj = obj.optJSONObject("usage")
        return SubscriptionItem(
            id = obj.optString("id", ""),
            remarks = obj.optString("remarks", ""),
            url = obj.optString("url", ""),
            moreUrls = readStringList(obj.optJSONArray("more_urls")),
            enabled = obj.optBoolean("enabled", true),
            autoUpdateMinutes = obj.optInt("auto_update_minutes", 0),
            userAgent = obj.optString("user_agent", ""),
            requestHeaders = readStringMap(obj.optJSONObject("request_headers")),
            includeRegex = obj.optString("include_regex", ""),
            excludeRegex = obj.optString("exclude_regex", ""),
            prevProfileId = obj.optString("prev_profile_id", ""),
            nextProfileId = obj.optString("next_profile_id", ""),
            updatedAtMs = obj.optLong("updated_at_ms", 0L),
            usage = if (uObj != null) {
                SubscriptionUsage(
                    uploadBytes = uObj.optLong("upload_bytes", -1L),
                    downloadBytes = uObj.optLong("download_bytes", -1L),
                    totalBytes = uObj.optLong("total_bytes", -1L),
                    expireUnixSec = uObj.optLong("expire_unix_sec", -1L),
                    profileTitle = uObj.optString("profile_title", ""),
                    webPageUrl = uObj.optString("web_page_url", ""),
                    supportUrl = uObj.optString("support_url", ""),
                )
            } else SubscriptionUsage(),
        )
    }

    internal fun encodeRoutingProfile(rp: RoutingProfileItem): JSONObject = JSONObject().apply {
        put("id", rp.id)
        put("name", rp.name)
        put("is_active", rp.isActive)
        put("domain_strategy", rp.domainStrategy)
        put("default_outbound", rp.defaultOutbound)
        put("rules", JSONArray().apply { rp.rules.forEach { put(encodeRoutingRule(it)) } })
    }

    internal fun decodeRoutingProfile(obj: JSONObject): RoutingProfileItem = RoutingProfileItem(
        id = obj.optString("id", "default"),
        name = obj.optString("name", "Default"),
        isActive = obj.optBoolean("is_active", false),
        domainStrategy = obj.optString("domain_strategy", "as-is"),
        defaultOutbound = obj.optString("default_outbound", "proxy"),
        rules = decodeArray(obj.optJSONArray("rules")) { decodeRoutingRule(it) },
    )

    private fun encodeRoutingRule(r: RoutingRuleItem): JSONObject = JSONObject().apply {
        put("id", r.id)
        put("enabled", r.enabled)
        put("locked", r.locked)
        put("scope", r.scope)
        put("target_type", r.targetType)
        put("target_profile_id", r.targetProfileId)
        put("domains", toJsonStringArray(r.domains))
        put("ips", toJsonStringArray(r.ips))
        put("rule_sets", toJsonStringArray(r.ruleSets))
        put("ports", toJsonStringArray(r.ports))
        put("networks", toJsonStringArray(r.networks))
        put("protocols", toJsonStringArray(r.protocols))
        put("desktop_process", toJsonStringArray(r.desktopProcess))
        put("android_packages", toJsonStringArray(r.androidPackages))
        put("tls_fragment", r.tlsFragment)
    }

    private fun decodeRoutingRule(obj: JSONObject): RoutingRuleItem = RoutingRuleItem(
        id = obj.optString("id", ""),
        enabled = obj.optBoolean("enabled", true),
        locked = obj.optBoolean("locked", false),
        scope = obj.optString("scope", "both"),
        targetType = obj.optString("target_type", "proxy"),
        targetProfileId = obj.optString("target_profile_id", ""),
        domains = readStringList(obj.optJSONArray("domains")),
        ips = readStringList(obj.optJSONArray("ips")),
        ruleSets = readStringList(obj.optJSONArray("rule_sets")),
        ports = readStringList(obj.optJSONArray("ports")),
        networks = readStringList(obj.optJSONArray("networks")),
        protocols = readStringList(obj.optJSONArray("protocols")),
        desktopProcess = readStringList(obj.optJSONArray("desktop_process")),
        androidPackages = readStringList(obj.optJSONArray("android_packages")),
        tlsFragment = obj.optBoolean("tls_fragment", false),
    )

    internal fun encodeDns(d: DnsConfig): JSONObject = JSONObject().apply {
        put("mode", d.mode)
        put("simple", JSONObject().apply {
            val s = d.simple
            put("bootstrap_dns", s.bootstrapDns)
            put("direct_dns", toJsonStringArray(s.directDns))
            put("remote_dns", toJsonStringArray(s.remoteDns))
            put("parallel_query", s.parallelQuery)
            put("direct_expected_rule_sets", toJsonStringArray(s.directExpectedRuleSets))
            put("fake_ip_enabled", s.fakeIpEnabled)
            put("fake_ip_v4_pool", s.fakeIpV4Pool)
            put("fake_ip_v6_pool", s.fakeIpV6Pool)
            put("fake_ip_global", s.fakeIpGlobal)
            put("block_aaaa", s.blockAaaa)
            put("block_svcb_https", s.blockSvcbHttps)
            put("serve_stale_seconds", s.serveStaleSeconds)
            put("use_system_hosts", s.useSystemHosts)
            put("hosts", toJsonStringMap(s.hosts))
            put("strategy", s.strategy)
        })
        put("raw_kdl", d.rawKdl)
    }

    internal fun decodeDns(obj: JSONObject): DnsConfig {
        val sObj = obj.optJSONObject("simple")
        val simple = if (sObj != null) {
            val hostsMap = linkedMapOf<String, String>()
            sObj.optJSONObject("hosts")?.let { h ->
                val keys = h.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val v = h.opt(k)
                    val resolved = when (v) {
                        is String -> v.trim()
                        is JSONArray -> readStringList(v).firstOrNull()?.trim().orEmpty()
                        else -> ""
                    }
                    if (k.isNotBlank() && resolved.isNotEmpty()) hostsMap[k] = resolved
                }
            }
            SimpleDnsConfig(
                bootstrapDns = sObj.optString("bootstrap_dns", "223.5.5.5"),
                directDns = readStringList(sObj.optJSONArray("direct_dns")).ifEmpty { listOf("local", "223.5.5.5") },
                remoteDns = readStringList(sObj.optJSONArray("remote_dns")).ifEmpty { listOf("https://1.1.1.1/dns-query") },
                parallelQuery = sObj.optBoolean("parallel_query", false),
                directExpectedRuleSets = readStringList(sObj.optJSONArray("direct_expected_rule_sets")),
                fakeIpEnabled = sObj.optBoolean("fake_ip_enabled", false),
                fakeIpV4Pool = sObj.optString("fake_ip_v4_pool", "198.18.0.0/16"),
                fakeIpV6Pool = sObj.optString("fake_ip_v6_pool", "fc00::/18"),
                fakeIpGlobal = sObj.optBoolean("fake_ip_global", false),
                blockAaaa = sObj.optBoolean("block_aaaa", false),
                blockSvcbHttps = sObj.optBoolean("block_svcb_https", false),
                serveStaleSeconds = sObj.optInt("serve_stale_seconds", 0),
                useSystemHosts = sObj.optBoolean("use_system_hosts", true),
                hosts = hostsMap,
                strategy = sObj.optString("strategy", "prefer_ipv4"),
            )
        } else SimpleDnsConfig()
        return DnsConfig(
            mode = obj.optString("mode", "simple"),
            simple = simple,
            rawKdl = obj.optString("raw_kdl", ""),
        )
    }

    internal fun encodeRuleSetAsset(a: RuleSetAsset): JSONObject = JSONObject().apply {
        put("tag", a.tag)
        put("source_type", a.sourceType)
        put("format", a.format)
        put("path", a.path)
        put("url", a.url)
        put("sha256", a.sha256)
        put("update_interval_ms", a.updateIntervalMs)
    }

    internal fun decodeRuleSetAsset(obj: JSONObject): RuleSetAsset = RuleSetAsset(
        tag = obj.optString("tag", ""),
        sourceType = obj.optString("source_type", "local"),
        format = obj.optString("format", "nxmm"),
        path = obj.optString("path", ""),
        url = obj.optString("url", ""),
        sha256 = obj.optString("sha256", ""),
        updateIntervalMs = obj.optLong("update_interval_ms", 0L),
    )

    internal fun encodeFullTemplate(ft: FullTemplateConfig): JSONObject = JSONObject().apply {
        put("enabled", ft.enabled)
        put("template_kdl", ft.templateKdl)
        put("append_proxies_only", ft.appendProxiesOnly)
        put("proxy_detour", ft.proxyDetour)
    }

    internal fun decodeFullTemplate(obj: JSONObject): FullTemplateConfig = FullTemplateConfig(
        enabled = obj.optBoolean("enabled", false),
        templateKdl = obj.optString("template_kdl", ""),
        appendProxiesOnly = obj.optBoolean("append_proxies_only", false),
        proxyDetour = obj.optString("proxy_detour", ""),
    )

    internal fun toJsonStringArray(items: List<String>): JSONArray = JSONArray().apply { items.forEach { put(it) } }
    internal fun toJsonStringMap(map: Map<String, String>): JSONObject = JSONObject().apply { map.forEach { (k, v) -> put(k, v) } }

    internal fun readStringList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        return buildList(arr.length()) {
            for (i in 0 until arr.length()) {
                val s = arr.optString(i, "")
                if (s.isNotEmpty()) add(s)
            }
        }
    }

    internal fun readStringMap(obj: JSONObject?): Map<String, String> {
        if (obj == null) return emptyMap()
        val out = linkedMapOf<String, String>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            out[k] = obj.optString(k, "")
        }
        return out
    }

    private inline fun <T> decodeArray(arr: JSONArray?, mapper: (JSONObject) -> T): List<T> {
        if (arr == null) return emptyList()
        return buildList(arr.length()) {
            for (i in 0 until arr.length()) {
                arr.optJSONObject(i)?.let { add(mapper(it)) }
            }
        }
    }
}
