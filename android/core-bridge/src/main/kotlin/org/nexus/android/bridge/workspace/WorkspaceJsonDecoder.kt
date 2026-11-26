package org.nexus.android.bridge.workspace

import org.json.JSONArray
import org.json.JSONObject

/**
 * Layer 1 portable `workspace.json` JSON decoder with forward/backward-compatible optional fields.
 */
internal object WorkspaceJsonDecoder {
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

    fun decodeProfile(obj: JSONObject): ProfileItem {
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
                    echQueryServerName = tlsObj.optString("ech_query_server_name", ""),
                    fragment = tlsObj.optBoolean("fragment", false),
                    recordFragment = tlsObj.optBoolean("record_fragment", false),
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
                    maxEarlyData = trObj.optInt("max_early_data", 0).coerceAtLeast(0),
                    earlyDataHeaderName = trObj.optString("early_data_header_name", ""),
                    grpcIdleTimeoutMs = trObj.optInt("grpc_idle_timeout_ms", 0).coerceAtLeast(0),
                    grpcPingTimeoutMs = trObj.optInt("grpc_ping_timeout_ms", 0).coerceAtLeast(0),
                    grpcPermitWithoutStream = trObj.optBoolean("grpc_permit_without_stream", false),
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

    private fun decodePolicyGroup(obj: JSONObject): PolicyGroupConfig = PolicyGroupConfig(
        strategy = obj.optString("strategy", "selector"),
        memberIds = readStringList(obj.optJSONArray("member_ids")),
        dynamicSubId = obj.optString("dynamic_sub_id", ""),
        includeRegex = obj.optString("include_regex", ""),
        excludeRegex = obj.optString("exclude_regex", ""),
        probeUrl = obj.optString("probe_url", "https://www.gstatic.com/generate_204"),
        probeIntervalMs = obj.optLong("probe_interval_ms", 300_000L),
        toleranceMs = obj.optInt("tolerance_ms", 50),
        interruptExistConnections = obj.optBoolean("interrupt_exist_connections", false),
    )

    fun decodeSubscription(obj: JSONObject): SubscriptionItem {
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

    fun decodeRoutingProfile(obj: JSONObject): RoutingProfileItem = RoutingProfileItem(
        id = obj.optString("id", "default"),
        name = obj.optString("name", "Default"),
        isActive = obj.optBoolean("is_active", false),
        domainStrategy = obj.optString("domain_strategy", "as-is"),
        defaultOutbound = obj.optString("default_outbound", "proxy"),
        rules = decodeArray(obj.optJSONArray("rules")) { decodeRoutingRule(it) },
        autoDetectInterface = obj.optBoolean("auto_detect_interface", false),
        findProcess = obj.optBoolean("find_process", false),
    )

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

    fun decodeDns(obj: JSONObject): DnsConfig {
        val sObj = obj.optJSONObject("simple")
        val simple = if (sObj != null) {
            val hostsMap = linkedMapOf<String, String>()
            sObj.optJSONObject("hosts")?.let { h ->
                val keys = h.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    val resolved = when (val raw = h.opt(k)) {
                        is String -> raw.trim()
                        is JSONArray -> readStringList(raw).firstOrNull()?.trim().orEmpty()
                        null -> ""
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

    fun decodeRuleSetAsset(obj: JSONObject): RuleSetAsset = RuleSetAsset(
        tag = obj.optString("tag", ""),
        sourceType = obj.optString("source_type", "local"),
        format = obj.optString("format", "nxmm"),
        path = obj.optString("path", ""),
        url = obj.optString("url", ""),
        sha256 = obj.optString("sha256", ""),
        updateIntervalMs = obj.optLong("update_interval_ms", 0L),
    )

    fun decodeFullTemplate(obj: JSONObject): FullTemplateConfig = FullTemplateConfig(
        enabled = obj.optBoolean("enabled", false),
        templateKdl = obj.optString("template_kdl", ""),
        appendProxiesOnly = obj.optBoolean("append_proxies_only", false),
        proxyDetour = obj.optString("proxy_detour", ""),
    )

    fun readStringList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        return buildList(arr.length()) {
            for (i in 0 until arr.length()) {
                val s = arr.optString(i, "")
                if (s.isNotEmpty()) add(s)
            }
        }
    }

    fun readStringMap(obj: JSONObject?): Map<String, String> {
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
