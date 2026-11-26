package org.nexus.android.bridge.workspace

import org.json.JSONArray
import org.json.JSONObject

/**
 * Layer 1 portable `workspace.json` JSON encoder.
 * Emits ONLY portable Layer 1 keys (zero host ports, zero per-app OS keys, zero telemetry).
 */
internal object WorkspaceJsonEncoder {
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

    fun encodeProfile(p: ProfileItem): JSONObject = JSONObject().apply {
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
            if (n.tls.echQueryServerName.isNotEmpty()) put("ech_query_server_name", n.tls.echQueryServerName)
            if (n.tls.fragment) put("fragment", true)
            if (n.tls.recordFragment) put("record_fragment", true)
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
            if (n.transport.maxEarlyData > 0) put("max_early_data", n.transport.maxEarlyData)
            if (n.transport.earlyDataHeaderName.isNotEmpty()) put("early_data_header_name", n.transport.earlyDataHeaderName)
            if (n.transport.grpcIdleTimeoutMs > 0) put("grpc_idle_timeout_ms", n.transport.grpcIdleTimeoutMs)
            if (n.transport.grpcPingTimeoutMs > 0) put("grpc_ping_timeout_ms", n.transport.grpcPingTimeoutMs)
            if (n.transport.grpcPermitWithoutStream) put("grpc_permit_without_stream", true)
        })
        put("multiplex", JSONObject().apply {
            put("enabled", n.multiplex.enabled)
            put("protocol", n.multiplex.protocol)
            put("max_connections", n.multiplex.maxConnections)
            put("padding", n.multiplex.padding)
        })
        put("extra", encodeNodeExtra(n.extra))
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

    private fun encodePolicyGroup(g: PolicyGroupConfig): JSONObject = JSONObject().apply {
        put("strategy", g.strategy)
        put("member_ids", toJsonStringArray(g.memberIds))
        put("dynamic_sub_id", g.dynamicSubId)
        put("include_regex", g.includeRegex)
        put("exclude_regex", g.excludeRegex)
        put("probe_url", g.probeUrl)
        put("probe_interval_ms", g.probeIntervalMs)
        put("tolerance_ms", g.toleranceMs)
        if (g.interruptExistConnections) put("interrupt_exist_connections", true)
    }

    fun encodeSubscription(s: SubscriptionItem): JSONObject = JSONObject().apply {
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

    fun encodeRoutingProfile(rp: RoutingProfileItem): JSONObject = JSONObject().apply {
        put("id", rp.id)
        put("name", rp.name)
        put("is_active", rp.isActive)
        put("domain_strategy", rp.domainStrategy)
        put("default_outbound", rp.defaultOutbound)
        if (rp.autoDetectInterface) put("auto_detect_interface", true)
        if (rp.findProcess) put("find_process", true)
        put("rules", JSONArray().apply { rp.rules.forEach { put(encodeRoutingRule(it)) } })
    }

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

    fun encodeDns(d: DnsConfig): JSONObject = JSONObject().apply {
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

    fun encodeRuleSetAsset(a: RuleSetAsset): JSONObject = JSONObject().apply {
        put("tag", a.tag)
        put("source_type", a.sourceType)
        put("format", a.format)
        put("path", a.path)
        put("url", a.url)
        put("sha256", a.sha256)
        put("update_interval_ms", a.updateIntervalMs)
    }

    fun encodeFullTemplate(ft: FullTemplateConfig): JSONObject = JSONObject().apply {
        put("enabled", ft.enabled)
        put("template_kdl", ft.templateKdl)
        put("append_proxies_only", ft.appendProxiesOnly)
        put("proxy_detour", ft.proxyDetour)
    }

    fun toJsonStringArray(items: List<String>): JSONArray = JSONArray().apply { items.forEach { put(it) } }
    fun toJsonStringMap(map: Map<String, String>): JSONObject = JSONObject().apply { map.forEach { (k, v) -> put(k, v) } }
}
