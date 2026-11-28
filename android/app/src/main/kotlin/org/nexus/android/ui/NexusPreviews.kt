package org.nexus.android.ui

import android.content.res.Configuration
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import org.nexus.android.apps.InstalledAppEntry
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.ipc.DnsAnswerRecord
import org.nexus.android.bridge.ipc.DnsQueryResult
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.ipc.OutboundProbeResult
import org.nexus.android.bridge.vpn.VpnTunnelState
import org.nexus.android.bridge.workspace.AndroidThemePreset
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.PolicyGroupConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.ProxyChainConfig
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.bridge.workspace.SubscriptionUsage
import org.nexus.android.bridge.workspace.WorkspaceDocument
import org.nexus.android.ui.theme.NexusTheme

internal const val PREVIEW_SAMPLE_CUSTOM_CONFIG = """schema-version 1
role "client"
outbound "direct" type="direct"
routing { final "direct"; }"""

internal val PREVIEW_SAMPLE_GROUPS = listOf(
    OutboundGroupSnapshot(
        tag = "Auto",
        mode = "url-test",
        active = "HK-01 香港 [示例]",
        manualOverride = false,
        members = listOf(
            OutboundMemberSnapshot("HK-01 香港 [示例]", "healthy", 42, selected = true, overridden = false),
            OutboundMemberSnapshot("SG-02 狮城 [示例]", "healthy", 118, selected = false, overridden = false),
            OutboundMemberSnapshot("JP-03 东京 [示例]", "healthy", 245, selected = false, overridden = false),
            OutboundMemberSnapshot("UK-06 伦敦 [示例]", "degraded", 388, selected = false, overridden = false),
            OutboundMemberSnapshot("US-04 硅谷 [示例]", "timeout", 0, selected = false, overridden = true),
            OutboundMemberSnapshot("DE-05 德国 [示例]", "unknown", -1, selected = false, overridden = false),
        ),
    ),
    OutboundGroupSnapshot(
        tag = "Streaming",
        mode = "selector",
        active = "SG-02 [示例]",
        manualOverride = true,
        members = listOf(
            OutboundMemberSnapshot("SG-02 [示例]", "healthy", 94, selected = true, overridden = true),
            OutboundMemberSnapshot("JP-03 [示例]", "healthy", 162, selected = false, overridden = false),
            OutboundMemberSnapshot("TW-07 [示例]", "healthy", 58, selected = false, overridden = false),
        ),
    ),
)

internal val PREVIEW_SAMPLE_CONNECTIONS = listOf(
    ActiveConnectionSnapshot(
        id = 1042,
        listener = 0,
        inbound = "tun-in",
        protocol = "udp/quic",
        path = "hk-01",
        source = "172.19.0.1:51842",
        target = "api.github.com:443",
        outbound = "Auto/HK-01",
        routeMode = "rule",
        routeRule = "geosite-dev -> Auto",
        processPath = "com.android.chrome",
        destinationPort = 443,
        durationMs = 1840,
        uploadBytes = 128_400,
        downloadBytes = 4_920_000,
        canClose = true,
    ),
    ActiveConnectionSnapshot(
        id = 1039,
        listener = 0,
        inbound = "tun-in",
        protocol = "tcp/tls",
        path = "sg-02",
        source = "172.19.0.1:49210",
        target = "cdn.jsdelivr.net:443",
        outbound = "Auto/SG-02",
        routeMode = "rule",
        routeRule = "domain-suffix -> Auto",
        processPath = "org.mozilla.firefox",
        destinationPort = 443,
        durationMs = 920,
        uploadBytes = 14_200,
        downloadBytes = 640_800,
        canClose = true,
    ),
    ActiveConnectionSnapshot(
        id = 1035,
        listener = 0,
        inbound = "socks-in",
        protocol = "tcp",
        path = "direct",
        source = "127.0.0.1:41008",
        target = "192.168.1.1:80",
        outbound = "direct",
        routeMode = "rule",
        routeRule = "ip-is-private -> direct",
        processPath = "termux",
        destinationPort = 80,
        durationMs = 310,
        uploadBytes = 1_240,
        downloadBytes = 8_910,
        canClose = true,
    ),
)

internal val PREVIEW_SAMPLE_APPS = listOf(
    InstalledAppEntry("com.android.chrome", "Chrome", isSystemApp = false),
    InstalledAppEntry("org.mozilla.firefox", "Firefox", isSystemApp = false),
    InstalledAppEntry("com.tencent.mm", "WeChat", isSystemApp = false),
    InstalledAppEntry("com.google.android.projection.gearhead", "Android Auto", isSystemApp = false),
)

internal val PREVIEW_SAMPLE_LOGS = listOf(
    UiLogLine(1L, "09:41:02 [info] core: nexus engine ready (epoll + io_uring worker pool)"),
    UiLogLine(2L, "09:41:04 [debug] dns: cache hit api.github.com -> 140.82.114.6 (2 ms)"),
    UiLogLine(3L, "09:41:07 [info] route: quic api.github.com:443 -> Auto/HK-01 (geosite-dev)"),
    UiLogLine(4L, "09:41:09 [warn] probe: UK-06 latency elevated to 388 ms"),
    UiLogLine(5L, "09:41:12 [error] quic: edge US-04 handshake timed out after 3000 ms"),
    UiLogLine(6L, "09:41:15 [info] control: hot-reloaded profile Tokyo-Core (gen #12)"),
)

internal val PREVIEW_SAMPLE_METRICS = MetricsSummary(
    controlGeneration = 12,
    activeSessions = 18,
    uploadBytes = 44_669_337,
    downloadBytes = 333_866_598,
)

internal val PREVIEW_SAMPLE_DL = listOf(
    480_000L, 920_000L, 1_650_000L, 2_800_000L, 3_400_000L, 2_450_000L,
    2_100_000L, 3_950_000L, 5_600_000L, 6_400_000L, 4_850_000L, 4_100_000L,
    5_900_000L, 7_450_000L, 7_800_000L, 6_150_000L, 4_300_000L, 3_800_000L,
    4_650_000L, 5_850_000L, 5_100_000L, 4_400_000L, 5_200_000L, 5_600_000L,
)

internal val PREVIEW_SAMPLE_UL = listOf(
    90_000L, 140_000L, 260_000L, 380_000L, 450_000L, 310_000L,
    240_000L, 390_000L, 620_000L, 540_000L, 410_000L, 360_000L,
    520_000L, 780_000L, 690_000L, 480_000L, 340_000L, 290_000L,
    370_000L, 510_000L, 460_000L, 390_000L, 440_000L, 480_000L,
)

internal val PREVIEW_SAMPLE_EXIT = ActiveExitSummary(
    groupTag = "Auto",
    memberName = "HK-01 [示例]",
    latencyMs = 42L,
    state = "healthy",
)

internal val PREVIEW_SAMPLE_LATENCIES = mapOf(
    "hk-01" to 38L,
    "sg-hy2" to 64L,
    "jp-wg" to 52L,
    "auto-grp" to 38L,
    "chain-01" to 91L,
)

internal val PREVIEW_SAMPLE_WORKSPACE = WorkspaceUiState(
    document = WorkspaceDocument(
        profiles = listOf(
            ProfileItem(id = "hk-01", remarks = "HK-01 香港高速 [示例]", subscriptionId = "main-sub", kind = ProfileKind.NODE, node = NodeConfig(protocol = "vless", server = "hk.example.com", port = 443, flow = "xtls-rprx-vision")),
            ProfileItem(id = "sg-hy2", remarks = "SG-02 狮城 Hysteria2 [示例]", subscriptionId = "main-sub", kind = ProfileKind.NODE, node = NodeConfig(protocol = "hysteria2", server = "sg.example.com", port = 8443)),
            ProfileItem(id = "jp-wg", remarks = "JP-03 东京 WireGuard [示例]", kind = ProfileKind.NODE, node = NodeConfig(protocol = "wireguard", server = "jp.example.com", port = 51820)),
            ProfileItem(id = "auto-grp", remarks = "Auto 测速策略组 [示例]", kind = ProfileKind.POLICY_GROUP, policyGroup = PolicyGroupConfig(strategy = "url-test", memberIds = listOf("hk-01", "sg-hy2"), interruptExistConnections = true)),
            ProfileItem(id = "chain-01", remarks = "双跳中继链 [示例]", kind = ProfileKind.PROXY_CHAIN, proxyChain = ProxyChainConfig(hopIds = listOf("hk-01", "jp-wg"))),
            ProfileItem(id = "custom-corp", remarks = "Corp-Split [示例]", kind = ProfileKind.FULL_CUSTOM_KDL, fullCustomKdl = PREVIEW_SAMPLE_CUSTOM_CONFIG),
        ),
        subscriptions = listOf(
            SubscriptionItem(
                id = "main-sub",
                remarks = "Tokyo-Core [示例]",
                url = "https://sub.example.com/nexus",
                usage = SubscriptionUsage(
                    uploadBytes = 12L * 1024 * 1024 * 1024,
                    downloadBytes = 68L * 1024 * 1024 * 1024,
                    totalBytes = 200L * 1024 * 1024 * 1024,
                    expireUnixSec = 1_800_000_000L,
                    profileTitle = "Tokyo-Core 专线 [示例]",
                ),
            ),
        ),
    ),
    activeProfileId = "hk-01",
    outboundMode = "rule",
)

@Composable
internal fun PreviewFrame(
    dark: Boolean,
    themePreset: AndroidThemePreset = if (dark) AndroidThemePreset.OBSIDIAN else AndroidThemePreset.PAPER,
    content: @Composable () -> Unit,
) {
    val nonTextFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { nonTextFocus.requestFocus() } }
    NexusTheme(darkTheme = dark, themePreset = themePreset) {
        Surface {
            Box {
                Box(modifier = Modifier.size(1.dp).focusRequester(nonTextFocus).focusable())
                content()
            }
        }
    }
}

@Composable
internal fun SampleRootPreview(
    dark: Boolean,
    running: Boolean,
    themePreset: AndroidThemePreset = if (dark) AndroidThemePreset.OBSIDIAN else AndroidThemePreset.PAPER,
    tunnelState: VpnTunnelState = if (running) VpnTunnelState.RUNNING else VpnTunnelState.STOPPED,
    lastError: String = "",
) {
    NexusTheme(darkTheme = dark, themePreset = themePreset) {
        NexusRootScreen(
            running = running,
            tunnelState = tunnelState,
            startedAtMs = if (running) System.currentTimeMillis() - 4_522_000L else 0L,
            lastError = lastError,
            powerSave = false,
            localLogs = if (running) PREVIEW_SAMPLE_LOGS else emptyList(),
            activeProfileName = "Tokyo-Core [示例]",
            excludedPackages = setOf("com.android.chrome", "com.google.android.projection.gearhead"),
            workspaceState = PREVIEW_SAMPLE_WORKSPACE,
            onToggleExcluded = { _, _ -> },
            onStartStop = {},
            onImportCustomConfig = { "已导入自定义配置" },
            onImportShareLink = { "" },
            onImportSubscription = { _, _ -> "" },
            onRefreshMetrics = { if (running) PREVIEW_SAMPLE_METRICS else MetricsSummary() },
            onClearCache = { true },
            onFetchGroups = { if (running) PREVIEW_SAMPLE_GROUPS else emptyList() },
            onFetchConnections = { if (running) PREVIEW_SAMPLE_CONNECTIONS else emptyList() },
            onInspectConnection = { PREVIEW_SAMPLE_CONNECTIONS.firstOrNull() },
            onResolveOwnerPackage = { "com.android.chrome (UID 10214)" },
            onCloseConnection = { true },
            onCloseAllConnections = { true },
            onSelectMember = { _, _ -> true },
            onResetAuto = { true },
            onProbeGroup = { true },
            onProbeOutbound = { tag -> OutboundProbeResult(ok = true, outbound = tag, state = "healthy", latencyMs = 38L) },
            onFetchLogs = { _, _ -> if (running) PREVIEW_SAMPLE_LOGS else emptyList() },
            onShareLogs = {},
            previewMetrics = if (running) PREVIEW_SAMPLE_METRICS else MetricsSummary(),
            previewApps = PREVIEW_SAMPLE_APPS,
            previewDownloadSamples = if (running) PREVIEW_SAMPLE_DL else List(12) { 0L },
            previewUploadSamples = if (running) PREVIEW_SAMPLE_UL else List(12) { 0L },
            previewActiveExit = if (running) PREVIEW_SAMPLE_EXIT else ActiveExitSummary(),
            previewQuickNodes = if (running) PREVIEW_SAMPLE_GROUPS.first().members else emptyList(),
            previewMemoryText = if (running) "9.4 MB" else "6.2 MB",
            previewOnsetMarkers = if (running) listOf(SparklineOnset(sampleIndex = 14, label = "HK-01")) else emptyList(),
            previewCachedGroups = if (running) PREVIEW_SAMPLE_GROUPS else emptyList(),
        )
    }
}

@Preview(name = "Phone Studio Amber Running", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewStudioAmberPreview() = SampleRootPreview(
    dark = true,
    running = true,
    themePreset = AndroidThemePreset.STUDIO_AMBER,
)

@Preview(name = "Quick Command Inline Diagnostic", showBackground = true, widthDp = 412, heightDp = 640, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun QuickCommandDiagnosticPreview() {
    PreviewFrame(dark = true, themePreset = AndroidThemePreset.OBSIDIAN) {
        QuickCommandContent(
            initialQuery = "api.github.com",
            running = true,
            outboundMode = "rule",
            groups = PREVIEW_SAMPLE_GROUPS,
            onDismiss = {},
            onSwitchMode = {},
            onSelectNode = { _, _ -> },
            onProbeAll = {},
            onFlushFakeIp = {},
            onClearCache = {},
            onOpenSplitTunnel = {},
            onCreateRuleForHost = { _, _, _ -> },
            previewExplain = RuleExplainSummary(
                dnsPolicy = "remote-doh",
                routeRule = "geosite-dev",
                action = "代理分流",
                outbound = "Auto/HK-01",
            ),
            previewDns = DnsQueryResult(
                ok = true,
                name = "api.github.com",
                type = "A",
                rcode = 0,
                rcodeName = "NOERROR",
                ttl = 60L,
                answers = listOf(DnsAnswerRecord("api.github.com", "A", 60L, "198.18.0.42")),
                elapsedMs = 4L,
            ),
        )
    }
}

@Preview(name = "Phone Dark Running", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewPhoneDarkPreview() = SampleRootPreview(dark = true, running = true)

@Preview(name = "Phone Light Running", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun OverviewPhoneLightPreview() = SampleRootPreview(dark = false, running = true)

@Preview(name = "Phone Light Standby", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun OverviewPhoneLightStandbyPreview() = SampleRootPreview(dark = false, running = false)

@Preview(name = "Phone Dark Standby", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewPhoneDarkStandbyPreview() = SampleRootPreview(dark = true, running = false)

@Preview(name = "Foldable Medium 674dp Rail", showBackground = true, widthDp = 674, heightDp = 841, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewFoldablePreview() = SampleRootPreview(dark = true, running = true)

@Preview(name = "Tablet Expanded Drawer", showBackground = true, widthDp = 960, heightDp = 720, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewTabletExpandedPreview() = SampleRootPreview(dark = true, running = true)

@Preview(name = "Groups Phone Dark", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun GroupsPhoneDarkPreview() {
    PreviewFrame(dark = true) {
        GroupsScreen(
            onFetchGroups = { PREVIEW_SAMPLE_GROUPS },
            onSelectMember = { _, _ -> true },
            onResetAuto = { true },
            onProbeGroup = { true },
            onProbeOutbound = { tag -> OutboundProbeResult(ok = true, outbound = tag, state = "healthy", latencyMs = 45L) },
            windowSizeClass = NexusWindowSizeClass.COMPACT,
            contentPadding = PaddingValues(16.dp),
        )
    }
}

@Preview(name = "Connections Expanded Two-Pane", showBackground = true, widthDp = 1024, heightDp = 680, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun ConnectionsExpandedPreview() {
    PreviewFrame(dark = true) {
        ConnectionsScreen(
            running = true,
            excludedPackages = setOf("com.android.chrome"),
            onFetchConnections = { PREVIEW_SAMPLE_CONNECTIONS },
            onInspectConnection = { PREVIEW_SAMPLE_CONNECTIONS.firstOrNull() },
            onResolveOwnerPackage = { "com.android.chrome (UID 10214)" },
            onCloseConnection = { true },
            onCloseAllConnections = { true },
            onCreateRuleFromConnection = { host, _, _ -> "已为 $host 创建规则" },
            onBypassPackage = {},
            onDiagnoseHost = {},
            windowSizeClass = NexusWindowSizeClass.EXPANDED,
            contentPadding = PaddingValues(16.dp),
            initialSelectedConnection = PREVIEW_SAMPLE_CONNECTIONS.first(),
            downloadRateBps = 5_557_452L,
            uploadRateBps = 480_051L,
        )
    }
}

@Preview(name = "Config Phone Dark", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun ConfigPhoneDarkPreview() {
    PreviewFrame(dark = true) {
        ConfigScreen(
            diagnostic = "工作区已校验并生效",
            onDiagnosticChange = {},
            onImportCustomConfig = { "已导入自定义配置" },
            onImportShareLink = { "" },
            onImportSubscription = { _, _ -> "" },
            windowSizeClass = NexusWindowSizeClass.COMPACT,
            contentPadding = PaddingValues(16.dp),
            onOpenSplitTunnel = {},
            onOpenDiagnostics = {},
            profileLatencies = PREVIEW_SAMPLE_LATENCIES,
            workspaceState = PREVIEW_SAMPLE_WORKSPACE,
        )
    }
}

@Preview(name = "Logs Phone Dark", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun LogsDarkPreview() {
    PreviewFrame(dark = true) {
        LogsScreen(
            logs = PREVIEW_SAMPLE_LOGS,
            logSearch = "",
            onLogSearchChange = {},
            logLevel = "trace",
            onLogLevelChange = {},
            onRefreshLogs = {},
            onShareLogs = {},
            contentPadding = PaddingValues(16.dp),
            running = true,
            sseStreaming = true,
            onSetCoreLogLevel = { true },
        )
    }
}
