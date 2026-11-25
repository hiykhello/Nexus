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
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.vpn.VpnTunnelState
import org.nexus.android.bridge.workspace.NodeConfig
import org.nexus.android.bridge.workspace.PolicyGroupConfig
import org.nexus.android.bridge.workspace.ProfileItem
import org.nexus.android.bridge.workspace.ProfileKind
import org.nexus.android.bridge.workspace.ProxyChainConfig
import org.nexus.android.bridge.workspace.SubscriptionItem
import org.nexus.android.bridge.workspace.SubscriptionUsage
import org.nexus.android.bridge.workspace.WorkspaceDocument
import org.nexus.android.ui.theme.NexusTheme

private const val SAMPLE_KDL = """schema-version 1
role "client"
inbound "tun" type="tun" {
    address "172.19.0.1/30"
    auto-route true
}
outbound "direct" type="direct"
outbound "hk-01" type="vless" {
    server "edge-hk.example.com" port=443
}
outbound "Auto" type="url-test" {
    member "hk-01"
    member "sg-02"
}
routing {
    default-outbound "Auto"
    tcp-program sniff-timeout-ms=300 unknown="skip" {
        rule action="route" outbound="direct" {
            ip-is-private true
        }
    }
}"""

private val SAMPLE_PROFILES = listOf(
    UiProfileChip("tokyo-core", "Tokyo-Core", active = true),
    UiProfileChip("hk-gaming", "HK-Gaming", active = false),
    UiProfileChip("corp-split", "Corp-Split", active = false),
)

private val SAMPLE_GROUPS = listOf(
    OutboundGroupSnapshot(
        tag = "Auto",
        mode = "url-test",
        active = "HK-01",
        manualOverride = false,
        members = listOf(
            OutboundMemberSnapshot("HK-01 香港", "healthy", 42, selected = true, overridden = false),
            OutboundMemberSnapshot("SG-02 狮城", "healthy", 118, selected = false, overridden = false),
            OutboundMemberSnapshot("JP-03 东京", "healthy", 245, selected = false, overridden = false),
            OutboundMemberSnapshot("UK-06 伦敦", "degraded", 388, selected = false, overridden = false),
            OutboundMemberSnapshot("US-04 硅谷", "timeout", 0, selected = false, overridden = true),
            OutboundMemberSnapshot("DE-05 德国", "unknown", -1, selected = false, overridden = false),
        ),
    ),
    OutboundGroupSnapshot(
        tag = "Streaming",
        mode = "selector",
        active = "SG-02",
        manualOverride = true,
        members = listOf(
            OutboundMemberSnapshot("SG-02", "healthy", 94, selected = true, overridden = true),
            OutboundMemberSnapshot("JP-03", "healthy", 162, selected = false, overridden = false),
            OutboundMemberSnapshot("TW-07", "healthy", 58, selected = false, overridden = false),
        ),
    ),
)

private val SAMPLE_CONNECTIONS = listOf(
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

private val SAMPLE_APPS = listOf(
    InstalledAppEntry("com.android.chrome", "Chrome", isSystemApp = false),
    InstalledAppEntry("org.mozilla.firefox", "Firefox", isSystemApp = false),
    InstalledAppEntry("com.tencent.mm", "WeChat", isSystemApp = false),
    InstalledAppEntry("com.google.android.projection.gearhead", "Android Auto", isSystemApp = false),
)

private val SAMPLE_LOGS = listOf(
    UiLogLine(1L, "09:41:02 [info] core: nexus engine ready (epoll + io_uring worker pool)"),
    UiLogLine(2L, "09:41:04 [debug] dns: cache hit api.github.com -> 140.82.114.6 (2 ms)"),
    UiLogLine(3L, "09:41:07 [info] route: quic api.github.com:443 -> Auto/HK-01 (geosite-dev)"),
    UiLogLine(4L, "09:41:09 [warn] probe: UK-06 latency elevated to 388 ms"),
    UiLogLine(5L, "09:41:12 [error] quic: edge US-04 handshake timed out after 3000 ms"),
    UiLogLine(6L, "09:41:15 [info] control: hot-reloaded profile Tokyo-Core (gen #12)"),
)

private val SAMPLE_METRICS = MetricsSummary(
    controlGeneration = 12,
    activeSessions = 18,
    uploadBytes = 44_669_337,
    downloadBytes = 333_866_598,
)

private val SAMPLE_DL = listOf(
    480_000L, 920_000L, 1_650_000L, 2_800_000L, 3_400_000L, 2_450_000L,
    2_100_000L, 3_950_000L, 5_600_000L, 6_400_000L, 4_850_000L, 4_100_000L,
    5_900_000L, 7_450_000L, 7_800_000L, 6_150_000L, 4_300_000L, 3_800_000L,
    4_650_000L, 5_850_000L, 5_100_000L, 4_400_000L, 5_200_000L, 5_600_000L,
)

private val SAMPLE_UL = listOf(
    90_000L, 140_000L, 260_000L, 380_000L, 450_000L, 310_000L,
    240_000L, 390_000L, 620_000L, 540_000L, 410_000L, 360_000L,
    520_000L, 780_000L, 690_000L, 480_000L, 340_000L, 290_000L,
    370_000L, 510_000L, 460_000L, 390_000L, 440_000L, 480_000L,
)

private val SAMPLE_EXIT = ActiveExitSummary(
    groupTag = "Auto",
    memberName = "HK-01",
    latencyMs = 42L,
    state = "healthy",
)

@Composable
private fun PreviewFrame(dark: Boolean, content: @Composable () -> Unit) {
    val nonTextFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { nonTextFocus.requestFocus() } }
    NexusTheme(darkTheme = dark) {
        Surface {
            Box {
                Box(modifier = Modifier.size(1.dp).focusRequester(nonTextFocus).focusable())
                content()
            }
        }
    }
}

@Composable
private fun SampleRootPreview(
    dark: Boolean,
    running: Boolean,
    tunnelState: VpnTunnelState = if (running) VpnTunnelState.RUNNING else VpnTunnelState.STOPPED,
    lastError: String = "",
    dashEditing: Boolean = false,
) {
    NexusTheme(darkTheme = dark) {
        NexusRootScreen(
            running = running,
            tunnelState = tunnelState,
            startedAtMs = if (running) System.currentTimeMillis() - 4_522_000L else 0L,
            lastError = lastError,
            powerSave = false,
            localLogs = if (running) SAMPLE_LOGS else emptyList(),
            initialKdl = SAMPLE_KDL,
            profiles = SAMPLE_PROFILES,
            activeProfileName = "Tokyo-Core",
            excludedPackages = setOf("com.android.chrome", "com.google.android.projection.gearhead"),
            onToggleExcluded = { _, _ -> },
            onStartStop = {},
            onValidateKdl = { true to "OK" },
            onSaveAndReload = { true to "Saved" },
            onImportShareLink = { _, cur -> cur to "" },
            onImportSubscription = { _, _ -> "" to "" },
            onRefreshMetrics = { if (running) SAMPLE_METRICS else MetricsSummary() },
            onClearCache = { true },
            onFetchGroups = { if (running) SAMPLE_GROUPS else emptyList() },
            onFetchConnections = { if (running) SAMPLE_CONNECTIONS else emptyList() },
            onInspectConnection = { SAMPLE_CONNECTIONS.firstOrNull() },
            onResolveOwnerPackage = { "com.android.chrome (UID 10214)" },
            onCloseConnection = { true },
            onCloseAllConnections = { true },
            onSelectMember = { _, _ -> true },
            onResetAuto = { true },
            onProbeGroup = { true },
            onFetchLogs = { _, _ -> if (running) SAMPLE_LOGS else emptyList() },
            onShareLogs = {},
            previewMetrics = if (running) SAMPLE_METRICS else MetricsSummary(),
            previewApps = SAMPLE_APPS,
            previewDownloadSamples = if (running) SAMPLE_DL else List(12) { 0L },
            previewUploadSamples = if (running) SAMPLE_UL else List(12) { 0L },
            previewActiveExit = if (running) SAMPLE_EXIT else ActiveExitSummary(),
            previewQuickNodes = if (running) SAMPLE_GROUPS.first().members else emptyList(),
            previewMemoryText = if (running) "9.4 MB" else "6.2 MB",
            previewDashEditing = dashEditing,
        )
    }
}

@Preview(name = "Phone Dark Running", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewPhoneDarkPreview() = SampleRootPreview(dark = true, running = true)

@Preview(name = "Phone Dark Customize Reorder", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun OverviewCustomizeDarkPreview() = SampleRootPreview(dark = true, running = true, dashEditing = true)

@Preview(name = "Phone Light Standby", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun OverviewPhoneLightPreview() = SampleRootPreview(dark = false, running = false)

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
            onFetchGroups = { SAMPLE_GROUPS },
            onSelectMember = { _, _ -> true },
            onResetAuto = { true },
            onProbeGroup = { true },
            windowSizeClass = NexusWindowSizeClass.COMPACT,
            contentPadding = PaddingValues(16.dp),
        )
    }
}

@Preview(name = "Groups Expanded Two-Pane", showBackground = true, widthDp = 920, heightDp = 720, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun GroupsExpandedPreview() {
    PreviewFrame(dark = true) {
        GroupsScreen(
            onFetchGroups = { SAMPLE_GROUPS },
            onSelectMember = { _, _ -> true },
            onResetAuto = { true },
            onProbeGroup = { true },
            windowSizeClass = NexusWindowSizeClass.EXPANDED,
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
            onFetchConnections = { SAMPLE_CONNECTIONS },
            onInspectConnection = { SAMPLE_CONNECTIONS.firstOrNull() },
            onResolveOwnerPackage = { "com.android.chrome (UID 10214)" },
            onCloseConnection = { true },
            onCloseAllConnections = { true },
            onCreateRuleFromConnection = { host, _, _ -> "已为 $host 创建规则" },
            onBypassPackage = {},
            windowSizeClass = NexusWindowSizeClass.EXPANDED,
            contentPadding = PaddingValues(16.dp),
            initialSelectedConnection = SAMPLE_CONNECTIONS.first(),
            downloadRateBps = 5_557_452L,
            uploadRateBps = 480_051L,
        )
    }
}

private val SAMPLE_WORKSPACE = WorkspaceUiState(
    document = WorkspaceDocument(
        profiles = listOf(
            ProfileItem(id = "hk-01", remarks = "HK-01 香港高速", kind = ProfileKind.NODE, node = NodeConfig(protocol = "vless", server = "hk.example.com", port = 443)),
            ProfileItem(id = "auto-grp", remarks = "Auto 测速策略组", kind = ProfileKind.POLICY_GROUP, policyGroup = PolicyGroupConfig(strategy = "url-test", memberIds = listOf("hk-01"))),
            ProfileItem(id = "chain-01", remarks = "双跳中继链", kind = ProfileKind.PROXY_CHAIN, proxyChain = ProxyChainConfig(hopIds = listOf("hk-01"))),
            ProfileItem(id = "legacy-corp", remarks = "Corp-Split", kind = ProfileKind.FULL_CUSTOM_KDL, fullCustomKdl = SAMPLE_KDL),
        ),
        subscriptions = listOf(
            SubscriptionItem(
                id = "main-sub",
                remarks = "Tokyo-Core",
                url = "https://sub.example.com/nexus",
                usage = SubscriptionUsage(
                    uploadBytes = 12L * 1024 * 1024 * 1024,
                    downloadBytes = 68L * 1024 * 1024 * 1024,
                    totalBytes = 200L * 1024 * 1024 * 1024,
                    expireUnixSec = 1_800_000_000L,
                    profileTitle = "Tokyo-Core 专线",
                ),
            ),
        ),
    ),
    activeProfileId = "hk-01",
    outboundMode = "rule",
)

@Preview(name = "Config Phone Dark", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun ConfigPhoneDarkPreview() {
    PreviewFrame(dark = true) {
        ConfigScreen(
            kdlText = SAMPLE_KDL,
            hasRemoteOutbound = true,
            profiles = SAMPLE_PROFILES,
            onApplyConfig = { true to "已校验保存并热重载" },
            diagnostic = "工作区已校验并生效",
            onDiagnosticChange = {},
            onImportShareLink = { _, cur -> cur to "" },
            onImportSubscription = { _, _ -> "" to "" },
            onSwitchProfile = { null to "" },
            onSaveProfileSnapshot = { _, _ -> "" },
            onValidateKdl = { true to "OK" },
            windowSizeClass = NexusWindowSizeClass.COMPACT,
            contentPadding = PaddingValues(16.dp),
            excludedCount = 2,
            onOpenSplitTunnel = {},
            workspaceState = SAMPLE_WORKSPACE,
        )
    }
}

@Preview(name = "Config Split Dark", showBackground = true, widthDp = 920, heightDp = 740, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun ConfigExpandedPreview() {
    PreviewFrame(dark = true) {
        ConfigScreen(
            kdlText = SAMPLE_KDL,
            hasRemoteOutbound = true,
            profiles = SAMPLE_PROFILES,
            onApplyConfig = { true to "已校验保存并热重载" },
            diagnostic = "已校验保存并热重载",
            onDiagnosticChange = {},
            onImportShareLink = { _, cur -> cur to "" },
            onImportSubscription = { _, _ -> "" to "" },
            onSwitchProfile = { null to "" },
            onSaveProfileSnapshot = { _, _ -> "" },
            onValidateKdl = { true to "OK" },
            windowSizeClass = NexusWindowSizeClass.EXPANDED,
            contentPadding = PaddingValues(16.dp),
            excludedCount = 2,
            onOpenSplitTunnel = {},
            workspaceState = SAMPLE_WORKSPACE,
        )
    }
}

@Preview(name = "Split Tunnel Medium", showBackground = true, widthDp = 680, heightDp = 760, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun SplitTunnelMediumPreview() {
    PreviewFrame(dark = true) {
        SplitTunnelScreen(
            running = true,
            excludedPackages = setOf("com.android.chrome", "com.google.android.projection.gearhead"),
            onToggleExcluded = { _, _ -> },
            onRestartVpn = {},
            windowSizeClass = NexusWindowSizeClass.MEDIUM,
            contentPadding = PaddingValues(16.dp),
            onBack = {},
            previewApps = SAMPLE_APPS,
        )
    }
}

@Preview(name = "Logs Phone Dark", showBackground = true, widthDp = 412, heightDp = 915, uiMode = Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun LogsDarkPreview() {
    PreviewFrame(dark = true) {
        LogsScreen(
            logs = SAMPLE_LOGS,
            logSearch = "",
            onLogSearchChange = {},
            logLevel = "trace",
            onLogLevelChange = {},
            onRefreshLogs = {},
            onShareLogs = {},
            contentPadding = PaddingValues(16.dp),
        )
    }
}
