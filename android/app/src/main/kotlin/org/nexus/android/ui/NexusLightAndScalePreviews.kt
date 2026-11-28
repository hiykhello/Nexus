package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewFontScale
import androidx.compose.ui.unit.dp
import org.nexus.android.bridge.ipc.OutboundProbeResult
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.bridge.workspace.AndroidThemePreset

/**
 * Light-mode & `@PreviewFontScale` accessibility verification previews across all subpages.
 */
@PreviewFontScale
@Composable
private fun OverviewFontScalePreview() = SampleRootPreview(dark = true, running = true)

@Preview(name = "Foldable Studio Amber 674dp", showBackground = true, widthDp = 674, heightDp = 841)
@Composable
private fun OverviewStudioAmberFoldablePreview() = SampleRootPreview(
    dark = true,
    running = true,
    themePreset = AndroidThemePreset.STUDIO_AMBER,
)

@Preview(name = "Groups Phone Light", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun GroupsPhoneLightPreview() {
    PreviewFrame(dark = false) {
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

@Preview(name = "Connections Phone Light", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun ConnectionsPhoneLightPreview() {
    PreviewFrame(dark = false) {
        ConnectionsScreen(
            running = true,
            excludedPackages = setOf("com.android.chrome"),
            perAppMode = AndroidPerAppMode.INCLUDE,
            onFetchConnections = { PREVIEW_SAMPLE_CONNECTIONS },
            onInspectConnection = { PREVIEW_SAMPLE_CONNECTIONS.firstOrNull() },
            onResolveOwnerPackage = { "com.android.chrome (UID 10214)" },
            onCloseConnection = { true },
            onCloseAllConnections = { true },
            onCreateRuleFromConnection = { host, _, _ -> "已为 $host 创建规则" },
            onBypassPackage = {},
            windowSizeClass = NexusWindowSizeClass.COMPACT,
            contentPadding = PaddingValues(16.dp),
            downloadRateBps = 5_557_452L,
            uploadRateBps = 480_051L,
        )
    }
}

@Preview(name = "Config Phone Light", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun ConfigPhoneLightPreview() {
    PreviewFrame(dark = false) {
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

@Preview(name = "Host & Routing Light", showBackground = true, widthDp = 412, heightDp = 1280)
@Composable
private fun HostAndRoutingLightPreview() {
    PreviewFrame(dark = false) {
        Column(
            modifier = Modifier
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            RoutingDnsPillarPane(
                state = PREVIEW_SAMPLE_WORKSPACE,
                actions = WorkspaceUiActions(),
                onOpenRuleDnsModal = {},
                onOpenDiagnostics = {},
                onFeedback = {},
            )
            HostSettingsCard(
                host = PREVIEW_SAMPLE_WORKSPACE.host,
                onUpdateHost = {},
                onOpenSplitTunnel = {},
            )
            WebDavSyncCard(
                state = PREVIEW_SAMPLE_WORKSPACE,
                actions = WorkspaceUiActions(),
                onFeedback = {},
            )
        }
    }
}

@PreviewFontScale
@Preview(name = "Split Tunnel Light Include Empty", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun SplitTunnelLightIncludePreview() {
    PreviewFrame(dark = false) {
        SplitTunnelScreen(
            running = true,
            excludedPackages = emptySet(),
            perAppMode = AndroidPerAppMode.INCLUDE,
            onToggleExcluded = { _, _ -> },
            onRestartVpn = {},
            windowSizeClass = NexusWindowSizeClass.COMPACT,
            contentPadding = PaddingValues(16.dp),
            onBack = {},
            previewApps = PREVIEW_SAMPLE_APPS,
        )
    }
}

@Preview(name = "Logs Phone Light", showBackground = true, widthDp = 412, heightDp = 915)
@Composable
private fun LogsLightPreview() {
    PreviewFrame(dark = false) {
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
