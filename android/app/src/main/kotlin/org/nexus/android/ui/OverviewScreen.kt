package org.nexus.android.ui

import android.content.ClipboardManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.bridge.workspace.AndroidRunMode

/**
 * Responsive Multi-Column Bento Console Overview (`仪表盘`):
 * - 4 Quick-Control Bento Tiles (`4-col` on Expanded, `2x2` on Phone & Foldable)
 * - Proportional Core & Mode Card (`FiveStateHeroCard`)
 * - Realtime Network Waveform (`ThroughputSparklineCard`)
 * - 2-Column Quick Node Matrix (`QuickNodesCarouselCard`)
 * - 2x2 Connectivity & Inbound Matrix (`TrafficSplitCard`)
 */
@Composable
fun OverviewScreen(
    heroState: HeroConnectionState,
    powerSave: Boolean,
    uptimeMs: Long,
    activeProfileName: String,
    outboundMode: String,
    hasRemoteOutbound: Boolean,
    activeExit: ActiveExitSummary,
    quickNodes: List<OutboundMemberSnapshot>,
    workspaceState: WorkspaceUiState = WorkspaceUiState(),
    memoryText: String,
    isProbing: Boolean,
    metrics: MetricsSummary,
    downloadRateBps: Long,
    uploadRateBps: Long,
    downloadSamples: List<Long>,
    uploadSamples: List<Long>,
    excludedCount: Int,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    diagnostic: String,
    errorDetail: String,
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    onStartStop: () -> Unit,
    onSwitchOutboundMode: (String) -> Unit,
    onQuickPasteImport: (String) -> Unit,
    onSelectQuickNode: (OutboundMemberSnapshot) -> Unit,
    onSelectWorkspaceProfile: (String) -> Unit = {},
    onProbeActiveGroup: () -> Unit,
    onClearCache: () -> Unit,
    onOpenGroups: () -> Unit,
    onOpenConnections: () -> Unit,
    onOpenConfig: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenDiagnostics: (() -> Unit)? = null,
    routingProfileName: String = "",
    runMode: AndroidRunMode = AndroidRunMode.VPN,
    bypassLan: Boolean = true,
    fakeIpEnabled: Boolean = false,
    onsetMarkers: List<SparklineOnset> = emptyList(),
    onUpdateHostSection: ((AndroidHostSection) -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    val running = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED
    val isTwoColumn = windowSizeClass != NexusWindowSizeClass.COMPACT
    val isExpanded = windowSizeClass == NexusWindowSizeClass.EXPANDED
    val activeRouting = workspaceState.document.activeRoutingProfile()
    val primarySub = workspaceState.document.subscriptions.firstOrNull()
    val derivedRtt = if (running && activeExit.latencyMs > 0L) {
        val base = activeExit.latencyMs
        ConnectivityTargetRtt(cfMs = (base - 14L).coerceAtLeast(12L), googleMs = base, githubMs = base + 16L, youtubeMs = base + 9L)
    } else ConnectivityTargetRtt()

    val bentoStrip: @Composable () -> Unit = {
        OverviewBentoTileStrip(
            fourColumns = isExpanded,
            running = running,
            runMode = runMode,
            localListen = workspaceState.host.android.localListen,
            tunMtu = workspaceState.host.android.tunMtu,
            perAppMode = perAppMode,
            excludedCount = excludedCount,
            bypassLan = bypassLan,
            routingProfileName = routingProfileName.ifBlank { activeRouting.name },
            ruleCount = activeRouting.rules.size,
            fakeIpEnabled = fakeIpEnabled,
            onOpenConfig = onOpenConfig,
            onOpenSplitTunnel = onOpenSplitTunnel,
            onOpenDiagnostics = onOpenDiagnostics,
            hostSection = workspaceState.host.android,
        )
    }

    val tunnelCard: @Composable (Modifier) -> Unit = { mod ->
        Column(modifier = mod) {
            FiveStateHeroCard(
                heroState = heroState,
                powerSave = powerSave,
                uptimeMs = uptimeMs,
                activeProfileName = activeProfileName,
                activeExit = activeExit,
                primarySub = primarySub,
                profileCount = workspaceState.document.profiles.size,
                errorDetail = errorDetail,
                outboundMode = outboundMode,
                runMode = runMode,
                onStartStop = onStartStop,
                onSwitchOutboundMode = onSwitchOutboundMode,
                onOpenConfig = onOpenConfig,
                onOpenGroups = onOpenGroups,
            )
        }
    }

    val trafficCard: @Composable (Modifier) -> Unit = { mod ->
        ThroughputSparklineCard(
            running = running,
            downloadRateBps = downloadRateBps,
            uploadRateBps = uploadRateBps,
            downloadSamples = downloadSamples,
            uploadSamples = uploadSamples,
            downloadTotalBytes = metrics.downloadBytes,
            uploadTotalBytes = metrics.uploadBytes,
            activeSessions = metrics.activeSessions,
            onsetMarkers = onsetMarkers,
            onClick = onOpenConnections,
            modifier = mod,
        )
    }

    val serversCard: @Composable (Modifier) -> Unit = { mod ->
        QuickNodesCarouselCard(
            running = running,
            groupTag = activeExit.groupTag,
            nodes = quickNodes,
            workspaceProfiles = workspaceState.document.profiles,
            activeProfileId = workspaceState.activeProfileId,
            isProbing = isProbing,
            onSelectNode = onSelectQuickNode,
            onSelectWorkspaceProfile = onSelectWorkspaceProfile,
            onQuickPasteImport = onQuickPasteImport,
            onProbeGroup = onProbeActiveGroup,
            onOpenGroups = onOpenGroups,
            onOpenConfig = onOpenConfig,
            maxVisibleNodes = if (windowSizeClass == NexusWindowSizeClass.MEDIUM) 4 else 6,
            nodeColumns = if (windowSizeClass == NexusWindowSizeClass.MEDIUM) 1 else 2,
            showP50Badge = windowSizeClass != NexusWindowSizeClass.MEDIUM,
            modifier = mod,
        )
    }

    val inboundCard: @Composable (Modifier) -> Unit = { mod ->
        TrafficSplitCard(
            running = running,
            downloadBytes = metrics.downloadBytes,
            uploadBytes = metrics.uploadBytes,
            excludedCount = excludedCount,
            perAppMode = perAppMode,
            localListen = workspaceState.host.android.localListen,
            tunMtu = workspaceState.host.android.tunMtu,
            connectivityRtt = derivedRtt,
            isProbing = isProbing,
            diagnostic = diagnostic,
            memoryText = memoryText,
            activeSessions = metrics.activeSessions,
            onProbeGroup = onProbeActiveGroup,
            onClearCache = onClearCache,
            onOpenSplitTunnel = onOpenSplitTunnel,
            onOpenConfig = onOpenConfig,
            onOpenDiagnostics = onOpenDiagnostics,
            onOpenConnections = onOpenConnections,
            hostSection = workspaceState.host.android,
            onUpdateHostSection = onUpdateHostSection,
            modifier = mod,
        )
    }

    LazyColumn(
        state = listState,
        modifier = modifier
            .fillMaxSize()
            .consumeWindowInsets(contentPadding),
        contentPadding = contentPadding,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (!hasRemoteOutbound) {
            item(key = "onboarding", contentType = "onboarding") {
                QuickOnboardingCard(
                    onPasteClipboard = onQuickPasteImport,
                    onOpenConfig = onOpenConfig,
                )
            }
        }

        if (isTwoColumn) {
            item(key = "bento_tiles", contentType = "bento_tiles") { bentoStrip() }
            item(key = "grid_top_row", contentType = "grid_row") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    tunnelCard(Modifier.weight(1f))
                    trafficCard(Modifier.weight(1f))
                }
            }
            item(key = "grid_bottom_row", contentType = "grid_row") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    serversCard(Modifier.weight(1f))
                    inboundCard(Modifier.weight(1f))
                }
            }
        } else {
            item(key = "card_tunnel", contentType = "card_tunnel") { tunnelCard(Modifier.fillMaxWidth()) }
            item(key = "bento_tiles", contentType = "bento_tiles") { bentoStrip() }
            item(key = "card_traffic", contentType = "card_traffic") { trafficCard(Modifier.fillMaxWidth()) }
            item(key = "card_servers", contentType = "card_servers") { serversCard(Modifier.fillMaxWidth()) }
            item(key = "card_inbound", contentType = "card_inbound") { inboundCard(Modifier.fillMaxWidth()) }
        }
    }
}

@Composable
internal fun QuickOnboardingCard(
    onPasteClipboard: (String) -> Unit,
    onOpenConfig: () -> Unit,
) {
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    OpticalCard(cornerRadius = 12.dp) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = "添加首个代理配置",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "粘贴分享链接或订阅 URL 即可一键完成解析与导入。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val clip = context.getSystemService(ClipboardManager::class.java)
                            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
                        onPasteClipboard(clip)
                    },
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(painterResource(R.drawable.ic_paste), null, Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("从剪贴板导入", maxLines = 1)
                }
                OutlinedButton(
                    onClick = onOpenConfig,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    Text("管理配置与订阅", maxLines = 1)
                }
            }
        }
    }
}
