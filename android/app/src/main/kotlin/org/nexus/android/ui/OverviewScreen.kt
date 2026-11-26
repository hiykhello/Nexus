package org.nexus.android.ui

import android.content.ClipboardManager
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.MetricsSummary
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusTheme

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
    memoryText: String,
    isProbing: Boolean,
    dashEditing: Boolean,
    dashVisibility: DashboardCardVisibility,
    metrics: MetricsSummary,
    downloadRateBps: Long,
    uploadRateBps: Long,
    peakRateBps: Long,
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
    onDashVisibilityChange: (DashboardCardVisibility) -> Unit,
    onQuickPasteImport: (String) -> Unit,
    onSelectQuickNode: (OutboundMemberSnapshot) -> Unit,
    onProbeActiveGroup: () -> Unit,
    onClearCache: () -> Unit,
    onOpenGroups: () -> Unit,
    onOpenConnections: () -> Unit,
    onOpenConfig: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenDiagnostics: (() -> Unit)? = null,
    routingProfileName: String = "",
    dnsSummaryText: String = "",
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    val running = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED
    val isTwoColumn = windowSizeClass != NexusWindowSizeClass.COMPACT
    val deduplicatedTools = dashVisibility.showNetworkMemory && dashVisibility.showSparkline
    val allowQuickNodes = isTwoColumn || (running && quickNodes.isNotEmpty())
    val orderedCards = remember(dashVisibility, allowQuickNodes) {
        dashVisibility.visibleOrderedCards(allowQuickNodes = allowQuickNodes)
    }
    val onRoutingTileClick: () -> Unit = {
        onOpenDiagnostics?.invoke() ?: onOpenConfig()
    }

    val renderDashboardCard: @Composable (String) -> Unit = { cardId ->
        when (cardId) {
            DashboardCardVisibility.KEY_SPARKLINE -> ThroughputSparklineCard(
                running = running,
                downloadRateBps = downloadRateBps,
                uploadRateBps = uploadRateBps,
                peakRateBps = peakRateBps,
                downloadSamples = downloadSamples,
                uploadSamples = uploadSamples,
                downloadTotalBytes = metrics.downloadBytes,
                uploadTotalBytes = metrics.uploadBytes,
            )
            DashboardCardVisibility.KEY_NETWORK_MEMORY -> OverviewStatusMiniPair(
                running = running,
                routingProfileName = routingProfileName,
                dnsSummaryText = dnsSummaryText,
                outboundMode = outboundMode,
                memoryText = memoryText,
                activeSessions = metrics.activeSessions,
                downloadBytes = metrics.downloadBytes,
                uploadBytes = metrics.uploadBytes,
                onRoutingClick = onRoutingTileClick,
                onConnectionsClick = onOpenConnections,
            )
            DashboardCardVisibility.KEY_QUICK_NODES -> QuickNodesCarouselCard(
                running = running,
                groupTag = activeExit.groupTag,
                nodes = quickNodes,
                isProbing = isProbing,
                onSelectNode = onSelectQuickNode,
                onProbeGroup = onProbeActiveGroup,
                onOpenGroups = onOpenGroups,
            )
            DashboardCardVisibility.KEY_TRAFFIC_SPLIT -> TrafficSplitCard(
                running = running,
                downloadBytes = metrics.downloadBytes,
                uploadBytes = metrics.uploadBytes,
                excludedCount = excludedCount,
                perAppMode = perAppMode,
                isProbing = isProbing,
                diagnostic = diagnostic,
                compactToolsOnly = deduplicatedTools,
                onProbeGroup = onProbeActiveGroup,
                onClearCache = onClearCache,
                onOpenSplitTunnel = onOpenSplitTunnel,
                onOpenDiagnostics = onOpenDiagnostics,
            )
            DashboardCardVisibility.KEY_KPI_GRID -> TelemetryKpiGrid(
                running = running,
                metrics = metrics,
                onOpenConnections = onOpenConnections,
            )
        }
    }

    LazyColumn(
        state = listState,
        modifier = modifier
            .fillMaxSize()
            .consumeWindowInsets(contentPadding),
        contentPadding = contentPadding,
        verticalArrangement = Arrangement.spacedBy(if (isTwoColumn) 12.dp else 11.dp),
    ) {
        item(key = "customize_bar", contentType = "customize_bar") {
            DashboardCustomizeBar(
                visible = dashEditing,
                visibility = dashVisibility,
                onChange = onDashVisibilityChange,
            )
        }

        if (!hasRemoteOutbound) {
            item(key = "onboarding", contentType = "onboarding") {
                QuickOnboardingCard(
                    onPasteClipboard = onQuickPasteImport,
                    onOpenConfig = onOpenConfig,
                )
            }
        }

        if (isTwoColumn) {
            val leftCards = orderedCards.withIndex().filter { (idx, _) -> idx == 2 || idx >= 4 }
            val rightCards = orderedCards.withIndex().filter { (idx, _) -> idx != 2 && idx < 4 }
            item(key = "bento_top", contentType = "bento_row") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalAlignment = Alignment.Top,
                ) {
                    Column(
                        modifier = Modifier.weight(1.06f),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        FiveStateHeroCard(
                            heroState = heroState,
                            powerSave = powerSave,
                            uptimeMs = uptimeMs,
                            activeProfileName = activeProfileName,
                            activeExit = activeExit,
                            errorDetail = errorDetail,
                            onStartStop = onStartStop,
                            onOpenConfig = onOpenConfig,
                            onOpenGroups = onOpenGroups,
                        )
                        OutboundModeCard(
                            outboundMode = outboundMode,
                            running = running,
                            starting = heroState == HeroConnectionState.STARTING,
                            onSelectMode = onSwitchOutboundMode,
                            onToggleTun = onStartStop,
                        )
                        leftCards.forEach { (idx, cardId) ->
                            key(cardId) {
                                ReorderableDashboardCardFrame(
                                    cardId = cardId,
                                    index = idx,
                                    totalCount = orderedCards.size,
                                    editing = dashEditing,
                                    onMoveUp = { onDashVisibilityChange(dashVisibility.moveCard(cardId, -1, orderedCards)) },
                                    onMoveDown = { onDashVisibilityChange(dashVisibility.moveCard(cardId, +1, orderedCards)) },
                                    onHide = { onDashVisibilityChange(dashVisibility.toggleCard(cardId)) },
                                ) {
                                    renderDashboardCard(cardId)
                                }
                            }
                        }
                    }
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        rightCards.forEach { (idx, cardId) ->
                            key(cardId) {
                                ReorderableDashboardCardFrame(
                                    cardId = cardId,
                                    index = idx,
                                    totalCount = orderedCards.size,
                                    editing = dashEditing,
                                    onMoveUp = { onDashVisibilityChange(dashVisibility.moveCard(cardId, -1, orderedCards)) },
                                    onMoveDown = { onDashVisibilityChange(dashVisibility.moveCard(cardId, +1, orderedCards)) },
                                    onHide = { onDashVisibilityChange(dashVisibility.toggleCard(cardId)) },
                                ) {
                                    renderDashboardCard(cardId)
                                }
                            }
                        }
                    }
                }
            }
        } else {
            item(key = "hero", contentType = "hero") {
                FiveStateHeroCard(
                    heroState = heroState,
                    powerSave = powerSave,
                    uptimeMs = uptimeMs,
                    activeProfileName = activeProfileName,
                    activeExit = activeExit,
                    errorDetail = errorDetail,
                    onStartStop = onStartStop,
                    onOpenConfig = onOpenConfig,
                    onOpenGroups = onOpenGroups,
                )
            }
            item(key = "mode", contentType = "mode") {
                OutboundModeCard(
                    outboundMode = outboundMode,
                    running = running,
                    starting = heroState == HeroConnectionState.STARTING,
                    onSelectMode = onSwitchOutboundMode,
                    onToggleTun = onStartStop,
                )
            }
            itemsIndexed(
                items = orderedCards,
                key = { _, cardId -> cardId },
                contentType = { _, cardId -> cardId },
            ) { idx, cardId ->
                ReorderableDashboardCardFrame(
                    cardId = cardId,
                    index = idx,
                    totalCount = orderedCards.size,
                    editing = dashEditing,
                    onMoveUp = { onDashVisibilityChange(dashVisibility.moveCard(cardId, -1, orderedCards)) },
                    onMoveDown = { onDashVisibilityChange(dashVisibility.moveCard(cardId, +1, orderedCards)) },
                    onHide = { onDashVisibilityChange(dashVisibility.toggleCard(cardId)) },
                    modifier = Modifier.animateItem(
                        fadeInSpec = spring(stiffness = Spring.StiffnessMediumLow),
                        placementSpec = spring(
                            dampingRatio = Spring.DampingRatioNoBouncy,
                            stiffness = Spring.StiffnessMediumLow,
                        ),
                    ),
                ) {
                    renderDashboardCard(cardId)
                }
            }
        }
    }
}

@Composable
private fun OutboundModeCard(
    outboundMode: String,
    running: Boolean,
    starting: Boolean,
    onSelectMode: (String) -> Unit,
    onToggleTun: () -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OpticalSegmentedControl(
            options = listOf(
                "rule" to "规则",
                "global" to "全局",
                "direct" to "直连",
            ),
            selectedKey = outboundMode,
            onSelect = onSelectMode,
            modifier = Modifier.weight(1f),
        )
        FilterChip(
            selected = running,
            enabled = !starting,
            onClick = {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onToggleTun()
            },
            shape = RoundedCornerShape(999.dp),
            leadingIcon = {
                if (running) {
                    Icon(
                        painter = painterResource(R.drawable.ic_check),
                        contentDescription = null,
                        modifier = Modifier.size(15.dp),
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .background(ext.muted, CircleShape),
                    )
                }
            },
            label = {
                Text(
                    text = "TUN",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    softWrap = false,
                )
            },
            colors = FilterChipDefaults.filterChipColors(
                containerColor = ext.wellSurface,
                labelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                selectedLeadingIconColor = MaterialTheme.colorScheme.primary,
            ),
            border = FilterChipDefaults.filterChipBorder(
                enabled = !starting,
                selected = running,
                borderColor = ext.hairline,
                selectedBorderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.45f),
            ),
            modifier = Modifier.heightIn(min = 48.dp),
        )
    }
}

@Composable
private fun TelemetryKpiGrid(
    running: Boolean,
    metrics: MetricsSummary,
    onOpenConnections: () -> Unit,
) {
    val ext = NexusTheme.colors
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        MetricStatCard(
            label = "活跃连接",
            value = "${metrics.activeSessions}",
            subvalue = if (running) "实时" else "待连接",
            dotColor = if (metrics.activeSessions > 0L) MaterialTheme.colorScheme.primary else ext.muted,
            onClick = onOpenConnections,
            modifier = Modifier.weight(1f),
        )
        MetricStatCard(
            label = "累计流量",
            value = formatTrafficBytes(metrics.uploadBytes + metrics.downloadBytes),
            subvalue = if (running) "本次会话" else "待连接",
            dotColor = ext.success,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
internal fun QuickOnboardingCard(
    onPasteClipboard: (String) -> Unit,
    onOpenConfig: () -> Unit,
) {
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    OpticalCard(
        cornerRadius = 16.dp,
        borderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.45f),
        accentTint = MaterialTheme.colorScheme.primary.copy(alpha = 0.06f),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("导入首个代理节点", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Text("复制节点分享链接或订阅地址后可一键导入。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val clip = context.getSystemService(ClipboardManager::class.java)
                            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
                        onPasteClipboard(clip)
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(painter = painterResource(R.drawable.ic_paste), contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("剪贴板导入", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                OutlinedButton(onClick = onOpenConfig) { Text("档案") }
            }
        }
    }
}
