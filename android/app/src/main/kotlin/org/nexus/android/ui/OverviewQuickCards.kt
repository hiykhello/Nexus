package org.nexus.android.ui

import androidx.annotation.DrawableRes
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Horizontal Bento quick-switch carousel for top nodes in the active policy group.
 */
@Composable
internal fun QuickNodesCarouselCard(
    running: Boolean,
    groupTag: String,
    nodes: List<OutboundMemberSnapshot>,
    isProbing: Boolean,
    onSelectNode: (OutboundMemberSnapshot) -> Unit,
    onProbeGroup: () -> Unit,
    onOpenGroups: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "快捷切换",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (groupTag.isNotEmpty()) {
                StatusPill(
                    text = groupTag,
                    containerColor = ext.wellSurface,
                    contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.weight(1f))
            if (running && groupTag.isNotEmpty()) {
                Surface(
                    onClick = {
                        if (!isProbing) {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onProbeGroup()
                        }
                    },
                    modifier = Modifier.minimumInteractiveComponentSize(),
                    shape = RoundedCornerShape(999.dp),
                    color = ext.wellSurface,
                    border = BorderStroke(1.dp, ext.hairlineStrong),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        if (isProbing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(12.dp),
                                strokeWidth = 1.8.dp,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        } else {
                            Icon(
                                painter = painterResource(R.drawable.ic_speed),
                                contentDescription = "测速",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(13.dp),
                            )
                        }
                        Text(
                            text = if (isProbing) "测速中" else "测速",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            softWrap = false,
                        )
                    }
                }
            }
            Row(
                modifier = Modifier
                    .minimumInteractiveComponentSize()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable(onClick = onOpenGroups)
                    .padding(horizontal = 6.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = "全部",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Icon(
                    painter = painterResource(R.drawable.ic_chevron_right),
                    contentDescription = "查看策略组",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(15.dp),
                )
            }
        }

        if (nodes.isNotEmpty()) {
            val topFour = nodes.take(4)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                topFour.chunked(2).forEach { pair ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        pair.forEach { node ->
                            QuickNodePillCard(
                                node = node,
                                onClick = {
                                    if (!node.selected) {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        onSelectNode(node)
                                    }
                                },
                                modifier = Modifier.weight(1f),
                            )
                        }
                        if (pair.size == 1) {
                            Spacer(Modifier.weight(1f))
                        }
                    }
                }
            }
        } else {
            Surface(
                onClick = onOpenGroups,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = if (running) "自动选优中" else "连接后显示快捷节点",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Icon(
                        painter = painterResource(R.drawable.ic_chevron_right),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
    }
}

/**
 * Slim 1-row quick tools bar (`清缓存` / `诊断` / `分应用` — deduplicated from QuickNodes's `测速`
 * button) or full TrafficSplit card when speed wave & status cards are hidden.
 */
@Composable
internal fun TrafficSplitCard(
    running: Boolean,
    downloadBytes: Long,
    uploadBytes: Long,
    excludedCount: Int,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    isProbing: Boolean,
    diagnostic: String,
    compactToolsOnly: Boolean = false,
    onProbeGroup: () -> Unit,
    onClearCache: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenDiagnostics: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val totalBytes = (downloadBytes + uploadBytes).coerceAtLeast(0L)
    val hasTraffic = totalBytes > 0L
    val dlPct = if (hasTraffic) ((downloadBytes * 100L) / totalBytes).toInt() else 0
    val ulPct = if (hasTraffic) (100 - dlPct) else 0

    val perAppPillLabel = when (perAppMode) {
        AndroidPerAppMode.OFF -> "分应用"
        AndroidPerAppMode.EXCLUDE -> if (excludedCount > 0) "绕过 · $excludedCount" else "分应用"
        AndroidPerAppMode.INCLUDE -> "仅代理 · $excludedCount"
    }

    val toolsRow: @Composable () -> Unit = {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (onOpenDiagnostics != null) {
                QuickActionPill(
                    label = "清缓存",
                    iconRes = R.drawable.ic_delete,
                    enabled = running,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onClearCache() },
                    modifier = Modifier.weight(1f),
                )
                QuickActionPill(
                    label = "诊断",
                    iconRes = R.drawable.ic_rule,
                    enabled = true,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onOpenDiagnostics() },
                    modifier = Modifier.weight(1f),
                )
            } else {
                QuickActionPill(
                    label = if (isProbing) "测速中" else "测速",
                    iconRes = R.drawable.ic_speed,
                    enabled = running && !isProbing,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.LongPress); onProbeGroup() },
                    modifier = Modifier.weight(1f),
                )
                QuickActionPill(
                    label = "清缓存",
                    iconRes = R.drawable.ic_delete,
                    enabled = running,
                    onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onClearCache() },
                    modifier = Modifier.weight(1f),
                )
            }
            QuickActionPill(
                label = perAppPillLabel,
                iconRes = R.drawable.ic_apps,
                enabled = true,
                onClick = onOpenSplitTunnel,
                modifier = Modifier.weight(1.18f),
            )
        }
    }

    val diagnosticBanner: @Composable () -> Unit = {
        if (diagnostic.isNotEmpty()) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = diagnostic,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                )
            }
        }
    }

    if (compactToolsOnly) {
        Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            toolsRow()
            diagnosticBanner()
        }
        return
    }

    OpticalCard(modifier = modifier.fillMaxWidth(), cornerRadius = 16.dp) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text("流量构成", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f))
                Text("↓ ${formatTrafficBytes(downloadBytes)}", style = NexusNumericStyles.monoBadge, color = ext.telemetryDownload, maxLines = 1, softWrap = false)
                Text("·", style = NexusNumericStyles.monoBadge, color = ext.muted)
                Text("↑ ${formatTrafficBytes(uploadBytes)}", style = NexusNumericStyles.monoBadge, color = ext.telemetryUpload, maxLines = 1, softWrap = false)
            }
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                NexusProportionBar(downloadBytes, uploadBytes, ext.telemetryDownload, ext.telemetryUpload)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(
                        text = if (hasTraffic) "下行 $dlPct%" else "暂无流量",
                        style = MaterialTheme.typography.labelSmall,
                        color = if (hasTraffic) ext.telemetryDownload else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (hasTraffic) {
                        Text("上行 $ulPct%", style = MaterialTheme.typography.labelSmall, color = ext.telemetryUpload)
                    }
                }
            }
            toolsRow()
            diagnosticBanner()
        }
    }
}

@Composable
private fun QuickActionPill(
    label: String,
    @DrawableRes iconRes: Int,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val interactionSource = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        enabled = enabled,
        interactionSource = interactionSource,
        modifier = modifier
            .minimumInteractiveComponentSize()
            .heightIn(min = 48.dp)
            .liquidPress(interactionSource = interactionSource, pressedScale = 0.97f)
            .alpha(if (enabled) 1f else 0.48f),
        shape = RoundedCornerShape(999.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            Icon(
                painter = painterResource(iconRes),
                contentDescription = null,
                tint = if (enabled) MaterialTheme.colorScheme.primary else ext.muted,
                modifier = Modifier.size(14.dp),
            )
            Spacer(Modifier.width(5.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                softWrap = false,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
