package org.nexus.android.ui

import androidx.annotation.DrawableRes
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
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
                    shape = RoundedCornerShape(999.dp),
                    color = ext.wellSurface,
                    border = BorderStroke(1.dp, ext.hairlineStrong),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
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
                    .clip(RoundedCornerShape(8.dp))
                    .clickable(onClick = onOpenGroups)
                    .padding(horizontal = 4.dp, vertical = 3.dp),
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
                shape = RoundedCornerShape(14.dp),
                color = ext.wellSurface,
                border = BorderStroke(1.dp, ext.hairline),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
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

@Composable
private fun QuickNodePillCard(
    node: OutboundMemberSnapshot,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val selected = node.selected
    val isTimeout = node.state.equals("timeout", ignoreCase = true) ||
        node.state.equals("unreachable", ignoreCase = true) ||
        node.latencyMs == 0L
    val unprobed = node.latencyMs < 0L && !isTimeout

    val borderColor by animateColorAsState(
        targetValue = if (selected) MaterialTheme.colorScheme.primary else ext.hairline,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "quickNodeBorder",
    )
    val bgColor by animateColorAsState(
        targetValue = if (selected) {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (ext.isDark) 0.65f else 0.72f)
        } else {
            ext.cardGradientTop
        },
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "quickNodeBg",
    )
    val (latencyText, latencyFg) = when {
        unprobed -> "--" to ext.muted
        isTimeout -> "超时" to ext.danger
        node.latencyMs < 80L -> "${node.latencyMs}ms" to ext.success
        node.latencyMs < 180L -> "${node.latencyMs}ms" to ext.warning
        node.latencyMs < 350L -> "${node.latencyMs}ms" to ext.slow
        else -> "${node.latencyMs}ms" to ext.danger
    }

    val interactionSource = remember { MutableInteractionSource() }
    val orbOuter = if (selected) MaterialTheme.colorScheme.primary else ext.muted
    val orbCore = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else ext.muted.copy(alpha = 0.55f)

    BoxWithConstraints(modifier = modifier) {
        val stacked = maxWidth < 168.dp
        val tileCorner = if (stacked) 16.dp else 22.dp
        val tileContent: @Composable () -> Unit = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = if (stacked) 8.dp else 9.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(20.dp)
                        .background(
                            brush = Brush.radialGradient(
                                0.0f to orbOuter.copy(alpha = if (selected) 0.52f else 0.24f),
                                0.65f to orbOuter.copy(alpha = if (selected) 0.22f else 0.10f),
                                1.0f to Color.Transparent,
                            ),
                            shape = CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .size(if (selected) 8.dp else 7.dp)
                            .background(color = orbCore, shape = CircleShape),
                    )
                }
                if (stacked) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                        Text(
                            text = node.name,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold,
                            color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = latencyText,
                            style = NexusNumericStyles.monoBadge,
                            color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.88f) else latencyFg,
                            maxLines = 1,
                            softWrap = false,
                        )
                    }
                } else {
                    Text(
                        text = node.name,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold,
                        color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = latencyText,
                        style = NexusNumericStyles.monoBadge,
                        color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.90f) else latencyFg,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
        }

        if (selected) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .liquidPress(interactionSource = interactionSource, pressedScale = 0.96f)
                    .liquidGlassSurface(
                        tint = MaterialTheme.colorScheme.primary,
                        surfaceBase = bgColor,
                        cornerRadius = tileCorner,
                        isDark = ext.isDark,
                        rimIntensity = 0.95f,
                    )
                    .clickable(interactionSource = interactionSource, indication = null, onClick = onClick),
            ) { tileContent() }
        } else {
            Surface(
                onClick = onClick,
                interactionSource = interactionSource,
                modifier = Modifier.fillMaxWidth().liquidPress(interactionSource = interactionSource, pressedScale = 0.96f),
                shape = RoundedCornerShape(if (stacked) 16.dp else 999.dp),
                color = bgColor,
                border = BorderStroke(1.dp, borderColor),
            ) { tileContent() }
        }
    }
}

/**
 * Slim 1-row quick tools bar (`测速` / `清缓存` / `分应用`) when the speed wave & status cards
 * already display totals and DL/UL proportions, or full TrafficSplit card when those are hidden.
 */
@Composable
internal fun TrafficSplitCard(
    running: Boolean,
    downloadBytes: Long,
    uploadBytes: Long,
    excludedCount: Int,
    isProbing: Boolean,
    diagnostic: String,
    compactToolsOnly: Boolean = false,
    onProbeGroup: () -> Unit,
    onClearCache: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val totalBytes = (downloadBytes + uploadBytes).coerceAtLeast(0L)
    val hasTraffic = totalBytes > 0L
    val dlPct = if (hasTraffic) ((downloadBytes * 100L) / totalBytes).toInt() else 0
    val ulPct = if (hasTraffic) (100 - dlPct) else 0

    val toolsRow: @Composable () -> Unit = {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
            QuickActionPill(
                label = if (excludedCount > 0) "分应用 · $excludedCount" else "分应用",
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

    OpticalCard(modifier = modifier.fillMaxWidth(), cornerRadius = 20.dp) {
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
            .liquidPress(interactionSource = interactionSource, pressedScale = 0.95f)
            .alpha(if (enabled) 1f else 0.48f),
        shape = RoundedCornerShape(999.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp),
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
