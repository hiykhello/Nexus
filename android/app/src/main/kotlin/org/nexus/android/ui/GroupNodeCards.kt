package org.nexus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.ui.theme.NexusTheme

@Composable
internal fun GroupSummaryStrip(
    group: OutboundGroupSnapshot,
    isProbing: Boolean,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val stats = remember(group) { computeGroupLatencyStats(group.members) }
    val activeMember = group.members.firstOrNull { it.selected }
    val modeLabel = when {
        group.manualOverride -> "手动"
        group.mode == "selector" -> "手动"
        else -> "自动优选"
    }
    val (modeBg, modeFg) = when {
        group.manualOverride -> ext.warningContainer to ext.warning
        group.mode == "selector" -> MaterialTheme.colorScheme.secondaryContainer to MaterialTheme.colorScheme.onSecondaryContainer
        else -> ext.wellSurface to MaterialTheme.colorScheme.onSurfaceVariant
    }

    OpticalCard(
        modifier = modifier.fillMaxWidth(),
        cornerRadius = 16.dp,
        borderColor = if (isProbing) MaterialTheme.colorScheme.primary.copy(alpha = 0.55f) else ext.hairline,
        accentTint = if (isProbing) MaterialTheme.colorScheme.primary.copy(alpha = 0.06f) else Color.Transparent,
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 15.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        Text(
                            text = group.tag,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false),
                        )
                        StatusPill(
                            text = modeLabel,
                            containerColor = modeBg,
                            contentColor = modeFg,
                        )
                    }
                    Text(
                        text = if (isProbing) "正在测速…" else "当前 ${group.active.ifEmpty { "-" }}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Column(
                    horizontalAlignment = Alignment.End,
                    verticalArrangement = Arrangement.spacedBy(5.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        if (stats.p50Ms != null) {
                            StatusPill(
                                text = "P50 ${stats.p50Ms} ms",
                                containerColor = ext.wellSurface,
                                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                mono = true,
                            )
                        }
                        if (activeMember != null) {
                            SignalBarsIndicator(latencyMs = activeMember.latencyMs, state = activeMember.state)
                        }
                    }
                    StatusPill(
                        text = "${stats.healthyCount}/${stats.total} 可用",
                        containerColor = if (stats.healthyCount > 0) ext.successContainer else ext.mutedContainer,
                        contentColor = if (stats.healthyCount > 0) ext.success else ext.muted,
                        mono = true,
                    )
                }
            }
            if (isProbing) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().height(2.dp),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = ext.wellSurface,
                )
            } else {
                LatencySpectrumBar(
                    stats = stats,
                    height = 3.dp,
                    modifier = Modifier.padding(start = 15.dp, end = 15.dp, bottom = 10.dp),
                )
            }
        }
    }
}

@Composable
internal fun GroupRailCard(
    group: OutboundGroupSnapshot,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val ext = NexusTheme.colors
    val stats = remember(group) { computeGroupLatencyStats(group.members) }
    OpticalCard(
        cornerRadius = 16.dp,
        borderColor = if (selected) MaterialTheme.colorScheme.primary else ext.hairline,
        borderWidth = if (selected) 1.5.dp else 1.dp,
        accentTint = if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.08f) else Color.Transparent,
        onClick = onClick,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = group.tag,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (!group.manualOverride && group.mode != "selector") {
                    StatusPill(
                        text = "自动",
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                } else if (group.manualOverride) {
                    StatusPill(
                        text = "手动",
                        containerColor = ext.warningContainer,
                        contentColor = ext.warning,
                    )
                }
            }
            val p50Suffix = stats.p50Ms?.let { " · P50 ${it}ms" }.orEmpty()
            Text(
                text = "${group.active.ifEmpty { "-" }} · ${stats.healthyCount}/${stats.total}$p50Suffix",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            LatencySpectrumBar(stats = stats, height = 2.dp)
        }
    }
}

@Composable
internal fun GroupMemberCard(
    member: OutboundMemberSnapshot,
    onSelect: () -> Unit,
    isProbing: Boolean = false,
    groupMaxHealthyMs: Long = 0L,
    onProbe: (() -> Unit)? = null,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val selected = member.selected
    val meterFraction = computeMemberRelativeFraction(member.latencyMs, member.state, groupMaxHealthyMs)
    val meterColor = when {
        meterFraction <= 0f -> Color.Transparent
        member.latencyMs < 80L -> ext.success
        member.latencyMs < 180L -> ext.warning
        member.latencyMs < 350L -> ext.slow
        else -> ext.danger
    }
    val meterAlpha = if (ext.isDark) 0.08f else 0.06f

    OpticalCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 16.dp,
        borderColor = if (selected) primary.copy(alpha = 0.80f) else ext.hairline,
        borderWidth = if (selected) 1.5.dp else 1.dp,
        accentTint = if (selected) primary.copy(alpha = if (ext.isDark) 0.12f else 0.06f) else Color.Transparent,
        onClick = if (!selected) onSelect else null,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .drawBehind {
                    if (!selected && meterFraction > 0f) {
                        drawRect(
                            color = meterColor.copy(alpha = meterAlpha),
                            topLeft = Offset.Zero,
                            size = Size(size.width * meterFraction, size.height),
                        )
                    }
                }
                .padding(start = 13.dp, end = if (onProbe != null) 4.dp else 13.dp, top = 11.dp, bottom = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                modifier = Modifier.size(20.dp),
                contentAlignment = Alignment.Center,
            ) {
                if (selected) {
                    Icon(
                        painter = painterResource(R.drawable.ic_check),
                        contentDescription = "当前节点",
                        tint = primary,
                        modifier = Modifier.size(18.dp),
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .background(ext.muted.copy(alpha = 0.42f), CircleShape),
                    )
                }
            }
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = member.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (member.overridden) {
                    StatusPill(
                        text = "手动",
                        containerColor = ext.warningContainer,
                        contentColor = ext.warning,
                    )
                }
            }
            SignalBarsIndicator(latencyMs = member.latencyMs, state = member.state)
            LatencyBadge(latencyMs = member.latencyMs, state = member.state)
            if (onProbe != null) {
                IconButton(
                    onClick = onProbe,
                    enabled = !isProbing,
                ) {
                    if (isProbing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = primary,
                        )
                    } else {
                        Icon(
                            painter = painterResource(R.drawable.ic_speed),
                            contentDescription = "单节点测速",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
            }
        }
    }
}
