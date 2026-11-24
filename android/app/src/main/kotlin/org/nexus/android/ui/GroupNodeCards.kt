package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.ui.theme.NexusTheme

private fun isMemberTimeout(member: OutboundMemberSnapshot): Boolean =
    member.state.equals("timeout", ignoreCase = true) ||
        member.state.equals("unreachable", ignoreCase = true) ||
        member.latencyMs == 0L

private fun isMemberHealthy(member: OutboundMemberSnapshot): Boolean =
    !isMemberTimeout(member) && member.latencyMs > 0L

@Composable
internal fun GroupSummaryStrip(
    group: OutboundGroupSnapshot,
    isProbing: Boolean,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val total = group.members.size
    val healthyCount = group.members.count { isMemberHealthy(it) }
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
        cornerRadius = 20.dp,
        borderColor = if (isProbing) MaterialTheme.colorScheme.primary.copy(alpha = 0.55f) else ext.hairline,
        accentTint = if (isProbing) MaterialTheme.colorScheme.primary.copy(alpha = 0.08f) else Color.Transparent,
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
                    if (activeMember != null) {
                        SignalBarsIndicator(latencyMs = activeMember.latencyMs, state = activeMember.state)
                    }
                    StatusPill(
                        text = "$healthyCount/$total 可用",
                        containerColor = if (healthyCount > 0) ext.successContainer else ext.mutedContainer,
                        contentColor = if (healthyCount > 0) ext.success else ext.muted,
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
    val healthyCount = group.members.count { isMemberHealthy(it) }
    OpticalCard(
        cornerRadius = 16.dp,
        borderColor = if (selected) MaterialTheme.colorScheme.primary else ext.hairline,
        borderWidth = if (selected) 1.5.dp else 1.dp,
        accentTint = if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.12f) else Color.Transparent,
        onClick = onClick,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
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
            Text(
                text = "${group.active.ifEmpty { "-" }} · $healthyCount/${group.members.size} 可用",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
internal fun GroupMemberCard(
    member: OutboundMemberSnapshot,
    onSelect: () -> Unit,
) {
    val ext = NexusTheme.colors
    val selected = member.selected
    val isTimeout = isMemberTimeout(member)
    val unprobed = member.latencyMs < 0L && !isTimeout
    val (qualityText, qualityColor, orbTint) = when {
        unprobed -> Triple("待测速", ext.muted, ext.muted)
        isTimeout -> Triple("不可达", ext.danger, ext.danger)
        member.latencyMs >= 350L -> Triple("高延迟", ext.danger, ext.danger)
        member.latencyMs >= 180L -> Triple("波动", ext.slow, ext.slow)
        member.latencyMs >= 80L -> Triple("良好", ext.warning, Color(0xFF60A5FA))
        else -> Triple("极速", ext.success, Color(0xFF38BDF8))
    }
    val effectiveOrbColor = if (selected) Color(0xFF3B82F6) else orbTint

    OpticalCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 18.dp,
        borderColor = if (selected) Color(0xFF3B82F6).copy(alpha = 0.80f) else ext.hairline,
        borderWidth = if (selected) 1.5.dp else 1.dp,
        accentTint = if (selected) Color(0xFF2563EB).copy(alpha = if (ext.isDark) 0.16f else 0.08f) else Color.Transparent,
        onClick = if (!selected) onSelect else null,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 13.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ConcentricNodeOrb(
                accent = effectiveOrbColor,
                selected = selected,
                isDark = ext.isDark,
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
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
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = qualityText,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Medium,
                        color = qualityColor,
                    )
                    SignalBarsIndicator(latencyMs = member.latencyMs, state = member.state)
                }
            }
            LatencyBadge(latencyMs = member.latencyMs, state = member.state)
            if (selected) {
                Icon(
                    painter = painterResource(R.drawable.ic_check),
                    contentDescription = "当前节点",
                    tint = Color(0xFF60A5FA),
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}

/**
 * Zero-allocation concentric radial node-orb matching `nexus_design_v8_android_subpages.jpg`.
 */
@Composable
private fun ConcentricNodeOrb(
    accent: Color,
    selected: Boolean,
    isDark: Boolean,
) {
    Box(
        modifier = Modifier
            .size(32.dp)
            .drawWithCache {
                val r = size.minDimension * 0.5f
                val orbCenter = Offset(size.width * 0.5f, size.height * 0.5f)
                val bloom = Brush.radialGradient(
                    0.0f to accent.copy(alpha = if (selected) 0.58f else if (isDark) 0.30f else 0.20f),
                    0.55f to accent.copy(alpha = if (selected) 0.24f else if (isDark) 0.12f else 0.07f),
                    1.0f to Color.Transparent,
                    center = orbCenter,
                    radius = r,
                )
                val ringOuter = Stroke(width = 1.2.dp.toPx())
                val ringInner = Stroke(width = 1.4.dp.toPx())
                val outerColor = accent.copy(alpha = if (selected) 0.72f else if (isDark) 0.36f else 0.30f)
                val innerColor = accent.copy(alpha = if (selected) 0.92f else if (isDark) 0.55f else 0.45f)
                val coreColor = if (selected) Color(0xFF93C5FD) else accent.copy(alpha = 0.85f)
                onDrawBehind {
                    drawCircle(brush = bloom, radius = r)
                    drawCircle(color = outerColor, radius = r * 0.84f, style = ringOuter)
                    drawCircle(color = innerColor, radius = r * 0.52f, style = ringInner)
                    drawCircle(color = coreColor, radius = r * 0.24f)
                }
            },
    )
}
