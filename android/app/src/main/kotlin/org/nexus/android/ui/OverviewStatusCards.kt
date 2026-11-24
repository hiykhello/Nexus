package org.nexus.android.ui

import androidx.annotation.DrawableRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme
import kotlin.math.roundToInt

internal fun sampleRuntimeMemoryText(): String {
    val rt = Runtime.getRuntime()
    val used = (rt.totalMemory() - rt.freeMemory()).coerceAtLeast(0L)
    return formatTrafficBytes(used)
}

/**
 * Nexus 2-segment proportion bar:
 * 8dp full-pill rounded bar with a 2dp animated gap between active segments and whole-percent
 * rounding so 1Hz telemetry jitter never replays layout animations unnecessarily.
 */
@Composable
internal fun NexusProportionBar(
    firstBytes: Long,
    secondBytes: Long,
    firstColor: Color,
    secondColor: Color,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val a = firstBytes.coerceAtLeast(0L)
    val b = secondBytes.coerceAtLeast(0L)
    val total = a + b
    val firstPct = if (total > 0L) ((a * 100.0) / total).roundToInt() else 0
    val secondPct = if (total > 0L) (100 - firstPct) else 0
    val hasBoth = firstPct > 0 && secondPct > 0
    val targetFirst = when {
        total == 0L -> 0f
        firstPct <= 0 -> 0f
        secondPct <= 0 -> 1f
        else -> (firstPct / 100f).coerceIn(0.06f, 0.94f)
    }
    val animFirst by animateFloatAsState(
        targetValue = targetFirst,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "propFirst",
    )
    val gapWidth by animateDpAsState(
        targetValue = if (hasBoth) 2.dp else 0.dp,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "propGap",
    )

    Row(
        modifier = modifier
            .fillMaxWidth()
            .height(8.dp)
            .clip(CircleShape)
            .background(ext.insetSurface),
    ) {
        if (total > 0L) {
            if (animFirst > 0.005f) {
                Box(Modifier.weight(animFirst).fillMaxHeight().background(firstColor))
            }
            if (gapWidth > 0.dp) {
                Spacer(Modifier.width(gapWidth))
            }
            val rem = (1f - animFirst).coerceAtLeast(0f)
            if (rem > 0.005f) {
                Box(Modifier.weight(rem).fillMaxHeight().background(secondColor))
            }
        }
    }
}

/**
 * Animated Overview Bento customization bar for card visibility and ordering.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun DashboardCustomizeBar(
    visible: Boolean,
    visibility: DashboardCardVisibility,
    onChange: (DashboardCardVisibility) -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val accent = MaterialTheme.colorScheme.primary
    AnimatedVisibility(
        visible = visible,
        enter = expandVertically() + fadeIn(),
        exit = shrinkVertically() + fadeOut(),
        modifier = modifier,
    ) {
        OpticalCard(
            cornerRadius = 18.dp,
            borderColor = accent.copy(alpha = 0.48f),
            accentTint = accent.copy(alpha = 0.09f),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 13.dp, vertical = 11.dp),
                verticalArrangement = Arrangement.spacedBy(9.dp),
            ) {
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = "自定义首页布局",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = "拖拽 ⠿ 或点按 ↑ ↓ 调整顺序 · 点选下方开关显隐",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    if (visibility.hasCustomLayout) {
                        Text(
                            text = "恢复默认",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = accent,
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onChange(DashboardCardVisibility())
                                }
                                .padding(horizontal = 8.dp, vertical = 4.dp),
                        )
                    }
                }
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(7.dp),
                    verticalArrangement = Arrangement.spacedBy(7.dp),
                ) {
                    DashboardCardVisibility.DEFAULT_CARD_ORDER.forEach { cardId ->
                        val active = visibility.isCardVisible(cardId)
                        Surface(
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onChange(visibility.toggleCard(cardId))
                            },
                            shape = RoundedCornerShape(999.dp),
                            color = if (active) accent.copy(alpha = if (ext.isDark) 0.24f else 0.14f) else ext.wellSurface,
                            border = BorderStroke(
                                width = 1.dp,
                                color = if (active) accent.copy(alpha = 0.65f) else ext.hairline,
                            ),
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(5.dp),
                            ) {
                                if (active) {
                                    Icon(
                                        painter = painterResource(R.drawable.ic_check),
                                        contentDescription = null,
                                        tint = accent,
                                        modifier = Modifier.size(13.dp),
                                    )
                                }
                                Text(
                                    text = DashboardCardVisibility.cardLabel(cardId),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = if (active) FontWeight.SemiBold else FontWeight.Medium,
                                    color = if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    softWrap = false,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * 2-column smoked-graphite mini-Bento status pair:
 * - Left (`网络状态`): live 4-bar signal + active exit & latency (tap triggers probe / opens Groups)
 * - Right (`内存与连接`): runtime memory + active connections + 2-segment DL/UL `NexusProportionBar`
 */
@Composable
internal fun OverviewStatusMiniPair(
    running: Boolean,
    activeExit: ActiveExitSummary,
    memoryText: String,
    activeSessions: Long,
    downloadBytes: Long,
    uploadBytes: Long,
    isProbing: Boolean,
    onNetworkClick: () -> Unit,
    onConnectionsClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val isTimeout = activeExit.state.equals("timeout", ignoreCase = true) ||
        activeExit.state.equals("unreachable", ignoreCase = true) ||
        activeExit.latencyMs == 0L
    val latencyColor = when {
        !running || activeExit.latencyMs < 0L -> ext.muted
        isTimeout -> ext.danger
        activeExit.latencyMs < 80L -> ext.success
        activeExit.latencyMs < 180L -> ext.warning
        activeExit.latencyMs < 350L -> ext.slow
        else -> ext.danger
    }
    val networkSub = when {
        !running -> "点击选择节点"
        isProbing -> "探测延迟"
        isTimeout -> "超时"
        activeExit.latencyMs > 0L -> "${activeExit.latencyMs} ms"
        else -> "未测速"
    }
    val qualityLabel = when {
        !running -> "待连接"
        isProbing -> "测速中…"
        isTimeout -> "超时"
        activeExit.latencyMs in 1L..79L -> "极佳"
        activeExit.latencyMs in 80L..179L -> "良好"
        activeExit.latencyMs >= 180L -> "波动"
        else -> "就绪"
    }

    Row(
        modifier = modifier.fillMaxWidth().height(IntrinsicSize.Max),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        StatusMiniBentoTile(
            title = "网络状态",
            trailingIconRes = R.drawable.ic_speed,
            trailingTint = if (running) ext.success else MaterialTheme.colorScheme.onSurfaceVariant,
            trailingLabel = "",
            onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onNetworkClick() },
            modifier = Modifier.weight(1f).fillMaxHeight(),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                SignalBarsIndicator(if (running) activeExit.latencyMs else -1L, if (running) activeExit.state else "unknown")
                Text(
                    text = qualityLabel,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.weight(1f))
            Text(
                text = if (running) "${activeExit.memberName.ifEmpty { "自动" }} · $networkSub" else networkSub,
                style = NexusNumericStyles.monoBadge,
                color = if (running) latencyColor else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        StatusMiniBentoTile(
            title = "连接与流量",
            trailingIconRes = null,
            trailingTint = MaterialTheme.colorScheme.onSurfaceVariant,
            trailingLabel = memoryText.ifEmpty { "--" },
            onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onConnectionsClick() },
            modifier = Modifier.weight(1f).fillMaxHeight(),
        ) {
            Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(
                    text = "$activeSessions",
                    style = MaterialTheme.typography.titleLarge.copy(
                        fontFamily = FontFamily.SansSerif,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 21.sp,
                        letterSpacing = (-0.5).sp,
                        fontFeatureSettings = "tnum",
                    ),
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    softWrap = false,
                )
                Text(
                    text = "活跃连接",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(bottom = 2.dp),
                )
            }
            Spacer(Modifier.weight(1f))
            NexusProportionBar(
                firstBytes = downloadBytes,
                secondBytes = uploadBytes,
                firstColor = ext.telemetryDownload,
                secondColor = ext.telemetryUpload,
                modifier = Modifier.padding(bottom = 2.dp),
            )
        }
    }
}

@Composable
private fun StatusMiniBentoTile(
    title: String,
    @DrawableRes trailingIconRes: Int?,
    trailingTint: Color,
    trailingLabel: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    body: @Composable ColumnScope.() -> Unit,
) {
    val ext = NexusTheme.colors
    val interactionSource = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        interactionSource = interactionSource,
        modifier = modifier.liquidPress(interactionSource = interactionSource, pressedScale = 0.96f),
        shape = RoundedCornerShape(20.dp),
        color = Color.Transparent,
        border = BorderStroke(1.dp, ext.hairline),
    ) {
        OpticalCard(
            modifier = Modifier.fillMaxHeight(),
            cornerRadius = 20.dp,
            borderColor = Color.Transparent,
            borderWidth = 0.dp,
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().fillMaxHeight().padding(horizontal = 12.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    if (trailingLabel.isNotEmpty()) {
                        Text(
                            text = trailingLabel,
                            style = NexusNumericStyles.monoBadge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            softWrap = false,
                        )
                    } else if (trailingIconRes != null) {
                        Icon(
                            painter = painterResource(trailingIconRes),
                            contentDescription = null,
                            tint = trailingTint,
                            modifier = Modifier.size(15.dp),
                        )
                    }
                }
                body()
            }
        }
    }
}
