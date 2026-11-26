package org.nexus.android.ui

import androidx.annotation.DrawableRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
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
import org.nexus.android.ui.theme.NexusTheme
import kotlin.math.roundToInt

internal fun sampleRuntimeMemoryText(): String {
    val rt = Runtime.getRuntime()
    val used = (rt.totalMemory() - rt.freeMemory()).coerceAtLeast(0L)
    return formatTrafficBytes(used)
}

/**
 * Nexus 2-segment proportion bar:
 * 8dp full-pill rounded bar rendered directly in the Draw phase (`drawBehind`) with 0ms functional
 * telemetry updates (no spring lag on 1Hz data ticks).
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
    val trackColor = ext.insetSurface

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(8.dp)
            .clip(CircleShape)
            .drawBehind {
                drawRect(color = trackColor)
                if (total > 0L && size.width > 0f) {
                    val gapPx = if (hasBoth) 2.dp.toPx() else 0f
                    val usable = (size.width - gapPx).coerceAtLeast(0f)
                    val firstFrac = targetFirst.coerceIn(0f, 1f)
                    val firstW = usable * firstFrac
                    val secondW = usable * (1f - firstFrac)
                    if (firstW > 0.5f) {
                        drawRect(color = firstColor, topLeft = Offset.Zero, size = Size(firstW, size.height))
                    }
                    if (secondW > 0.5f) {
                        val startX = if (firstW > 0.5f) firstW + gapPx else 0f
                        drawRect(color = secondColor, topLeft = Offset(startX, 0f), size = Size(secondW, size.height))
                    }
                }
            },
    )
}

/**
 * Animated Overview Bento customization bar for card visibility and ordering (capped <= 180ms ease-out).
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
    val reducedMotion = isReducedMotionEnabled()
    val enterDuration = if (reducedMotion) 0 else 180
    val exitDuration = if (reducedMotion) 0 else 150
    val accent = MaterialTheme.colorScheme.primary

    AnimatedVisibility(
        visible = visible,
        enter = expandVertically(tween(enterDuration, easing = FastOutSlowInEasing)) +
            fadeIn(tween(enterDuration, easing = FastOutSlowInEasing)),
        exit = shrinkVertically(tween(exitDuration, easing = FastOutSlowInEasing)) +
            fadeOut(tween(exitDuration, easing = FastOutSlowInEasing)),
        modifier = modifier,
    ) {
        OpticalCard(
            cornerRadius = 16.dp,
            borderColor = accent.copy(alpha = 0.45f),
            accentTint = accent.copy(alpha = 0.05f),
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
                        Box(
                            modifier = Modifier
                                .minimumInteractiveComponentSize()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onChange(DashboardCardVisibility())
                                }
                                .padding(horizontal = 8.dp, vertical = 8.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                text = "恢复默认",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = accent,
                            )
                        }
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
                            modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 36.dp),
                            shape = RoundedCornerShape(999.dp),
                            color = if (active) accent.copy(alpha = if (ext.isDark) 0.22f else 0.14f) else ext.wellSurface,
                            border = BorderStroke(
                                width = 1.dp,
                                color = if (active) accent.copy(alpha = 0.60f) else ext.hairline,
                            ),
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
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
 * 2-column flat M3 tonal mini-Bento status pair (zero duplication with Hero Card):
 * - Left (`路由与 DNS`): active routing profile & DNS/FakeIP status (tap opens Diagnostics/Config)
 * - Right (`活跃连接`): active connection count + honestly labeled app memory + DL/UL proportion bar
 */
@Composable
internal fun OverviewStatusMiniPair(
    running: Boolean,
    routingProfileName: String = "",
    dnsSummaryText: String = "",
    outboundMode: String = "rule",
    memoryText: String,
    activeSessions: Long,
    downloadBytes: Long,
    uploadBytes: Long,
    onRoutingClick: () -> Unit,
    onConnectionsClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val modeLabel = when (outboundMode) {
        "global" -> "全局代理"
        "direct" -> "全局直连"
        else -> routingProfileName.ifEmpty { "智能分流" }
    }
    val dnsLine = dnsSummaryText.ifEmpty {
        if (running) "FakeIP · 生效中" else "点击查看规则"
    }

    Row(
        modifier = modifier.fillMaxWidth().height(IntrinsicSize.Max),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        StatusMiniBentoTile(
            title = "路由与 DNS",
            trailingIconRes = R.drawable.ic_rule,
            trailingTint = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            onClick = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove); onRoutingClick() },
            modifier = Modifier.weight(1f).fillMaxHeight(),
        ) {
            Text(
                text = modeLabel,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.weight(1f))
            Text(
                text = dnsLine,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        StatusMiniBentoTile(
            title = "活跃连接",
            trailingIconRes = R.drawable.ic_nav_connections,
            trailingTint = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
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
                if (memoryText.isNotEmpty()) {
                    Text(
                        text = "应用 $memoryText",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(bottom = 2.dp),
                    )
                }
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
    @DrawableRes trailingIconRes: Int,
    trailingTint: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    body: @Composable ColumnScope.() -> Unit,
) {
    val ext = NexusTheme.colors
    val interactionSource = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        interactionSource = interactionSource,
        modifier = modifier.liquidPress(interactionSource = interactionSource, pressedScale = 0.97f),
        shape = RoundedCornerShape(16.dp),
        color = ext.cardSurface,
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(1.dp, ext.hairline),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().fillMaxHeight().padding(horizontal = 12.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
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
                Icon(
                    painter = painterResource(trailingIconRes),
                    contentDescription = null,
                    tint = trailingTint,
                    modifier = Modifier.size(15.dp),
                )
            }
            body()
        }
    }
}
