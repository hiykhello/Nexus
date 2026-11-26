package org.nexus.android.ui

import androidx.annotation.DrawableRes
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Optical Precision card container: subtle vertical elevation gradient, crisp 1dp hairline border,
 * and a directional 1dp top-edge specular highlight (`topSpeculum`).
 */
@Composable
fun OpticalCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 16.dp,
    borderColor: Color = NexusTheme.colors.hairline,
    borderWidth: Dp = 1.dp,
    accentTint: Color = Color.Transparent,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val ext = NexusTheme.colors
    val shape = RoundedCornerShape(cornerRadius)
    val clickModifier = if (onClick != null) {
        Modifier.clip(shape).clickable(onClick = onClick)
    } else {
        Modifier
    }
    Surface(
        modifier = modifier.then(clickModifier),
        shape = shape,
        color = Color.Transparent,
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = BorderStroke(borderWidth, borderColor),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        listOf(ext.cardGradientTop, ext.cardGradientBottom),
                    ),
                )
                .then(
                    if (accentTint != Color.Transparent) {
                        Modifier.background(
                            Brush.verticalGradient(
                                listOf(accentTint, Color.Transparent),
                            ),
                        )
                    } else {
                        Modifier
                    },
                ),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp)
                    .height(1.dp)
                    .background(
                        Brush.horizontalGradient(
                            listOf(Color.Transparent, ext.topSpeculum, ext.topSpeculum, Color.Transparent),
                        ),
                    ),
            )
            Column(
                modifier = Modifier.fillMaxWidth(),
                content = content,
            )
        }
    }
}

@Composable
fun OpticalSegmentedControl(
    options: List<Pair<String, String>>,
    selectedKey: String,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val count = options.size.coerceAtLeast(1)
    val selectedIdx = options.indexOfFirst { it.first == selectedKey }.coerceAtLeast(0)
    val pillShape = RoundedCornerShape(999.dp)

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = pillShape,
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxWidth().padding(4.dp),
        ) {
            val slotWidth = maxWidth / count
            val indicatorOffset by animateDpAsState(
                targetValue = slotWidth * selectedIdx,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioLowBouncy,
                    stiffness = Spring.StiffnessMediumLow,
                ),
                label = "segOffset",
            )
            Box(
                modifier = Modifier
                    .offset(x = indicatorOffset)
                    .width(slotWidth)
                    .height(36.dp)
                    .liquidGlassSurface(
                        tint = MaterialTheme.colorScheme.primary,
                        surfaceBase = MaterialTheme.colorScheme.primaryContainer,
                        cornerRadius = 18.dp,
                        isDark = ext.isDark,
                        rimIntensity = 0.95f,
                    ),
            )
            Row(modifier = Modifier.fillMaxWidth()) {
                options.forEach { (key, label) ->
                    val selected = key == selectedKey
                    val fg by animateColorAsState(
                        targetValue = if (selected) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
                        label = "segFg",
                    )
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(36.dp)
                            .clip(pillShape)
                            .clickable(enabled = enabled && !selected) {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onSelect(key)
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                            color = fg,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }
    }
}

/**
 * Edge-to-edge translucent top protection gradient ensuring status bar icons remain legible
 * while scrollable lists glide beneath the system status bar.
 */
@Composable
fun StatusBarProtection(
    color: Color = MaterialTheme.colorScheme.surface,
    modifier: Modifier = Modifier,
) {
    val density = LocalDensity.current
    val topPx = WindowInsets.statusBars.getTop(density)
    if (topPx <= 0) return
    val heightDp = with(density) { (topPx * 1.18f).toDp() }
    Spacer(
        modifier = modifier
            .fillMaxWidth()
            .height(heightDp)
            .background(
                Brush.verticalGradient(
                    colors = listOf(color, color.copy(alpha = 0.80f), Color.Transparent),
                ),
            ),
    )
}

@Composable
fun StatusPill(
    text: String,
    containerColor: Color,
    contentColor: Color,
    modifier: Modifier = Modifier,
    mono: Boolean = false,
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(6.dp),
        color = containerColor,
    ) {
        Text(
            text = text,
            color = contentColor,
            style = if (mono) NexusNumericStyles.monoBadge else MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

/**
 * 5-tier semantic latency pill decoupled from brand accent colors:
 * - Unprobed: Neutral "未测速"
 * - Timeout / 0ms: Danger "超时"
 * - <80ms: Emerald
 * - 80..179ms: Amber
 * - 180..349ms: Orange-Coral (slow)
 * - >=350ms: Danger Rose
 */
@Composable
fun LatencyBadge(
    latencyMs: Long,
    state: String,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val isTimeout = state.equals("timeout", ignoreCase = true) ||
        state.equals("unreachable", ignoreCase = true) ||
        latencyMs == 0L
    val unprobed = latencyMs < 0L && !isTimeout
    val (bg, fg, label) = when {
        unprobed -> Triple(ext.mutedContainer, ext.muted, "未测速")
        isTimeout -> Triple(ext.dangerContainer, ext.danger, "超时")
        latencyMs < 80L -> Triple(ext.successContainer, ext.success, "$latencyMs ms")
        latencyMs < 180L -> Triple(ext.warningContainer, ext.warning, "$latencyMs ms")
        latencyMs < 350L -> Triple(ext.slowContainer, ext.slow, "$latencyMs ms")
        else -> Triple(ext.dangerContainer, ext.danger, "$latencyMs ms")
    }
    StatusPill(
        text = label,
        containerColor = bg,
        contentColor = fg,
        mono = !unprobed && !isTimeout,
        modifier = modifier,
    )
}

/**
 * 4-bar ascending optical signal strength indicator aligned with Desktop Slint UI:
 * - <80ms: 4 bars (Emerald)
 * - 80..179ms: 3 bars (Amber)
 * - 180..349ms: 2 bars (Orange-Coral slow)
 * - >=350ms: 1 bar (Rose danger)
 * - Timeout / Unprobed: 0 active bars
 */
@Composable
fun SignalBarsIndicator(
    latencyMs: Long,
    state: String,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val isTimeout = state.equals("timeout", ignoreCase = true) ||
        state.equals("unreachable", ignoreCase = true) ||
        latencyMs == 0L
    val unprobed = latencyMs < 0L && !isTimeout
    val (activeBars, activeColor) = when {
        unprobed -> 0 to ext.muted
        isTimeout -> 0 to ext.danger
        latencyMs < 80L -> 4 to ext.success
        latencyMs < 180L -> 3 to ext.warning
        latencyMs < 350L -> 2 to ext.slow
        else -> 1 to ext.danger
    }
    val inactiveColor = if (isTimeout) {
        ext.danger.copy(alpha = 0.24f)
    } else {
        ext.muted.copy(alpha = 0.28f)
    }
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(2.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        listOf(4.dp, 7.dp, 10.dp, 13.dp).forEachIndexed { idx, h ->
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .height(h)
                    .background(
                        color = if (idx < activeBars) activeColor else inactiveColor,
                        shape = RoundedCornerShape(1.5.dp),
                    ),
            )
        }
    }
}

@Composable
fun MetricStatCard(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    subvalue: String = "",
    dotColor: Color = MaterialTheme.colorScheme.primary,
    onClick: (() -> Unit)? = null,
) {
    OpticalCard(
        modifier = modifier,
        cornerRadius = 14.dp,
        onClick = onClick,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 11.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .background(dotColor, CircleShape),
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (onClick != null) {
                    Icon(
                        painter = painterResource(R.drawable.ic_chevron_right),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(14.dp),
                    )
                }
            }
            Text(
                text = value,
                style = NexusNumericStyles.kpiCompact,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (subvalue.isNotEmpty()) {
                Text(
                    text = subvalue,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
fun EmptyStateCard(
    title: String,
    subtitle: String,
    @DrawableRes iconRes: Int,
    modifier: Modifier = Modifier,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    OpticalCard(
        modifier = modifier.fillMaxWidth(),
        cornerRadius = 16.dp,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 26.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    painter = painterResource(iconRes),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.size(22.dp),
                )
            }
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (actionLabel != null && onAction != null) {
                Spacer(Modifier.height(4.dp))
                FilledTonalButton(onClick = onAction) {
                    Text(actionLabel)
                }
            }
        }
    }
}
