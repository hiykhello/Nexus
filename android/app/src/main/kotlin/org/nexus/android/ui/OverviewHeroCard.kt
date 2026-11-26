package org.nexus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

enum class HeroConnectionState {
    STANDBY,
    STARTING,
    CONNECTED,
    DEGRADED,
    ERROR,
}

data class ActiveExitSummary(
    val groupTag: String = "",
    val memberName: String = "",
    val latencyMs: Long = -1L,
    val state: String = "unknown",
)

@Composable
internal fun FiveStateHeroCard(
    heroState: HeroConnectionState,
    powerSave: Boolean,
    uptimeMs: Long,
    activeProfileName: String,
    activeExit: ActiveExitSummary,
    errorDetail: String,
    onStartStop: () -> Unit,
    onOpenConfig: () -> Unit,
    onOpenGroups: () -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val isLive = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED

    val accentColor = when (heroState) {
        HeroConnectionState.CONNECTED -> ext.success
        HeroConnectionState.STARTING -> ext.warning
        HeroConnectionState.DEGRADED -> ext.warning
        HeroConnectionState.ERROR -> ext.danger
        HeroConnectionState.STANDBY -> ext.muted
    }
    val borderColor = if (heroState == HeroConnectionState.STANDBY) {
        ext.hairline
    } else {
        accentColor.copy(alpha = 0.45f)
    }
    val tint = if (heroState == HeroConnectionState.STANDBY) {
        Color.Transparent
    } else {
        accentColor.copy(alpha = if (ext.isDark) 0.05f else 0.035f)
    }

    val statusLabel = when (heroState) {
        HeroConnectionState.STANDBY -> "未连接"
        HeroConnectionState.STARTING -> "正在连接"
        HeroConnectionState.CONNECTED -> if (powerSave) "已连接 · 省电" else "已连接"
        HeroConnectionState.DEGRADED -> "线路波动"
        HeroConnectionState.ERROR -> "连接失败"
    }
    val primaryHeadline = when {
        heroState == HeroConnectionState.ERROR -> errorDetail.ifEmpty { "连接未能建立" }
        heroState == HeroConnectionState.STARTING -> "正在建立加密连接…"
        isLive && activeExit.memberName.isNotEmpty() -> activeExit.memberName
        isLive -> activeProfileName.ifEmpty { "默认配置" }
        else -> activeProfileName.ifEmpty { "未连接" }
    }
    val latencyColor = when {
        !isLive || activeExit.latencyMs < 0L -> ext.muted
        activeExit.state.equals("timeout", ignoreCase = true) ||
            activeExit.state.equals("unreachable", ignoreCase = true) ||
            activeExit.latencyMs == 0L -> ext.danger
        activeExit.latencyMs < 80L -> ext.success
        activeExit.latencyMs < 180L -> ext.warning
        activeExit.latencyMs < 350L -> ext.slow
        else -> ext.danger
    }
    val latencyText = when {
        activeExit.state.equals("timeout", ignoreCase = true) ||
            activeExit.state.equals("unreachable", ignoreCase = true) ||
            activeExit.latencyMs == 0L -> "超时"
        activeExit.latencyMs > 0L -> "${activeExit.latencyMs} ms"
        else -> ""
    }

    OpticalCard(
        cornerRadius = 16.dp,
        borderColor = borderColor,
        accentTint = tint,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(5.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                    ) {
                        HeroStatusOrb(heroState = heroState, accentColor = accentColor)
                        Text(
                            text = statusLabel,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = if (heroState == HeroConnectionState.ERROR) ext.danger else MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (isLive && activeExit.memberName.isNotEmpty()) {
                            Row(
                                modifier = Modifier
                                    .minimumInteractiveComponentSize()
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable(onClick = onOpenGroups)
                                    .padding(horizontal = 4.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(5.dp),
                            ) {
                                SignalBarsIndicator(latencyMs = activeExit.latencyMs, state = activeExit.state)
                                if (latencyText.isNotEmpty()) {
                                    Text(
                                        text = latencyText,
                                        style = NexusNumericStyles.monoBadge,
                                        color = latencyColor,
                                        maxLines = 1,
                                        softWrap = false,
                                    )
                                }
                            }
                        }
                    }

                    Text(
                        text = primaryHeadline,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (heroState == HeroConnectionState.ERROR) ext.danger else MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .clickable(onClick = if (isLive) onOpenGroups else onOpenConfig)
                            .padding(vertical = 2.dp),
                    )

                    val subline = when {
                        isLive && uptimeMs > 0L -> "运行时长 ${formatDurationClock(uptimeMs)}"
                        heroState == HeroConnectionState.STANDBY -> "点击右侧开关连接"
                        heroState == HeroConnectionState.STARTING -> "请稍候…"
                        else -> ""
                    }
                    if (subline.isNotEmpty()) {
                        Text(
                            text = subline,
                            style = if (isLive) NexusNumericStyles.monoBadge else MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                HeroPowerButton(
                    heroState = heroState,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onStartStop()
                    },
                )
            }

            if (heroState == HeroConnectionState.DEGRADED || heroState == HeroConnectionState.ERROR) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (heroState == HeroConnectionState.DEGRADED) {
                        FilledTonalButton(
                            onClick = onOpenGroups,
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.ic_speed),
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text("切换线路")
                        }
                    } else {
                        FilledTonalButton(
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                onStartStop()
                            },
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.ic_refresh),
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text("重试连接")
                        }
                        OutlinedButton(
                            onClick = onOpenConfig,
                            modifier = Modifier.weight(1f),
                        ) {
                            Text("检查配置")
                        }
                    }
                }
            }
        }
    }
}

/**
 * Clean native Material 3 `56.dp` circular `FilledIconButton` harmonized with semantic connection
 * state colors and Dynamic Color, with restrained scale-only press feedback.
 */
@Composable
private fun HeroPowerButton(
    heroState: HeroConnectionState,
    onClick: () -> Unit,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val onPrimary = MaterialTheme.colorScheme.onPrimary
    val isLive = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED
    val isStarting = heroState == HeroConnectionState.STARTING
    val interactionSource = remember { MutableInteractionSource() }

    val (containerColor, contentColor) = when (heroState) {
        HeroConnectionState.CONNECTED -> ext.success to Color(0xFF04261B)
        HeroConnectionState.STARTING, HeroConnectionState.DEGRADED -> ext.warning to Color(0xFF2B1902)
        HeroConnectionState.ERROR -> ext.danger to Color.White
        HeroConnectionState.STANDBY -> primary to onPrimary
    }
    val resolvedContent = if (ext.isDark || heroState == HeroConnectionState.STANDBY) {
        contentColor
    } else {
        Color.White
    }

    FilledIconButton(
        onClick = onClick,
        enabled = !isStarting,
        interactionSource = interactionSource,
        shape = CircleShape,
        colors = IconButtonDefaults.filledIconButtonColors(
            containerColor = containerColor,
            contentColor = resolvedContent,
            disabledContainerColor = containerColor.copy(alpha = 0.72f),
            disabledContentColor = resolvedContent,
        ),
        modifier = Modifier
            .size(56.dp)
            .liquidPress(interactionSource = interactionSource, pressedScale = 0.96f),
    ) {
        when {
            isStarting -> CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.4.dp,
                color = resolvedContent,
            )
            heroState == HeroConnectionState.ERROR -> Icon(
                painter = painterResource(R.drawable.ic_refresh),
                contentDescription = "重试连接",
                modifier = Modifier.size(22.dp),
            )
            isLive -> Icon(
                painter = painterResource(R.drawable.ic_stop),
                contentDescription = "断开连接",
                modifier = Modifier.size(20.dp),
            )
            else -> Icon(
                painter = painterResource(R.drawable.ic_play),
                contentDescription = "连接",
                modifier = Modifier.size(22.dp),
            )
        }
    }
}

@Composable
private fun HeroStatusOrb(
    heroState: HeroConnectionState,
    accentColor: Color,
) {
    Box(
        modifier = Modifier.size(18.dp),
        contentAlignment = Alignment.Center,
    ) {
        if (heroState == HeroConnectionState.STARTING) {
            CircularProgressIndicator(
                modifier = Modifier.size(14.dp),
                strokeWidth = 2.dp,
                color = accentColor,
            )
        } else {
            Box(
                modifier = Modifier
                    .size(14.dp)
                    .background(accentColor.copy(alpha = 0.20f), CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .background(accentColor, CircleShape),
                )
            }
        }
    }
}
