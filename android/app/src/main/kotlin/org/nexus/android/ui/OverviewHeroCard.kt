package org.nexus.android.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import org.nexus.android.bridge.workspace.AndroidHostConfig
import org.nexus.android.bridge.workspace.AndroidHostSection
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.bridge.workspace.AndroidRunMode
import org.nexus.android.bridge.workspace.SubscriptionItem
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

/**
 * Responsive 4-Tile Bento Strip (`4-col` on Expanded, `2x2` Grid on Phone & Foldable — never horizontal strips).
 */
@Composable
internal fun OverviewBentoTileStrip(
    fourColumns: Boolean,
    running: Boolean,
    runMode: AndroidRunMode,
    localListen: String,
    tunMtu: Int,
    perAppMode: AndroidPerAppMode,
    excludedCount: Int,
    bypassLan: Boolean,
    routingProfileName: String,
    ruleCount: Int,
    fakeIpEnabled: Boolean,
    onOpenConfig: () -> Unit,
    onOpenSplitTunnel: () -> Unit,
    onOpenDiagnostics: (() -> Unit)? = null,
    hostSection: AndroidHostSection? = null,
    modifier: Modifier = Modifier,
) {
    val inbSub = hostSection?.let { h ->
        val summary = AndroidHostConfig.formatActiveInboundsSummary(h)
        if (h.allowLan) "$summary · LAN" else summary
    } ?: localListen.removePrefix("127.0.0.1")
    val splitSub = when (perAppMode) {
        AndroidPerAppMode.OFF -> if (bypassLan) "全局 · 绕局域网" else "全局应用接管"
        AndroidPerAppMode.EXCLUDE -> if (excludedCount > 0) "绕过 $excludedCount 个应用" else "未排除 · 绕局域网"
        AndroidPerAppMode.INCLUDE -> "仅代理 $excludedCount 个应用"
    }

    @Composable
    fun Tile1(mod: Modifier) = BentoQuickTile(R.drawable.ic_speed, if (runMode == AndroidRunMode.VPN) "VPN" else "PROXY", running, if (runMode == AndroidRunMode.VPN) "VPN 模式" else "本地代理", inbSub, true, onOpenConfig, mod)

    @Composable
    fun Tile2(mod: Modifier) = BentoQuickTile(R.drawable.ic_apps, if (perAppMode == AndroidPerAppMode.OFF) "ALL" else "$excludedCount", perAppMode != AndroidPerAppMode.OFF && excludedCount > 0, "分应用", splitSub, false, onOpenSplitTunnel, mod)

    @Composable
    fun Tile3(mod: Modifier) = BentoQuickTile(R.drawable.ic_rule, "${ruleCount}条", false, "分流规则", routingProfileName.ifBlank { "默认分流" }, false, onOpenConfig, mod)

    @Composable
    fun Tile4(mod: Modifier) = BentoQuickTile(R.drawable.ic_search, if (fakeIpEnabled) "FakeIP" else "DoH", fakeIpEnabled, "DNS", if (fakeIpEnabled) "FakeIP 映射" else "加密上游", false, { onOpenDiagnostics?.invoke() ?: onOpenConfig() }, mod)

    if (fourColumns) {
        Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Tile1(Modifier.weight(1f))
            Tile2(Modifier.weight(1f))
            Tile3(Modifier.weight(1f))
            Tile4(Modifier.weight(1f))
        }
    } else {
        Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Tile1(Modifier.weight(1f))
                Tile2(Modifier.weight(1f))
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Tile3(Modifier.weight(1f))
                Tile4(Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun BentoQuickTile(
    iconRes: Int,
    badge: String,
    badgeActive: Boolean,
    title: String,
    subtitle: String,
    monoSub: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val interaction = remember { MutableInteractionSource() }
    val reducedMotion = isReducedMotionEnabled()
    val borderColor = animateColorAsState(
        targetValue = if (badgeActive) MaterialTheme.colorScheme.primary.copy(alpha = 0.48f) else ext.hairline,
        animationSpec = tween(if (reducedMotion) 0 else 150, easing = NexusStrongEaseOut),
        label = "tileBorder",
    ).value
    val wellBg = animateColorAsState(
        targetValue = if (badgeActive) MaterialTheme.colorScheme.primary.copy(alpha = 0.14f) else ext.wellSurface,
        animationSpec = tween(if (reducedMotion) 0 else 150, easing = NexusStrongEaseOut),
        label = "tileWellBg",
    ).value
    Surface(
        onClick = onClick,
        interactionSource = interaction,
        shape = RoundedCornerShape(12.dp),
        color = ext.cardSurface,
        border = BorderStroke(1.dp, borderColor),
        modifier = modifier.heightIn(min = 84.dp).tactilePress(interaction, pressedScale = 0.97f),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(wellBg),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        painter = painterResource(iconRes),
                        contentDescription = null,
                        tint = if (badgeActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(15.dp),
                    )
                }
                StatusPill(
                    text = badge,
                    containerColor = if (badgeActive) ext.successContainer else ext.wellSurface,
                    contentColor = if (badgeActive) ext.success else MaterialTheme.colorScheme.onSurfaceVariant,
                    mono = true,
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = subtitle,
                    style = if (monoSub) NexusNumericStyles.monoBadge else MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

/**
 * Proportional Core & Mode Bento Card (`12dp` single-level Card Console container):
 * - Status indicator + tabular uptime
 * - `52dp` Electric Cobalt (Standby) / Signal Emerald (Connected) primary button
 * - Recessed 3-way `规则分流 / 全局代理 / 全局直连` segmented bar
 * - 2-Column Mini Bento Wells (Active Exit + Subscription Quota)
 */
@Composable
internal fun FiveStateHeroCard(
    heroState: HeroConnectionState,
    powerSave: Boolean,
    uptimeMs: Long,
    activeProfileName: String,
    activeExit: ActiveExitSummary,
    primarySub: SubscriptionItem? = null,
    profileCount: Int = 0,
    errorDetail: String,
    outboundMode: String = "rule",
    runMode: AndroidRunMode = AndroidRunMode.VPN,
    onStartStop: () -> Unit,
    onSwitchOutboundMode: (String) -> Unit = {},
    onOpenConfig: () -> Unit,
    onOpenGroups: () -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val isLive = heroState == HeroConnectionState.CONNECTED || heroState == HeroConnectionState.DEGRADED
    val isStarting = heroState == HeroConnectionState.STARTING

    val dotColor = when (heroState) {
        HeroConnectionState.CONNECTED -> ext.success
        HeroConnectionState.STARTING, HeroConnectionState.DEGRADED -> ext.warning
        HeroConnectionState.ERROR -> ext.danger
        HeroConnectionState.STANDBY -> ext.muted
    }

    val statusTitle = when (heroState) {
        HeroConnectionState.STANDBY -> "核心待命"
        HeroConnectionState.STARTING -> "正在建立连接"
        HeroConnectionState.CONNECTED -> if (powerSave) "已连接 · 省电" else "隧道运行中"
        HeroConnectionState.DEGRADED -> "线路波动"
        HeroConnectionState.ERROR -> "连接异常"
    }

    val buttonTitle = when (heroState) {
        HeroConnectionState.STARTING -> "正在连接…"
        HeroConnectionState.ERROR -> errorDetail.ifEmpty { "启动失败 · 重试" }
        HeroConnectionState.CONNECTED, HeroConnectionState.DEGRADED ->
            if (runMode == AndroidRunMode.VPN) "已连接 · VPN" else "已连接 · 代理"
        HeroConnectionState.STANDBY -> "启动连接"
    }

    val buttonBg = when {
        isStarting -> Color(0xFF2563EB).copy(alpha = 0.76f)
        heroState == HeroConnectionState.ERROR -> Color(0xFFDC2626)
        isLive -> Color(0xFF059669)
        else -> Color(0xFF2563EB)
    }

    val isDirect = isLive && outboundMode == "direct"
    val exitName = when {
        isDirect -> "全局直连"
        isLive && activeExit.memberName.isNotEmpty() -> activeExit.memberName
        activeProfileName.isNotEmpty() -> activeProfileName
        else -> "选择配置"
    }

    val reducedMotion = isReducedMotionEnabled()
    val animatedButtonBg = animateColorAsState(
        targetValue = buttonBg,
        animationSpec = tween(if (reducedMotion) 0 else 180, easing = NexusStrongEaseOut),
        label = "ctaBg",
    ).value

    OpticalCard(cornerRadius = 12.dp) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(11.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(modifier = Modifier.size(18.dp), contentAlignment = Alignment.Center) {
                    if ((isLive || isStarting) && !powerSave && !reducedMotion) {
                        val pulse = rememberInfiniteTransition(label = "heroHalo").animateFloat(
                            initialValue = 0f,
                            targetValue = 1f,
                            animationSpec = infiniteRepeatable(tween(2200, easing = NexusStrongEaseOut), RepeatMode.Restart),
                            label = "haloFrac",
                        ).value
                        Box(
                            modifier = Modifier
                                .size(9.dp + 9.dp * pulse)
                                .background(dotColor.copy(alpha = 0.36f * (1f - pulse)), CircleShape),
                        )
                    }
                    Box(modifier = Modifier.size(9.dp).background(dotColor, CircleShape))
                }
                Text(
                    text = statusTitle,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = if (isLive && uptimeMs > 0L) formatDurationClock(uptimeMs) else "00:00:00",
                    style = NexusNumericStyles.monoBadge,
                    color = if (isLive) ext.success else ext.muted,
                    maxLines = 1,
                    softWrap = false,
                )
            }

            val pwrInteraction = remember { MutableInteractionSource() }
            Surface(
                onClick = {
                    if (!isStarting) {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onStartStop()
                    }
                },
                enabled = !isStarting,
                interactionSource = pwrInteraction,
                shape = RoundedCornerShape(10.dp),
                color = animatedButtonBg,
                contentColor = Color.White,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 52.dp)
                    .tactilePress(pwrInteraction, pressedScale = 0.98f),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 13.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    if (isStarting) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.2.dp, color = Color.White)
                    } else {
                        Icon(
                            painter = painterResource(
                                when {
                                    heroState == HeroConnectionState.ERROR -> R.drawable.ic_refresh
                                    isLive -> R.drawable.ic_stop
                                    else -> R.drawable.ic_play
                                },
                            ),
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                    Text(
                        text = buttonTitle,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = when {
                            isStarting -> "连接中"
                            heroState == HeroConnectionState.ERROR -> "重试"
                            isLive -> "断开"
                            else -> "启动"
                        },
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color.White.copy(alpha = 0.90f),
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }

            OpticalSegmentedControl(
                options = listOf("rule" to "规则分流", "global" to "全局代理", "direct" to "全局直连"),
                selectedKey = outboundMode,
                onSelect = onSwitchOutboundMode,
                modifier = Modifier.fillMaxWidth(),
            )

            // 2-Column Mini Bento Wells (Active Exit + Subscription Quota)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Surface(
                    onClick = if (isLive) onOpenGroups else onOpenConfig,
                    shape = RoundedCornerShape(8.dp),
                    color = ext.wellSurface,
                    modifier = Modifier.weight(1f).heightIn(min = 60.dp),
                ) {
                    Column(
                        modifier = Modifier.padding(horizontal = 11.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text("当前出口", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            if (!isDirect && activeExit.latencyMs > 0L) {
                                LatencyReadoutText(activeExit.latencyMs, activeExit.state)
                            } else {
                                Icon(painterResource(R.drawable.ic_chevron_right), null, tint = ext.muted, modifier = Modifier.size(13.dp))
                            }
                        }
                        Text(
                            text = exitName,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                Surface(
                    onClick = onOpenConfig,
                    shape = RoundedCornerShape(8.dp),
                    color = ext.wellSurface,
                    modifier = Modifier.weight(1f).heightIn(min = 60.dp),
                ) {
                    Column(
                        modifier = Modifier.padding(horizontal = 11.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = primarySub?.remarks?.ifBlank { primarySub.id } ?: "本地配置库",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (primarySub != null && primarySub.usage.hasQuota) {
                            val used = primarySub.usage.usedBytes
                            val rem = (primarySub.usage.totalBytes - used).coerceAtLeast(0L)
                            NexusProportionBar(used, rem, MaterialTheme.colorScheme.primary, ext.insetSurface)
                            Text(
                                text = "${formatCompactQuotaBytes(used)} / ${formatCompactQuotaBytes(primarySub.usage.totalBytes)}",
                                style = NexusNumericStyles.monoBadge,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        } else {
                            Text(
                                text = "共 $profileCount 个配置项",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 1,
                            )
                        }
                    }
                }
            }
        }
    }
}
