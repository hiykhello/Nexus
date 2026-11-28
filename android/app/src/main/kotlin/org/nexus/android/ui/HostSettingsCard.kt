package org.nexus.android.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val MTU_PRESETS = listOf(1280, 1400, 1500, 9000)

/**
 * Layer 3 Android Host Adapter Settings card (local-only, never synced with workspace).
 */
@Composable
internal fun HostSettingsCard(
    host: AndroidHostConfig,
    onUpdateHost: (AndroidHostConfig) -> Unit,
    onOpenSplitTunnel: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val reducedMotion = isReducedMotionEnabled()
    val a = host.android
    var mixedDraft by rememberSaveable(a.localListen) { mutableStateOf(a.localListen) }
    var httpDraft by rememberSaveable(a.httpListen) { mutableStateOf(a.httpListen) }
    var socksDraft by rememberSaveable(a.socksListen) { mutableStateOf(a.socksListen) }

    fun updateAndroid(transform: (AndroidHostSection) -> AndroidHostSection) {
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        onUpdateHost(host.copy(android = transform(host.android)))
    }

    OpticalCard(cornerRadius = 12.dp, modifier = modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(15.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "本机运行与 VPN 设置",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                StatusPill(
                    text = "仅本机生效",
                    containerColor = ext.insetSurface,
                    contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            ThemePresetSwatches(
                selectedPreset = a.themePreset,
                dynamicColor = a.dynamicColor,
                surfaceAlpha = a.surfaceAlpha,
                onSelectPreset = { preset -> updateAndroid { it.copy(themePreset = preset) } },
                onToggleDynamicColor = { enabled -> updateAndroid { it.copy(dynamicColor = enabled) } },
                onChangeSurfaceAlpha = { alpha -> updateAndroid { it.copy(surfaceAlpha = alpha) } },
            )

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("运行模式", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OpticalSegmentedControl(
                    options = listOf(
                        AndroidRunMode.VPN.wire to "VPN 隧道",
                        AndroidRunMode.PROXY_ONLY.wire to "仅本地代理",
                    ),
                    selectedKey = a.runMode.wire,
                    onSelect = { key -> updateAndroid { it.copy(runMode = AndroidRunMode.fromWire(key)) } },
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("分应用模式", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OpticalSegmentedControl(
                    options = listOf(
                        AndroidPerAppMode.OFF.wire to "关闭",
                        AndroidPerAppMode.EXCLUDE.wire to "排除",
                        AndroidPerAppMode.INCLUDE.wire to "仅代理",
                    ),
                    selectedKey = a.perAppMode.wire,
                    onSelect = { key -> updateAndroid { it.copy(perAppMode = AndroidPerAppMode.fromWire(key)) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                if (onOpenSplitTunnel != null) {
                    OutlinedButton(
                        onClick = onOpenSplitTunnel,
                        shape = RoundedCornerShape(999.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 9.dp),
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    ) {
                        Icon(painterResource(R.drawable.ic_apps), null, Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        val modeText = when (a.perAppMode) {
                            AndroidPerAppMode.OFF -> "管理分应用列表"
                            AndroidPerAppMode.EXCLUDE -> "排除应用列表 (${a.perAppPackages.size})"
                            AndroidPerAppMode.INCLUDE -> "仅代理应用列表 (${a.perAppPackages.size})"
                        }
                        Text(modeText, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }

            // Arbitrary-Combination Local Inbound Protocols (Mixed / HTTP / SOCKS5 + Allow LAN)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "本地代理入站组合（可自由多选）",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    Surface(
                        onClick = { updateAndroid { it.copy(allowLan = !it.allowLan) } },
                        shape = RoundedCornerShape(999.dp),
                        color = if (a.allowLan) MaterialTheme.colorScheme.primary.copy(alpha = if (ext.isDark) 0.22f else 0.12f) else ext.wellSurface,
                        border = BorderStroke(1.dp, if (a.allowLan) MaterialTheme.colorScheme.primary.copy(alpha = 0.72f) else ext.hairline),
                    ) {
                        Text(
                            text = if (a.allowLan) "局域网 0.0.0.0 开" else "仅本机 127.0.0.1",
                            style = NexusNumericStyles.monoBadge,
                            fontWeight = FontWeight.Bold,
                            color = if (a.allowLan) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                        )
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AndroidInboundProtoTile(
                        title = "Mixed",
                        port = AndroidHostConfig.parseHostPort(a.localListen)?.second ?: 10808,
                        active = a.enableLocalProxy,
                        onClick = { updateAndroid { it.copy(enableLocalProxy = !it.enableLocalProxy) } },
                        modifier = Modifier.weight(1f),
                    )
                    AndroidInboundProtoTile(
                        title = "HTTP",
                        port = AndroidHostConfig.parseHostPort(a.httpListen)?.second ?: 10809,
                        active = a.enableHttp,
                        onClick = { updateAndroid { it.copy(enableHttp = !it.enableHttp) } },
                        modifier = Modifier.weight(1f),
                    )
                    AndroidInboundProtoTile(
                        title = "SOCKS5",
                        port = AndroidHostConfig.parseHostPort(a.socksListen)?.second ?: 10806,
                        active = a.enableSocks,
                        onClick = { updateAndroid { it.copy(enableSocks = !it.enableSocks) } },
                        modifier = Modifier.weight(1f),
                    )
                }

                val expandSpec = expandVertically(tween(if (reducedMotion) 0 else 170, easing = NexusStrongEaseOut)) + fadeIn(tween(if (reducedMotion) 0 else 150))
                val shrinkSpec = shrinkVertically(tween(if (reducedMotion) 0 else 130, easing = FastOutSlowInEasing)) + fadeOut(tween(if (reducedMotion) 0 else 110))

                AnimatedVisibility(visible = a.enableLocalProxy, enter = expandSpec, exit = shrinkSpec) {
                    InboundListenEditRow(
                        label = "Mixed 监听地址 (HTTP + SOCKS5)",
                        draft = mixedDraft,
                        saved = a.localListen,
                        onDraftChange = { mixedDraft = it },
                        onApply = { updateAndroid { it.copy(localListen = mixedDraft.trim()) } },
                    )
                }
                AnimatedVisibility(visible = a.enableHttp, enter = expandSpec, exit = shrinkSpec) {
                    InboundListenEditRow(
                        label = "HTTP 代理监听地址",
                        draft = httpDraft,
                        saved = a.httpListen,
                        onDraftChange = { httpDraft = it },
                        onApply = { updateAndroid { it.copy(httpListen = httpDraft.trim()) } },
                    )
                }
                AnimatedVisibility(visible = a.enableSocks, enter = expandSpec, exit = shrinkSpec) {
                    InboundListenEditRow(
                        label = "SOCKS5 代理监听地址",
                        draft = socksDraft,
                        saved = a.socksListen,
                        onDraftChange = { socksDraft = it },
                        onApply = { updateAndroid { it.copy(socksListen = socksDraft.trim()) } },
                    )
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "TUN MTU",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = AndroidHostConfig.formatActiveInboundsSummary(a),
                        style = NexusNumericStyles.monoBadge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    MTU_PRESETS.forEach { preset ->
                        val active = a.tunMtu == preset
                        val accent = MaterialTheme.colorScheme.primary
                        Surface(
                            onClick = { updateAndroid { it.copy(tunMtu = preset) } },
                            shape = RoundedCornerShape(999.dp),
                            color = if (active) accent.copy(alpha = if (ext.isDark) 0.24f else 0.14f) else ext.wellSurface,
                            border = BorderStroke(1.dp, if (active) accent.copy(alpha = 0.72f) else ext.hairline),
                            modifier = Modifier.weight(1f).minimumInteractiveComponentSize().heightIn(min = 48.dp),
                        ) {
                            Row(
                                modifier = Modifier.padding(vertical = 10.dp),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = "$preset",
                                    style = NexusNumericStyles.monoBadge,
                                    fontWeight = if (active) FontWeight.Bold else FontWeight.Medium,
                                    color = if (active) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = ext.wellSurface,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    HostToggleItem(
                        title = "排除本应用出 VPN",
                        subtitle = "默认关闭：本应用经隧道更新订阅与测速",
                        checked = a.excludeSelfFromVpn,
                        onCheckedChange = { v -> updateAndroid { it.copy(excludeSelfFromVpn = v) } },
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)
                    HostToggleItem(
                        title = "允许应用绕过 VPN",
                        subtitle = "允许系统应用在需要时直连物理网络",
                        checked = a.allowBypass,
                        onCheckedChange = { v -> updateAndroid { it.copy(allowBypass = v) } },
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)
                    HostToggleItem(
                        title = "绕过局域网地址",
                        subtitle = "私有网段直连（保留 DNS 与 FakeIPv6 路由）",
                        checked = a.bypassLan,
                        onCheckedChange = { v -> updateAndroid { it.copy(bypassLan = v) } },
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)
                    HostToggleItem(
                        title = "启用 IPv6 隧道",
                        subtitle = "支持双栈流量与 FakeIPv6 (fc00::/18)",
                        checked = a.enableIpv6,
                        onCheckedChange = { v -> updateAndroid { it.copy(enableIpv6 = v) } },
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)
                    HostToggleItem(
                        title = "附加 HTTP 代理到 VPN",
                        subtitle = AndroidHostConfig.selectHttpProxyEndpoint(a)
                            ?.let { "Android 10+ 为应用自动声明本地代理 (${it.first}:${it.second})" }
                            ?: "Android 10+ 声明本地代理（需开启 HTTP 或 Mixed 入站）",
                        checked = a.appendHttpProxy,
                        onCheckedChange = { v -> updateAndroid { it.copy(appendHttpProxy = v) } },
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)
                    HostToggleItem(
                        title = "开机自动启动",
                        subtitle = "检测到异常崩溃时下次开机自动中止防循环",
                        checked = a.autoStartOnBoot,
                        onCheckedChange = { v -> updateAndroid { it.copy(autoStartOnBoot = v) } },
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)
                    HostToggleItem(
                        title = "低电耗与息屏省电",
                        subtitle = "低电耗或息屏时暂停高频流量统计以降低功耗",
                        checked = a.dozePauseEnabled && a.screenOffPauseStats,
                        onCheckedChange = { v -> updateAndroid { it.copy(dozePauseEnabled = v, screenOffPauseStats = v) } },
                    )
                }
            }
        }
    }
}

@Composable
private fun HostToggleItem(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun InboundListenEditRow(
    label: String,
    draft: String,
    saved: String,
    onDraftChange: (String) -> Unit,
    onApply: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = draft,
            onValueChange = onDraftChange,
            label = { Text(label) },
            shape = RoundedCornerShape(8.dp),
            singleLine = true,
            modifier = Modifier.weight(1f),
        )
        OutlinedButton(
            enabled = draft.trim().isNotEmpty() && draft.trim() != saved,
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.heightIn(min = 48.dp),
            onClick = onApply,
        ) {
            Text("应用")
        }
    }
}
