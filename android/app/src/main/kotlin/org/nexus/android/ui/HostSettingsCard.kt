package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
 * Layer 3 Android Host Adapter Settings card (`host.json`, strictly never synced with workspace).
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
    val a = host.android

    fun updateAndroid(transform: (AndroidHostSection) -> AndroidHostSection) {
        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
        onUpdateHost(host.copy(android = transform(host.android)))
    }

    OpticalCard(cornerRadius = 20.dp, modifier = modifier.fillMaxWidth()) {
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
                        AndroidPerAppMode.EXCLUDE.wire to "排除所选",
                        AndroidPerAppMode.INCLUDE.wire to "仅代理所选",
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
                        modifier = Modifier.fillMaxWidth(),
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

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "TUN MTU",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = a.localListen,
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
                            color = if (active) accent.copy(alpha = if (ext.isDark) 0.25f else 0.14f) else ext.wellSurface,
                            border = BorderStroke(1.dp, if (active) accent.copy(alpha = 0.72f) else ext.hairline),
                            modifier = Modifier.weight(1f),
                        ) {
                            Row(
                                modifier = Modifier.padding(vertical = 7.dp),
                                horizontalArrangement = Arrangement.Center,
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

            HostToggleRow(
                title = "排除本应用出 VPN",
                subtitle = "默认关闭：本应用经 Protect-FD 走隧道，可直接经隧道更新订阅与测速",
                checked = a.excludeSelfFromVpn,
                onCheckedChange = { v -> updateAndroid { it.copy(excludeSelfFromVpn = v) } },
            )
            HostToggleRow(
                title = "允许应用绕过 VPN",
                subtitle = "开启 allowBypass 允许系统应用在需要时直连物理网卡",
                checked = a.allowBypass,
                onCheckedChange = { v -> updateAndroid { it.copy(allowBypass = v) } },
            )
            HostToggleRow(
                title = "绕过局域网地址",
                subtitle = "私有网段直连（保留 DNS 哨兵与 FakeIPv6 路由）",
                checked = a.bypassLan,
                onCheckedChange = { v -> updateAndroid { it.copy(bypassLan = v) } },
            )
            HostToggleRow(
                title = "启用 IPv6 隧道",
                subtitle = "支持双栈流量与 FakeIPv6 (fc00::/18)",
                checked = a.enableIpv6,
                onCheckedChange = { v -> updateAndroid { it.copy(enableIpv6 = v) } },
            )
            HostToggleRow(
                title = "附加 HTTP 代理到 VPN",
                subtitle = "Android 10+ 为应用自动声明本地代理 (${a.localListen})",
                checked = a.appendHttpProxy,
                onCheckedChange = { v -> updateAndroid { it.copy(appendHttpProxy = v) } },
            )
            HostToggleRow(
                title = "开机自动启动",
                subtitle = "检测到异常崩溃时下次开机自动中止防循环",
                checked = a.autoStartOnBoot,
                onCheckedChange = { v -> updateAndroid { it.copy(autoStartOnBoot = v) } },
            )
            HostToggleRow(
                title = "Doze 与息屏省电暂停轮询",
                subtitle = "低电耗或息屏时暂停高频流量统计以降低功耗",
                checked = a.dozePauseEnabled && a.screenOffPauseStats,
                onCheckedChange = { v -> updateAndroid { it.copy(dozePauseEnabled = v, screenOffPauseStats = v) } },
            )
        }
    }
}

@Composable
private fun HostToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    val ext = NexusTheme.colors
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = ext.wellSurface,
        border = BorderStroke(1.dp, ext.hairline),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 9.dp),
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
}
