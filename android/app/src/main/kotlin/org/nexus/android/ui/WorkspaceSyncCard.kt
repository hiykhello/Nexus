package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.bridge.workspace.UdpProbeKind
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * E2EE WebDAV Sync card (`nexus-sync-v1`, scrypt + XChaCha20-Poly1305) backed strictly by
 * local Layer 3 `0600` `host.json` credentials (never exported into `workspace.json`).
 */
@Composable
internal fun WebDavSyncCard(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val ext = NexusTheme.colors
    val a = state.host.android

    var url by rememberSaveable(a.webdavUrl) { mutableStateOf(a.webdavUrl) }
    var username by rememberSaveable(a.webdavUsername) { mutableStateOf(a.webdavUsername) }
    var password by rememberSaveable(a.webdavPassword) { mutableStateOf(a.webdavPassword) }
    var passphrase by rememberSaveable(a.syncPassphrase) { mutableStateOf(a.syncPassphrase) }
    var deviceLabel by rememberSaveable(a.syncDeviceLabel) { mutableStateOf(a.syncDeviceLabel) }

    fun persistDraftIfChanged(after: suspend () -> Unit) {
        scope.launch {
            val dirty = url != a.webdavUrl || username != a.webdavUsername ||
                password != a.webdavPassword || passphrase != a.syncPassphrase ||
                deviceLabel != a.syncDeviceLabel
            if (dirty) {
                actions.onUpdateSyncSettings(
                    url.trim(),
                    username.trim(),
                    password,
                    passphrase,
                    deviceLabel.trim().ifBlank { "Android" },
                )
            }
            after()
        }
    }

    OpticalCard(cornerRadius = 16.dp, modifier = modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("端到端加密 WebDAV 同步", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                StatusPill("端到端加密", ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant)
            }
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("WebDAV 服务器地址 (HTTPS)") },
                placeholder = { Text("https://dav.example.com/nexus/", maxLines = 1) },
                shape = RoundedCornerShape(14.dp),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("用户名") },
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = deviceLabel,
                    onValueChange = { deviceLabel = it },
                    label = { Text("设备名") },
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(0.85f),
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("WebDAV 密码") },
                    visualTransformation = PasswordVisualTransformation(),
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("端到端同步口令") },
                    visualTransformation = PasswordVisualTransformation(),
                    shape = RoundedCornerShape(14.dp),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
            }
            if (a.lastSyncedRevision > 0L) {
                Text(
                    text = "上次同步: rev ${a.lastSyncedRevision}${if (a.lastSyncedEtag.isNotBlank()) " · ETag ${a.lastSyncedEtag.take(12)}" else ""}",
                    style = NexusNumericStyles.monoBadge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(
                    enabled = !state.isSyncing && url.isNotBlank() && passphrase.isNotBlank(),
                    onClick = { persistDraftIfChanged { onFeedback(actions.onPushWebDav(false)) } },
                    shape = RoundedCornerShape(999.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 9.dp),
                    modifier = Modifier.weight(1f),
                ) { Text(if (state.isSyncing) "同步中..." else "上传加密快照", maxLines = 1) }
                OutlinedButton(
                    enabled = !state.isSyncing && url.isNotBlank() && passphrase.isNotBlank(),
                    onClick = { persistDraftIfChanged { onFeedback(actions.onPullWebDav(false)) } },
                    shape = RoundedCornerShape(999.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 9.dp),
                    modifier = Modifier.weight(1f),
                ) { Text("拉取远端快照", maxLines = 1) }
            }

            state.syncConflict?.let { conflict ->
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = ext.warningContainer,
                    border = BorderStroke(1.dp, ext.warning.copy(alpha = 0.55f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "检测到远端版本冲突",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold,
                                color = ext.warning,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(
                                enabled = !state.isSyncing,
                                onClick = actions.onDismissSyncConflict,
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                            ) { Text("暂不处理", style = MaterialTheme.typography.labelSmall) }
                        }
                        Text(
                            text = "${conflict.message}（远端 rev ${conflict.remoteRevision} · 设备 ${conflict.remoteDevice.ifBlank { "未知" }}）",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilledTonalButton(
                                enabled = !state.isSyncing,
                                onClick = { persistDraftIfChanged { onFeedback(actions.onPullWebDav(true)) } },
                                shape = RoundedCornerShape(999.dp),
                                modifier = Modifier.weight(1f),
                            ) { Text("保留远端", maxLines = 1) }
                            OutlinedButton(
                                enabled = !state.isSyncing,
                                onClick = { persistDraftIfChanged { onFeedback(actions.onPushWebDav(true)) } },
                                shape = RoundedCornerShape(999.dp),
                                modifier = Modifier.weight(1f),
                            ) { Text("强制覆盖远端", maxLines = 1) }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Quick UDP protocol probe card (`STUN` / `DNS` / `NTP` via Core `tools udp-probe`).
 */
@Composable
internal fun UdpProbeCard(
    state: WorkspaceUiState,
    actions: WorkspaceUiActions,
    onFeedback: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val ext = NexusTheme.colors

    OpticalCard(cornerRadius = 16.dp, modifier = modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(15.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("UDP 连通性与 NAT 探测", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                StatusPill(
                    text = if (state.isProbingUdp) "探测中..." else "STUN / DNS / NTP",
                    containerColor = ext.insetSurface,
                    contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    mono = true,
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UdpProbeKind.entries.forEach { kind ->
                    OutlinedButton(
                        enabled = !state.isProbingUdp,
                        onClick = { scope.launch { onFeedback(actions.onRunUdpProbe(kind)) } },
                        shape = RoundedCornerShape(999.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                        modifier = Modifier.weight(1f),
                    ) { Text(kind.label, maxLines = 1) }
                }
            }
            state.udpProbeResult?.let { res ->
                val accent = if (res.ok) ext.success else ext.danger
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = ext.wellSurface,
                    border = BorderStroke(1.dp, accent.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Box(Modifier.size(7.dp).background(accent, CircleShape))
                        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(
                                text = "${res.kind.uppercase()} · ${if (res.ok) "${res.rttMs} ms" else "失败"} · ${if (res.viaSocks5) "SOCKS5 UDP" else "直连 UDP"}",
                                style = NexusNumericStyles.monoBadge,
                                fontWeight = FontWeight.SemiBold,
                                color = accent,
                            )
                            val detail = if (res.ok) res.detail else res.error
                            if (detail.isNotBlank()) {
                                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    }
                }
            }
        }
    }
}
