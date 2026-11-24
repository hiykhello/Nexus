package org.nexus.android.ui

import android.content.ClipboardManager
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

data class UiProfileChip(
    val id: String,
    val name: String,
    val active: Boolean,
)

/**
 * Graphite Bento Mobile Profiles & Import (`档案`) screen:
 * - Structured import card (clipboard 1-click, share link, HTTPS subscription, rules/DNS, split-tunnel)
 * - Clean profile lifecycle card (switch active profile, snapshot current config, validate/reload)
 */
@Composable
fun ConfigScreen(
    kdlText: String,
    hasRemoteOutbound: Boolean,
    profiles: List<UiProfileChip>,
    onApplyConfig: suspend (String) -> Pair<Boolean, String>,
    diagnostic: String,
    onDiagnosticChange: (String) -> Unit,
    onImportShareLink: suspend (String, String) -> Pair<String?, String>,
    onImportSubscription: suspend (String, String) -> Pair<String, String>,
    onSwitchProfile: suspend (String) -> Pair<String?, String>,
    onSaveProfileSnapshot: suspend (String, String) -> String,
    onValidateKdl: suspend (String) -> Pair<Boolean, String>,
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    excludedCount: Int = 0,
    onOpenSplitTunnel: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val layoutDirection = LocalLayoutDirection.current
    val ext = NexusTheme.colors

    var shareUri by rememberSaveable { mutableStateOf("") }
    var subUrl by rememberSaveable { mutableStateOf("") }
    var newProfileName by rememberSaveable { mutableStateOf("") }
    var showRuleDnsSheet by rememberSaveable { mutableStateOf(false) }
    val lineCount = remember(kdlText) { if (kdlText.isEmpty()) 0 else kdlText.count { it == '\n' } + 1 }
    val diagnosticError = diagnostic.contains("失败") || diagnostic.contains("拒绝") || diagnostic.contains("错误")

    val importClipboard: () -> Unit = {
        val raw = context.getSystemService(ClipboardManager::class.java)
            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            onDiagnosticChange("剪贴板为空，请先复制节点、订阅链接或配置内容")
        } else {
            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
            val looksLikeConfig = raw.contains("schema-version") ||
                (raw.contains("routing {") && raw.contains("outbound "))
            scope.launch {
                if (looksLikeConfig) {
                    val (_, note) = onApplyConfig(raw)
                    onDiagnosticChange(note)
                } else {
                    val lower = raw.lowercase()
                    val looksLikeSub = (lower.startsWith("https://") || lower.startsWith("http://127.0.0.1")) &&
                        !lower.contains("@")
                    val note = if (looksLikeSub) {
                        onImportSubscription("subscription", raw).second
                    } else {
                        onImportShareLink(raw, kdlText).second
                    }
                    onDiagnosticChange(note)
                }
            }
        }
    }

    val importCard: @Composable () -> Unit = {
        OpticalCard(cornerRadius = 20.dp) {
            Column(
                modifier = Modifier.padding(15.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = "导入节点与订阅",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.weight(1f),
                    )
                    FilledTonalButton(onClick = importClipboard, shape = RoundedCornerShape(999.dp)) {
                        Icon(painterResource(R.drawable.ic_paste), null, Modifier.size(15.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("剪贴板导入")
                    }
                }
                if (!hasRemoteOutbound) {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = "粘贴节点分享链接或订阅地址即可自动校验并导入。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        )
                    }
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = shareUri,
                        onValueChange = { shareUri = it },
                        label = { Text("分享链接 (vless/hy2/ss)", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        shape = RoundedCornerShape(14.dp),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    FilledTonalButton(
                        enabled = shareUri.isNotBlank(),
                        shape = RoundedCornerShape(999.dp),
                        onClick = {
                            val raw = shareUri
                            scope.launch {
                                val (updated, note) = onImportShareLink(raw, kdlText)
                                if (updated != null) shareUri = ""
                                onDiagnosticChange(note)
                            }
                        },
                    ) {
                        Icon(painterResource(R.drawable.ic_add), null, Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("导入")
                    }
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = subUrl,
                        onValueChange = { subUrl = it },
                        label = { Text("HTTPS 订阅链接", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        shape = RoundedCornerShape(14.dp),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedButton(
                        enabled = subUrl.isNotBlank(),
                        shape = RoundedCornerShape(999.dp),
                        onClick = {
                            val url = subUrl
                            scope.launch {
                                val (updated, note) = onImportSubscription("subscription", url)
                                if (updated.isNotEmpty()) subUrl = ""
                                onDiagnosticChange(note)
                            }
                        },
                    ) { Text("拉取") }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = { showRuleDnsSheet = true },
                        shape = RoundedCornerShape(999.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
                        modifier = Modifier.weight(1.06f),
                    ) {
                        Icon(painterResource(R.drawable.ic_rule), null, Modifier.size(15.dp))
                        Spacer(Modifier.width(5.dp))
                        Text("路由与 DNS 规则", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    if (onOpenSplitTunnel != null) {
                        OutlinedButton(
                            onClick = onOpenSplitTunnel,
                            shape = RoundedCornerShape(999.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
                            modifier = Modifier.weight(0.94f),
                        ) {
                            Icon(painterResource(R.drawable.ic_apps), null, Modifier.size(15.dp))
                            Spacer(Modifier.width(5.dp))
                            Text(
                                text = if (excludedCount > 0) "分应用绕过 ($excludedCount)" else "分应用绕过",
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }
    }

    val profilesCard: @Composable () -> Unit = {
        OpticalCard(cornerRadius = 20.dp) {
            Column(
                modifier = Modifier.padding(15.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "配置档案",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )

                if (profiles.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        profiles.forEach { profile ->
                            val rowInteraction = remember { MutableInteractionSource() }
                            Surface(
                                onClick = {
                                    if (!profile.active) {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        scope.launch { onDiagnosticChange(onSwitchProfile(profile.id).second) }
                                    }
                                },
                                interactionSource = rowInteraction,
                                modifier = Modifier.fillMaxWidth().liquidPress(rowInteraction, pressedScale = 0.98f),
                                shape = RoundedCornerShape(14.dp),
                                color = if (profile.active) Color(0xFF2563EB).copy(alpha = if (ext.isDark) 0.24f else 0.12f) else ext.wellSurface,
                                border = BorderStroke(
                                    width = if (profile.active) 1.3.dp else 1.dp,
                                    color = if (profile.active) Color(0xFF3B82F6).copy(alpha = 0.78f) else ext.hairline,
                                ),
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(horizontal = 13.dp, vertical = 11.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                ) {
                                    Box(
                                        modifier = Modifier.size(8.dp).background(
                                            if (profile.active) Color(0xFF60A5FA) else ext.muted.copy(alpha = 0.5f),
                                            CircleShape,
                                        ),
                                    )
                                    Text(
                                        text = profile.name,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = if (profile.active) FontWeight.Bold else FontWeight.Medium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        modifier = Modifier.weight(1f),
                                    )
                                    if (profile.active) {
                                        StatusPill("当前使用", Color(0xFF2563EB), Color.White)
                                    } else {
                                        Text("切换", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                }
                            }
                        }
                    }
                }

                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = newProfileName,
                        onValueChange = { newProfileName = it },
                        placeholder = { Text("新档案名称", maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        shape = RoundedCornerShape(14.dp),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedButton(
                        enabled = newProfileName.isNotBlank(),
                        shape = RoundedCornerShape(999.dp),
                        onClick = {
                            val name = newProfileName.trim()
                            scope.launch {
                                val note = onSaveProfileSnapshot(name, kdlText)
                                newProfileName = ""
                                onDiagnosticChange(note)
                            }
                        },
                    ) { Text("存快照") }
                }

                // Compact validation & reload status footer strip
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = ext.wellSurface,
                    border = BorderStroke(1.dp, ext.hairline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .background(if (hasRemoteOutbound) ext.success else ext.warning, CircleShape),
                        )
                        Text(
                            text = if (hasRemoteOutbound) "已同步 · $lineCount 行" else "等待导入节点",
                            style = NexusNumericStyles.monoBadge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                        )
                        Surface(
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                scope.launch { onDiagnosticChange(onValidateKdl(kdlText).second) }
                            },
                            shape = RoundedCornerShape(999.dp),
                            color = ext.insetSurface,
                        ) {
                            Text("校验", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp))
                        }
                        Surface(
                            onClick = {
                                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                scope.launch { onDiagnosticChange(onApplyConfig(kdlText).second) }
                            },
                            shape = RoundedCornerShape(999.dp),
                            color = ext.insetSurface,
                        ) {
                            Text("重载", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp))
                        }
                    }
                }
            }
        }
    }

    val diagnosticCard: @Composable () -> Unit = {
        if (diagnostic.isNotEmpty()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = if (diagnosticError) ext.dangerContainer else ext.successContainer,
                border = BorderStroke(1.dp, (if (diagnosticError) ext.danger else ext.success).copy(alpha = 0.45f)),
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        painter = painterResource(if (diagnosticError) R.drawable.ic_warning else R.drawable.ic_check),
                        contentDescription = null,
                        tint = if (diagnosticError) ext.danger else ext.success,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        text = diagnostic,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (diagnosticError) ext.danger else ext.success,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }

    val startPad = contentPadding.calculateStartPadding(layoutDirection)
    val endPad = contentPadding.calculateEndPadding(layoutDirection)
    val topPad = contentPadding.calculateTopPadding()
    val bottomPad = contentPadding.calculateBottomPadding()

    if (windowSizeClass == NexusWindowSizeClass.EXPANDED) {
        Row(
            modifier = modifier
                .fillMaxSize()
                .consumeWindowInsets(contentPadding)
                .imePadding()
                .padding(start = startPad, end = endPad),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            LazyColumn(
                state = rememberLazyListState(),
                modifier = Modifier.weight(1f).fillMaxHeight(),
                contentPadding = PaddingValues(top = topPad, bottom = bottomPad + 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item(key = "import") { importCard() }
                if (diagnostic.isNotEmpty()) item(key = "diag") { diagnosticCard() }
            }
            LazyColumn(
                state = rememberLazyListState(),
                modifier = Modifier.weight(1f).fillMaxHeight(),
                contentPadding = PaddingValues(top = topPad, bottom = bottomPad + 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item(key = "profiles") { profilesCard() }
            }
        }
    } else {
        LazyColumn(
            state = rememberLazyListState(),
            modifier = modifier
                .fillMaxSize()
                .consumeWindowInsets(contentPadding)
                .imePadding(),
            contentPadding = contentPadding,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "import") { importCard() }
            item(key = "profiles") { profilesCard() }
            if (diagnostic.isNotEmpty()) item(key = "diag") { diagnosticCard() }
        }
    }

    if (showRuleDnsSheet) {
        RuleDnsModalSheet(
            kdlText = kdlText,
            onApplyConfig = onApplyConfig,
            onResultFeedback = onDiagnosticChange,
            onDismiss = { showRuleDnsSheet = false },
        )
    }
}
