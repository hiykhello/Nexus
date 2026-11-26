package org.nexus.android.ui

import android.content.ClipboardManager
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.bridge.workspace.WorkspaceSyncBridge
import org.nexus.android.ui.theme.NexusTheme

data class UiProfileChip(
    val id: String,
    val name: String,
    val active: Boolean,
)

/**
 * Graphite Bento Mobile 4-Pillar Workspace & Host Settings (`档案`) screen:
 * - Hoisted `LazyListState`s above responsive branches
 * - Flattened `profilesPillarItems(...)` so 100+ subscription nodes stay virtualized
 */
@Composable
fun ConfigScreen(
    kdlText: String,
    onApplyConfig: suspend (String) -> Pair<Boolean, String>,
    diagnostic: String,
    onDiagnosticChange: (String) -> Unit,
    onImportShareLink: suspend (String, String) -> Pair<String?, String>,
    onImportSubscription: suspend (String, String) -> Pair<String, String>,
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    onOpenSplitTunnel: (() -> Unit)? = null,
    onOpenDiagnostics: (() -> Unit)? = null,
    workspaceState: WorkspaceUiState = WorkspaceUiState(),
    workspaceActions: WorkspaceUiActions = WorkspaceUiActions(),
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val layoutDirection = LocalLayoutDirection.current
    val ext = NexusTheme.colors
    // Hoisted scroll states above responsive branches.
    val primaryListState = rememberLazyListState()
    val secondaryListState = rememberLazyListState()

    var activePillar by rememberSaveable { mutableStateOf("profiles") }
    var showRuleDnsSheet by rememberSaveable { mutableStateOf(false) }
    val diagnosticError = diagnostic.contains("失败") || diagnostic.contains("拒绝") || diagnostic.contains("错误") || diagnostic.contains("无效")

    val importClipboard: () -> Unit = {
        val raw = context.getSystemService(ClipboardManager::class.java)
            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            onDiagnosticChange("剪贴板为空，请先复制节点、订阅链接或便携工作区 JSON")
        } else {
            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
            scope.launch {
                val lower = raw.lowercase()
                when {
                    raw.startsWith(WorkspaceSyncBridge.SHARE_URI_PREFIX) -> {
                        onDiagnosticChange(workspaceActions.onImportShareUri(raw))
                    }
                    raw.startsWith("{") && raw.contains("\"schema_version\"") -> {
                        onDiagnosticChange(workspaceActions.onImportWorkspaceJson(raw))
                    }
                    raw.contains("schema-version") || (raw.contains("routing {") && raw.contains("outbound ")) -> {
                        onDiagnosticChange(onApplyConfig(raw).second)
                    }
                    (lower.startsWith("https://") || lower.startsWith("http://127.0.0.1")) && !lower.contains("@") -> {
                        val note = workspaceActions.onAddSubscription("订阅", raw)
                        onDiagnosticChange(note.ifBlank { onImportSubscription("subscription", raw).second })
                    }
                    else -> {
                        onDiagnosticChange(onImportShareLink(raw, kdlText).second)
                    }
                }
            }
        }
    }

    val headerCard: @Composable () -> Unit = {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "工作区与本机配置",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                FilledTonalButton(onClick = importClipboard, shape = RoundedCornerShape(999.dp)) {
                    Icon(painterResource(R.drawable.ic_paste), null, Modifier.size(15.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("剪贴板导入")
                }
            }
            OpticalSegmentedControl(
                options = listOf(
                    "profiles" to "节点",
                    "subs" to "订阅",
                    "routing" to "路由DNS",
                    "host" to "本机",
                ),
                selectedKey = activePillar,
                onSelect = { activePillar = it },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }

    val diagnosticBanner: @Composable () -> Unit = {
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

    fun LazyListScope.emitActivePillarItems() {
        item(key = "hdr", contentType = "header") { headerCard() }
        if (diagnostic.isNotEmpty()) {
            item(key = "diag", contentType = "diag") { diagnosticBanner() }
        }
        when (activePillar) {
            "subs" -> item(key = "subs_pane", contentType = "subs") {
                SubscriptionsPillarPane(
                    state = workspaceState,
                    actions = workspaceActions,
                    onFeedback = onDiagnosticChange,
                )
            }
            "routing" -> item(key = "routing_pane", contentType = "routing") {
                RoutingDnsPillarPane(
                    state = workspaceState,
                    actions = workspaceActions,
                    onOpenRuleDnsModal = { showRuleDnsSheet = true },
                    onOpenDiagnostics = onOpenDiagnostics,
                    onFeedback = onDiagnosticChange,
                )
            }
            "host" -> {
                item(key = "host_card", contentType = "host") {
                    HostSettingsCard(
                        host = workspaceState.host,
                        onUpdateHost = { next -> scope.launch { onDiagnosticChange(workspaceActions.onUpdateHost(next)) } },
                        onOpenSplitTunnel = onOpenSplitTunnel,
                    )
                }
                item(key = "sync_card", contentType = "sync") {
                    WebDavSyncCard(
                        state = workspaceState,
                        actions = workspaceActions,
                        onFeedback = onDiagnosticChange,
                    )
                }
                item(key = "udp_card", contentType = "udp") {
                    UdpProbeCard(
                        state = workspaceState,
                        actions = workspaceActions,
                        onFeedback = onDiagnosticChange,
                    )
                }
            }
            else -> profilesPillarItems(
                state = workspaceState,
                actions = workspaceActions,
                scope = scope,
                context = context,
                onFeedback = onDiagnosticChange,
                onQuickShareImport = { uri ->
                    scope.launch { onDiagnosticChange(onImportShareLink(uri, kdlText).second) }
                },
            )
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
                state = primaryListState,
                modifier = Modifier.weight(1.08f).fillMaxHeight(),
                contentPadding = PaddingValues(top = topPad, bottom = bottomPad + 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                emitActivePillarItems()
            }
            LazyColumn(
                state = secondaryListState,
                modifier = Modifier.weight(0.92f).fillMaxHeight(),
                contentPadding = PaddingValues(top = topPad, bottom = bottomPad + 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (activePillar != "routing") {
                    item(key = "side_routing", contentType = "routing") {
                        RoutingDnsPillarPane(
                            state = workspaceState,
                            actions = workspaceActions,
                            onOpenRuleDnsModal = { showRuleDnsSheet = true },
                            onOpenDiagnostics = onOpenDiagnostics,
                            onFeedback = onDiagnosticChange,
                        )
                    }
                }
                if (activePillar != "host") {
                    item(key = "side_host", contentType = "host") {
                        HostSettingsCard(
                            host = workspaceState.host,
                            onUpdateHost = { next -> scope.launch { onDiagnosticChange(workspaceActions.onUpdateHost(next)) } },
                            onOpenSplitTunnel = onOpenSplitTunnel,
                        )
                    }
                }
            }
        }
    } else {
        LazyColumn(
            state = primaryListState,
            modifier = modifier
                .fillMaxSize()
                .consumeWindowInsets(contentPadding)
                .imePadding(),
            contentPadding = contentPadding,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            emitActivePillarItems()
        }
    }

    if (showRuleDnsSheet) {
        RuleDnsModalSheet(
            workspaceState = workspaceState,
            workspaceActions = workspaceActions,
            onResultFeedback = onDiagnosticChange,
            onDismiss = { showRuleDnsSheet = false },
        )
    }
}
