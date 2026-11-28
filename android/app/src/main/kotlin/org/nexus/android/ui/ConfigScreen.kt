package org.nexus.android.ui

import android.content.ClipboardManager
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
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusTheme

data class UiProfileChip(
    val id: String,
    val name: String,
    val active: Boolean,
)

/**
 * 3-Pillar Configuration & Server Console (`配置文件`):
 * - Pillar 1 (`profiles`): Unified Server Table + Subscription Group Filter Bar + Create/Edit 13-Protocol Wizard
 * - Pillar 2 (`routing`): Routing Sets + `domain_strategy` + Rules Table + `RuleSetAsset` (`nxmm`/`srs`) Manager
 * - Pillar 3 (`host`): Full `SimpleDns` (`FakeIP`, `Hosts`, advanced DNS) + Global Template + Local Inbounds/VPN/Opacity + WebDAV Sync
 */
@Composable
fun ConfigScreen(
    diagnostic: String,
    onDiagnosticChange: (String) -> Unit,
    onImportCustomConfig: suspend (String) -> String = { "" },
    onImportShareLink: suspend (String) -> String = { "" },
    onImportSubscription: suspend (String, String) -> String = { _, _ -> "" },
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    onOpenSplitTunnel: (() -> Unit)? = null,
    onOpenDiagnostics: (() -> Unit)? = null,
    profileLatencies: Map<String, Long> = emptyMap(),
    isProbingProfiles: Boolean = false,
    onProbeProfiles: () -> Unit = {},
    workspaceState: WorkspaceUiState = WorkspaceUiState(),
    workspaceActions: WorkspaceUiActions = WorkspaceUiActions(),
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val layoutDirection = LocalLayoutDirection.current
    val ext = NexusTheme.colors
    val reducedMotion = isReducedMotionEnabled()

    val primaryListState = rememberLazyListState()
    val secondaryListState = rememberLazyListState()

    var activePillar by rememberSaveable { mutableStateOf("profiles") }
    var selectedSubTab by rememberSaveable { mutableStateOf("all") }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var sortMode by rememberSaveable { mutableStateOf("default") }
    var showSubDrawer by rememberSaveable { mutableStateOf(false) }
    var showRuleDnsSheet by rememberSaveable { mutableStateOf(false) }
    var editorOpen by rememberSaveable { mutableStateOf(false) }
    var editingProfileId by rememberSaveable { mutableStateOf<String?>(null) }
    val editingProfile = editingProfileId?.let { id -> workspaceState.document.profiles.firstOrNull { it.id == id } }
    LaunchedEffect(editorOpen, editingProfileId, workspaceState.document.profiles) {
        if (editorOpen && editingProfileId != null && editingProfile == null && workspaceState.document.profiles.isNotEmpty()) {
            editorOpen = false
            editingProfileId = null
        }
    }

    val diagnosticError = diagnostic.contains("失败") || diagnostic.contains("拒绝") || diagnostic.contains("错误") || diagnostic.contains("无效")

    val importClipboard: () -> Unit = {
        val raw = context.getSystemService(ClipboardManager::class.java)
            ?.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            onDiagnosticChange("剪贴板为空，请先复制节点链接、Base64 订阅、HTTPS 订阅地址或备份")
        } else {
            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
            scope.launch {
                val note = importClipboardPayload(
                    raw = raw,
                    onImportWorkspaceShare = workspaceActions.onImportShareUri,
                    onImportWorkspaceBackup = workspaceActions.onImportWorkspaceJson,
                    onImportCustomConfig = onImportCustomConfig,
                    onImportSubscription = { name, url ->
                        workspaceActions.onAddSubscription(name, url).ifBlank { onImportSubscription(name, url) }
                    },
                    onImportShareLink = onImportShareLink,
                )
                onDiagnosticChange(note)
            }
        }
    }

    val pillarSwitcher: @Composable () -> Unit = {
        OpticalSegmentedControl(
            options = listOf(
                "profiles" to "服务器与订阅",
                "routing" to "路由与规则集",
                "host" to "DNS 与入站",
            ),
            selectedKey = activePillar,
            onSelect = { activePillar = it },
            modifier = Modifier.fillMaxWidth(),
        )
    }

    val diagnosticBanner: @Composable () -> Unit = {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
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
        item(key = "hdr", contentType = "header") { pillarSwitcher() }
        item(key = "diag", contentType = "diag") {
            AnimatedVisibility(
                visible = diagnostic.isNotEmpty(),
                enter = expandVertically(tween(if (reducedMotion) 0 else 165, easing = NexusStrongEaseOut)) + fadeIn(tween(if (reducedMotion) 0 else 150)),
                exit = shrinkVertically(tween(if (reducedMotion) 0 else 120, easing = FastOutSlowInEasing)) + fadeOut(tween(if (reducedMotion) 0 else 110)),
            ) {
                diagnosticBanner()
            }
        }
        when (activePillar) {
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
                item(key = "dns_card", contentType = "dns") {
                    DnsConfigurationCard(
                        state = workspaceState,
                        actions = workspaceActions,
                        onFeedback = onDiagnosticChange,
                    )
                }
                item(key = "host_card", contentType = "host") {
                    HostSettingsCard(
                        host = workspaceState.host,
                        onUpdateHost = { next -> scope.launch { onDiagnosticChange(workspaceActions.onUpdateHost(next)) } },
                        onOpenSplitTunnel = onOpenSplitTunnel,
                    )
                }
                item(key = "tpl_card", contentType = "tpl") {
                    FullTemplateCard(
                        state = workspaceState,
                        actions = workspaceActions,
                        onFeedback = onDiagnosticChange,
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
                selectedSubTab = selectedSubTab,
                onSelectSubTab = { selectedSubTab = it },
                searchQuery = searchQuery,
                onSearchChange = { searchQuery = it },
                sortMode = sortMode,
                onCycleSort = {
                    sortMode = when (sortMode) {
                        "default" -> "latency"
                        "latency" -> "name"
                        "name" -> "protocol"
                        else -> "default"
                    }
                },
                profileLatencies = profileLatencies,
                isProbingProfiles = isProbingProfiles,
                onProbeProfiles = onProbeProfiles,
                showSubDrawer = showSubDrawer,
                onToggleSubDrawer = { showSubDrawer = !showSubDrawer },
                onCreateProfile = { editingProfileId = null; editorOpen = true },
                onEditProfile = { p -> editingProfileId = p.id; editorOpen = true },
                onImportClipboard = importClipboard,
                onFeedback = onDiagnosticChange,
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
                modifier = Modifier.weight(1.12f).fillMaxHeight(),
                contentPadding = PaddingValues(top = topPad, bottom = bottomPad + 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                emitActivePillarItems()
            }
            LazyColumn(
                state = secondaryListState,
                modifier = Modifier.weight(0.88f).fillMaxHeight(),
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
                    item(key = "side_dns", contentType = "dns") {
                        DnsConfigurationCard(
                            state = workspaceState,
                            actions = workspaceActions,
                            onFeedback = onDiagnosticChange,
                        )
                    }
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

    if (editorOpen && (editingProfileId == null || editingProfile != null)) {
        ProfileEditorSheet(
            editingProfile = editingProfile,
            defaultSubId = selectedSubTab,
            workspaceState = workspaceState,
            workspaceActions = workspaceActions,
            onFeedback = onDiagnosticChange,
            onDismiss = { editorOpen = false; editingProfileId = null },
        )
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
