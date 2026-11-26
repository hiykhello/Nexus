package org.nexus.android.ui

import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.apps.AppIconCache
import org.nexus.android.apps.InstalledAppEntry
import org.nexus.android.apps.InstalledAppsRepository
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusTheme

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SplitTunnelScreen(
    running: Boolean,
    excludedPackages: Set<String>,
    onToggleExcluded: (packageName: String, excluded: Boolean) -> Unit,
    onRestartVpn: () -> Unit,
    windowSizeClass: NexusWindowSizeClass,
    contentPadding: PaddingValues,
    onBack: (() -> Unit)? = null,
    previewApps: List<InstalledAppEntry>? = null,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    onPerAppModeChange: (AndroidPerAppMode) -> Unit = {},
    excludeSelfFromVpn: Boolean = false,
    onToggleExcludeSelf: (Boolean) -> Unit = {},
    allowBypass: Boolean = false,
    onToggleAllowBypass: (Boolean) -> Unit = {},
    onAddExcludedBatch: ((Set<String>) -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val density = LocalDensity.current
    val ext = NexusTheme.colors
    // Hoisted above conditional branches to keep scroll position across filter changes.
    val gridState = rememberLazyGridState()
    val iconSizePx = remember(density) { with(density) { 40.dp.roundToPx() } }

    var filter by rememberSaveable { mutableStateOf("") }
    var includeSystem by rememberSaveable { mutableStateOf(false) }
    var needsRestartBanner by rememberSaveable { mutableStateOf(false) }

    val apps by produceState(
        initialValue = previewApps ?: emptyList(),
        key1 = previewApps,
    ) {
        value = previewApps ?: InstalledAppsRepository(context).listInstalledApps(includeSystem = true)
    }

    val visible = remember(apps, filter, includeSystem) {
        val q = filter.trim().lowercase()
        apps.filter { entry ->
            (includeSystem || !entry.isSystemApp) &&
                (q.isEmpty() || entry.label.lowercase().contains(q) || entry.packageName.lowercase().contains(q))
        }
    }

    val layoutDirection = LocalLayoutDirection.current
    val startPad = contentPadding.calculateStartPadding(layoutDirection) + 16.dp
    val endPad = contentPadding.calculateEndPadding(layoutDirection) + 16.dp
    val topPad = contentPadding.calculateTopPadding()
    val bottomPad = contentPadding.calculateBottomPadding()

    Column(
        modifier = modifier
            .fillMaxSize()
            .consumeWindowInsets(contentPadding)
            .imePadding()
            .padding(start = startPad, end = endPad, top = topPad),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        OpticalCard(cornerRadius = 16.dp) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    if (onBack != null) {
                        IconButton(onClick = onBack) {
                            Icon(
                                painter = painterResource(R.drawable.ic_back),
                                contentDescription = "返回",
                                modifier = Modifier.size(20.dp),
                            )
                        }
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        if (onBack != null) {
                            Text(
                                text = "分应用分流控制",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                            )
                        }
                        val modeDesc = when (perAppMode) {
                            AndroidPerAppMode.OFF -> "当前已关闭分应用，全部应用经 VPN 隧道"
                            AndroidPerAppMode.EXCLUDE -> "已选择 ${excludedPackages.size} 个应用直连绕过 VPN 隧道"
                            AndroidPerAppMode.INCLUDE -> "仅 ${excludedPackages.size} 个所选应用经 VPN 隧道代理"
                        }
                        Text(
                            text = modeDesc,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                OpticalSegmentedControl(
                    options = listOf(
                        AndroidPerAppMode.OFF.wire to "关闭",
                        AndroidPerAppMode.EXCLUDE.wire to "排除",
                        AndroidPerAppMode.INCLUDE.wire to "仅代理",
                    ),
                    selectedKey = perAppMode.wire,
                    onSelect = { key ->
                        onPerAppModeChange(AndroidPerAppMode.fromWire(key))
                        if (running) needsRestartBanner = true
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    FilterChip(
                        selected = includeSystem,
                        onClick = { includeSystem = !includeSystem },
                        label = { Text("系统应用") },
                    )
                    FilterChip(
                        selected = !excludeSelfFromVpn,
                        onClick = {
                            onToggleExcludeSelf(!excludeSelfFromVpn)
                            if (running) needsRestartBanner = true
                        },
                        label = { Text("本应用走 VPN") },
                    )
                    FilterChip(
                        selected = allowBypass,
                        onClick = {
                            onToggleAllowBypass(!allowBypass)
                            if (running) needsRestartBanner = true
                        },
                        label = { Text("允许绕过") },
                    )
                    if (perAppMode == AndroidPerAppMode.EXCLUDE) {
                        AssistChip(
                            onClick = {
                                val recommended = InstalledAppsRepository.RECOMMENDED_BYPASS_PACKAGES
                                if (onAddExcludedBatch != null) {
                                    onAddExcludedBatch(recommended)
                                } else {
                                    recommended.forEach { pkg -> onToggleExcluded(pkg, true) }
                                }
                                if (running) needsRestartBanner = true
                            },
                            label = { Text("推荐绕过") },
                        )
                    }
                }
            }
        }

        if (perAppMode == AndroidPerAppMode.INCLUDE && excludedPackages.isEmpty()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = ext.warningContainer,
                border = BorderStroke(1.dp, ext.warning.copy(alpha = 0.45f)),
            ) {
                Text(
                    text = "当前「仅代理」未勾选任何应用，第三方应用均不会经过 VPN；请在下方勾选需要代理的应用。",
                    style = MaterialTheme.typography.bodySmall,
                    color = ext.warning,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                )
            }
        }

        if (running && needsRestartBanner) {
            val bannerText = when (perAppMode) {
                AndroidPerAppMode.INCLUDE -> "代理应用列表已变更，重启隧道后立即生效"
                AndroidPerAppMode.EXCLUDE -> "绕过应用列表已变更，重启隧道后立即生效"
                AndroidPerAppMode.OFF -> "分应用模式已关闭，重启隧道后立即生效"
            }
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = ext.warningContainer,
                border = BorderStroke(1.dp, ext.warning.copy(alpha = 0.45f)),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = bannerText,
                        style = MaterialTheme.typography.bodySmall,
                        color = ext.warning,
                        modifier = Modifier.weight(1f),
                    )
                    FilledTonalButton(
                        onClick = {
                            needsRestartBanner = false
                            onRestartVpn()
                        },
                    ) {
                        Text("立即重启")
                    }
                }
            }
        }

        OutlinedTextField(
            value = filter,
            onValueChange = { filter = it },
            placeholder = { Text("搜索应用名称或包名…", maxLines = 1, overflow = TextOverflow.Ellipsis) },
            shape = RoundedCornerShape(999.dp),
            leadingIcon = {
                Icon(
                    painter = painterResource(R.drawable.ic_search),
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
            },
            trailingIcon = {
                if (filter.isNotEmpty()) {
                    IconButton(onClick = { filter = "" }) {
                        Icon(
                            painter = painterResource(R.drawable.ic_close),
                            contentDescription = "清除",
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
            },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        if (visible.isEmpty()) {
            EmptyStateCard(
                title = "未找到匹配应用",
                subtitle = "请尝试更换搜索关键字或开启「系统应用」。",
                iconRes = R.drawable.ic_apps,
            )
        } else {
            val cols = if (windowSizeClass == NexusWindowSizeClass.COMPACT) {
                GridCells.Fixed(1)
            } else {
                GridCells.Adaptive(minSize = 280.dp)
            }
            LazyVerticalGrid(
                state = gridState,
                columns = cols,
                modifier = Modifier.weight(1f).fillMaxWidth(),
                contentPadding = PaddingValues(bottom = bottomPad + 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(
                    items = visible,
                    key = { it.packageName },
                    contentType = { "app_row" },
                ) { app ->
                    SplitTunnelAppRow(
                        app = app,
                        context = context,
                        iconSizePx = iconSizePx,
                        loadIcons = previewApps == null,
                        checkedProvider = { excludedPackages.contains(app.packageName) },
                        onToggle = { next ->
                            onToggleExcluded(app.packageName, next)
                            if (running) needsRestartBanner = true
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun SplitTunnelAppRow(
    app: InstalledAppEntry,
    context: Context,
    iconSizePx: Int,
    loadIcons: Boolean,
    checkedProvider: () -> Boolean,
    onToggle: (Boolean) -> Unit,
) {
    val checked = checkedProvider()
    val ext = NexusTheme.colors
    val iconBitmap: ImageBitmap? by produceState(
        initialValue = if (loadIcons) AppIconCache.peek(app.packageName, iconSizePx) else null,
        key1 = app.packageName,
        key2 = loadIcons,
    ) {
        if (loadIcons && value == null) {
            value = AppIconCache.load(context, app.packageName, iconSizePx)
        }
    }

    OpticalCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 16.dp,
        borderColor = if (checked) MaterialTheme.colorScheme.primary else ext.hairline,
        accentTint = if (checked) MaterialTheme.colorScheme.primary.copy(alpha = 0.06f) else Color.Transparent,
        onClick = { onToggle(!checked) },
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (iconBitmap != null) {
                Image(
                    bitmap = iconBitmap!!,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(40.dp).clip(RoundedCornerShape(10.dp)),
                )
            } else {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(
                            color = if (checked) MaterialTheme.colorScheme.primaryContainer else ext.wellSurface,
                            shape = RoundedCornerShape(10.dp),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = app.label.take(1).uppercase(),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (checked) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = app.label,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (app.isSystemApp) {
                        StatusPill(
                            text = "系统",
                            containerColor = ext.mutedContainer,
                            contentColor = ext.muted,
                        )
                    }
                }
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = onToggle,
            )
        }
    }
}
