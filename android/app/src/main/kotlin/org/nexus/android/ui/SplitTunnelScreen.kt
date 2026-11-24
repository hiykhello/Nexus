package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.apps.InstalledAppEntry
import org.nexus.android.apps.InstalledAppsRepository
import org.nexus.android.ui.theme.NexusTheme

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
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val ext = NexusTheme.colors
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
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (onBack != null) {
                        IconButton(onClick = onBack, modifier = Modifier.size(32.dp)) {
                            Icon(
                                painter = painterResource(R.drawable.ic_back),
                                contentDescription = "返回",
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "分应用绕过",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = "已选择 ${excludedPackages.size} 个应用直连绕过 VPN 隧道",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    FilterChip(
                        selected = includeSystem,
                        onClick = { includeSystem = !includeSystem },
                        label = { Text("包含系统应用") },
                    )
                    AssistChip(
                        onClick = {
                            InstalledAppsRepository.RECOMMENDED_BYPASS_PACKAGES.forEach { pkg ->
                                onToggleExcluded(pkg, true)
                            }
                            if (running) needsRestartBanner = true
                        },
                        label = { Text("应用推荐绕过") },
                    )
                }
            }
        }

        if (running && needsRestartBanner) {
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
                        text = "绕过列表已变更，重启隧道后立即生效",
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
            placeholder = { Text("搜索应用名称或包名...") },
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
                subtitle = "请尝试更换搜索关键字或开启「包含系统应用」。",
                iconRes = R.drawable.ic_apps,
            )
        } else {
            val cols = if (windowSizeClass == NexusWindowSizeClass.COMPACT) {
                GridCells.Fixed(1)
            } else {
                GridCells.Adaptive(minSize = 280.dp)
            }
            LazyVerticalGrid(
                state = rememberLazyGridState(),
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
    checkedProvider: () -> Boolean,
    onToggle: (Boolean) -> Unit,
) {
    val checked = checkedProvider()
    val ext = NexusTheme.colors

    OpticalCard(
        modifier = Modifier.fillMaxWidth(),
        cornerRadius = 14.dp,
        borderColor = if (checked) MaterialTheme.colorScheme.primary else ext.hairline,
        accentTint = if (checked) MaterialTheme.colorScheme.primary.copy(alpha = 0.08f) else Color.Transparent,
        onClick = { onToggle(!checked) },
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
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
