package org.nexus.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot

@Composable
fun ConnectionsScreen(
    onFetchConnections: suspend () -> List<ActiveConnectionSnapshot>,
    onInspectConnection: suspend (Long) -> ActiveConnectionSnapshot?,
    onResolveOwnerPackage: (ActiveConnectionSnapshot) -> String?,
    onCloseConnection: suspend (Long) -> Boolean,
    onCloseAllConnections: suspend () -> Boolean,
) {
    val scope = rememberCoroutineScope()
    val twoPane = LocalConfiguration.current.screenWidthDp >= 840
    var connections by remember { mutableStateOf<List<ActiveConnectionSnapshot>>(emptyList()) }
    var selectedDetail by remember { mutableStateOf<ActiveConnectionSnapshot?>(null) }
    var resolvedOwner by remember { mutableStateOf<String?>(null) }
    var query by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        connections = onFetchConnections()
    }

    val filtered = remember(connections, query) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) connections
        else connections.filter {
            it.protocol.lowercase().contains(q) ||
                it.path.lowercase().contains(q) ||
                it.outbound.lowercase().contains(q) ||
                it.inbound.lowercase().contains(q) ||
                it.target.lowercase().contains(q) ||
                it.destinationPort.toString().contains(q)
        }
    }

    val inspect: (ActiveConnectionSnapshot) -> Unit = { conn ->
        scope.launch {
            val detail = onInspectConnection(conn.id) ?: conn
            selectedDetail = detail
            resolvedOwner = onResolveOwnerPackage(detail)
        }
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("按协议/入站/出站/目标/端口过滤 (${filtered.size})") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(onClick = {
                scope.launch {
                    if (onCloseAllConnections()) {
                        selectedDetail = null
                        resolvedOwner = null
                        connections = onFetchConnections()
                    }
                }
            }) {
                Text("全部断开")
            }
            OutlinedButton(onClick = { scope.launch { connections = onFetchConnections() } }) {
                Text("刷新")
            }
        }

        if (!twoPane && selectedDetail != null) {
            ConnectionDetailPane(
                detail = selectedDetail!!,
                ownerPackage = resolvedOwner,
                onDismiss = {
                    selectedDetail = null
                    resolvedOwner = null
                },
                onClose = { id ->
                    scope.launch {
                        if (onCloseConnection(id)) {
                            selectedDetail = null
                            resolvedOwner = null
                            connections = onFetchConnections()
                        }
                    }
                },
            )
        }

        Row(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(modifier = Modifier.weight(1f).fillMaxHeight()) {
                if (filtered.isEmpty()) {
                    Text("当前无活跃连接", style = MaterialTheme.typography.bodyMedium)
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(filtered, key = { it.id }) { conn ->
                            val isSelected = selectedDetail?.id == conn.id
                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { inspect(conn) },
                                colors = if (isSelected) {
                                    CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
                                } else {
                                    CardDefaults.cardColors()
                                },
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp),
                                ) {
                                    Text(
                                        "#${conn.id} · ${conn.protocol} · ${conn.outbound.ifEmpty { conn.path }} → ${conn.target.ifEmpty { ":${conn.destinationPort}" }}",
                                        style = MaterialTheme.typography.titleSmall,
                                    )
                                    Text(
                                        "入站: ${conn.inbound.ifEmpty { "listener ${conn.listener}" }} · ↑ ${conn.uploadBytes / 1024} KiB · ↓ ${conn.downloadBytes / 1024} KiB · ${conn.durationMs} ms",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        OutlinedButton(onClick = { inspect(conn) }) { Text("详情") }
                                        OutlinedButton(onClick = {
                                            scope.launch {
                                                if (onCloseConnection(conn.id)) {
                                                    if (selectedDetail?.id == conn.id) {
                                                        selectedDetail = null
                                                        resolvedOwner = null
                                                    }
                                                    connections = onFetchConnections()
                                                }
                                            }
                                        }) {
                                            Text("断开")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (twoPane) {
                Column(modifier = Modifier.weight(0.85f).fillMaxHeight()) {
                    val detail = selectedDetail
                    if (detail != null) {
                        ConnectionDetailPane(
                            detail = detail,
                            ownerPackage = resolvedOwner,
                            onDismiss = {
                                selectedDetail = null
                                resolvedOwner = null
                            },
                            onClose = { id ->
                                scope.launch {
                                    if (onCloseConnection(id)) {
                                        selectedDetail = null
                                        resolvedOwner = null
                                        connections = onFetchConnections()
                                    }
                                }
                            },
                        )
                    } else {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("连接详情", style = MaterialTheme.typography.titleMedium)
                                Text(
                                    "点击左侧任意活跃连接以查看所属应用包名、SNI/目标、命中规则与进程元数据。",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ConnectionDetailPane(
    detail: ActiveConnectionSnapshot,
    ownerPackage: String?,
    onDismiss: () -> Unit,
    onClose: (Long) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("连接 #${detail.id} 全链路详情", style = MaterialTheme.typography.titleMedium)
            Text("所属应用: ${ownerPackage ?: "系统 / 未识别"}", style = MaterialTheme.typography.bodySmall)
            Text(
                "入站: ${detail.inbound.ifEmpty { detail.protocol }} · 出站: ${detail.outbound.ifEmpty { detail.path }}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "来源: ${detail.source.ifEmpty { "-" }} → 目标/SNI: ${detail.target.ifEmpty { ":${detail.destinationPort}" }}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "路由模式: ${detail.routeMode.ifEmpty { "-" }} · 命中规则: ${detail.routeRule.ifEmpty { "-" }}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "持续时长: ${detail.durationMs} ms · 进程: ${detail.processPath.ifEmpty { "-" }}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "流量统计: ↑ ${detail.uploadBytes / 1024} KiB · ↓ ${detail.downloadBytes / 1024} KiB",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { onClose(detail.id) }) { Text("断开连接") }
                OutlinedButton(onClick = onDismiss) { Text("收起") }
            }
        }
    }
}
