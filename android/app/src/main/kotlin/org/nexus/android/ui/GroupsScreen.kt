package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot

@Composable
fun GroupsScreen(
    onFetchGroups: suspend () -> List<OutboundGroupSnapshot>,
    onSelectMember: suspend (group: String, member: String) -> Boolean,
    onResetAuto: suspend (group: String) -> Boolean,
    onProbeGroup: suspend (group: String) -> Boolean,
) {
    val scope = rememberCoroutineScope()
    var groups by remember { mutableStateOf<List<OutboundGroupSnapshot>>(emptyList()) }
    var selectedTag by remember { mutableStateOf("") }
    var feedback by remember { mutableStateOf("") }

    suspend fun reload() {
        val loaded = onFetchGroups()
        groups = loaded
        if (selectedTag.isEmpty() || loaded.none { it.tag == selectedTag }) {
            selectedTag = loaded.firstOrNull()?.tag.orEmpty()
        }
    }

    LaunchedEffect(Unit) { reload() }

    val activeGroup = groups.firstOrNull { it.tag == selectedTag }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "出站策略组",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            if (activeGroup != null && (activeGroup.mode == "url-test" || activeGroup.mode == "fallback")) {
                OutlinedButton(onClick = {
                    scope.launch {
                        val ok = onProbeGroup(activeGroup.tag)
                        feedback = if (ok) "已触发 ${activeGroup.tag} 立即测速" else "测速触发失败"
                        reload()
                    }
                }) { Text("测速") }
            }
            if (activeGroup != null && activeGroup.manualOverride) {
                OutlinedButton(onClick = {
                    scope.launch {
                        val ok = onResetAuto(activeGroup.tag)
                        feedback = if (ok) "已恢复自动选优" else "恢复失败"
                        reload()
                    }
                }) { Text("恢复自动") }
            }
            OutlinedButton(onClick = { scope.launch { reload() } }) { Text("刷新") }
        }

        if (groups.isEmpty()) {
            Text("当前未检测到策略组（请确认核心运行并启用 HTTP 控制面）。")
        } else {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(groups, key = { it.tag }) { group ->
                    FilterChip(
                        selected = group.tag == selectedTag,
                        onClick = { selectedTag = group.tag },
                        label = { Text("${group.tag} (${group.active})") },
                    )
                }
            }
            if (feedback.isNotEmpty()) {
                Text(feedback, style = MaterialTheme.typography.bodySmall)
            }
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                val members = activeGroup?.members.orEmpty()
                items(members, key = { it.name }) { member ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = if (member.overridden) "${member.name} [手动覆盖]" else member.name,
                                    style = MaterialTheme.typography.bodyLarge,
                                )
                                Text(
                                    text = if (member.latencyMs >= 0) "${member.state} · ${member.latencyMs} ms" else member.state,
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Button(
                                enabled = !member.selected,
                                onClick = {
                                    val g = activeGroup?.tag ?: return@Button
                                    scope.launch {
                                        val ok = onSelectMember(g, member.name)
                                        feedback = if (ok) "已切换至 ${member.name}" else "切换失败"
                                        reload()
                                    }
                                },
                            ) { Text(if (member.selected) "当前" else "切换") }
                        }
                    }
                }
            }
        }
    }
}
