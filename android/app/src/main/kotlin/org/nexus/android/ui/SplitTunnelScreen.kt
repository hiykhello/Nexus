package org.nexus.android.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledAppEntry(val packageName: String, val label: String)

@Composable
fun SplitTunnelScreen(
    excludedPackages: Set<String>,
    onToggleExcluded: (packageName: String, excluded: Boolean) -> Unit,
) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<InstalledAppEntry>>(emptyList()) }
    var filter by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) { loadUserApps(context) }
    }

    val visible = remember(apps, filter) {
        val q = filter.trim().lowercase()
        if (q.isEmpty()) apps
        else apps.filter { it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q) }
    }

    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(
            text = "分应用绕过（勾选的应用将直连不走 VPN 隧道，下次启动隧道生效）",
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = filter,
            onValueChange = { filter = it },
            label = { Text("搜索应用名或包名") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(visible, key = { it.packageName }) { app ->
                val checked = excludedPackages.contains(app.packageName)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(
                        checked = checked,
                        onCheckedChange = { onToggleExcluded(app.packageName, it) },
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(app.label, style = MaterialTheme.typography.bodyMedium)
                        Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

private fun loadUserApps(context: Context): List<InstalledAppEntry> {
    val pm = context.packageManager
    val selfPkg = context.packageName
    return pm.getInstalledApplications(0)
        .asSequence()
        .filter { it.packageName != selfPkg && (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
        .map { InstalledAppEntry(it.packageName, pm.getApplicationLabel(it).toString()) }
        .sortedBy { it.label.lowercase() }
        .toList()
}
