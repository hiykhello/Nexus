package org.nexus.android.ui

import androidx.compose.foundation.clickable
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.nexus.android.apps.InstalledAppEntry
import org.nexus.android.apps.InstalledAppsRepository
import org.nexus.android.bridge.model.PerAppMode
import org.nexus.android.data.ProfileRepository

@Composable
fun SplitTunnelingPane(
    appsRepository: InstalledAppsRepository,
    profileRepository: ProfileRepository,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var includeSystem by remember { mutableStateOf(false) }
    var selectedPackages by remember { mutableStateOf(emptySet<String>()) }
    var mode by remember { mutableStateOf(PerAppMode.DISALLOW_LIST) }

    val apps by produceState<List<InstalledAppEntry>>(initialValue = emptyList(), includeSystem) {
        val profile = profileRepository.loadActiveProfile()
        mode = profile.config.perAppMode
        selectedPackages = profile.config.packages
        value = appsRepository.listInstalledApps(includeSystem)
    }

    val filteredApps = remember(apps, query) {
        val needle = query.trim()
        if (needle.isEmpty()) apps
        else apps.filter {
            it.label.contains(needle, ignoreCase = true) ||
                it.packageName.contains(needle, ignoreCase = true)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                mode = if (mode == PerAppMode.DISALLOW_LIST) PerAppMode.ALLOW_LIST else PerAppMode.DISALLOW_LIST
                scope.launch { profileRepository.saveSplitTunneling(mode, selectedPackages) }
            }) {
                Text(if (mode == PerAppMode.DISALLOW_LIST) "模式: 绕过已选应用" else "模式: 仅代理已选应用")
            }
            OutlinedButton(onClick = {
                val merged = selectedPackages + InstalledAppsRepository.RECOMMENDED_BYPASS_PACKAGES
                selectedPackages = merged
                scope.launch { profileRepository.saveSplitTunneling(mode, merged) }
            }) {
                Text("加入推荐绕过")
            }
        }

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("搜索应用名或包名") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(
                items = filteredApps,
                key = { it.packageName },
                contentType = { "installed_app_row" },
            ) { app ->
                AppSelectionRow(
                    app = app,
                    // Defer Set lookup to leaf row scope to avoid recomposing all visible rows on toggle.
                    isSelectedProvider = { selectedPackages.contains(app.packageName) },
                    onToggle = {
                        val next = if (selectedPackages.contains(app.packageName)) {
                            selectedPackages - app.packageName
                        } else {
                            selectedPackages + app.packageName
                        }
                        selectedPackages = next
                        scope.launch { profileRepository.saveSplitTunneling(mode, next) }
                    },
                )
            }
        }
    }
}

@Composable
private fun AppSelectionRow(
    app: InstalledAppEntry,
    isSelectedProvider: () -> Boolean,
    onToggle: () -> Unit,
) {
    val selected = isSelectedProvider()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Checkbox(checked = selected, onCheckedChange = { onToggle() })
        Column(modifier = Modifier.weight(1f)) {
            Text(text = app.label, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
