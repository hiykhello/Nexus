package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

@Composable
fun ConfigScreen(
    kdlText: String,
    onKdlChange: (String) -> Unit,
    diagnostic: String,
    onDiagnosticChange: (String) -> Unit,
    onImportShareLink: (String, String) -> Pair<String, String>,
    onImportSubscription: suspend (String, String) -> Pair<String, String>,
    onValidateKdl: suspend (String) -> Pair<Boolean, String>,
    onSaveAndReload: suspend (String) -> Pair<Boolean, String>,
) {
    val scope = rememberCoroutineScope()
    var shareUri by remember { mutableStateOf("") }
    var subUrl by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = shareUri,
                onValueChange = { shareUri = it },
                label = { Text("导入 vless/trojan/hy2/ss 链接") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(onClick = {
                val (updated, note) = onImportShareLink(shareUri, kdlText)
                onKdlChange(updated)
                onDiagnosticChange(note)
                shareUri = ""
            }) { Text("导入") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = subUrl,
                onValueChange = { subUrl = it },
                label = { Text("HTTPS 订阅链接") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(onClick = {
                val url = subUrl
                scope.launch {
                    val (updated, note) = onImportSubscription("subscription", url)
                    if (updated.isNotEmpty()) onKdlChange(updated)
                    onDiagnosticChange(note)
                }
            }) { Text("拉取") }
        }
        OutlinedTextField(
            value = kdlText,
            onValueChange = onKdlChange,
            label = { Text("config.kdl") },
            modifier = Modifier.fillMaxWidth().height(280.dp),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { scope.launch { onDiagnosticChange(onValidateKdl(kdlText).second) } }) {
                Text("校验")
            }
            Button(onClick = { scope.launch { onDiagnosticChange(onSaveAndReload(kdlText).second) } }) {
                Text("保存重载")
            }
        }
        if (diagnostic.isNotEmpty()) Text(diagnostic)
    }
}
