package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.nexus.android.bridge.uds.ControlSocketClient

@Composable
fun RuntimeControlCard(
    controlClient: ControlSocketClient,
    enabled: Boolean,
) {
    val scope = rememberCoroutineScope()
    var logLevel by remember { mutableStateOf("info") }
    var lastReply by remember { mutableStateOf("") }

    fun send(block: () -> Result<String>) {
        scope.launch {
            val result = withContext(Dispatchers.IO) { block() }
            lastReply = result.fold(
                onSuccess = { it.trim() },
                onFailure = { "控制面未就绪: ${it.message}" },
            )
        }
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "实时控制面 (c.sock)", style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = enabled, onClick = { send { controlClient.status() } }) {
                    Text("查询状态")
                }
                OutlinedButton(enabled = enabled, onClick = { send { controlClient.reload() } }) {
                    Text("热重载")
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = logLevel,
                    onValueChange = { logLevel = it },
                    label = { Text("日志级别") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Button(
                    enabled = enabled && logLevel.isNotBlank(),
                    onClick = { send { controlClient.setLogLevel(logLevel.trim()) } },
                ) {
                    Text("应用")
                }
            }
            if (lastReply.isNotEmpty()) {
                Text(text = lastReply, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
