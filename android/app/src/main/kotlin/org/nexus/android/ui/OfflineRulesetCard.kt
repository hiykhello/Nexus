package org.nexus.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.nexus.android.bridge.core.CoreArtifactVerifier
import java.io.File

@Composable
fun OfflineRulesetCard(metered: Boolean) {
    val context = LocalContext.current
    var scanEpoch by remember { mutableIntStateOf(0) }
    var lowPowerPolicy by remember(metered) { mutableStateOf(metered) }

    val binaryStatus = remember(scanEpoch, context) {
        val candidate = File(context.applicationInfo.nativeLibraryDir, "libnexus.so")
        CoreArtifactVerifier.verifyCoreBinary(candidate, expectedSha256Hex = null, requireArm64Elf = true)
    }
    val rulesetSummary = remember(scanEpoch, context) {
        val rulesDir = File(context.noBackupFilesDir, "rulesets")
        CoreArtifactVerifier.evaluateOfflineRulesets(rulesDir)
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "内核产物校验与离线规则集", style = MaterialTheme.typography.titleMedium)
            Text(
                text = if (binaryStatus.valid) {
                    "Sidecar (aarch64 ELF64): 已通过 · SHA-256 ${binaryStatus.sha256Hex.take(16)}…"
                } else {
                    "Sidecar (aarch64 ELF64): ${binaryStatus.reason}"
                },
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                text = "离线规则集缓存: 共 ${rulesetSummary.totalFiles} 份（有效 ${rulesetSummary.freshFiles} / 待更新 ${rulesetSummary.staleFiles} · ${rulesetSummary.totalBytes / 1024} KiB）",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                text = if (lowPowerPolicy) {
                    "网络与续航策略: 低电 / 计费网络省流模式（已延长健康探测周期）"
                } else {
                    "网络与续航策略: 标准均衡模式"
                },
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(onClick = { scanEpoch += 1 }) {
                Text("重新扫描产物与离线规则")
            }
        }
    }
}
