package org.nexus.android.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.dp
import org.nexus.android.bridge.workspace.WorkspaceSyncBridge

enum class NexusWindowSizeClass {
    COMPACT,
    MEDIUM,
    EXPANDED,
}

data class UiLogLine(
    val seq: Long,
    val text: String,
)

@Composable
fun rememberWindowSizeClass(): NexusWindowSizeClass {
    val density = LocalDensity.current
    val widthDp = with(density) { LocalWindowInfo.current.containerSize.width.toDp() }
    return when {
        widthDp >= 840.dp -> NexusWindowSizeClass.EXPANDED
        widthDp >= 600.dp -> NexusWindowSizeClass.MEDIUM
        else -> NexusWindowSizeClass.COMPACT
    }
}

fun formatTrafficBytes(bytes: Long): String {
    val safe = bytes.coerceAtLeast(0L)
    return when {
        safe >= 1024L * 1024L * 1024L -> "%.2f GB".format(safe / (1024.0 * 1024.0 * 1024.0))
        safe >= 1024L * 1024L -> "%.1f MB".format(safe / (1024.0 * 1024.0))
        safe >= 1024L -> "${safe / 1024L} KB"
        else -> "$safe B"
    }
}

fun formatTrafficRate(bytesPerSec: Long): String {
    val (value, unit) = splitTrafficRate(bytesPerSec)
    return "$value $unit"
}

fun splitTrafficRate(bytesPerSec: Long): Pair<String, String> {
    val safe = bytesPerSec.coerceAtLeast(0L)
    return when {
        safe >= 1024L * 1024L * 1024L -> "%.2f".format(safe / (1024.0 * 1024.0 * 1024.0)) to "GB/s"
        safe >= 1024L * 1024L -> "%.1f".format(safe / (1024.0 * 1024.0)) to "MB/s"
        safe >= 1024L -> "%.1f".format(safe / 1024.0) to "KB/s"
        else -> "$safe" to "B/s"
    }
}

fun formatDurationClock(elapsedMs: Long): String {
    val totalSec = (elapsedMs / 1000L).coerceAtLeast(0L)
    val hrs = totalSec / 3600L
    val mins = (totalSec % 3600L) / 60L
    val secs = totalSec % 60L
    return "%02d:%02d:%02d".format(hrs, mins, secs)
}

internal suspend fun importClipboardPayload(
    raw: String,
    onImportWorkspaceShare: suspend (String) -> String,
    onImportWorkspaceBackup: suspend (String) -> String,
    onImportCustomConfig: suspend (String) -> String,
    onImportSubscription: suspend (String, String) -> String,
    onImportShareLink: suspend (String) -> String,
): String {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return "剪贴板为空，请先复制节点链接、订阅地址或工作区备份"
    val lower = trimmed.lowercase()
    return when {
        trimmed.startsWith(WorkspaceSyncBridge.SHARE_URI_PREFIX) -> onImportWorkspaceShare(trimmed)
        trimmed.startsWith("{") && trimmed.contains("\"schema_version\"") -> onImportWorkspaceBackup(trimmed)
        trimmed.contains("schema-version") || (trimmed.contains("routing {") && trimmed.contains("outbound ")) ->
            onImportCustomConfig(trimmed)
        (lower.startsWith("https://") || lower.startsWith("http://127.0.0.1")) && !lower.contains("@") ->
            onImportSubscription("订阅", trimmed)
        else -> onImportShareLink(trimmed)
    }
}
