package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

private val LOG_LEVELS = listOf("trace", "error", "warn", "info", "debug")
private val CORE_LOG_LEVELS = listOf("error", "warn", "info", "debug", "trace")
private val LOG_TIMESTAMP_REGEX = Regex("^(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?)\\s+(.*)$")
private val LOG_LEVEL_TAG_REGEX = Regex("^\\[(error|warn|warning|info|debug|trace)]\\s*(.*)$", RegexOption.IGNORE_CASE)

@Composable
internal fun CoreLogLevelDropdownPill(
    currentLevel: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onSelectLevel: (String) -> Unit,
) {
    Box {
        Surface(
            onClick = { onExpandedChange(!expanded) },
            modifier = Modifier.minimumInteractiveComponentSize(),
            shape = RoundedCornerShape(999.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)),
        ) {
            Text(
                text = "内核:${currentLevel.uppercase()} ▾",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { onExpandedChange(false) },
            shape = RoundedCornerShape(14.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            CORE_LOG_LEVELS.forEach { lvl ->
                val isSel = currentLevel.equals(lvl, ignoreCase = true)
                DropdownMenuItem(
                    text = {
                        Text(
                            text = "内核输出: ${lvl.uppercase()}",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = if (isSel) FontWeight.Bold else FontWeight.Medium,
                            color = if (isSel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                        )
                    },
                    onClick = { onSelectLevel(lvl) },
                )
            }
        }
    }
}

@Composable
internal fun LogLevelDropdownPill(
    selectedLevel: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onSelectLevel: (String) -> Unit,
) {
    val ext = NexusTheme.colors
    val (pillBg, pillFg, pillText) = when (selectedLevel) {
        "error" -> Triple(ext.dangerContainer, ext.danger, "ERR ▾")
        "warn" -> Triple(ext.warningContainer, ext.warning, "WRN ▾")
        "info" -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, "INF ▾")
        "debug" -> Triple(ext.insetSurface, MaterialTheme.colorScheme.onSurfaceVariant, "DBG ▾")
        else -> Triple(ext.insetSurface, MaterialTheme.colorScheme.onSurface, "全部 ▾")
    }

    Box {
        Surface(
            onClick = { onExpandedChange(!expanded) },
            modifier = Modifier.minimumInteractiveComponentSize(),
            shape = RoundedCornerShape(999.dp),
            color = pillBg,
            border = BorderStroke(
                width = 1.dp,
                color = if (selectedLevel == "trace") ext.hairline else pillFg.copy(alpha = 0.45f),
            ),
        ) {
            Text(
                text = pillText,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = pillFg,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { onExpandedChange(false) },
            shape = RoundedCornerShape(14.dp),
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            LOG_LEVELS.forEach { lvl ->
                val isSelected = selectedLevel == lvl
                val dotColor = when (lvl) {
                    "error" -> ext.danger
                    "warn" -> ext.warning
                    "info" -> ext.telemetryDownload
                    "debug" -> ext.muted
                    else -> MaterialTheme.colorScheme.primary
                }
                val itemLabel = if (lvl == "trace") "筛选: 全部" else "筛选: ${lvl.uppercase()}"
                DropdownMenuItem(
                    text = {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Box(Modifier.size(7.dp).background(dotColor, CircleShape))
                            Text(
                                text = itemLabel,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                            )
                        }
                    },
                    trailingIcon = if (isSelected) {
                        {
                            Icon(
                                painter = painterResource(R.drawable.ic_check),
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    } else null,
                    onClick = { onSelectLevel(lvl) },
                )
            }
        }
    }
}

private data class ParsedLogEntry(
    val level: String,
    val timestamp: String,
    val message: String,
)

private fun parseLogEntry(raw: String): ParsedLogEntry {
    var rest = raw.trim()
    var timestamp = ""
    LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { m ->
        timestamp = m.groupValues[1]
        rest = m.groupValues[2].trimStart()
    }
    var level = "LOG"
    LOG_LEVEL_TAG_REGEX.matchEntire(rest)?.let { m ->
        level = when (m.groupValues[1].lowercase()) {
            "error" -> "ERR"
            "warn", "warning" -> "WRN"
            "info" -> "INF"
            "debug", "trace" -> "DBG"
            else -> "LOG"
        }
        rest = m.groupValues[2]
    }
    if (timestamp.isEmpty()) {
        LOG_TIMESTAMP_REGEX.matchEntire(rest)?.let { m ->
            timestamp = m.groupValues[1]
            rest = m.groupValues[2].trimStart()
        }
    }
    return ParsedLogEntry(level = level, timestamp = timestamp, message = rest.ifEmpty { raw })
}

@Composable
internal fun LogLineRow(line: String) {
    val ext = NexusTheme.colors
    val parsed = remember(line) { parseLogEntry(line) }
    val (badgeBg, badgeFg, rowTint) = when (parsed.level) {
        "ERR" -> Triple(ext.dangerContainer, ext.danger, ext.dangerContainer.copy(alpha = 0.28f))
        "WRN" -> Triple(ext.warningContainer, ext.warning, ext.warningContainer.copy(alpha = 0.16f))
        "INF" -> Triple(ext.telemetryDownloadContainer, ext.telemetryDownload, Color.Transparent)
        "DBG" -> Triple(ext.mutedContainer, ext.muted, Color.Transparent)
        else -> Triple(ext.mutedContainer, ext.muted, Color.Transparent)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(rowTint, RoundedCornerShape(8.dp))
            .padding(horizontal = 6.dp, vertical = 5.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Surface(
            modifier = Modifier.width(40.dp),
            shape = RoundedCornerShape(6.dp),
            color = badgeBg,
            border = BorderStroke(1.dp, badgeFg.copy(alpha = 0.30f)),
        ) {
            Text(
                text = parsed.level,
                style = NexusNumericStyles.monoBadge,
                color = badgeFg,
                textAlign = TextAlign.Center,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
            )
        }
        if (parsed.timestamp.isNotEmpty()) {
            Text(
                text = parsed.timestamp,
                style = NexusNumericStyles.monoBadge,
                color = ext.muted,
                maxLines = 1,
                softWrap = false,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Text(
            text = parsed.message,
            style = NexusNumericStyles.codeBlock,
            color = if (parsed.level == "ERR") ext.danger else MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}
