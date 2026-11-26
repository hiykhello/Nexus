package org.nexus.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.ActiveConnectionSnapshot
import org.nexus.android.bridge.model.EndpointParser
import org.nexus.android.bridge.workspace.AndroidPerAppMode
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Flagship `24.dp` Optical Precision connection inspector rendered inside either:
 * - Material 3 `ModalBottomSheet` on Compact & Medium widths (`<840dp`)
 * - Persistent Right Detail Pane on Expanded widths (`>=840dp`)
 */
@Composable
fun ConnectionDetailContent(
    detail: ActiveConnectionSnapshot,
    ownerPackage: String?,
    excludedPackages: Set<String>,
    perAppMode: AndroidPerAppMode = AndroidPerAppMode.EXCLUDE,
    actionFeedback: String,
    showDismissButton: Boolean,
    onDismiss: () -> Unit,
    onCloseConnection: (Long) -> Unit,
    onCreateRule: (targetHost: String, action: String, outbound: String) -> Unit,
    onBypassOwnerApp: (packageName: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    var copiedHost by remember(detail.id) { mutableStateOf(false) }
    var ruleTargetMode by remember(detail.id) { mutableStateOf("proxy") }

    val targetDisplay = detail.target.ifEmpty {
        if (detail.destinationPort > 0) "${detail.path}:${detail.destinationPort}" else detail.path
    }
    val ruleHost = EndpointParser.stripPortAndBrackets(targetDisplay)
    val resolvedPkg = extractOwnerPackageName(ownerPackage) ?: extractOwnerPackageName(detail.processPath)
    val perAppAction = resolvedPkg?.let { computePerAppConnectionAction(perAppMode, it, excludedPackages) }
    val shortApp = formatShortAppLabel(resolvedPkg, detail.processPath)
    val shortRule = detail.routeRule.substringBefore("->").trim().ifEmpty { "默认" }
    val shortExit = detail.outbound.ifEmpty { detail.path }.substringAfterLast('/').ifEmpty { "-" }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            StatusPill(
                text = formatProtocolLabel(detail.protocol),
                containerColor = protocolContainerColor(detail.protocol),
                contentColor = protocolContentColor(detail.protocol),
                mono = true,
            )
            Text(
                text = "连接 #${detail.id}",
                style = NexusNumericStyles.kpiCompact,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            StatusPill(
                text = formatCompactDuration(detail.durationMs),
                containerColor = ext.wellSurface,
                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                mono = true,
            )
            if (showDismissButton) {
                IconButton(onClick = onDismiss) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = "关闭",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }
            }
        }

        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(999.dp),
            color = ext.wellSurface,
            border = BorderStroke(1.dp, ext.hairline),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 9.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = shortApp,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text("  →  ", style = MaterialTheme.typography.labelMedium, color = ext.muted)
                Text(
                    text = shortRule,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                Text("  →  ", style = MaterialTheme.typography.labelMedium, color = ext.muted)
                Text(
                    text = shortExit,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            color = ext.wellSurface,
            border = BorderStroke(1.dp, ext.hairline),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 10.dp),
                verticalArrangement = Arrangement.spacedBy(5.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text("目标", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(40.dp))
                    Text(
                        text = targetDisplay,
                        style = NexusNumericStyles.rateReadout,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        textAlign = TextAlign.End,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(
                        onClick = {
                            val cm = context.getSystemService(ClipboardManager::class.java)
                            cm?.setPrimaryClip(ClipData.newPlainText("nexus_target", targetDisplay))
                            copiedHost = true
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        },
                    ) {
                        Icon(
                            painter = painterResource(if (copiedHost) R.drawable.ic_check else R.drawable.ic_copy),
                            contentDescription = "复制目标",
                            tint = if (copiedHost) ext.success else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(16.dp),
                        )
                    }
                }
                DetailMetaRow(label = "来源", value = detail.source.ifEmpty { "-" }, mono = true, endPadding = 8.dp)
                if (resolvedPkg != null) {
                    DetailMetaRow(label = "应用", value = resolvedPkg, endPadding = 8.dp)
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            NexusProportionBar(
                firstBytes = detail.downloadBytes,
                secondBytes = detail.uploadBytes,
                firstColor = ext.telemetryDownload,
                secondColor = ext.telemetryUpload,
            )
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("↓ ${formatTrafficBytes(detail.downloadBytes)}", style = NexusNumericStyles.rateReadout, color = ext.telemetryDownload)
                Text("↑ ${formatTrafficBytes(detail.uploadBytes)}", style = NexusNumericStyles.rateReadout, color = ext.telemetryUpload)
            }
        }

        if (ruleHost.isNotEmpty()) {
            Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text("快速分流", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OpticalSegmentedControl(
                    options = listOf("direct" to "直连", "proxy" to "代理", "reject" to "拒绝"),
                    selectedKey = ruleTargetMode,
                    onSelect = { ruleTargetMode = it },
                )
                Button(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val action = if (ruleTargetMode == "reject") "reject" else "route"
                        val outbound = if (ruleTargetMode == "direct") "direct" else "proxy"
                        onCreateRule(ruleHost, action, outbound)
                    },
                    shape = RoundedCornerShape(999.dp),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                ) {
                    Icon(painter = painterResource(R.drawable.ic_rule), contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("保存规则", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, maxLines = 1)
                }
            }
        }

        if (actionFeedback.isNotEmpty()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = ext.successContainer,
                border = BorderStroke(1.dp, ext.success.copy(alpha = 0.4f)),
            ) {
                Text(
                    text = actionFeedback,
                    style = MaterialTheme.typography.bodySmall,
                    color = ext.success,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (resolvedPkg != null && perAppAction != null) {
                val bypassInteraction = remember { MutableInteractionSource() }
                Surface(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onBypassOwnerApp(resolvedPkg)
                    },
                    enabled = perAppAction.enabled,
                    interactionSource = bypassInteraction,
                    modifier = Modifier.weight(1f).heightIn(min = 48.dp).liquidPress(bypassInteraction, pressedScale = 0.96f),
                    shape = RoundedCornerShape(999.dp),
                    color = ext.wellSurface,
                    border = BorderStroke(1.dp, ext.hairline),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        Icon(
                            painter = painterResource(if (!perAppAction.enabled) R.drawable.ic_check else R.drawable.ic_apps),
                            contentDescription = null,
                            tint = if (!perAppAction.enabled) ext.muted else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(15.dp),
                        )
                        Spacer(Modifier.width(5.dp))
                        Text(
                            text = perAppAction.label,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = if (!perAppAction.enabled) ext.muted else MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            } else if (showDismissButton) {
                Surface(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                    shape = RoundedCornerShape(999.dp),
                    color = ext.wellSurface,
                    border = BorderStroke(1.dp, ext.hairline),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = "收起",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }
            val closeInteraction = remember { MutableInteractionSource() }
            Surface(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onCloseConnection(detail.id)
                },
                interactionSource = closeInteraction,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).liquidPress(closeInteraction, pressedScale = 0.96f),
                shape = RoundedCornerShape(999.dp),
                color = ext.dangerContainer,
                border = BorderStroke(1.dp, ext.danger.copy(alpha = 0.45f)),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                ) {
                    Icon(painter = painterResource(R.drawable.ic_close), contentDescription = null, tint = ext.danger, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(5.dp))
                    Text("断开连接", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, color = ext.danger, maxLines = 1)
                }
            }
        }
    }
}

@Composable
private fun DetailMetaRow(
    label: String,
    value: String,
    mono: Boolean = false,
    endPadding: Dp = 0.dp,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(end = endPadding),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(40.dp),
        )
        Text(
            text = value,
            style = if (mono) NexusNumericStyles.rateReadout else MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(1f),
        )
    }
}
