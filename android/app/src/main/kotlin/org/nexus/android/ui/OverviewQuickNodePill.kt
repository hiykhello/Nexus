package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Compact 2-line quick-switch node card built on flat Material 3 tonal surfaces (`12.dp` inner
 * radius, comfortable >=50dp touch target, clean selection indicator without decorative gloss).
 */
@Composable
internal fun QuickNodePillCard(
    node: OutboundMemberSnapshot,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    val selected = node.selected
    val isTimeout = node.state.equals("timeout", ignoreCase = true) ||
        node.state.equals("unreachable", ignoreCase = true) ||
        node.latencyMs == 0L
    val unprobed = node.latencyMs < 0L && !isTimeout

    val borderColor = if (selected) primary else ext.hairline
    val bgColor = if (selected) MaterialTheme.colorScheme.primaryContainer else ext.cardSurface
    val (latencyText, latencyFg) = when {
        unprobed -> "--" to ext.muted
        isTimeout -> "超时" to ext.danger
        node.latencyMs < 80L -> "${node.latencyMs} ms" to ext.success
        node.latencyMs < 180L -> "${node.latencyMs} ms" to ext.warning
        node.latencyMs < 350L -> "${node.latencyMs} ms" to ext.slow
        else -> "${node.latencyMs} ms" to ext.danger
    }

    val interactionSource = remember { MutableInteractionSource() }
    Surface(
        onClick = onClick,
        interactionSource = interactionSource,
        modifier = modifier
            .fillMaxWidth()
            .liquidPress(interactionSource = interactionSource, pressedScale = 0.97f),
        shape = RoundedCornerShape(12.dp),
        color = bgColor,
        border = BorderStroke(if (selected) 1.5.dp else 1.dp, borderColor),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 50.dp)
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier.size(18.dp),
                contentAlignment = Alignment.Center,
            ) {
                if (selected) {
                    Icon(
                        painter = painterResource(R.drawable.ic_check),
                        contentDescription = "当前节点",
                        tint = primary,
                        modifier = Modifier.size(16.dp),
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(7.dp)
                            .background(ext.muted.copy(alpha = 0.45f), CircleShape),
                    )
                }
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(
                    text = node.name,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = if (selected) FontWeight.Bold else FontWeight.SemiBold,
                    color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = latencyText,
                    style = NexusNumericStyles.monoBadge,
                    color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.88f) else latencyFg,
                    maxLines = 1,
                    softWrap = false,
                )
            }
        }
    }
}
