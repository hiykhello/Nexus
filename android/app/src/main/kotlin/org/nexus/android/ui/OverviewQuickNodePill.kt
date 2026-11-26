package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.bridge.ipc.OutboundMemberSnapshot
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Compact 2-line quick-switch node pill card (zero `BoxWithConstraints` subcomposition,
 * semantic Material primary tokens, comfortable >=48dp touch height).
 */
@Composable
internal fun QuickNodePillCard(
    node: OutboundMemberSnapshot,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val selected = node.selected
    val isTimeout = node.state.equals("timeout", ignoreCase = true) ||
        node.state.equals("unreachable", ignoreCase = true) ||
        node.latencyMs == 0L
    val unprobed = node.latencyMs < 0L && !isTimeout

    val borderColor = if (selected) MaterialTheme.colorScheme.primary else ext.hairline
    val bgColor = if (selected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (ext.isDark) 0.65f else 0.72f)
    } else {
        ext.cardGradientTop
    }
    val (latencyText, latencyFg) = when {
        unprobed -> "--" to ext.muted
        isTimeout -> "超时" to ext.danger
        node.latencyMs < 80L -> "${node.latencyMs}ms" to ext.success
        node.latencyMs < 180L -> "${node.latencyMs}ms" to ext.warning
        node.latencyMs < 350L -> "${node.latencyMs}ms" to ext.slow
        else -> "${node.latencyMs}ms" to ext.danger
    }

    val interactionSource = remember { MutableInteractionSource() }
    val orbOuter = if (selected) MaterialTheme.colorScheme.primary else ext.muted
    val orbCore = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else ext.muted.copy(alpha = 0.55f)
    val tileCorner = 16.dp

    val tileContent: @Composable () -> Unit = {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 50.dp)
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(20.dp)
                    .background(
                        brush = Brush.radialGradient(
                            0.0f to orbOuter.copy(alpha = if (selected) 0.52f else 0.24f),
                            0.65f to orbOuter.copy(alpha = if (selected) 0.22f else 0.10f),
                            1.0f to Color.Transparent,
                        ),
                        shape = CircleShape,
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(if (selected) 8.dp else 7.dp)
                        .background(color = orbCore, shape = CircleShape),
                )
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

    if (selected) {
        Box(
            modifier = modifier
                .fillMaxWidth()
                .liquidPress(interactionSource = interactionSource, pressedScale = 0.96f)
                .liquidGlassSurface(
                    tint = MaterialTheme.colorScheme.primary,
                    surfaceBase = bgColor,
                    cornerRadius = tileCorner,
                    isDark = ext.isDark,
                    rimIntensity = 0.95f,
                )
                .clickable(interactionSource = interactionSource, indication = null, onClick = onClick),
        ) { tileContent() }
    } else {
        Surface(
            onClick = onClick,
            interactionSource = interactionSource,
            modifier = modifier.fillMaxWidth().liquidPress(interactionSource = interactionSource, pressedScale = 0.96f),
            shape = RoundedCornerShape(tileCorner),
            color = bgColor,
            border = BorderStroke(1.dp, borderColor),
        ) { tileContent() }
    }
}
