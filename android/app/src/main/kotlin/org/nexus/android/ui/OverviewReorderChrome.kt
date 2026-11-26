package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import org.nexus.android.R
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme

/**
 * Slim drag-header reorder chrome displayed directly above Overview Bento cards while Customize
 * Mode (`dashEditing == true`) is active — avoids outer double-bordered wrappers and renders
 * [content] directly with zero overhead during daily usage (`dashEditing == false`).
 */
@Composable
internal fun ReorderableDashboardCardFrame(
    cardId: String,
    index: Int,
    totalCount: Int,
    editing: Boolean,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit,
    onHide: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    if (!editing) {
        content()
        return
    }

    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val density = LocalDensity.current
    val dragStepPx = remember(density) { with(density) { 64.dp.toPx() } }
    val latestMoveUp by rememberUpdatedState(onMoveUp)
    val latestMoveDown by rememberUpdatedState(onMoveDown)
    val latestIndex by rememberUpdatedState(index)
    val latestTotal by rememberUpdatedState(totalCount)

    var dragAccumPx by remember(cardId) { mutableFloatStateOf(0f) }
    var dragging by remember(cardId) { mutableStateOf(false) }

    val canMoveUp = index > 0
    val canMoveDown = index < totalCount - 1
    val accent = MaterialTheme.colorScheme.primary

    Column(
        modifier = modifier
            .fillMaxWidth()
            .zIndex(if (dragging) 4f else 0f)
            .graphicsLayer {
                translationY = if (dragging) dragAccumPx.coerceIn(-dragStepPx * 0.75f, dragStepPx * 0.75f) else 0f
                val s = if (dragging) 1.015f else 1f
                scaleX = s
                scaleY = s
            },
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = if (dragging) MaterialTheme.colorScheme.primaryContainer else ext.wellSurface,
            border = BorderStroke(
                width = 1.dp,
                color = if (dragging) accent.copy(alpha = 0.65f) else ext.hairline,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 10.dp, end = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Row(
                    modifier = Modifier
                        .padding(vertical = 8.dp)
                        .pointerInput(cardId) {
                            detectVerticalDragGestures(
                                onDragStart = {
                                    dragging = true
                                    dragAccumPx = 0f
                                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                },
                                onDragEnd = {
                                    dragging = false
                                    dragAccumPx = 0f
                                },
                                onDragCancel = {
                                    dragging = false
                                    dragAccumPx = 0f
                                },
                                onVerticalDrag = { change, dragAmount ->
                                    change.consume()
                                    dragAccumPx += dragAmount
                                    if (dragAccumPx <= -dragStepPx && latestIndex > 0) {
                                        dragAccumPx += dragStepPx
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        latestMoveUp()
                                    } else if (dragAccumPx >= dragStepPx && latestIndex < latestTotal - 1) {
                                        dragAccumPx -= dragStepPx
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        latestMoveDown()
                                    }
                                },
                            )
                        },
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = "⠿",
                        style = MaterialTheme.typography.labelLarge,
                        color = if (dragging) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "#${index + 1}",
                        style = NexusNumericStyles.monoBadge,
                        color = accent,
                    )
                    Text(
                        text = DashboardCardVisibility.cardLabel(cardId),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                    )
                }

                Spacer(Modifier.weight(1f))

                ReorderActionButton(
                    label = "↑",
                    enabled = canMoveUp,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onMoveUp()
                    },
                )
                ReorderActionButton(
                    label = "↓",
                    enabled = canMoveDown,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onMoveDown()
                    },
                )
                IconButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onHide()
                    },
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_close),
                        contentDescription = "隐藏卡片",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }

        content()
    }
}

@Composable
private fun ReorderActionButton(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val accent = MaterialTheme.colorScheme.primary
    val disabledColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
    IconButton(onClick = onClick, enabled = enabled) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = label,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = if (enabled) accent else disabledColor,
            )
        }
    }
}
