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
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.graphics.Color
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
 * Tactile reorder chrome displayed around Overview Bento cards strictly while Customize Mode
 * (`dashEditing == true`) is active. Renders [content] directly with zero wrapper overhead or
 * gesture interception during normal daily usage (`dashEditing == false`).
 * All action buttons use 48dp IconButton touch targets wrapping sleek 30dp optical badges.
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

    Surface(
        modifier = modifier
            .fillMaxWidth()
            .zIndex(if (dragging) 4f else 0f)
            .graphicsLayer {
                translationY = if (dragging) dragAccumPx.coerceIn(-dragStepPx * 0.75f, dragStepPx * 0.75f) else 0f
                val s = if (dragging) 1.015f else 1f
                scaleX = s
                scaleY = s
            },
        shape = RoundedCornerShape(22.dp),
        color = accent.copy(alpha = if (dragging) 0.14f else if (ext.isDark) 0.08f else 0.05f),
        border = BorderStroke(
            width = if (dragging) 1.5.dp else 1.dp,
            color = accent.copy(alpha = if (dragging) 0.78f else 0.40f),
        ),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(7.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Surface(
                    shape = RoundedCornerShape(999.dp),
                    color = if (dragging) accent.copy(alpha = 0.28f) else ext.insetSurface,
                    border = BorderStroke(1.dp, if (dragging) accent.copy(alpha = 0.65f) else ext.hairline),
                    modifier = Modifier.pointerInput(cardId) {
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
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
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
                }

                Spacer(Modifier.weight(1f))

                ReorderActionPill(
                    label = "↑",
                    enabled = canMoveUp,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onMoveUp()
                    },
                )
                ReorderActionPill(
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
                    Surface(
                        shape = CircleShape,
                        color = ext.insetSurface,
                        border = BorderStroke(1.dp, ext.hairline),
                        modifier = Modifier.size(30.dp),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                painter = painterResource(R.drawable.ic_close),
                                contentDescription = "隐藏卡片",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(14.dp),
                            )
                        }
                    }
                }
            }

            content()
        }
    }
}

@Composable
private fun ReorderActionPill(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val ext = NexusTheme.colors
    val accent = MaterialTheme.colorScheme.primary
    IconButton(onClick = onClick, enabled = enabled) {
        Surface(
            shape = CircleShape,
            color = if (enabled) accent.copy(alpha = if (ext.isDark) 0.22f else 0.12f) else ext.wellSurface,
            border = BorderStroke(1.dp, if (enabled) accent.copy(alpha = 0.50f) else ext.hairline),
            modifier = Modifier.size(30.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (enabled) accent else Color.Gray.copy(alpha = 0.45f),
                )
            }
        }
    }
}
