package org.nexus.android.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.ipc.OutboundGroupSnapshot
import org.nexus.android.ui.theme.NexusTheme

internal const val GROUPS_SORT_DEFAULT = "default"
internal const val GROUPS_SORT_LATENCY = "latency"

@Composable
internal fun GroupChipRow(
    groups: List<OutboundGroupSnapshot>,
    selectedTag: String,
    onSelectTag: (String) -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    val primary = MaterialTheme.colorScheme.primary
    val onPrimary = MaterialTheme.colorScheme.onPrimary

    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        items(items = groups, key = { it.tag }, contentType = { "group_chip" }) { group ->
            val isSel = group.tag == selectedTag
            val modeSuffix = if (!group.manualOverride && group.mode != "selector") " · 自动" else ""
            val chipInteraction = remember { MutableInteractionSource() }
            Surface(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onSelectTag(group.tag)
                },
                interactionSource = chipInteraction,
                modifier = Modifier
                    .minimumInteractiveComponentSize()
                    .heightIn(min = 40.dp)
                    .liquidPress(chipInteraction, pressedScale = 0.97f),
                shape = RoundedCornerShape(999.dp),
                color = if (isSel) primary else ext.wellSurface,
                border = BorderStroke(
                    1.dp,
                    if (isSel) primary.copy(alpha = 0.85f) else ext.hairline,
                ),
            ) {
                Box(
                    modifier = Modifier.padding(horizontal = 15.dp, vertical = 9.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "${group.tag}$modeSuffix",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (isSel) FontWeight.Bold else FontWeight.Medium,
                        color = if (isSel) onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun GroupFilterToolbar(
    sortMode: String,
    hideTimeout: Boolean,
    showResetAuto: Boolean,
    onSortChange: (String) -> Unit,
    onToggleHideTimeout: () -> Unit,
    onResetAuto: () -> Unit,
) {
    val ext = NexusTheme.colors
    val haptic = LocalHapticFeedback.current
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
        itemVerticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            shape = RoundedCornerShape(999.dp),
            color = ext.wellSurface,
            border = BorderStroke(1.dp, ext.hairline),
        ) {
            Row(
                modifier = Modifier.padding(3.dp),
                horizontalArrangement = Arrangement.spacedBy(3.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                listOf(
                    GROUPS_SORT_DEFAULT to "默认",
                    GROUPS_SORT_LATENCY to "按延迟",
                ).forEach { (key, label) ->
                    val active = sortMode == key
                    Box(
                        modifier = Modifier
                            .minimumInteractiveComponentSize()
                            .heightIn(min = 38.dp)
                            .clip(RoundedCornerShape(999.dp))
                            .background(if (active) MaterialTheme.colorScheme.primaryContainer else Color.Transparent)
                            .clickable {
                                if (!active) {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onSortChange(key)
                                }
                            }
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = if (active) FontWeight.Bold else FontWeight.Medium,
                            color = if (active) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            softWrap = false,
                        )
                    }
                }
            }
        }
        FilterChip(
            selected = hideTimeout,
            onClick = {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onToggleHideTimeout()
            },
            shape = RoundedCornerShape(999.dp),
            leadingIcon = if (hideTimeout) {
                {
                    Icon(
                        painter = painterResource(R.drawable.ic_check),
                        contentDescription = null,
                        modifier = Modifier.size(15.dp),
                    )
                }
            } else null,
            label = {
                Text(
                    text = "隐藏超时",
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                    softWrap = false,
                )
            },
            colors = FilterChipDefaults.filterChipColors(
                containerColor = ext.wellSurface,
                labelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                selectedLeadingIconColor = MaterialTheme.colorScheme.primary,
            ),
            border = FilterChipDefaults.filterChipBorder(
                enabled = true,
                selected = hideTimeout,
                borderColor = ext.hairline,
                selectedBorderColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.45f),
            ),
            modifier = Modifier.heightIn(min = 44.dp),
        )
        if (showResetAuto) {
            Surface(
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onResetAuto()
                },
                modifier = Modifier.minimumInteractiveComponentSize().heightIn(min = 44.dp),
                shape = RoundedCornerShape(999.dp),
                color = ext.warningContainer,
                border = BorderStroke(1.dp, ext.warning.copy(alpha = 0.45f)),
            ) {
                Box(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "恢复自动",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = ext.warning,
                        maxLines = 1,
                        softWrap = false,
                    )
                }
            }
        }
    }
}

@Composable
internal fun GroupProbeFab(
    isProbing: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    ExtendedFloatingActionButton(
        onClick = { if (!isProbing) onClick() },
        shape = RoundedCornerShape(16.dp),
        containerColor = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        elevation = FloatingActionButtonDefaults.elevation(defaultElevation = 2.dp),
        modifier = modifier,
        icon = {
            if (isProbing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            } else {
                Icon(
                    painter = painterResource(R.drawable.ic_speed),
                    contentDescription = "全部测速",
                    modifier = Modifier.size(18.dp),
                )
            }
        },
        text = {
            Text(
                text = if (isProbing) "测速中" else "全部测速",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
        },
    )
}
