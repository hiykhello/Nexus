package org.nexus.android.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import org.nexus.android.ui.theme.NexusTheme
import kotlin.math.roundToInt

internal fun sampleRuntimeMemoryText(): String {
    val rt = Runtime.getRuntime()
    val used = (rt.totalMemory() - rt.freeMemory()).coerceAtLeast(0L)
    return formatTrafficBytes(used)
}

/**
 * Nexus 2-segment proportion bar:
 * 8dp full-pill rounded bar rendered directly in the Draw phase (`drawBehind`) with smooth
 * ease-out ratio updates (instant when system reduced-motion is enabled).
 */
@Composable
internal fun NexusProportionBar(
    firstBytes: Long,
    secondBytes: Long,
    firstColor: Color,
    secondColor: Color,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val a = firstBytes.coerceAtLeast(0L)
    val b = secondBytes.coerceAtLeast(0L)
    val total = a + b
    val firstPct = if (total > 0L) ((a * 100.0) / total).roundToInt() else 0
    val secondPct = if (total > 0L) (100 - firstPct) else 0
    val hasBoth = firstPct > 0 && secondPct > 0
    val targetFirst = when {
        total == 0L -> 0f
        firstPct <= 0 -> 0f
        secondPct <= 0 -> 1f
        else -> (firstPct / 100f).coerceIn(0.06f, 0.94f)
    }
    val trackColor = ext.insetSurface
    val reducedMotion = isReducedMotionEnabled()
    val animatedFirstState = animateFloatAsState(
        targetValue = targetFirst,
        animationSpec = tween(if (reducedMotion) 0 else 200, easing = NexusStrongEaseOut),
        label = "proportionFirst",
    )

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(8.dp)
            .clip(CircleShape)
            .drawBehind {
                drawRect(color = trackColor)
                if (total > 0L && size.width > 0f) {
                    val gapPx = if (hasBoth) 2.dp.toPx() else 0f
                    val usable = (size.width - gapPx).coerceAtLeast(0f)
                    val firstFrac = animatedFirstState.value.coerceIn(0f, 1f)
                    val firstW = usable * firstFrac
                    val secondW = usable * (1f - firstFrac)
                    if (firstW > 0.5f) {
                        drawRect(color = firstColor, topLeft = Offset.Zero, size = Size(firstW, size.height))
                    }
                    if (secondW > 0.5f) {
                        val startX = if (firstW > 0.5f) firstW + gapPx else 0f
                        drawRect(color = secondColor, topLeft = Offset(startX, 0f), size = Size(secondW, size.height))
                    }
                }
            },
    )
}
