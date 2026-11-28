package org.nexus.android.ui

import android.content.Context
import android.provider.Settings
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.interaction.InteractionSource
import androidx.compose.foundation.interaction.PressInteraction
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Measurable
import androidx.compose.ui.layout.MeasureResult
import androidx.compose.ui.layout.MeasureScope
import androidx.compose.ui.node.CompositionLocalConsumerModifierNode
import androidx.compose.ui.node.LayoutModifierNode
import androidx.compose.ui.node.ModifierNodeElement
import androidx.compose.ui.node.currentValueOf
import androidx.compose.ui.platform.InspectorInfo
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.Constraints
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

internal val NexusStrongEaseOut = CubicBezierEasing(0.23f, 1.0f, 0.32f, 1.0f)

private val PRESS_DOWN_SPEC = tween<Float>(
    durationMillis = 95,
    easing = NexusStrongEaseOut,
)

private val PRESS_RELEASE_SPRING = spring<Float>(
    dampingRatio = 0.72f,
    stiffness = 620f,
)

internal fun nexusPageTransition(reducedMotion: Boolean): ContentTransform =
    if (reducedMotion) {
        fadeIn(tween(0)) togetherWith fadeOut(tween(0))
    } else {
        (fadeIn(tween(175, easing = NexusStrongEaseOut)) +
            slideInVertically(tween(185, easing = NexusStrongEaseOut)) { h -> (h / 28).coerceAtMost(14) }) togetherWith
            fadeOut(tween(115, easing = FastOutSlowInEasing))
    }

internal fun isAnimatorScaleZero(context: Context): Boolean =
    runCatching {
        Settings.Global.getFloat(
            context.contentResolver,
            Settings.Global.ANIMATOR_DURATION_SCALE,
            1f,
        ) == 0f
    }.getOrDefault(false)

@Composable
internal fun isReducedMotionEnabled(): Boolean {
    val context = LocalContext.current
    return remember(context) { isAnimatorScaleZero(context) }
}

/**
 * Restrained tactile press feedback implemented via `Modifier.Node` + `Animatable`
 * (zero recompositions, critically damped 120ms ease-out scale-only `0.97f`, honors Android's
 * system `ANIMATOR_DURATION_SCALE == 0f` reduced-motion setting).
 */
fun Modifier.tactilePress(
    interactionSource: InteractionSource,
    pressedScale: Float = 0.97f,
): Modifier = this then TactilePressElement(interactionSource, pressedScale)

private data class TactilePressElement(
    val interactionSource: InteractionSource,
    val pressedScale: Float,
) : ModifierNodeElement<TactilePressNode>() {
    override fun create(): TactilePressNode = TactilePressNode(interactionSource, pressedScale)

    override fun update(node: TactilePressNode) {
        node.updateParams(interactionSource, pressedScale)
    }

    override fun InspectorInfo.inspectableProperties() {
        name = "tactilePress"
        properties["pressedScale"] = pressedScale
    }
}

private class TactilePressNode(
    private var interactionSource: InteractionSource,
    private var pressedScale: Float,
) : Modifier.Node(), LayoutModifierNode, CompositionLocalConsumerModifierNode {
    private val scaleAnim = Animatable(1f)
    private var collectJob: Job? = null

    override fun onAttach() {
        startCollecting()
    }

    override fun onDetach() {
        collectJob?.cancel()
        collectJob = null
    }

    override fun onReset() {
        collectJob?.cancel()
        collectJob = null
        if (isAttached) {
            coroutineScope.launch(start = CoroutineStart.UNDISPATCHED) {
                scaleAnim.snapTo(1f)
            }
        }
    }

    fun updateParams(newSource: InteractionSource, newPressedScale: Float) {
        pressedScale = newPressedScale
        if (interactionSource !== newSource) {
            interactionSource = newSource
            if (isAttached) startCollecting()
        }
    }

    private fun startCollecting() {
        collectJob?.cancel()
        val source = interactionSource
        collectJob = coroutineScope.launch(start = CoroutineStart.UNDISPATCHED) {
            scaleAnim.snapTo(1f)
            var activePressCount = 0
            source.interactions.collect { interaction ->
                when (interaction) {
                    is PressInteraction.Press -> activePressCount++
                    is PressInteraction.Release, is PressInteraction.Cancel ->
                        activePressCount = (activePressCount - 1).coerceAtLeast(0)
                }
                val pressed = activePressCount > 0
                val reduced = isAttached && isAnimatorScaleZero(currentValueOf(LocalContext))
                val target = if (pressed && !reduced) pressedScale else 1f
                if (reduced) {
                    scaleAnim.snapTo(1f)
                } else {
                    val spec = if (pressed) PRESS_DOWN_SPEC else PRESS_RELEASE_SPRING
                    launch { scaleAnim.animateTo(target, spec) }
                }
            }
        }
    }

    override fun MeasureScope.measure(
        measurable: Measurable,
        constraints: Constraints,
    ): MeasureResult {
        val placeable = measurable.measure(constraints)
        return layout(placeable.width, placeable.height) {
            placeable.placeWithLayer(0, 0) {
                val s = scaleAnim.value
                scaleX = s
                scaleY = s
            }
        }
    }
}
