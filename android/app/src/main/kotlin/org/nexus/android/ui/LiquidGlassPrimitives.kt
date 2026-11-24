package org.nexus.android.ui

import android.graphics.RuntimeShader
import android.os.Build
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ShaderBrush
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

private const val AGSL_LIQUID_CAUSTIC = """
    uniform float2 resolution;
    uniform float phase;
    uniform float intensity;
    half4 main(float2 fragCoord) {
        float2 uv = fragCoord / max(resolution, float2(1.0, 1.0));
        float diag = uv.x * 0.85 + uv.y * 0.45;
        float d = (diag - (phase * 1.6 - 0.3)) * 5.2;
        float band = exp(-(d * d));
        float dy = (uv.y - 0.08) * 3.4;
        float horiz = max(1.0 - abs(uv.x - 0.5) * 0.9, 0.0);
        float dome = exp(-(dy * dy)) * horiz;
        float a = clamp((band * 0.16 + dome * 0.12) * intensity, 0.0, 0.32);
        return half4(a, a, a, a);
    }
"""

/**
 * Spring-elastic tactile press squish with deferred graphicsLayer state reads
 * (zero recomposition / zero relayout overhead during press animations).
 */
fun Modifier.liquidPress(
    interactionSource: MutableInteractionSource,
    pressedScale: Float = 0.96f,
): Modifier = composed {
    val pressed by interactionSource.collectIsPressedAsState()
    val scaleState = animateFloatAsState(
        targetValue = if (pressed) pressedScale else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMedium,
        ),
        label = "liquidPressScale",
    )
    val liftYState = animateFloatAsState(
        targetValue = if (pressed) 1.5f else 0f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMedium,
        ),
        label = "liquidPressLift",
    )
    this.graphicsLayer {
        val s = scaleState.value
        scaleX = s
        scaleY = s
        translationY = liftYState.value
    }
}

/**
 * Multi-layer Optical Liquid Glass surface:
 * - Translucent vertical depth fill with upper luminous dome
 * - Top meniscus catchlight + razor specular upper filament
 * - Bottom internal tinted caustic refraction bounce
 * - Optional living diagonal specular sheen (premultiplied AGSL RuntimeShader on API 33+ runtime,
 *   translated cached Canvas Brush fallback on API 29-32 and static Compose Previews)
 * - Directional 1.25dp Fresnel rim border
 * - Zero per-frame recompositions and zero per-frame allocations (all animation reads deferred to `onDrawBehind`)
 */
fun Modifier.liquidGlassSurface(
    tint: Color,
    surfaceBase: Color,
    cornerRadius: Dp = 16.dp,
    isDark: Boolean = true,
    rimIntensity: Float = 1f,
    livingSheen: Boolean = false,
    enableAgslCaustic: Boolean = true,
): Modifier = composed {
    val isPreview = LocalInspectionMode.current
    val sheenPhaseState = if (livingSheen) {
        val infinite = rememberInfiniteTransition(label = "liquidSheen")
        infinite.animateFloat(
            initialValue = 0.30f,
            targetValue = 1.15f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 3200, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "liquidSheenPhase",
        )
    } else {
        null
    }

    val runtimeShader = remember(enableAgslCaustic, isPreview) {
        if (enableAgslCaustic && !isPreview && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            runCatching { RuntimeShader(AGSL_LIQUID_CAUSTIC) }.getOrNull()
        } else {
            null
        }
    }

    val shape = RoundedCornerShape(cornerRadius)
    this
        .clip(shape)
        .drawWithCache {
            val radiusPx = cornerRadius.toPx()
            val cr = CornerRadius(radiusPx, radiusPx)
            val strokePx = 1.25.dp.toPx()
            val halfStroke = strokePx * 0.5f
            val innerCr = CornerRadius((radiusPx - halfStroke).coerceAtLeast(0f))
            val innerSize = Size(
                (size.width - strokePx).coerceAtLeast(0f),
                (size.height - strokePx).coerceAtLeast(0f),
            )

            // 1. Translucent glass depth gradient
            val topLift = lerp(surfaceBase, Color.White, if (isDark) 0.14f else 0.32f)
            val bottomDepth = lerp(surfaceBase, tint, if (isDark) 0.22f else 0.14f)
            val depthBrush = Brush.verticalGradient(
                0.0f to topLift,
                0.48f to surfaceBase,
                1.0f to bottomDepth,
            )

            // 2. Top meniscus dome catchlight
            val meniscusBrush = Brush.radialGradient(
                colors = listOf(
                    Color.White.copy(alpha = if (isDark) 0.30f else 0.58f),
                    Color.White.copy(alpha = if (isDark) 0.08f else 0.18f),
                    Color.Transparent,
                ),
                center = Offset(size.width * 0.50f, -size.height * 0.22f),
                radius = maxOf(size.width * 0.66f, size.height * 1.15f),
            )

            // 3. Bottom internal caustic refraction glow
            val causticBounceBrush = Brush.radialGradient(
                colors = listOf(
                    tint.copy(alpha = if (isDark) 0.34f else 0.22f),
                    Color.Transparent,
                ),
                center = Offset(size.width * 0.50f, size.height * 1.18f),
                radius = maxOf(size.width * 0.58f, size.height * 0.95f),
            )

            // 4. Razor top specular meniscus filament
            val filamentInset = (radiusPx * 0.55f).coerceAtMost(size.width * 0.25f)
            val filamentBrush = Brush.horizontalGradient(
                colors = listOf(
                    Color.Transparent,
                    Color.White.copy(alpha = (if (isDark) 0.52f else 0.85f) * rimIntensity),
                    Color.White.copy(alpha = (if (isDark) 0.52f else 0.85f) * rimIntensity),
                    Color.Transparent,
                ),
                startX = filamentInset,
                endX = (size.width - filamentInset).coerceAtLeast(filamentInset + 1f),
            )

            // 5. Directional Fresnel rim border
            val fresnelStroke = Stroke(width = strokePx)
            val fresnelBrush = Brush.linearGradient(
                colorStops = arrayOf(
                    0.00f to Color.White.copy(alpha = (if (isDark) 0.58f else 0.88f) * rimIntensity),
                    0.28f to Color.White.copy(alpha = (if (isDark) 0.18f else 0.34f) * rimIntensity),
                    0.65f to tint.copy(alpha = 0.24f * rimIntensity),
                    1.00f to tint.copy(alpha = (if (isDark) 0.56f else 0.44f) * rimIntensity),
                ),
                start = Offset.Zero,
                end = Offset(size.width, size.height),
            )

            // 6. Specular glass sheen (AGSL shader cached once on API 33+, or translated Canvas Brush fallback)
            val agslBrush: Brush? = if (runtimeShader != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                runCatching {
                    runtimeShader.setFloatUniform("resolution", size.width, size.height)
                    runtimeShader.setFloatUniform("intensity", if (livingSheen) 1.0f else 0.55f)
                    ShaderBrush(runtimeShader)
                }.getOrNull()
            } else {
                null
            }
            val sheenHalfW = maxOf(size.width * 0.24f, 36.dp.toPx())
            val fallbackSheenBrush: Brush? = if (agslBrush == null) {
                Brush.linearGradient(
                    colors = listOf(
                        Color.Transparent,
                        Color.White.copy(
                            alpha = if (livingSheen) {
                                if (isDark) 0.15f else 0.26f
                            } else {
                                if (isDark) 0.08f else 0.16f
                            },
                        ),
                        Color.Transparent,
                    ),
                    start = Offset(-sheenHalfW, 0f),
                    end = Offset(sheenHalfW, size.height),
                )
            } else {
                null
            }

            onDrawBehind {
                drawRoundRect(brush = depthBrush, cornerRadius = cr)
                drawRoundRect(brush = meniscusBrush, cornerRadius = cr)
                drawRoundRect(brush = causticBounceBrush, cornerRadius = cr)

                val phase = sheenPhaseState?.value ?: 0.28f
                if (agslBrush != null && runtimeShader != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    runtimeShader.setFloatUniform("phase", phase)
                    drawRoundRect(brush = agslBrush, cornerRadius = cr)
                } else if (fallbackSheenBrush != null) {
                    val shiftX = size.width * (phase * 1.4f - 0.2f)
                    withTransform({
                        translate(left = shiftX)
                    }) {
                        drawRect(
                            brush = fallbackSheenBrush,
                            topLeft = Offset(-sheenHalfW, 0f),
                            size = Size(sheenHalfW * 2f, size.height),
                        )
                    }
                }

                drawLine(
                    brush = filamentBrush,
                    start = Offset(filamentInset, strokePx),
                    end = Offset((size.width - filamentInset).coerceAtLeast(filamentInset), strokePx),
                    strokeWidth = strokePx,
                )
                drawRoundRect(
                    brush = fresnelBrush,
                    topLeft = Offset(halfStroke, halfStroke),
                    size = innerSize,
                    cornerRadius = innerCr,
                    style = fresnelStroke,
                )
            }
        }
}

/**
 * Flagship tactile Liquid Glass button combining spring-elastic press squish,
 * colored ambient glow shadow, multi-layer liquid refraction surface, and crisp ripple feedback.
 */
@Composable
fun LiquidGlassButton(
    onClick: () -> Unit,
    tint: Color,
    surfaceBase: Color,
    contentColor: Color,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    cornerRadius: Dp = 16.dp,
    isDark: Boolean = true,
    elevation: Dp = 6.dp,
    pressedScale: Float = 0.96f,
    livingSheen: Boolean = false,
    contentAlignment: Alignment = Alignment.Center,
    content: @Composable BoxScope.() -> Unit,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val shape = RoundedCornerShape(cornerRadius)
    Box(
        modifier = modifier
            .liquidPress(interactionSource = interactionSource, pressedScale = pressedScale)
            .shadow(
                elevation = if (enabled) elevation else 1.dp,
                shape = shape,
                ambientColor = tint.copy(alpha = 0.45f),
                spotColor = tint.copy(alpha = 0.55f),
            )
            .liquidGlassSurface(
                tint = tint,
                surfaceBase = surfaceBase,
                cornerRadius = cornerRadius,
                isDark = isDark,
                rimIntensity = if (enabled) 1f else 0.55f,
                livingSheen = livingSheen && enabled,
            )
            .clickable(
                interactionSource = interactionSource,
                indication = ripple(color = contentColor),
                enabled = enabled,
                role = Role.Button,
                onClick = onClick,
            ),
        contentAlignment = contentAlignment,
        content = content,
    )
}
