package org.nexus.android.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import org.nexus.android.bridge.workspace.AndroidThemePreset

/**
 * Modern Flagship Card Console Material 3 Adaptive tokens (aligned with Clash Verge Rev & FlClash):
 * - Cool Mist-Slate Light ground (`#F4F6F9`) with crisp `#FFFFFF` `12dp` single-level cards (`#E2E8F0` hairline)
 * - Deep Slate-Obsidian Dark ground (`#0F141C`) with elevated `#171E29` cards (`#263142` hairline)
 * - Electric Cobalt primary (`#2563EB` / `#60A5FA`), Signal Emerald live/TX (`#059669` / `#10B981`), Warm Amber (`#D97706` / `#F59E0B`)
 * - Continuous `surfaceAlpha` (`0.50f..1.0f`) translucency support
 */
@Immutable
data class NexusExtendedColors(
    val isDark: Boolean,
    val success: Color,
    val successContainer: Color,
    val warning: Color,
    val warningContainer: Color,
    val slow: Color,
    val slowContainer: Color,
    val danger: Color,
    val dangerContainer: Color,
    val muted: Color,
    val mutedContainer: Color,
    val telemetryDownload: Color,
    val telemetryDownloadContainer: Color,
    val telemetryUpload: Color,
    val telemetryUploadContainer: Color,
    val protocolQuic: Color,
    val protocolQuicContainer: Color,
    val protocolTls: Color,
    val protocolTlsContainer: Color,
    val protocolDirect: Color,
    val protocolDirectContainer: Color,
    val ruleVermilion: Color,
    val ruleVermilionContainer: Color,
    val commandSurface: Color,
    val commandWell: Color,
    val commandBorder: Color,
    val onCommandSurface: Color,
    val onCommandSurfaceVariant: Color,
    val hairline: Color,
    val hairlineStrong: Color,
    val cardSurface: Color,
    val wellSurface: Color,
    val insetSurface: Color,
    val surfaceAlpha: Float = 1.0f,
)

private val ObsidianExtendedBase = NexusExtendedColors(
    isDark = true,
    success = Color(0xFF10B981),
    successContainer = Color(0xFF0E2E24),
    warning = Color(0xFFF59E0B),
    warningContainer = Color(0xFF332512),
    slow = Color(0xFFFB923C),
    slowContainer = Color(0xFF362115),
    danger = Color(0xFFF87171),
    dangerContainer = Color(0xFF381A1F),
    muted = Color(0xFF7E8FA6),
    mutedContainer = Color(0xFF1E2736),
    telemetryDownload = Color(0xFF60A5FA),
    telemetryDownloadContainer = Color(0xFF172B4D),
    telemetryUpload = Color(0xFF10B981),
    telemetryUploadContainer = Color(0xFF0E2E24),
    protocolQuic = Color(0xFFF59E0B),
    protocolQuicContainer = Color(0xFF332512),
    protocolTls = Color(0xFF60A5FA),
    protocolTlsContainer = Color(0xFF172B4D),
    protocolDirect = Color(0xFF10B981),
    protocolDirectContainer = Color(0xFF0E2E24),
    ruleVermilion = Color(0xFFF59E0B),
    ruleVermilionContainer = Color(0xFF332512),
    commandSurface = Color(0xFF171E29),
    commandWell = Color(0xFF1E2736),
    commandBorder = Color(0xFF263142),
    onCommandSurface = Color(0xFFF1F5F9),
    onCommandSurfaceVariant = Color(0xFF94A3B8),
    hairline = Color(0xFF263142),
    hairlineStrong = Color(0xFF37465E),
    cardSurface = Color(0xFF171E29),
    wellSurface = Color(0xFF1E2736),
    insetSurface = Color(0xFF283447),
)

private val StudioAmberExtendedBase = ObsidianExtendedBase.copy(
    muted = Color(0xFFA89F91),
    mutedContainer = Color(0xFF24201B),
    telemetryDownload = Color(0xFFF59E0B),
    telemetryDownloadContainer = Color(0xFF362813),
    commandSurface = Color(0xFF1B1815),
    commandWell = Color(0xFF24201B),
    commandBorder = Color(0xFF2E2923),
    onCommandSurface = Color(0xFFF5F1E8),
    onCommandSurfaceVariant = Color(0xFFB8AEA0),
    hairline = Color(0xFF2E2923),
    hairlineStrong = Color(0xFF453D34),
    cardSurface = Color(0xFF1B1815),
    wellSurface = Color(0xFF24201B),
    insetSurface = Color(0xFF302B24),
)

private val PaperExtendedBase = NexusExtendedColors(
    isDark = false,
    success = Color(0xFF059669),
    successContainer = Color(0xFFD1FAE5),
    warning = Color(0xFFD97706),
    warningContainer = Color(0xFFFEF3C7),
    slow = Color(0xFFEA580C),
    slowContainer = Color(0xFFFFEDD5),
    danger = Color(0xFFDC2626),
    dangerContainer = Color(0xFFFEE2E2),
    muted = Color(0xFF64748B),
    mutedContainer = Color(0xFFF1F5F9),
    telemetryDownload = Color(0xFF2563EB),
    telemetryDownloadContainer = Color(0xFFDBEAFE),
    telemetryUpload = Color(0xFF059669),
    telemetryUploadContainer = Color(0xFFD1FAE5),
    protocolQuic = Color(0xFFD97706),
    protocolQuicContainer = Color(0xFFFEF3C7),
    protocolTls = Color(0xFF2563EB),
    protocolTlsContainer = Color(0xFFDBEAFE),
    protocolDirect = Color(0xFF059669),
    protocolDirectContainer = Color(0xFFD1FAE5),
    ruleVermilion = Color(0xFFD97706),
    ruleVermilionContainer = Color(0xFFFEF3C7),
    commandSurface = Color(0xFFFFFFFF),
    commandWell = Color(0xFFF1F5F9),
    commandBorder = Color(0xFFE2E8F0),
    onCommandSurface = Color(0xFF0F172A),
    onCommandSurfaceVariant = Color(0xFF475569),
    hairline = Color(0xFFE2E8F0),
    hairlineStrong = Color(0xFFCBD5E1),
    cardSurface = Color(0xFFFFFFFF),
    wellSurface = Color(0xFFF1F5F9),
    insetSurface = Color(0xFFE2E8F0),
)

private fun deriveExtendedColors(
    colorScheme: ColorScheme,
    darkTheme: Boolean,
    amberBase: Boolean = false,
    dynamicActive: Boolean = false,
    surfaceAlpha: Float = 1.0f,
): NexusExtendedColors {
    val alpha = surfaceAlpha.coerceIn(0.50f, 1.0f)
    val base = when {
        !darkTheme -> PaperExtendedBase
        amberBase -> StudioAmberExtendedBase
        else -> ObsidianExtendedBase
    }
    val rawCard = colorScheme.surfaceContainerLow
    val cardWithAlpha = if (alpha < 0.995f) rawCard.copy(alpha = alpha) else rawCard
    val wellWithAlpha = if (alpha < 0.995f) colorScheme.surfaceContainerHigh.copy(alpha = alpha) else colorScheme.surfaceContainerHigh
    val insetWithAlpha = if (alpha < 0.995f) colorScheme.surfaceContainerHighest.copy(alpha = alpha) else colorScheme.surfaceContainerHighest
    val cmdLight = rawCard.luminance() > 0.45f

    return base.copy(
        commandSurface = cardWithAlpha,
        commandWell = wellWithAlpha,
        commandBorder = colorScheme.outlineVariant,
        onCommandSurface = if (dynamicActive) (if (cmdLight) Color(0xFF0F172A) else Color(0xFFF1F5F9)) else colorScheme.onSurface,
        onCommandSurfaceVariant = colorScheme.onSurfaceVariant,
        cardSurface = cardWithAlpha,
        wellSurface = wellWithAlpha,
        insetSurface = insetWithAlpha,
        hairline = colorScheme.outlineVariant,
        hairlineStrong = colorScheme.outline,
        surfaceAlpha = alpha,
    )
}

val LocalNexusExtendedColors = staticCompositionLocalOf { PaperExtendedBase }

private val ObsidianDarkColorScheme = darkColorScheme(
    primary = Color(0xFF60A5FA),
    onPrimary = Color(0xFF081A38),
    primaryContainer = Color(0xFF1E3A6E),
    onPrimaryContainer = Color(0xFFDBEAFE),
    secondary = Color(0xFF93C5FD),
    onSecondary = Color(0xFF0B2149),
    secondaryContainer = Color(0xFF1E2736),
    onSecondaryContainer = Color(0xFFE2E8F0),
    tertiary = Color(0xFF10B981),
    onTertiary = Color(0xFF042217),
    background = Color(0xFF0F141C),
    onBackground = Color(0xFFF1F5F9),
    surface = Color(0xFF0F141C),
    onSurface = Color(0xFFF1F5F9),
    surfaceVariant = Color(0xFF1E2736),
    onSurfaceVariant = Color(0xFF94A3B8),
    surfaceContainerLowest = Color(0xFF0A0E14),
    surfaceContainerLow = Color(0xFF171E29),
    surfaceContainer = Color(0xFF131923),
    surfaceContainerHigh = Color(0xFF1E2736),
    surfaceContainerHighest = Color(0xFF283447),
    outline = Color(0xFF37465E),
    outlineVariant = Color(0xFF263142),
    error = Color(0xFFF87171),
    onError = Color(0xFF3B0813),
    errorContainer = Color(0xFF381A1F),
    onErrorContainer = Color(0xFFFECACA),
)

private val PaperLightColorScheme = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDBEAFE),
    onPrimaryContainer = Color(0xFF1E3A8A),
    secondary = Color(0xFF3B82F6),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFF1F5F9),
    onSecondaryContainer = Color(0xFF0F172A),
    tertiary = Color(0xFF059669),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF4F6F9),
    onBackground = Color(0xFF0F172A),
    surface = Color(0xFFF4F6F9),
    onSurface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFFF1F5F9),
    onSurfaceVariant = Color(0xFF475569),
    surfaceContainerLowest = Color(0xFFE9EEF5),
    surfaceContainerLow = Color(0xFFFFFFFF),
    surfaceContainer = Color(0xFFEEF2F7),
    surfaceContainerHigh = Color(0xFFF1F5F9),
    surfaceContainerHighest = Color(0xFFE2E8F0),
    outline = Color(0xFFCBD5E1),
    outlineVariant = Color(0xFFE2E8F0),
    error = Color(0xFFDC2626),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF7F1D1D),
)

private val StudioAmberDarkColorScheme = darkColorScheme(
    primary = Color(0xFFF59E0B),
    onPrimary = Color(0xFF17120A),
    primaryContainer = Color(0xFF3D2A0F),
    onPrimaryContainer = Color(0xFFFDE68A),
    secondary = Color(0xFFFBBF24),
    onSecondary = Color(0xFF1A140B),
    secondaryContainer = Color(0xFF24201B),
    onSecondaryContainer = Color(0xFFF0EAE0),
    tertiary = Color(0xFF10B981),
    onTertiary = Color(0xFF052218),
    background = Color(0xFF12100E),
    onBackground = Color(0xFFF5F1E8),
    surface = Color(0xFF12100E),
    onSurface = Color(0xFFF5F1E8),
    surfaceVariant = Color(0xFF24201B),
    onSurfaceVariant = Color(0xFFB8AEA0),
    surfaceContainerLowest = Color(0xFF0D0B0A),
    surfaceContainerLow = Color(0xFF1B1815),
    surfaceContainer = Color(0xFF161411),
    surfaceContainerHigh = Color(0xFF24201B),
    surfaceContainerHighest = Color(0xFF302B24),
    outline = Color(0xFF453D34),
    outlineVariant = Color(0xFF2E2923),
    error = Color(0xFFF87171),
    onError = Color(0xFF3B0813),
    errorContainer = Color(0xFF381A1F),
    onErrorContainer = Color(0xFFFECACA),
)

fun resolveEffectiveDarkTheme(
    preset: AndroidThemePreset,
    systemDark: Boolean,
): Boolean = when (preset) {
    AndroidThemePreset.SYSTEM -> systemDark
    AndroidThemePreset.OBSIDIAN, AndroidThemePreset.STUDIO_AMBER -> true
    AndroidThemePreset.PAPER -> false
}

object NexusTheme {
    val colors: NexusExtendedColors
        @Composable
        get() = LocalNexusExtendedColors.current
}

@Composable
fun NexusTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    themePreset: AndroidThemePreset = AndroidThemePreset.SYSTEM,
    dynamicColor: Boolean = false,
    surfaceAlpha: Float = 1.0f,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val effectiveDark = resolveEffectiveDarkTheme(themePreset, darkTheme)
    val dynamicActive = dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val useAmberBase = !dynamicActive && themePreset == AndroidThemePreset.STUDIO_AMBER
    val clampedAlpha = surfaceAlpha.coerceIn(0.50f, 1.0f)
    val rawScheme = when {
        dynamicActive -> {
            if (effectiveDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        themePreset == AndroidThemePreset.STUDIO_AMBER -> StudioAmberDarkColorScheme
        effectiveDark -> ObsidianDarkColorScheme
        else -> PaperLightColorScheme
    }
    val colorScheme = remember(rawScheme, clampedAlpha) {
        if (clampedAlpha < 0.995f) {
            rawScheme.copy(
                surfaceContainer = rawScheme.surfaceContainer.copy(alpha = clampedAlpha),
                surfaceContainerLow = rawScheme.surfaceContainerLow.copy(alpha = clampedAlpha),
                surfaceContainerHigh = rawScheme.surfaceContainerHigh.copy(alpha = clampedAlpha),
            )
        } else rawScheme
    }
    val extendedColors = remember(colorScheme, effectiveDark, useAmberBase, dynamicActive, clampedAlpha) {
        deriveExtendedColors(
            colorScheme = colorScheme,
            darkTheme = effectiveDark,
            amberBase = useAmberBase,
            dynamicActive = dynamicActive,
            surfaceAlpha = clampedAlpha,
        )
    }

    CompositionLocalProvider(LocalNexusExtendedColors provides extendedColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = NexusTypography,
            content = content,
        )
    }
}
