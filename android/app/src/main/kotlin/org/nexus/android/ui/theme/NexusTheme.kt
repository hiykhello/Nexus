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
import androidx.compose.ui.platform.LocalContext
import org.nexus.android.bridge.workspace.AndroidThemePreset

/**
 * Calibrated Material 3 Adaptive instrument semantic tokens:
 * - Decoupled telemetry channels: Download Sky Cyan (`telemetryDownload`) & Upload Prism Violet (`telemetryUpload`)
 * - Dedicated Signal Emerald (`success`) reserved strictly for live connected/healthy link state
 * - 5-tier latency scale: <80ms Emerald, 80..179ms Amber, 180..349ms Orange, >=350ms/Timeout Rose, Unprobed Neutral
 * - Flat matte surfaces (`cardSurface`, `wellSurface`, `insetSurface`) & hairlines derived from `ColorScheme`
 *   so all 3 static instrument themes AND API 31+ Material You dynamic color harmonize cleanly.
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
    val hairline: Color,
    val hairlineStrong: Color,
    val cardSurface: Color,
    val wellSurface: Color,
    val insetSurface: Color,
)

private val ObsidianExtendedBase = NexusExtendedColors(
    isDark = true,
    success = Color(0xFF34D399),
    successContainer = Color(0xFF0E2D24),
    warning = Color(0xFFFBBF24),
    warningContainer = Color(0xFF312716),
    slow = Color(0xFFFB923C),
    slowContainer = Color(0xFF352316),
    danger = Color(0xFFFB7185),
    dangerContainer = Color(0xFF361C24),
    muted = Color(0xFF939DAF),
    mutedContainer = Color(0xFF202530),
    telemetryDownload = Color(0xFF38BDF8),
    telemetryDownloadContainer = Color(0xFF142A3A),
    telemetryUpload = Color(0xFFC084FC),
    telemetryUploadContainer = Color(0xFF2A1E3A),
    protocolQuic = Color(0xFFF59E0B),
    protocolQuicContainer = Color(0xFF312615),
    protocolTls = Color(0xFF38BDF8),
    protocolTlsContainer = Color(0xFF142A3A),
    protocolDirect = Color(0xFF34D399),
    protocolDirectContainer = Color(0xFF0E2D24),
    hairline = Color(0xFF2A303E),
    hairlineStrong = Color(0xFF384152),
    cardSurface = Color(0xFF191D25),
    wellSurface = Color(0xFF202530),
    insetSurface = Color(0xFF282E3B),
)

private val StudioAmberExtendedBase = ObsidianExtendedBase.copy(
    muted = Color(0xFFA69D8E),
    mutedContainer = Color(0xFF25221E),
    hairline = Color(0xFF302C26),
    hairlineStrong = Color(0xFF423C33),
    cardSurface = Color(0xFF1C1A17),
    wellSurface = Color(0xFF25221E),
    insetSurface = Color(0xFF2F2B25),
)

private val PaperExtendedBase = NexusExtendedColors(
    isDark = false,
    success = Color(0xFF047857),
    successContainer = Color(0xFFD1FAE5),
    warning = Color(0xFF9A5B00),
    warningContainer = Color(0xFFFEF3C7),
    slow = Color(0xFFC2410C),
    slowContainer = Color(0xFFFFEDD5),
    danger = Color(0xFFBE123C),
    dangerContainer = Color(0xFFFFE4E6),
    muted = Color(0xFF545B69),
    mutedContainer = Color(0xFFE5E2D9),
    telemetryDownload = Color(0xFF0369A1),
    telemetryDownloadContainer = Color(0xFFE0F2FE),
    telemetryUpload = Color(0xFF7C3AED),
    telemetryUploadContainer = Color(0xFFF3E8FF),
    protocolQuic = Color(0xFF9A5B00),
    protocolQuicContainer = Color(0xFFFEF3C7),
    protocolTls = Color(0xFF0369A1),
    protocolTlsContainer = Color(0xFFE0F2FE),
    protocolDirect = Color(0xFF047857),
    protocolDirectContainer = Color(0xFFD1FAE5),
    hairline = Color(0xFFDDD9D0),
    hairlineStrong = Color(0xFFC9C5BB),
    cardSurface = Color(0xFFFFFFFF),
    wellSurface = Color(0xFFEFEDE7),
    insetSurface = Color(0xFFE5E2D9),
)

private fun deriveExtendedColors(
    colorScheme: ColorScheme,
    darkTheme: Boolean,
    amberBase: Boolean = false,
): NexusExtendedColors {
    val base = when {
        !darkTheme -> PaperExtendedBase
        amberBase -> StudioAmberExtendedBase
        else -> ObsidianExtendedBase
    }
    return base.copy(
        cardSurface = colorScheme.surfaceContainerLow,
        wellSurface = colorScheme.surfaceContainerHigh,
        insetSurface = colorScheme.surfaceContainerHighest,
        hairline = colorScheme.outlineVariant,
        hairlineStrong = colorScheme.outline,
    )
}

val LocalNexusExtendedColors = staticCompositionLocalOf { PaperExtendedBase }

private val ObsidianDarkColorScheme = darkColorScheme(
    primary = Color(0xFF6F8BFF),
    onPrimary = Color(0xFF091026),
    primaryContainer = Color(0xFF1E2B57),
    onPrimaryContainer = Color(0xFFDDE5FF),
    secondary = Color(0xFF93B0FF),
    onSecondary = Color(0xFF0B193D),
    secondaryContainer = Color(0xFF202530),
    onSecondaryContainer = Color(0xFFE5E9F2),
    tertiary = Color(0xFF34D399),
    onTertiary = Color(0xFF052218),
    background = Color(0xFF12151B),
    onBackground = Color(0xFFF2F4F8),
    surface = Color(0xFF12151B),
    onSurface = Color(0xFFF2F4F8),
    surfaceVariant = Color(0xFF202530),
    onSurfaceVariant = Color(0xFFA7B0C0),
    surfaceContainerLowest = Color(0xFF0D0F13),
    surfaceContainerLow = Color(0xFF191D25),
    surfaceContainer = Color(0xFF151820),
    surfaceContainerHigh = Color(0xFF202530),
    surfaceContainerHighest = Color(0xFF282E3B),
    outline = Color(0xFF384152),
    outlineVariant = Color(0xFF2A303E),
    error = Color(0xFFFB7185),
    onError = Color(0xFF3B0813),
    errorContainer = Color(0xFF361C24),
    onErrorContainer = Color(0xFFFFD6DD),
)

private val PaperLightColorScheme = lightColorScheme(
    primary = Color(0xFF3452D6),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE1E7FF),
    onPrimaryContainer = Color(0xFF142670),
    secondary = Color(0xFF4763DB),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFEFEDE7),
    onSecondaryContainer = Color(0xFF181C24),
    tertiary = Color(0xFF047857),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF6F5F2),
    onBackground = Color(0xFF181C24),
    surface = Color(0xFFF6F5F2),
    onSurface = Color(0xFF181C24),
    surfaceVariant = Color(0xFFEFEDE7),
    onSurfaceVariant = Color(0xFF545B69),
    surfaceContainerLowest = Color(0xFFECEAE4),
    surfaceContainerLow = Color(0xFFFFFFFF),
    surfaceContainer = Color(0xFFECEAE4),
    surfaceContainerHigh = Color(0xFFEFEDE7),
    surfaceContainerHighest = Color(0xFFE5E2D9),
    outline = Color(0xFFC9C5BB),
    outlineVariant = Color(0xFFDDD9D0),
    error = Color(0xFFBE123C),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFE4E6),
    onErrorContainer = Color(0xFF7F1D1D),
)

private val StudioAmberDarkColorScheme = darkColorScheme(
    primary = Color(0xFFE59A2E),
    onPrimary = Color(0xFF14120F),
    primaryContainer = Color(0xFF3B2910),
    onPrimaryContainer = Color(0xFFFCE3B8),
    secondary = Color(0xFFF0B45B),
    onSecondary = Color(0xFF1A140B),
    secondaryContainer = Color(0xFF25221E),
    onSecondaryContainer = Color(0xFFF0EAE0),
    tertiary = Color(0xFF34D399),
    onTertiary = Color(0xFF052218),
    background = Color(0xFF141311),
    onBackground = Color(0xFFF5F1E8),
    surface = Color(0xFF141311),
    onSurface = Color(0xFFF5F1E8),
    surfaceVariant = Color(0xFF25221E),
    onSurfaceVariant = Color(0xFFB3AA9B),
    surfaceContainerLowest = Color(0xFF0E0D0C),
    surfaceContainerLow = Color(0xFF1C1A17),
    surfaceContainer = Color(0xFF171512),
    surfaceContainerHigh = Color(0xFF25221E),
    surfaceContainerHighest = Color(0xFF2F2B25),
    outline = Color(0xFF423C33),
    outlineVariant = Color(0xFF302C26),
    error = Color(0xFFFB7185),
    onError = Color(0xFF3B0813),
    errorContainer = Color(0xFF361C24),
    onErrorContainer = Color(0xFFFFD6DD),
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
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val effectiveDark = resolveEffectiveDarkTheme(themePreset, darkTheme)
    val useAmberBase = !dynamicColor && themePreset == AndroidThemePreset.STUDIO_AMBER
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (effectiveDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        themePreset == AndroidThemePreset.STUDIO_AMBER -> StudioAmberDarkColorScheme
        effectiveDark -> ObsidianDarkColorScheme
        else -> PaperLightColorScheme
    }
    val extendedColors = remember(colorScheme, effectiveDark, useAmberBase) {
        deriveExtendedColors(colorScheme, effectiveDark, amberBase = useAmberBase)
    }

    CompositionLocalProvider(LocalNexusExtendedColors provides extendedColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = NexusTypography,
            content = content,
        )
    }
}
