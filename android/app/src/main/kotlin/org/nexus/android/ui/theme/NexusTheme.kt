package org.nexus.android.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

/**
 * Optical Precision semantic tokens strictly decoupled from brand accent colors:
 * - Download (`telemetryDownload`) = Sky Cyan (`#38BDF8` Dark / `#0284C7` Light)
 * - Upload (`telemetryUpload`) = Prism Violet (`#C084FC` Dark / `#7C3AED` Light)
 * - 5-tier latency scale: <80ms Emerald, 80..179ms Amber, 180..349ms Orange-Coral, >=350ms/Timeout Rose, Unprobed Neutral
 * - Optical surface lighting: 1dp hairline border + subtle directional top specular highlight
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
    val topSpeculum: Color,
    val cardGradientTop: Color,
    val cardGradientBottom: Color,
    val wellSurface: Color,
    val insetSurface: Color,
)

private val DarkExtendedColors = NexusExtendedColors(
    isDark = true,
    success = Color(0xFF34D399),
    successContainer = Color(0xFF182D26),
    warning = Color(0xFFFBBF24),
    warningContainer = Color(0xFF312716),
    slow = Color(0xFFFB923C),
    slowContainer = Color(0xFF352316),
    danger = Color(0xFFFB7185),
    dangerContainer = Color(0xFF361C24),
    muted = Color(0xFF8890A0),
    mutedContainer = Color(0xFF2B2E37),
    telemetryDownload = Color(0xFF38BDF8),
    telemetryDownloadContainer = Color(0xFF162C3B),
    telemetryUpload = Color(0xFFC084FC),
    telemetryUploadContainer = Color(0xFF2B203B),
    protocolQuic = Color(0xFFF59E0B),
    protocolQuicContainer = Color(0xFF312615),
    protocolTls = Color(0xFF38BDF8),
    protocolTlsContainer = Color(0xFF162B3A),
    protocolDirect = Color(0xFF34D399),
    protocolDirectContainer = Color(0xFF182D26),
    hairline = Color(0x14FFFFFF),
    hairlineStrong = Color(0x22FFFFFF),
    topSpeculum = Color(0x26FFFFFF),
    cardGradientTop = Color(0xFF242730),
    cardGradientBottom = Color(0xFF1E2027),
    wellSurface = Color(0xFF2B2E37),
    insetSurface = Color(0xFF383C47),
)

private val LightExtendedColors = NexusExtendedColors(
    isDark = false,
    success = Color(0xFF047857),
    successContainer = Color(0xFFDCFCE7),
    warning = Color(0xFFB45309),
    warningContainer = Color(0xFFFEF3C7),
    slow = Color(0xFFC2410C),
    slowContainer = Color(0xFFFFEDD5),
    danger = Color(0xFFBE123C),
    dangerContainer = Color(0xFFFFE4E6),
    muted = Color(0xFF475569),
    mutedContainer = Color(0xFFE2E8F0),
    telemetryDownload = Color(0xFF0369A1),
    telemetryDownloadContainer = Color(0xFFE0F2FE),
    telemetryUpload = Color(0xFF7C3AED),
    telemetryUploadContainer = Color(0xFFF3E8FF),
    protocolQuic = Color(0xFFB45309),
    protocolQuicContainer = Color(0xFFFEF3C7),
    protocolTls = Color(0xFF0369A1),
    protocolTlsContainer = Color(0xFFE0F2FE),
    protocolDirect = Color(0xFF047857),
    protocolDirectContainer = Color(0xFFDCFCE7),
    hairline = Color(0x180F172A),
    hairlineStrong = Color(0x280F172A),
    topSpeculum = Color(0xD8FFFFFF),
    cardGradientTop = Color(0xFFFFFFFF),
    cardGradientBottom = Color(0xFFF6F9FE),
    wellSurface = Color(0xFFE6ECF5),
    insetSurface = Color(0xFFD6E0F0),
)

val LocalNexusExtendedColors = staticCompositionLocalOf { LightExtendedColors }

private val NexusDarkColorScheme = darkColorScheme(
    primary = Color(0xFF5899FF),
    onPrimary = Color(0xFF061836),
    primaryContainer = Color(0xFF1A3562),
    onPrimaryContainer = Color(0xFFDCEBFF),
    secondary = Color(0xFF93C5FD),
    onSecondary = Color(0xFF0B2547),
    secondaryContainer = Color(0xFF2B2E37),
    onSecondaryContainer = Color(0xFFE7EAF0),
    tertiary = Color(0xFF34D399),
    onTertiary = Color(0xFF052218),
    background = Color(0xFF101114),
    onBackground = Color(0xFFF5F6F9),
    surface = Color(0xFF101114),
    onSurface = Color(0xFFF5F6F9),
    surfaceVariant = Color(0xFF252832),
    onSurfaceVariant = Color(0xFFA8AEB9),
    surfaceContainerLowest = Color(0xFF0C0D10),
    surfaceContainerLow = Color(0xFF17191F),
    surfaceContainer = Color(0xFF202229),
    surfaceContainerHigh = Color(0xFF2B2E37),
    surfaceContainerHighest = Color(0xFF383C47),
    outline = Color(0xFF535968),
    outlineVariant = Color(0xFF2F333E),
    error = Color(0xFFFB7185),
    onError = Color(0xFF3B0813),
    errorContainer = Color(0xFF361C24),
    onErrorContainer = Color(0xFFFFD6DD),
)

private val NexusLightColorScheme = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDBEAFE),
    onPrimaryContainer = Color(0xFF1E3A8A),
    secondary = Color(0xFF3B82F6),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE6EEF9),
    onSecondaryContainer = Color(0xFF1E293B),
    tertiary = Color(0xFF059669),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFEEF2F8),
    onBackground = Color(0xFF0F172A),
    surface = Color(0xFFEEF2F8),
    onSurface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFFE2EAF5),
    onSurfaceVariant = Color(0xFF475569),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF9FBFE),
    surfaceContainer = Color(0xFFEDF2FA),
    surfaceContainerHigh = Color(0xFFE2E9F4),
    surfaceContainerHighest = Color(0xFFD6E0F0),
    outline = Color(0xFF94A3B8),
    outlineVariant = Color(0xFFCBD5E1),
    error = Color(0xFFBE123C),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFE4E6),
    onErrorContainer = Color(0xFF7F1D1D),
)

object NexusTheme {
    val colors: NexusExtendedColors
        @Composable
        get() = LocalNexusExtendedColors.current
}

@Composable
fun NexusTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> NexusDarkColorScheme
        else -> NexusLightColorScheme
    }
    val extendedColors = if (darkTheme) DarkExtendedColors else LightExtendedColors

    CompositionLocalProvider(LocalNexusExtendedColors provides extendedColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = NexusTypography,
            content = content,
        )
    }
}
