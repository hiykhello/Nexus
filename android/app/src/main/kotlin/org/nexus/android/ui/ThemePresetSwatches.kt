package org.nexus.android.ui

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.nexus.android.R
import org.nexus.android.bridge.workspace.AndroidThemePreset
import org.nexus.android.ui.theme.NexusNumericStyles
import org.nexus.android.ui.theme.NexusTheme
import kotlin.math.roundToInt

private data class ThemeSwatchSpec(
    val preset: AndroidThemePreset,
    val label: String,
    val railColor: Color,
    val canvasColor: Color,
    val cardColor: Color,
    val accentColor: Color,
    val emeraldColor: Color,
    val splitSystemPreview: Boolean = false,
)

private val THEME_SWATCHES = listOf(
    ThemeSwatchSpec(
        preset = AndroidThemePreset.SYSTEM,
        label = "跟随系统",
        railColor = Color(0xFFEEF2F7),
        canvasColor = Color(0xFFF4F6F9),
        cardColor = Color(0xFFFFFFFF),
        accentColor = Color(0xFF2563EB),
        emeraldColor = Color(0xFF059669),
        splitSystemPreview = true,
    ),
    ThemeSwatchSpec(
        preset = AndroidThemePreset.PAPER,
        label = "雾白卡片",
        railColor = Color(0xFFEEF2F7),
        canvasColor = Color(0xFFF4F6F9),
        cardColor = Color(0xFFFFFFFF),
        accentColor = Color(0xFF2563EB),
        emeraldColor = Color(0xFF059669),
    ),
    ThemeSwatchSpec(
        preset = AndroidThemePreset.OBSIDIAN,
        label = "曜石深色",
        railColor = Color(0xFF131923),
        canvasColor = Color(0xFF0F141C),
        cardColor = Color(0xFF171E29),
        accentColor = Color(0xFF60A5FA),
        emeraldColor = Color(0xFF10B981),
    ),
    ThemeSwatchSpec(
        preset = AndroidThemePreset.STUDIO_AMBER,
        label = "暖金深色",
        railColor = Color(0xFF161411),
        canvasColor = Color(0xFF12100E),
        cardColor = Color(0xFF1B1815),
        accentColor = Color(0xFFF59E0B),
        emeraldColor = Color(0xFF10B981),
    ),
)

/**
 * Miniature Card Console theme swatch selector (`0ms` instant apply) paired with continuous
 * `surfaceAlpha` (`50%..100%`) slider and API 31+ Material You Dynamic Color toggle.
 * Uses borderless `wellSurface` fills so it never creates nested bordered cards inside `HostSettingsCard`.
 */
@Composable
internal fun ThemePresetSwatches(
    selectedPreset: AndroidThemePreset,
    dynamicColor: Boolean,
    surfaceAlpha: Float = 1.0f,
    onSelectPreset: (AndroidThemePreset) -> Unit,
    onToggleDynamicColor: (Boolean) -> Unit,
    onChangeSurfaceAlpha: (Float) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val compact = rememberWindowSizeClass() == NexusWindowSizeClass.COMPACT
    val supportsDynamic = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = "外观主题与卡片透明度",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (compact) {
            THEME_SWATCHES.chunked(2).forEach { pair ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    pair.forEach { spec ->
                        ThemeSwatchCard(
                            spec = spec,
                            selected = selectedPreset == spec.preset,
                            onClick = { onSelectPreset(spec.preset) },
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                THEME_SWATCHES.forEach { spec ->
                    ThemeSwatchCard(
                        spec = spec,
                        selected = selectedPreset == spec.preset,
                        onClick = { onSelectPreset(spec.preset) },
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }

        Surface(
            shape = RoundedCornerShape(8.dp),
            color = ext.wellSurface,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = "界面与卡片透明度",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = "${(surfaceAlpha.coerceIn(0.50f, 1.0f) * 100f).roundToInt()}%",
                            style = NexusNumericStyles.monoBadge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    Slider(
                        value = surfaceAlpha.coerceIn(0.50f, 1.0f),
                        onValueChange = { raw ->
                            val stepped = ((raw * 20f).roundToInt() / 20f).coerceIn(0.50f, 1.0f)
                            onChangeSurfaceAlpha(stepped)
                        },
                        valueRange = 0.50f..1.0f,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp), color = ext.hairline)

                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = "Material You 动态取色",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = if (supportsDynamic) {
                                "跟随系统壁纸主色，保留延迟与吞吐语义信号色"
                            } else {
                                "仅 Android 12+ 可用"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Switch(
                        checked = dynamicColor && supportsDynamic,
                        enabled = supportsDynamic,
                        onCheckedChange = onToggleDynamicColor,
                    )
                }
            }
        }
    }
}

@Composable
private fun ThemeSwatchCard(
    spec: ThemeSwatchSpec,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ext = NexusTheme.colors
    val primary = MaterialTheme.colorScheme.primary
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(8.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (ext.isDark) 0.55f else 0.55f) else ext.wellSurface,
        border = if (selected) BorderStroke(1.5.dp, primary) else null,
        modifier = modifier
            .heightIn(min = 68.dp)
            .semantics { this.selected = selected },
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            val miniCardBorder = if (spec.preset == AndroidThemePreset.PAPER) Color(0xFFCBD5E1) else Color(0xFF334155)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(28.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(spec.canvasColor)
                    .border(1.dp, ext.hairlineStrong, RoundedCornerShape(6.dp)),
            ) {
                if (spec.splitSystemPreview) {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .background(Color(0xFFF4F6F9))
                            .padding(4.dp),
                        contentAlignment = Alignment.BottomStart,
                    ) {
                        Box(Modifier.size(5.dp).background(Color(0xFF2563EB), CircleShape))
                    }
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .background(Color(0xFF0F141C))
                            .padding(4.dp),
                        contentAlignment = Alignment.BottomEnd,
                    ) {
                        Box(Modifier.size(5.dp).background(Color(0xFF10B981), CircleShape))
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .width(10.dp)
                            .fillMaxHeight()
                            .background(spec.railColor),
                    )
                    Row(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .padding(4.dp),
                        horizontalArrangement = Arrangement.spacedBy(3.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(3.dp))
                                .background(spec.cardColor)
                                .border(1.dp, miniCardBorder, RoundedCornerShape(3.dp))
                                .padding(3.dp),
                            contentAlignment = Alignment.CenterStart,
                        ) {
                            Box(Modifier.size(5.dp).background(spec.accentColor, CircleShape))
                        }
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(3.dp))
                                .background(spec.cardColor)
                                .border(1.dp, miniCardBorder, RoundedCornerShape(3.dp))
                                .padding(3.dp),
                            contentAlignment = Alignment.CenterStart,
                        ) {
                            Box(Modifier.size(5.dp).background(spec.emeraldColor, CircleShape))
                        }
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = spec.label,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                    color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (selected) {
                    Icon(
                        painter = painterResource(R.drawable.ic_check),
                        contentDescription = null,
                        tint = primary,
                        modifier = Modifier.size(13.dp),
                    )
                }
            }
        }
    }
}
