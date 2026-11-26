package org.nexus.android.ui

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import org.nexus.android.ui.theme.NexusTheme

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
        railColor = Color(0xFF0D0F13),
        canvasColor = Color(0xFF12151B),
        cardColor = Color(0xFFFFFFFF),
        accentColor = Color(0xFF3452D6),
        emeraldColor = Color(0xFF10B981),
        splitSystemPreview = true,
    ),
    ThemeSwatchSpec(
        preset = AndroidThemePreset.OBSIDIAN,
        label = "曜石仪表",
        railColor = Color(0xFF0D0F13),
        canvasColor = Color(0xFF12151B),
        cardColor = Color(0xFF191D25),
        accentColor = Color(0xFF6F8BFF),
        emeraldColor = Color(0xFF34D399),
    ),
    ThemeSwatchSpec(
        preset = AndroidThemePreset.PAPER,
        label = "暖纸日光",
        railColor = Color(0xFFECEAE4),
        canvasColor = Color(0xFFF6F5F2),
        cardColor = Color(0xFFFFFFFF),
        accentColor = Color(0xFF3452D6),
        emeraldColor = Color(0xFF047857),
    ),
    ThemeSwatchSpec(
        preset = AndroidThemePreset.STUDIO_AMBER,
        label = "精密琥珀",
        railColor = Color(0xFF0E0D0C),
        canvasColor = Color(0xFF141311),
        cardColor = Color(0xFF1C1A17),
        accentColor = Color(0xFFE59A2E),
        emeraldColor = Color(0xFF34D399),
    ),
)

/**
 * Pure-Compose miniature instrument theme swatch selector (`0ms` instant apply) paired with
 * API 31+ Material You Dynamic Color harmony toggle.
 */
@Composable
internal fun ThemePresetSwatches(
    selectedPreset: AndroidThemePreset,
    dynamicColor: Boolean,
    onSelectPreset: (AndroidThemePreset) -> Unit,
    onToggleDynamicColor: (Boolean) -> Unit,
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
            text = "外观与仪表主题",
            style = MaterialTheme.typography.labelMedium,
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
            shape = RoundedCornerShape(12.dp),
            color = ext.wellSurface,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 9.dp),
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
                            "跟随系统壁纸色系，保留遥测与链路信号色解耦"
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
        shape = RoundedCornerShape(12.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (ext.isDark) 0.55f else 0.45f) else ext.wellSurface,
        border = BorderStroke(
            width = if (selected) 1.5.dp else 1.dp,
            color = if (selected) primary else ext.hairline,
        ),
        modifier = modifier
            .heightIn(min = 68.dp)
            .semantics { this.selected = selected },
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(28.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(spec.canvasColor),
            ) {
                if (spec.splitSystemPreview) {
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .background(Color(0xFF191D25))
                            .padding(4.dp),
                        contentAlignment = Alignment.BottomStart,
                    ) {
                        Box(Modifier.size(5.dp).background(Color(0xFF6F8BFF), CircleShape))
                    }
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .background(Color(0xFFF6F5F2))
                            .padding(4.dp),
                        contentAlignment = Alignment.BottomEnd,
                    ) {
                        Box(Modifier.size(5.dp).background(Color(0xFF047857), CircleShape))
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .width(12.dp)
                            .fillMaxHeight()
                            .background(spec.railColor),
                    )
                    Row(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .padding(4.dp),
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight()
                                .clip(RoundedCornerShape(3.dp))
                                .background(spec.cardColor)
                                .padding(3.dp),
                            contentAlignment = Alignment.CenterStart,
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
                                Box(Modifier.size(5.dp).background(spec.accentColor, CircleShape))
                                Box(Modifier.size(5.dp).background(spec.emeraldColor, CircleShape))
                            }
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
