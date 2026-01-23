package com.atlas.ttp.demo.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Atlas Brand Colors
val AtlasPrimary = Color(0xFF1E3A5F)
val AtlasPrimaryDark = Color(0xFF0D1F33)
val AtlasSecondary = Color(0xFF4ECDC4)
val AtlasAccent = Color(0xFFFF6B6B)

// Status Colors
val Success = Color(0xFF4CAF50)
val Warning = Color(0xFFFF9800)
val Error = Color(0xFFF44336)
val Info = Color(0xFF2196F3)

// Light Theme Colors
private val LightColorScheme = lightColorScheme(
    primary = AtlasPrimary,
    onPrimary = Color.White,
    primaryContainer = AtlasPrimary.copy(alpha = 0.1f),
    onPrimaryContainer = AtlasPrimary,
    secondary = AtlasSecondary,
    onSecondary = Color.White,
    secondaryContainer = AtlasSecondary.copy(alpha = 0.1f),
    onSecondaryContainer = AtlasPrimaryDark,
    tertiary = AtlasAccent,
    onTertiary = Color.White,
    background = Color(0xFFF8F9FA),
    onBackground = Color(0xFF212121),
    surface = Color.White,
    onSurface = Color(0xFF212121),
    surfaceVariant = Color(0xFFF5F5F5),
    onSurfaceVariant = Color(0xFF757575),
    error = Error,
    onError = Color.White
)

// Dark Theme Colors
private val DarkColorScheme = darkColorScheme(
    primary = AtlasSecondary,
    onPrimary = AtlasPrimaryDark,
    primaryContainer = AtlasPrimary,
    onPrimaryContainer = Color.White,
    secondary = AtlasSecondary,
    onSecondary = AtlasPrimaryDark,
    secondaryContainer = AtlasPrimaryDark,
    onSecondaryContainer = AtlasSecondary,
    tertiary = AtlasAccent,
    onTertiary = Color.White,
    background = Color(0xFF121212),
    onBackground = Color.White,
    surface = Color(0xFF1E1E1E),
    onSurface = Color.White,
    surfaceVariant = Color(0xFF2C2C2C),
    onSurfaceVariant = Color(0xFFBBBBBB),
    error = Error,
    onError = Color.White
)

@Composable
fun TtpDemoTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
