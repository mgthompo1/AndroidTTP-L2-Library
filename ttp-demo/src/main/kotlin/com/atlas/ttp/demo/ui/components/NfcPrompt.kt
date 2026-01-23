package com.atlas.ttp.demo.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Contactless
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.atlas.ttp.demo.payment.PaymentStatus
import com.atlas.ttp.demo.ui.theme.*

/**
 * Animated NFC tap prompt with status display.
 */
@Composable
fun NfcPrompt(
    status: PaymentStatus,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier.size(200.dp),
            contentAlignment = Alignment.Center
        ) {
            // Animated ripple circles
            if (status is PaymentStatus.WaitingForCard) {
                NfcRippleAnimation()
            }

            // Center icon
            val (icon, tint) = when (status) {
                is PaymentStatus.WaitingForCard -> Icons.Default.Contactless to AtlasPrimary
                is PaymentStatus.CardDetected -> Icons.Default.CreditCard to AtlasSecondary
                is PaymentStatus.ReadingCard -> Icons.Default.CreditCard to Warning
                is PaymentStatus.Processing -> Icons.Default.CreditCard to Info
            }

            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = tint
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Status text
        val statusText = when (status) {
            is PaymentStatus.WaitingForCard -> "Tap Card to Pay"
            is PaymentStatus.CardDetected -> "Card Detected"
            is PaymentStatus.ReadingCard -> "Reading Card..."
            is PaymentStatus.Processing -> "Processing Payment..."
        }

        Text(
            text = statusText,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Medium,
            textAlign = TextAlign.Center
        )

        // Subtitle
        val subtitle = when (status) {
            is PaymentStatus.WaitingForCard -> "Hold your card near the device"
            is PaymentStatus.CardDetected -> "Please hold card steady"
            is PaymentStatus.ReadingCard -> "Do not remove card"
            is PaymentStatus.Processing -> "Please wait..."
        }

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )

        // Progress indicator for processing states
        if (status is PaymentStatus.ReadingCard || status is PaymentStatus.Processing) {
            Spacer(modifier = Modifier.height(24.dp))
            LoadingDots()
        }
    }
}

@Composable
private fun LoadingDots() {
    val infiniteTransition = rememberInfiniteTransition(label = "loading_dots")

    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        repeat(3) { index ->
            val alpha by infiniteTransition.animateFloat(
                initialValue = 0.3f,
                targetValue = 1f,
                animationSpec = infiniteRepeatable(
                    animation = tween(600, delayMillis = index * 200, easing = LinearEasing),
                    repeatMode = RepeatMode.Reverse
                ),
                label = "dot_$index"
            )
            Canvas(
                modifier = Modifier
                    .size(10.dp)
                    .alpha(alpha)
            ) {
                drawCircle(color = AtlasSecondary)
            }
        }
    }
}

@Composable
private fun NfcRippleAnimation() {
    val infiniteTransition = rememberInfiniteTransition(label = "nfc_ripple")

    val ripples = (0..2).map { index ->
        val delay = index * 400
        val alpha by infiniteTransition.animateFloat(
            initialValue = 0.6f,
            targetValue = 0f,
            animationSpec = infiniteRepeatable(
                animation = tween(1200, delayMillis = delay, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "alpha_$index"
        )
        val scale by infiniteTransition.animateFloat(
            initialValue = 0.3f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(1200, delayMillis = delay, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "scale_$index"
        )
        alpha to scale
    }

    Canvas(modifier = Modifier.fillMaxSize()) {
        val centerX = size.width / 2
        val centerY = size.height / 2
        val maxRadius = size.minDimension / 2

        ripples.forEach { (alpha, scale) ->
            drawCircle(
                color = AtlasPrimary.copy(alpha = alpha),
                radius = maxRadius * scale,
                center = androidx.compose.ui.geometry.Offset(centerX, centerY),
                style = Stroke(width = 3.dp.toPx())
            )
        }
    }
}

/**
 * Result display component for payment outcomes.
 */
@Composable
fun PaymentResultDisplay(
    isSuccess: Boolean,
    title: String,
    message: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = if (isSuccess) Icons.Default.CheckCircle else Icons.Default.Error,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = if (isSuccess) Success else Error
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = title,
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = if (isSuccess) Success else Error,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = message,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
    }
}
