package com.atlas.softpos.cvm

import android.content.Context
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.view.WindowManager
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.atlas.softpos.crypto.EmvCrypto
import kotlinx.coroutines.delay
import timber.log.Timber
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Online PIN Entry Component
 *
 * Secure PIN entry UI for EMV Online PIN verification.
 *
 * Security Features:
 * - Randomized keypad layout (optional)
 * - No PIN echo (dots only)
 * - Automatic clear after timeout
 * - Screenshot prevention (FLAG_SECURE)
 * - Haptic feedback instead of audio
 * - PIN block encryption before return
 * - Memory clearing after use
 * - Max attempts limiting
 *
 * PIN Block Formats Supported:
 * - ISO 9564-1 Format 0 (default)
 * - ISO 9564-1 Format 4 (AES)
 * - Visa Format (for Visa cards)
 */
class OnlinePinEntry(
    private val config: OnlinePinConfig = OnlinePinConfig()
) {
    /**
     * Show PIN entry dialog and collect encrypted PIN block
     *
     * @param pan Primary Account Number (for PIN block calculation)
     * @param amount Transaction amount (for display)
     * @param currencySymbol Currency symbol for display
     * @param pinEncryptionKey Working key for PIN encryption (TDES or AES)
     * @return PIN entry result with encrypted PIN block
     */
    @Composable
    fun PinEntryDialog(
        pan: String,
        amount: Long,
        currencySymbol: String = "$",
        pinEncryptionKey: ByteArray,
        onResult: (OnlinePinResult) -> Unit,
        onDismiss: () -> Unit
    ) {
        var pinDigits by remember { mutableStateOf("") }
        var attempts by remember { mutableStateOf(0) }
        var isProcessing by remember { mutableStateOf(false) }
        var errorMessage by remember { mutableStateOf<String?>(null) }
        var keypadLayout by remember { mutableStateOf(generateKeypadLayout(config.randomizeKeypad)) }

        val haptic = LocalHapticFeedback.current
        val context = LocalContext.current
        val view = LocalView.current

        // Auto-clear PIN after timeout
        LaunchedEffect(pinDigits) {
            if (pinDigits.isNotEmpty()) {
                delay(config.pinTimeoutMs)
                if (pinDigits.isNotEmpty()) {
                    pinDigits = ""
                    errorMessage = "PIN entry timed out"
                }
            }
        }

        // Set FLAG_SECURE to prevent screenshots
        DisposableEffect(Unit) {
            val window = (context as? android.app.Activity)?.window
            window?.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
            onDispose {
                window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }

        Dialog(
            onDismissRequest = {
                clearPinFromMemory(pinDigits)
                onDismiss()
            },
            properties = DialogProperties(
                dismissOnBackPress = true,
                dismissOnClickOutside = false,
                usePlatformDefaultWidth = false
            )
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth(0.9f)
                    .wrapContentHeight(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Header
                    Text(
                        text = "Enter PIN",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF1A1A1A)
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    // Amount display
                    Text(
                        text = "$currencySymbol${formatAmount(amount)}",
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF2196F3)
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    // Masked PAN
                    Text(
                        text = maskPan(pan),
                        fontSize = 14.sp,
                        color = Color.Gray
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    // PIN dots display
                    PinDotsDisplay(
                        length = pinDigits.length,
                        maxLength = config.maxPinLength,
                        hasError = errorMessage != null
                    )

                    // Error message
                    errorMessage?.let { error ->
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = error,
                            fontSize = 12.sp,
                            color = Color.Red
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    // Numeric keypad
                    NumericKeypad(
                        layout = keypadLayout,
                        enabled = !isProcessing && pinDigits.length < config.maxPinLength,
                        onDigitPressed = { digit ->
                            errorMessage = null
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            if (pinDigits.length < config.maxPinLength) {
                                pinDigits += digit
                            }
                        },
                        onBackspace = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            if (pinDigits.isNotEmpty()) {
                                pinDigits = pinDigits.dropLast(1)
                            }
                        },
                        onClear = {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            pinDigits = ""
                            errorMessage = null
                        }
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    // Action buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Cancel button
                        OutlinedButton(
                            onClick = {
                                clearPinFromMemory(pinDigits)
                                onResult(OnlinePinResult.Cancelled)
                            },
                            modifier = Modifier.weight(1f),
                            enabled = !isProcessing
                        ) {
                            Text("Cancel")
                        }

                        // Confirm button
                        Button(
                            onClick = {
                                if (pinDigits.length >= config.minPinLength) {
                                    isProcessing = true

                                    try {
                                        val pinBlock = buildPinBlock(
                                            pin = pinDigits,
                                            pan = pan,
                                            format = config.pinBlockFormat
                                        )

                                        val encryptedPinBlock = encryptPinBlock(
                                            pinBlock = pinBlock,
                                            key = pinEncryptionKey,
                                            useAes = config.pinBlockFormat == PinBlockFormat.ISO_FORMAT_4
                                        )

                                        clearPinFromMemory(pinDigits)
                                        pinDigits = ""

                                        onResult(OnlinePinResult.Success(
                                            encryptedPinBlock = encryptedPinBlock,
                                            pinBlockFormat = config.pinBlockFormat,
                                            ksn = null // KSN would come from DUKPT if used
                                        ))
                                    } catch (e: Exception) {
                                        Timber.e(e, "PIN encryption failed")
                                        attempts++
                                        isProcessing = false

                                        if (attempts >= config.maxAttempts) {
                                            clearPinFromMemory(pinDigits)
                                            onResult(OnlinePinResult.MaxAttemptsExceeded)
                                        } else {
                                            errorMessage = "PIN processing failed. Try again."
                                            pinDigits = ""
                                            if (config.randomizeKeypad) {
                                                keypadLayout = generateKeypadLayout(true)
                                            }
                                        }
                                    }
                                } else {
                                    errorMessage = "PIN must be at least ${config.minPinLength} digits"
                                }
                            },
                            modifier = Modifier.weight(1f),
                            enabled = !isProcessing && pinDigits.length >= config.minPinLength
                        ) {
                            if (isProcessing) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    color = Color.White,
                                    strokeWidth = 2.dp
                                )
                            } else {
                                Text("Confirm")
                            }
                        }
                    }

                    // Bypass option (if enabled)
                    if (config.allowBypass) {
                        Spacer(modifier = Modifier.height(12.dp))
                        TextButton(
                            onClick = {
                                clearPinFromMemory(pinDigits)
                                onResult(OnlinePinResult.Bypassed)
                            },
                            enabled = !isProcessing
                        ) {
                            Text(
                                text = "Skip PIN",
                                color = Color.Gray,
                                fontSize = 12.sp
                            )
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun PinDotsDisplay(
        length: Int,
        maxLength: Int,
        hasError: Boolean
    ) {
        val dotColor = if (hasError) Color.Red else Color(0xFF1A1A1A)
        val emptyDotColor = Color(0xFFE0E0E0)

        Row(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.height(24.dp)
        ) {
            repeat(maxLength) { index ->
                val isFilled = index < length

                Box(
                    modifier = Modifier
                        .size(16.dp)
                        .clip(CircleShape)
                        .background(if (isFilled) dotColor else Color.Transparent)
                        .border(2.dp, if (isFilled) dotColor else emptyDotColor, CircleShape)
                )
            }
        }
    }

    @Composable
    private fun NumericKeypad(
        layout: List<List<String>>,
        enabled: Boolean,
        onDigitPressed: (String) -> Unit,
        onBackspace: () -> Unit,
        onClear: () -> Unit
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            layout.forEachIndexed { rowIndex, row ->
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    row.forEach { key ->
                        KeypadButton(
                            key = key,
                            enabled = enabled || key == "⌫" || key == "C",
                            modifier = Modifier.weight(1f),
                            onClick = {
                                when (key) {
                                    "⌫" -> onBackspace()
                                    "C" -> onClear()
                                    "" -> { /* Empty space */ }
                                    else -> onDigitPressed(key)
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun KeypadButton(
        key: String,
        enabled: Boolean,
        modifier: Modifier = Modifier,
        onClick: () -> Unit
    ) {
        val backgroundColor = when {
            key.isEmpty() -> Color.Transparent
            key == "⌫" || key == "C" -> Color(0xFFF5F5F5)
            else -> Color(0xFFFAFAFA)
        }

        val textColor = when {
            key.isEmpty() -> Color.Transparent
            !enabled -> Color.LightGray
            key == "C" -> Color.Red
            else -> Color(0xFF1A1A1A)
        }

        Box(
            modifier = modifier
                .aspectRatio(1.5f)
                .clip(RoundedCornerShape(8.dp))
                .background(backgroundColor)
                .then(
                    if (key.isNotEmpty() && enabled) {
                        Modifier.clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = androidx.compose.material.ripple.rememberRipple(),
                            onClick = onClick
                        )
                    } else Modifier
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = key,
                fontSize = if (key == "⌫" || key == "C") 18.sp else 24.sp,
                fontWeight = FontWeight.Medium,
                color = textColor
            )
        }
    }

    /**
     * Build PIN Block according to specified format
     */
    private fun buildPinBlock(pin: String, pan: String, format: PinBlockFormat): ByteArray {
        return when (format) {
            PinBlockFormat.ISO_FORMAT_0 -> buildIsoFormat0PinBlock(pin, pan)
            PinBlockFormat.ISO_FORMAT_4 -> buildIsoFormat4PinBlock(pin, pan)
            PinBlockFormat.VISA -> buildVisaPinBlock(pin, pan)
        }
    }

    /**
     * ISO 9564-1 Format 0 (most common for EMV Online PIN)
     *
     * PIN Block = PIN Field XOR PAN Field
     *
     * PIN Field: 0 | PIN Length | PIN | F padding
     * PAN Field: 0000 | 12 rightmost digits of PAN (excluding check digit)
     */
    private fun buildIsoFormat0PinBlock(pin: String, pan: String): ByteArray {
        // Build PIN field: 0 | length | PIN | F padding
        val pinField = StringBuilder()
        pinField.append("0")
        pinField.append(pin.length.toString(16).uppercase())
        pinField.append(pin)
        while (pinField.length < 16) {
            pinField.append("F")
        }

        // Build PAN field: 0000 | 12 rightmost digits (excluding check digit)
        val panDigits = pan.replace("[^0-9]".toRegex(), "")
        val panForBlock = if (panDigits.length >= 13) {
            panDigits.substring(panDigits.length - 13, panDigits.length - 1)
        } else {
            panDigits.dropLast(1).padStart(12, '0')
        }
        val panField = "0000$panForBlock"

        // XOR the fields
        val pinBytes = pinField.toString().chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val panBytes = panField.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        return ByteArray(8) { i ->
            (pinBytes[i].toInt() xor panBytes[i].toInt()).toByte()
        }
    }

    /**
     * ISO 9564-1 Format 4 (AES-based)
     */
    private fun buildIsoFormat4PinBlock(pin: String, pan: String): ByteArray {
        // Format 4 uses a different structure for AES
        val pinField = StringBuilder()
        pinField.append("4")  // Format code
        pinField.append(pin.length.toString(16).uppercase())
        pinField.append(pin)

        // Pad with random digits
        val random = SecureRandom()
        while (pinField.length < 32) {
            pinField.append(random.nextInt(10).toString())
        }

        return pinField.toString().chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Visa PIN Block format
     */
    private fun buildVisaPinBlock(pin: String, pan: String): ByteArray {
        // Visa typically uses ISO Format 0
        return buildIsoFormat0PinBlock(pin, pan)
    }

    /**
     * Encrypt PIN block with working key
     */
    private fun encryptPinBlock(pinBlock: ByteArray, key: ByteArray, useAes: Boolean): ByteArray {
        return if (useAes) {
            // AES encryption for Format 4
            val cipher = Cipher.getInstance("AES/ECB/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            cipher.init(Cipher.ENCRYPT_MODE, keySpec)
            cipher.doFinal(pinBlock)
        } else {
            // Triple DES for Format 0
            EmvCrypto.encryptTripleDes(pinBlock, key)
        }
    }

    private fun generateKeypadLayout(randomize: Boolean): List<List<String>> {
        val digits = if (randomize) {
            (0..9).map { it.toString() }.shuffled(SecureRandom())
        } else {
            (1..9).map { it.toString() } + listOf("0")
        }

        return if (randomize) {
            listOf(
                digits.subList(0, 3),
                digits.subList(3, 6),
                digits.subList(6, 9),
                listOf("C", digits[9], "⌫")
            )
        } else {
            listOf(
                listOf("1", "2", "3"),
                listOf("4", "5", "6"),
                listOf("7", "8", "9"),
                listOf("C", "0", "⌫")
            )
        }
    }

    private fun formatAmount(amountCents: Long): String {
        val dollars = amountCents / 100
        val cents = amountCents % 100
        return "$dollars.${cents.toString().padStart(2, '0')}"
    }

    private fun maskPan(pan: String): String {
        val cleanPan = pan.replace("[^0-9]".toRegex(), "")
        if (cleanPan.length < 8) return cleanPan
        return "**** **** **** ${cleanPan.takeLast(4)}"
    }

    /**
     * Securely clear PIN from memory
     */
    private fun clearPinFromMemory(pin: String) {
        // Note: String is immutable in Kotlin/Java, so we can't truly clear it
        // In production, use CharArray and clear each element
        // This is a best-effort approach
        try {
            val field = String::class.java.getDeclaredField("value")
            field.isAccessible = true
            val chars = field.get(pin) as? CharArray
            chars?.fill('\u0000')
        } catch (e: Exception) {
            // Ignore - some JVM implementations may not allow this
        }
    }
}

/**
 * Online PIN Entry Configuration
 */
data class OnlinePinConfig(
    val minPinLength: Int = 4,
    val maxPinLength: Int = 6,
    val maxAttempts: Int = 3,
    val pinTimeoutMs: Long = 30_000,
    val randomizeKeypad: Boolean = false,
    val allowBypass: Boolean = false,
    val pinBlockFormat: PinBlockFormat = PinBlockFormat.ISO_FORMAT_0
)

/**
 * PIN Block Formats
 */
enum class PinBlockFormat {
    ISO_FORMAT_0,   // Most common - XOR with PAN
    ISO_FORMAT_4,   // AES-based
    VISA            // Visa specific (usually same as Format 0)
}

/**
 * Online PIN Entry Result
 */
sealed class OnlinePinResult {
    data class Success(
        val encryptedPinBlock: ByteArray,
        val pinBlockFormat: PinBlockFormat,
        val ksn: ByteArray? = null  // Key Serial Number for DUKPT
    ) : OnlinePinResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Success) return false
            return encryptedPinBlock.contentEquals(other.encryptedPinBlock) &&
                    pinBlockFormat == other.pinBlockFormat &&
                    (ksn?.contentEquals(other.ksn) ?: (other.ksn == null))
        }

        override fun hashCode(): Int {
            var result = encryptedPinBlock.contentHashCode()
            result = 31 * result + pinBlockFormat.hashCode()
            result = 31 * result + (ksn?.contentHashCode() ?: 0)
            return result
        }
    }
    object Cancelled : OnlinePinResult()
    object Bypassed : OnlinePinResult()
    object MaxAttemptsExceeded : OnlinePinResult()
    data class Error(val message: String) : OnlinePinResult()
}
