package com.atlas.softpos.hal

import kotlinx.coroutines.flow.Flow

/**
 * Hardware Abstraction Layer - PIN Pad Interface
 *
 * Abstracts PIN entry operations for portability across:
 * - SoftPOS (on-screen PIN entry)
 * - PAX terminals (hardware PIN pad)
 * - Castles terminals (hardware PIN pad)
 * - External PIN pads (Bluetooth/USB)
 */
interface PinPadInterface {

    /**
     * Initialize the PIN pad hardware
     *
     * @param config PIN pad configuration
     * @return true if initialization successful
     */
    suspend fun initialize(config: PinPadConfig): Boolean

    /**
     * Request PIN entry from cardholder
     *
     * @param request PIN entry request parameters
     * @return Flow of PIN entry events, completing with result
     */
    fun requestPin(request: PinEntryRequest): Flow<PinEntryEvent>

    /**
     * Cancel ongoing PIN entry
     */
    suspend fun cancelPinEntry()

    /**
     * Check if PIN pad is ready
     */
    fun isReady(): Boolean

    /**
     * Get PIN pad capabilities
     */
    fun getCapabilities(): PinPadCapabilities

    /**
     * Update display message
     *
     * @param message Message to display
     * @param line Display line (for multi-line displays)
     */
    suspend fun displayMessage(message: String, line: Int = 0)

    /**
     * Clear display
     */
    suspend fun clearDisplay()

    /**
     * Play beep/tone
     *
     * @param type Type of beep
     */
    suspend fun beep(type: BeepType = BeepType.KEY_PRESS)

    /**
     * Release PIN pad resources
     */
    suspend fun release()
}

/**
 * PIN pad configuration
 */
data class PinPadConfig(
    /**
     * Minimum PIN length
     */
    val minPinLength: Int = 4,

    /**
     * Maximum PIN length
     */
    val maxPinLength: Int = 12,

    /**
     * PIN entry timeout in seconds
     */
    val timeoutSeconds: Int = 30,

    /**
     * Enable bypass (no PIN) option
     */
    val bypassEnabled: Boolean = false,

    /**
     * Show PIN digits as they're entered (as asterisks)
     */
    val showPinDigits: Boolean = true,

    /**
     * Randomize keypad layout (SoftPOS security requirement)
     */
    val randomizeKeypad: Boolean = true,

    /**
     * Auto-submit when max length reached
     */
    val autoSubmit: Boolean = false,

    /**
     * PIN block format
     */
    val pinBlockFormat: PinBlockFormat = PinBlockFormat.ISO_FORMAT_0,

    /**
     * Terminal-specific configuration
     */
    val terminalConfig: Map<String, Any> = emptyMap()
)

/**
 * PIN entry request
 */
data class PinEntryRequest(
    /**
     * PAN for PIN block generation
     */
    val pan: String,

    /**
     * Transaction amount for display
     */
    val amount: Long,

    /**
     * Currency symbol for display
     */
    val currencySymbol: String = "$",

    /**
     * PIN encryption key (for software encryption)
     * For hardware PIN pads, this may be a key index
     */
    val encryptionKey: ByteArray? = null,

    /**
     * Key slot/index for hardware security module
     */
    val keySlot: Int? = null,

    /**
     * KSN for DUKPT (if using DUKPT key management)
     */
    val ksn: ByteArray? = null,

    /**
     * Custom prompt message
     */
    val promptMessage: String = "Enter PIN",

    /**
     * Allow bypass
     */
    val allowBypass: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PinEntryRequest) return false
        return pan == other.pan &&
                amount == other.amount &&
                currencySymbol == other.currencySymbol &&
                encryptionKey.contentEquals(other.encryptionKey) &&
                keySlot == other.keySlot
    }

    override fun hashCode(): Int {
        var result = pan.hashCode()
        result = 31 * result + amount.hashCode()
        result = 31 * result + (encryptionKey?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * PIN entry events
 */
sealed class PinEntryEvent {
    /**
     * PIN pad ready for input
     */
    object Ready : PinEntryEvent()

    /**
     * Key pressed (digit count updated)
     */
    data class KeyPressed(val digitCount: Int) : PinEntryEvent()

    /**
     * Key cleared (backspace)
     */
    data class KeyCleared(val digitCount: Int) : PinEntryEvent()

    /**
     * All digits cleared
     */
    object Cleared : PinEntryEvent()

    /**
     * PIN entry completed successfully
     */
    data class Completed(val result: PinEntryResult) : PinEntryEvent()

    /**
     * PIN entry cancelled by user
     */
    object Cancelled : PinEntryEvent()

    /**
     * PIN entry bypassed
     */
    object Bypassed : PinEntryEvent()

    /**
     * PIN entry timed out
     */
    object Timeout : PinEntryEvent()

    /**
     * Error occurred
     */
    data class Error(val exception: Throwable) : PinEntryEvent()
}

/**
 * PIN entry result
 */
data class PinEntryResult(
    /**
     * Encrypted PIN block
     */
    val pinBlock: ByteArray,

    /**
     * PIN block format used
     */
    val format: PinBlockFormat,

    /**
     * KSN (if DUKPT was used)
     */
    val ksn: ByteArray? = null,

    /**
     * Key slot used (for hardware encryption)
     */
    val keySlot: Int? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PinEntryResult) return false
        return pinBlock.contentEquals(other.pinBlock) &&
                format == other.format &&
                ksn.contentEquals(other.ksn)
    }

    override fun hashCode(): Int {
        var result = pinBlock.contentHashCode()
        result = 31 * result + format.hashCode()
        result = 31 * result + (ksn?.contentHashCode() ?: 0)
        return result
    }

    /**
     * Clear sensitive data
     */
    fun clear() {
        pinBlock.fill(0)
        ksn?.fill(0)
    }
}

/**
 * PIN block formats
 */
enum class PinBlockFormat {
    ISO_FORMAT_0,   // ISO 9564-1 Format 0 (XOR with PAN)
    ISO_FORMAT_1,   // ISO 9564-1 Format 1 (Random fill)
    ISO_FORMAT_2,   // ISO 9564-1 Format 2 (Chip cards)
    ISO_FORMAT_3,   // ISO 9564-1 Format 3 (Random + PAN)
    ISO_FORMAT_4,   // ISO 9564-1 Format 4 (AES-based)
    VISA_FORMAT,    // Visa PIN block format
    ANSI_FORMAT     // ANSI X9.8 format
}

/**
 * PIN pad capabilities
 */
data class PinPadCapabilities(
    /**
     * Hardware or software PIN pad
     */
    val type: PinPadType,

    /**
     * PCI PTS certified
     */
    val pciPtsCertified: Boolean,

    /**
     * Certification level (if certified)
     */
    val certificationLevel: String?,

    /**
     * Supports DUKPT
     */
    val dukptSupported: Boolean,

    /**
     * Supports TR-31 key blocks
     */
    val tr31Supported: Boolean,

    /**
     * Supported PIN block formats
     */
    val supportedFormats: Set<PinBlockFormat>,

    /**
     * Supports secure key injection
     */
    val secureKeyInjection: Boolean,

    /**
     * Number of key slots
     */
    val keySlotCount: Int,

    /**
     * Has dedicated display
     */
    val hasDisplay: Boolean,

    /**
     * Display lines
     */
    val displayLines: Int,

    /**
     * Display columns
     */
    val displayColumns: Int,

    /**
     * Manufacturer
     */
    val manufacturer: String,

    /**
     * Model
     */
    val model: String
)

/**
 * PIN pad types
 */
enum class PinPadType {
    SOFTWARE,           // On-screen PIN entry (SoftPOS)
    HARDWARE_INTERNAL,  // Built-in hardware PIN pad
    HARDWARE_EXTERNAL,  // External PIN pad (USB/Bluetooth)
    HSM_INTEGRATED      // HSM-integrated PIN pad
}

/**
 * Beep types
 */
enum class BeepType {
    KEY_PRESS,
    SUCCESS,
    ERROR,
    ALERT
}

/**
 * PIN pad exception
 */
open class PinPadException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

class PinEntryTimeoutException : PinPadException("PIN entry timed out")
class PinEntryCancelledException : PinPadException("PIN entry cancelled")
class PinEncryptionException(message: String) : PinPadException(message)
