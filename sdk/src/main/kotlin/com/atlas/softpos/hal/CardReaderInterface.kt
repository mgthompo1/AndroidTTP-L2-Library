package com.atlas.softpos.hal

import kotlinx.coroutines.flow.Flow

/**
 * Hardware Abstraction Layer - Card Reader Interface
 *
 * Abstracts NFC/contactless card reader operations for portability across:
 * - SoftPOS (Android NFC)
 * - PAX terminals
 * - Castles terminals
 * - Ingenico terminals
 * - Other payment terminals
 */
interface CardReaderInterface {

    /**
     * Initialize the card reader hardware
     *
     * @param config Reader configuration
     * @return true if initialization successful
     */
    suspend fun initialize(config: CardReaderConfig): Boolean

    /**
     * Start polling for card presentation
     *
     * @param timeout Timeout in milliseconds (0 = infinite)
     * @return Flow of card detection events
     */
    fun startPolling(timeout: Long = 0): Flow<CardDetectionEvent>

    /**
     * Stop polling for cards
     */
    suspend fun stopPolling()

    /**
     * Transmit APDU command to card
     *
     * @param apdu Command APDU bytes
     * @return Response APDU bytes
     * @throws CardCommunicationException on transmission failure
     */
    suspend fun transceive(apdu: ByteArray): ByteArray

    /**
     * Check if card is still present
     */
    suspend fun isCardPresent(): Boolean

    /**
     * Disconnect from card
     *
     * @param reset If true, reset the card before disconnecting
     */
    suspend fun disconnect(reset: Boolean = false)

    /**
     * Get reader capabilities
     */
    fun getCapabilities(): CardReaderCapabilities

    /**
     * Get current reader status
     */
    fun getStatus(): CardReaderStatus

    /**
     * Release reader resources
     */
    suspend fun release()
}

/**
 * Card reader configuration
 */
data class CardReaderConfig(
    /**
     * Technologies to enable (NFC-A, NFC-B, NFC-F, etc.)
     */
    val enabledTechnologies: Set<CardTechnology> = setOf(
        CardTechnology.NFC_A,
        CardTechnology.NFC_B
    ),

    /**
     * Polling interval in milliseconds
     */
    val pollingIntervalMs: Long = 100,

    /**
     * Maximum APDU response size
     */
    val maxApduSize: Int = 261,

    /**
     * Enable extended length APDUs
     */
    val extendedLengthEnabled: Boolean = true,

    /**
     * Transmission timeout in milliseconds
     */
    val transceiveTimeoutMs: Long = 2000,

    /**
     * Auto-reconnect on tag lost
     */
    val autoReconnect: Boolean = false,

    /**
     * Terminal-specific configuration
     */
    val terminalConfig: Map<String, Any> = emptyMap()
)

/**
 * Card detection event
 */
sealed class CardDetectionEvent {
    /**
     * Card detected and ready for communication
     */
    data class CardDetected(
        val technology: CardTechnology,
        val uid: ByteArray?,
        val atr: ByteArray?,
        val historicalBytes: ByteArray?
    ) : CardDetectionEvent() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CardDetected) return false
            return technology == other.technology &&
                    uid.contentEquals(other.uid) &&
                    atr.contentEquals(other.atr)
        }

        override fun hashCode(): Int {
            var result = technology.hashCode()
            result = 31 * result + (uid?.contentHashCode() ?: 0)
            result = 31 * result + (atr?.contentHashCode() ?: 0)
            return result
        }
    }

    /**
     * Card removed from field
     */
    object CardRemoved : CardDetectionEvent()

    /**
     * Multiple cards detected
     */
    data class CollisionDetected(val count: Int) : CardDetectionEvent()

    /**
     * Polling timeout reached
     */
    object Timeout : CardDetectionEvent()

    /**
     * Reader error occurred
     */
    data class Error(val exception: Throwable) : CardDetectionEvent()
}

/**
 * Card communication technologies
 */
enum class CardTechnology {
    NFC_A,      // ISO 14443-3A
    NFC_B,      // ISO 14443-3B
    NFC_F,      // JIS 6319-4
    NFC_V,      // ISO 15693
    ISO_DEP,    // ISO 14443-4
    MIFARE_CLASSIC,
    MIFARE_ULTRALIGHT
}

/**
 * Card reader capabilities
 */
data class CardReaderCapabilities(
    /**
     * Supported card technologies
     */
    val supportedTechnologies: Set<CardTechnology>,

    /**
     * Supports extended length APDUs
     */
    val extendedLengthSupported: Boolean,

    /**
     * Maximum APDU command size
     */
    val maxCommandSize: Int,

    /**
     * Maximum APDU response size
     */
    val maxResponseSize: Int,

    /**
     * Supports collision detection
     */
    val collisionDetectionSupported: Boolean,

    /**
     * Reader manufacturer
     */
    val manufacturer: String,

    /**
     * Reader model
     */
    val model: String,

    /**
     * Firmware version
     */
    val firmwareVersion: String
)

/**
 * Card reader status
 */
data class CardReaderStatus(
    val isInitialized: Boolean,
    val isPolling: Boolean,
    val isCardPresent: Boolean,
    val lastError: Throwable? = null,
    val activeSession: Boolean = false
)

/**
 * Card communication exception
 */
open class CardCommunicationException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

class TagLostException(message: String = "Tag was lost") : CardCommunicationException(message)
class TransceiveFailedException(message: String = "Transceive failed") : CardCommunicationException(message)
class CollisionException(message: String = "Card collision detected") : CardCommunicationException(message)
