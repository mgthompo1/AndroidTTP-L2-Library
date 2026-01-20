package com.atlas.softpos.nfc

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.types.toHexString
import com.atlas.softpos.kernel.common.CardTransceiver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import timber.log.Timber
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * NFC Card Reader for Android
 *
 * Provides NFC communication with contactless payment cards using Android's
 * IsoDep (ISO 14443-4) interface.
 *
 * Usage:
 * ```
 * val reader = NfcCardReader(activity)
 * reader.startReading { tag ->
 *     val transceiver = reader.getTransceiver(tag)
 *     // Use transceiver with Entry Point and Kernels
 * }
 * ```
 */
class NfcCardReader(private val activity: Activity) {

    private val nfcAdapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)

    private var currentIsoDep: IsoDep? = null
    private var onTagDiscovered: ((Tag) -> Unit)? = null
    private var onError: ((NfcError) -> Unit)? = null

    /**
     * Check if NFC is available and enabled
     */
    fun checkNfcStatus(): NfcStatus {
        return when {
            nfcAdapter == null -> NfcStatus.NOT_AVAILABLE
            !nfcAdapter.isEnabled -> NfcStatus.DISABLED
            else -> NfcStatus.ENABLED
        }
    }

    /**
     * Start listening for NFC tags
     *
     * Call this in Activity.onResume()
     */
    fun startReading(
        onTagDiscovered: (Tag) -> Unit,
        onError: (NfcError) -> Unit = {}
    ) {
        this.onTagDiscovered = onTagDiscovered
        this.onError = onError

        val adapter = nfcAdapter ?: run {
            onError(NfcError.NotAvailable)
            return
        }

        if (!adapter.isEnabled) {
            onError(NfcError.Disabled)
            return
        }

        val flags = NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
                NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS

        val extras = Bundle().apply {
            // Set presence check delay (helps with some cards)
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250)
        }

        adapter.enableReaderMode(
            activity,
            { tag -> handleTagDiscovered(tag) },
            flags,
            extras
        )

        Timber.d("NFC reader mode enabled")
    }

    /**
     * Stop listening for NFC tags
     *
     * Call this in Activity.onPause()
     */
    fun stopReading() {
        nfcAdapter?.disableReaderMode(activity)
        disconnect()
        onTagDiscovered = null
        onError = null
        Timber.d("NFC reader mode disabled")
    }

    /**
     * Handle discovered tag
     */
    private fun handleTagDiscovered(tag: Tag) {
        Timber.d("Tag discovered: ${tag.techList.joinToString()}")

        // Check for IsoDep support (required for EMV)
        if (!tag.techList.contains("android.nfc.tech.IsoDep")) {
            onError?.invoke(NfcError.UnsupportedCard)
            return
        }

        onTagDiscovered?.invoke(tag)
    }

    /**
     * Create a CardTransceiver for the given tag
     */
    fun getTransceiver(tag: Tag): CardTransceiver {
        val isoDep = IsoDep.get(tag) ?: throw NfcException("Failed to get IsoDep from tag")
        return NfcTransceiver(isoDep)
    }

    /**
     * Connect to a tag and return a transceiver
     */
    suspend fun connect(tag: Tag): NfcTransceiver = withContext(Dispatchers.IO) {
        val isoDep = IsoDep.get(tag) ?: throw NfcException("Failed to get IsoDep from tag")

        isoDep.connect()
        isoDep.timeout = 5000  // 5 second timeout

        currentIsoDep = isoDep

        Timber.d("Connected to card. Max transceive length: ${isoDep.maxTransceiveLength}")
        Timber.d("Historical bytes: ${isoDep.historicalBytes?.toHexString() ?: "none"}")

        NfcTransceiver(isoDep)
    }

    /**
     * Disconnect from current card
     */
    fun disconnect() {
        try {
            currentIsoDep?.close()
        } catch (e: Exception) {
            Timber.e(e, "Error closing IsoDep")
        }
        currentIsoDep = null
    }

    /**
     * Check if currently connected to a card
     */
    fun isConnected(): Boolean = currentIsoDep?.isConnected == true
}

/**
 * NFC Transceiver implementation
 */
class NfcTransceiver(private val isoDep: IsoDep) : CardTransceiver {

    init {
        if (!isoDep.isConnected) {
            isoDep.connect()
        }
    }

    override suspend fun transceive(command: CommandApdu): ResponseApdu =
        withContext(Dispatchers.IO) {
            try {
                val commandBytes = command.encode()
                Timber.d(">>> ${commandBytes.toHexString()}")

                val responseBytes = isoDep.transceive(commandBytes)
                Timber.d("<<< ${responseBytes.toHexString()}")

                var response = ResponseApdu.fromBytes(responseBytes)

                // Handle GET RESPONSE for 61XX status
                while (response.hasMoreData) {
                    val getResponseCmd = CommandApdu(
                        cla = 0x00,
                        ins = 0xC0.toByte(),
                        p1 = 0x00,
                        p2 = 0x00,
                        le = response.additionalDataLength
                    )

                    Timber.d(">>> GET RESPONSE: ${getResponseCmd.encode().toHexString()}")
                    val additionalData = isoDep.transceive(getResponseCmd.encode())
                    Timber.d("<<< ${additionalData.toHexString()}")

                    val additionalResponse = ResponseApdu.fromBytes(additionalData)
                    response = ResponseApdu(
                        data = response.data + additionalResponse.data,
                        sw1 = additionalResponse.sw1,
                        sw2 = additionalResponse.sw2
                    )
                }

                response
            } catch (e: Exception) {
                Timber.e(e, "Transceive error")
                throw NfcException("Card communication failed: ${e.message}")
            }
        }

    /**
     * Check if card is still present
     */
    fun isCardPresent(): Boolean = isoDep.isConnected

    /**
     * Get maximum transceive length
     */
    fun getMaxTransceiveLength(): Int = isoDep.maxTransceiveLength

    /**
     * Get historical bytes (ATR)
     */
    fun getHistoricalBytes(): ByteArray? = isoDep.historicalBytes

    /**
     * Close connection
     */
    fun close() {
        try {
            isoDep.close()
        } catch (e: Exception) {
            Timber.e(e, "Error closing IsoDep connection")
        }
    }
}

/**
 * NFC Status
 */
enum class NfcStatus {
    ENABLED,
    DISABLED,
    NOT_AVAILABLE
}

/**
 * NFC Errors
 */
sealed class NfcError {
    object NotAvailable : NfcError()
    object Disabled : NfcError()
    object UnsupportedCard : NfcError()
    data class CommunicationError(val message: String) : NfcError()
    data class TagLost(val message: String) : NfcError()
}

/**
 * NFC Exception
 */
class NfcException(message: String) : Exception(message)

/**
 * Extension to wait for a tag with coroutines
 */
suspend fun NfcCardReader.awaitTag(): Tag = suspendCancellableCoroutine { continuation ->
    startReading(
        onTagDiscovered = { tag ->
            continuation.resume(tag)
        },
        onError = { error ->
            continuation.resumeWithException(
                NfcException("NFC Error: $error")
            )
        }
    )

    continuation.invokeOnCancellation {
        stopReading()
    }
}
