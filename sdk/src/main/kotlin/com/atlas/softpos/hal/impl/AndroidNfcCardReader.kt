package com.atlas.softpos.hal.impl

import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import com.atlas.softpos.hal.*
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Android NFC Card Reader Implementation
 *
 * Implements CardReaderInterface for Android SoftPOS using the Android NFC API.
 * This implementation works with the device's built-in NFC reader.
 */
class AndroidNfcCardReader : CardReaderInterface {

    private var config: CardReaderConfig? = null
    private var currentTag: Tag? = null
    private var isoDep: IsoDep? = null
    private var isPolling: Boolean = false
    private var isInitialized: Boolean = false

    // Callback for tag discovery (set by NFC foreground dispatch)
    private var tagCallback: ((Tag) -> Unit)? = null

    override suspend fun initialize(config: CardReaderConfig): Boolean {
        this.config = config
        isInitialized = true
        return true
    }

    override fun startPolling(timeout: Long): Flow<CardDetectionEvent> = callbackFlow {
        isPolling = true

        tagCallback = { tag ->
            val technology = detectTechnology(tag)
            val uid = tag.id
            val atr = getAtr(tag)
            val historicalBytes = getHistoricalBytes(tag)

            trySend(CardDetectionEvent.CardDetected(
                technology = technology,
                uid = uid,
                atr = atr,
                historicalBytes = historicalBytes
            ))

            currentTag = tag
        }

        // Timeout handling would be done by the Activity's NFC dispatch
        // The flow stays open until cancelled

        awaitClose {
            isPolling = false
            tagCallback = null
        }
    }

    override suspend fun stopPolling() {
        isPolling = false
        tagCallback = null
    }

    /**
     * Connect to the discovered tag
     * Must be called after receiving CardDetected event
     */
    suspend fun connect(tag: Tag): Boolean {
        currentTag = tag

        return suspendCancellableCoroutine { continuation ->
            try {
                val iso = IsoDep.get(tag)
                if (iso != null) {
                    iso.connect()
                    config?.let { cfg ->
                        iso.timeout = cfg.transceiveTimeoutMs.toInt()
                        if (cfg.extendedLengthEnabled && iso.isExtendedLengthApduSupported) {
                            // Extended length already supported
                        }
                    }
                    isoDep = iso
                    continuation.resume(true)
                } else {
                    continuation.resume(false)
                }
            } catch (e: Exception) {
                continuation.resumeWithException(
                    CardCommunicationException("Failed to connect to tag", e)
                )
            }
        }
    }

    override suspend fun transceive(apdu: ByteArray): ByteArray {
        val iso = isoDep ?: throw CardCommunicationException("Not connected to card")

        return suspendCancellableCoroutine { continuation ->
            try {
                val response = iso.transceive(apdu)
                continuation.resume(response)
            } catch (e: TagLostException) {
                continuation.resumeWithException(
                    com.atlas.softpos.hal.TagLostException("Tag was lost during transceive")
                )
            } catch (e: IOException) {
                val message = e.message ?: "Unknown error"
                when {
                    message.contains("tag", ignoreCase = true) &&
                            message.contains("lost", ignoreCase = true) -> {
                        continuation.resumeWithException(
                            com.atlas.softpos.hal.TagLostException(message)
                        )
                    }
                    message.contains("transceive", ignoreCase = true) -> {
                        continuation.resumeWithException(
                            TransceiveFailedException(message)
                        )
                    }
                    else -> {
                        continuation.resumeWithException(
                            CardCommunicationException(message, e)
                        )
                    }
                }
            } catch (e: Exception) {
                continuation.resumeWithException(
                    CardCommunicationException("Transceive failed: ${e.message}", e)
                )
            }
        }
    }

    override suspend fun isCardPresent(): Boolean {
        return try {
            isoDep?.isConnected == true
        } catch (e: Exception) {
            false
        }
    }

    override suspend fun disconnect(reset: Boolean) {
        try {
            isoDep?.close()
        } catch (e: Exception) {
            // Ignore close errors
        } finally {
            isoDep = null
            currentTag = null
        }
    }

    override fun getCapabilities(): CardReaderCapabilities {
        return CardReaderCapabilities(
            supportedTechnologies = setOf(
                CardTechnology.NFC_A,
                CardTechnology.NFC_B,
                CardTechnology.ISO_DEP
            ),
            extendedLengthSupported = isoDep?.isExtendedLengthApduSupported ?: true,
            maxCommandSize = isoDep?.maxTransceiveLength ?: 261,
            maxResponseSize = isoDep?.maxTransceiveLength ?: 261,
            collisionDetectionSupported = false,
            manufacturer = "Android",
            model = "Built-in NFC",
            firmwareVersion = android.os.Build.VERSION.SDK_INT.toString()
        )
    }

    override fun getStatus(): CardReaderStatus {
        return CardReaderStatus(
            isInitialized = isInitialized,
            isPolling = isPolling,
            isCardPresent = isoDep?.isConnected == true,
            activeSession = isoDep != null
        )
    }

    override suspend fun release() {
        disconnect(false)
        isInitialized = false
        config = null
    }

    /**
     * Handle tag discovered from NFC foreground dispatch
     * Called by the hosting Activity when a tag is discovered
     */
    fun onTagDiscovered(tag: Tag) {
        tagCallback?.invoke(tag)
    }

    private fun detectTechnology(tag: Tag): CardTechnology {
        val techList = tag.techList

        return when {
            techList.contains(IsoDep::class.java.name) -> CardTechnology.ISO_DEP
            techList.contains(NfcA::class.java.name) -> CardTechnology.NFC_A
            techList.contains(NfcB::class.java.name) -> CardTechnology.NFC_B
            else -> CardTechnology.NFC_A
        }
    }

    private fun getAtr(tag: Tag): ByteArray? {
        return try {
            val isoDep = IsoDep.get(tag)
            isoDep?.historicalBytes ?: isoDep?.hiLayerResponse
        } catch (e: Exception) {
            null
        }
    }

    private fun getHistoricalBytes(tag: Tag): ByteArray? {
        return try {
            IsoDep.get(tag)?.historicalBytes
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * CardTransceiver adapter for kernel compatibility
 *
 * Wraps AndroidNfcCardReader to provide the CardTransceiver interface
 * expected by the EMV kernels.
 */
class CardTransceiverAdapter(
    private val cardReader: CardReaderInterface
) {
    suspend fun transceive(command: ByteArray): ByteArray {
        return cardReader.transceive(command)
    }

    suspend fun isConnected(): Boolean {
        return cardReader.isCardPresent()
    }
}
