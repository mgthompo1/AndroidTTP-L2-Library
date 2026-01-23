package com.atlas.ttp.demo.payment

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.kernel.common.SelectedApplication
import com.atlas.softpos.kernel.mastercard.MastercardContactlessKernel
import com.atlas.softpos.kernel.mastercard.MastercardKernelConfig
import com.atlas.softpos.kernel.mastercard.MastercardKernelOutcome
import com.atlas.softpos.kernel.mastercard.MastercardTransactionParams
import com.atlas.softpos.kernel.visa.VisaContactlessKernel
import com.atlas.softpos.kernel.visa.VisaKernelConfiguration
import com.atlas.softpos.kernel.visa.VisaKernelOutcome
import com.atlas.softpos.kernel.visa.VisaTransactionData
import com.atlas.softpos.nfc.CardTransceiver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import timber.log.Timber
import kotlin.coroutines.resume

/**
 * Clean wrapper around the Atlas SoftPOS SDK for payment processing.
 *
 * This class provides a simplified, coroutine-based API for processing
 * contactless payments using the SDK.
 */
class PaymentProcessor(private val activity: Activity) {

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private var intentFilters: Array<IntentFilter>? = null
    private var techLists: Array<Array<String>>? = null

    private var currentCallback: ((Tag) -> Unit)? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    init {
        setupNfc()
    }

    private fun setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(activity)

        if (nfcAdapter == null) {
            Timber.e("NFC not available on this device")
            return
        }

        pendingIntent = PendingIntent.getActivity(
            activity, 0,
            Intent(activity, activity.javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )

        val techDiscovered = IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)
        intentFilters = arrayOf(techDiscovered)
        techLists = arrayOf(arrayOf(IsoDep::class.java.name))

        Timber.d("NFC initialized successfully")
    }

    fun enableNfc() {
        nfcAdapter?.enableForegroundDispatch(activity, pendingIntent, intentFilters, techLists)
    }

    fun disableNfc() {
        nfcAdapter?.disableForegroundDispatch(activity)
    }

    fun isNfcEnabled(): Boolean = nfcAdapter?.isEnabled == true

    fun isNfcAvailable(): Boolean = nfcAdapter != null

    fun handleIntent(intent: Intent) {
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            @Suppress("DEPRECATION")
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            tag?.let { currentCallback?.invoke(it) }
        }
    }

    /**
     * Process a contactless payment.
     *
     * @param amountInCents The transaction amount in cents
     * @param onStatusUpdate Callback for status updates during processing
     * @return PaymentResult indicating the transaction outcome
     */
    suspend fun processPayment(
        amountInCents: Long,
        onStatusUpdate: (PaymentStatus) -> Unit
    ): PaymentResult = suspendCancellableCoroutine { continuation ->
        onStatusUpdate(PaymentStatus.WaitingForCard)

        currentCallback = callback@{ tag ->
            currentCallback = null
            val isoDep = IsoDep.get(tag)

            if (isoDep == null) {
                if (continuation.isActive) {
                    continuation.resume(PaymentResult.Error("Card does not support contactless"))
                }
                return@callback
            }

            // Process in background
            scope.launch {
                val result = processTag(isoDep, amountInCents, onStatusUpdate)
                if (continuation.isActive) {
                    continuation.resume(result)
                }
            }
        }

        continuation.invokeOnCancellation {
            currentCallback = null
        }
    }

    private suspend fun processTag(
        isoDep: IsoDep,
        amountInCents: Long,
        onStatusUpdate: (PaymentStatus) -> Unit
    ): PaymentResult = withContext(Dispatchers.IO) {
        try {
            onStatusUpdate(PaymentStatus.CardDetected)
            isoDep.connect()
            isoDep.timeout = 5000

            val transceiver = IsoDepTransceiver(isoDep)

            // Select PPSE
            onStatusUpdate(PaymentStatus.ReadingCard)
            val ppseResponse = selectPpse(transceiver)
                ?: return@withContext PaymentResult.Error("Failed to select PPSE")

            // Parse available AIDs
            val availableAids = parsePpseResponse(ppseResponse)
            if (availableAids.isEmpty()) {
                return@withContext PaymentResult.Error("No payment applications found")
            }

            // Select first available AID
            val candidateAid = availableAids.first()
            val selectResult = selectAid(transceiver, candidateAid)
            if (!selectResult.success) {
                return@withContext PaymentResult.Error("Failed to select payment application")
            }

            // Process based on card network
            onStatusUpdate(PaymentStatus.Processing)
            val result = when {
                isVisaAid(candidateAid) -> processVisaTransaction(
                    transceiver, candidateAid, selectResult.pdol, amountInCents
                )
                isMastercardAid(candidateAid) -> processMastercardTransaction(
                    transceiver, candidateAid, selectResult.pdol, amountInCents
                )
                else -> PaymentResult.Error("Unsupported card type")
            }

            isoDep.close()
            result
        } catch (e: Exception) {
            Timber.e(e, "Transaction error")
            PaymentResult.Error("Transaction failed: ${e.message}")
        }
    }

    private suspend fun processVisaTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        pdol: ByteArray?,
        amountInCents: Long
    ): PaymentResult {
        val config = VisaKernelConfiguration(
            terminalCountryCode = byteArrayOf(0x08, 0x40),
            transactionCurrencyCode = byteArrayOf(0x08, 0x40),
            // Terminal Capabilities for contactless SoftPOS:
            // Byte 1: 00 = No manual entry, no mag stripe (contactless only)
            // Byte 2: E0 = Plaintext PIN + Enciphered PIN online + Signature (+ CDCVM implied for contactless)
            // Byte 3: C8 = SDA + DDA + CDA supported
            terminalCapabilities = byteArrayOf(0x00.toByte(), 0xE0.toByte(), 0xC8.toByte()),
            terminalType = 0x22, // Attended, online only
            additionalTerminalCapabilities = byteArrayOf(
                // Byte 1: E0 = Cash, Goods, Services, Cashback
                // Byte 2: F0 = Numeric keys, command keys, function keys, print
                // Byte 3: C0 = Display cardholder, display merchant
                // Byte 4: 00
                // Byte 5: 01 = Code table 1
                0xE0.toByte(), 0xF0.toByte(), 0xC0.toByte(), 0x00, 0x01
            ),
            ifdSerialNumber = "TTPDemo001".toByteArray(),
            merchantCategoryCode = byteArrayOf(0x54, 0x11),
            terminalFloorLimit = 0,
            cvmRequiredLimit = 5000,  // $50 - requires CVM above this
            contactlessTransactionLimit = 25000  // $250 max contactless
        )

        val transactionData = VisaTransactionData(
            amount = amountInCents,
            transactionType = 0x00
        )

        val kernel = VisaContactlessKernel(transceiver, config)
        return when (val outcome = kernel.processTransaction(aid, pdol, transactionData)) {
            is VisaKernelOutcome.Approved -> PaymentResult.Approved(
                authCode = "000000",
                last4 = outcome.authData.maskedPan.takeLast(4),
                cardNetwork = "Visa",
                cryptogram = outcome.authData.applicationCryptogram
            )
            is VisaKernelOutcome.OnlineRequest -> {
                val auth = outcome.authData
                val iccString = buildWindcaveIccString(auth)
                Timber.i("========== WINDCAVE ICC STRING ==========")
                Timber.i(iccString)
                Timber.i("==========================================")
                Timber.i("9F26 (Cryptogram): ${auth.applicationCryptogram}")
                Timber.i("9F27 (CID): ${auth.cryptogramInformationData}")
                Timber.i("9F10 (IAD): ${auth.issuerApplicationData}")
                Timber.i("9F37 (UN): ${auth.unpredictableNumber}")
                Timber.i("9F36 (ATC): ${auth.atc}")
                Timber.i("95 (TVR): ${auth.terminalVerificationResults}")
                Timber.i("9A (Date): ${auth.transactionDate}")
                Timber.i("9C (Type): ${auth.transactionType}")
                Timber.i("9F02 (Amount): ${auth.amountAuthorized}")
                Timber.i("5F2A (Currency): ${auth.transactionCurrencyCode}")
                Timber.i("82 (AIP): ${auth.applicationInterchangeProfile}")
                Timber.i("9F1A (Country): ${auth.terminalCountryCode}")
                Timber.i("9F34 (CVM): ${auth.cvmResults}")
                Timber.i("9F33 (Capabilities): ${auth.terminalCapabilities}")
                Timber.i("9F35 (Terminal Type): ${auth.terminalType}")
                Timber.i("84 (AID): ${auth.aid}")
                Timber.i("5F34 (PAN Seq): ${auth.panSequenceNumber}")
                PaymentResult.OnlineRequired(
                    arqc = outcome.authData.applicationCryptogram,
                    last4 = outcome.authData.maskedPan.takeLast(4),
                    cardNetwork = "Visa",
                    iccData = iccString
                )
            }
            is VisaKernelOutcome.Declined -> PaymentResult.Declined(outcome.reason)
            is VisaKernelOutcome.TryAnotherInterface -> PaymentResult.Declined("Card requests contact interface")
            is VisaKernelOutcome.EndApplication -> PaymentResult.Error(outcome.reason)
            is VisaKernelOutcome.TryAgain -> PaymentResult.Error("Please try again: ${outcome.reason}")
        }
    }

    private suspend fun processMastercardTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        pdol: ByteArray?,
        amountInCents: Long
    ): PaymentResult {
        val config = MastercardKernelConfig()
        val transactionParams = MastercardTransactionParams(
            amount = amountInCents,
            type = 0x00
        )

        val application = SelectedApplication(
            aid = aid,
            label = "Mastercard",
            pdol = pdol,
            languagePreference = null,
            fciData = byteArrayOf()
        )

        val kernel = MastercardContactlessKernel(transceiver, config)
        return when (val outcome = kernel.processTransaction(application, transactionParams)) {
            is MastercardKernelOutcome.Approved -> PaymentResult.Approved(
                authCode = "000000",
                last4 = outcome.authorizationData.pan.takeLast(4),
                cardNetwork = "Mastercard",
                cryptogram = outcome.authorizationData.applicationCryptogram
            )
            is MastercardKernelOutcome.OnlineRequest -> PaymentResult.OnlineRequired(
                arqc = outcome.authorizationData.applicationCryptogram,
                last4 = outcome.authorizationData.pan.takeLast(4),
                cardNetwork = "Mastercard"
            )
            is MastercardKernelOutcome.Declined -> PaymentResult.Declined(outcome.reason)
            is MastercardKernelOutcome.TryAnotherInterface -> PaymentResult.Declined("Card requests contact interface: ${outcome.reason}")
            is MastercardKernelOutcome.EndApplication -> PaymentResult.Error(outcome.error.name)
        }
    }

    // PPSE and AID selection helpers
    private suspend fun selectPpse(transceiver: CardTransceiver): ByteArray? {
        val ppseAid = "2PAY.SYS.DDF01".toByteArray(Charsets.US_ASCII)
        val selectCommand = CommandApdu(
            cla = 0x00,
            ins = 0xA4.toByte(),
            p1 = 0x04,
            p2 = 0x00,
            data = ppseAid,
            le = 0
        )
        val response = transceiver.transceive(selectCommand)
        return if (response.sw1 == 0x90.toByte() && response.sw2 == 0x00.toByte()) {
            response.data
        } else null
    }

    private suspend fun selectAid(transceiver: CardTransceiver, aid: ByteArray): SelectAidResult {
        val selectCommand = CommandApdu(
            cla = 0x00,
            ins = 0xA4.toByte(),
            p1 = 0x04,
            p2 = 0x00,
            data = aid,
            le = 0
        )
        val response = transceiver.transceive(selectCommand)
        if (response.sw1 != 0x90.toByte() || response.sw2 != 0x00.toByte()) {
            return SelectAidResult(success = false, pdol = null)
        }
        val pdol = extractPdolFromFci(response.data)
        return SelectAidResult(success = true, pdol = pdol)
    }

    private fun parsePpseResponse(response: ByteArray): List<ByteArray> {
        val aids = mutableListOf<ByteArray>()
        var i = 0
        while (i < response.size - 2) {
            if (response[i] == 0x4F.toByte()) {
                val length = response[i + 1].toInt() and 0xFF
                if (i + 2 + length <= response.size) {
                    aids.add(response.copyOfRange(i + 2, i + 2 + length))
                }
                i += 2 + length
            } else {
                i++
            }
        }
        return aids
    }

    private fun extractPdolFromFci(fci: ByteArray): ByteArray? {
        val fciTemplate = findTlvTag(fci, 0x6F) ?: return null
        val fciProprietary = findTlvTag(fciTemplate, 0xA5) ?: return null
        return findTlvTag(fciProprietary, 0x9F38)
    }

    private fun findTlvTag(data: ByteArray, targetTag: Int): ByteArray? {
        var i = 0
        while (i < data.size) {
            var tag = data[i].toInt() and 0xFF
            i++
            if ((tag and 0x1F) == 0x1F && i < data.size) {
                tag = (tag shl 8) or (data[i].toInt() and 0xFF)
                i++
            }
            if (i >= data.size) break
            var length = data[i].toInt() and 0xFF
            i++
            if (length == 0x81 && i < data.size) {
                length = data[i].toInt() and 0xFF
                i++
            } else if (length == 0x82 && i + 1 < data.size) {
                length = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                i += 2
            }
            if (i + length > data.size) break
            if (tag == targetTag) {
                return data.copyOfRange(i, i + length)
            }
            i += length
        }
        return null
    }

    private fun isVisaAid(aid: ByteArray): Boolean {
        val visaPrefix = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x03)
        return aid.size >= 5 && aid.take(5).toByteArray().contentEquals(visaPrefix)
    }

    private fun isMastercardAid(aid: ByteArray): Boolean {
        val mcPrefix = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x04)
        return aid.size >= 5 && aid.take(5).toByteArray().contentEquals(mcPrefix)
    }

    private fun List<Byte>.toByteArray(): ByteArray = ByteArray(size) { this[it] }

    private data class SelectAidResult(val success: Boolean, val pdol: ByteArray?)

    /**
     * Build complete ICC TLV string for Windcave
     */
    private fun buildWindcaveIccString(auth: com.atlas.softpos.kernel.visa.VisaAuthorizationData): String {
        val sb = StringBuilder()

        fun addTlv(tag: String, value: String) {
            if (value.isNotEmpty()) {
                val cleanValue = value.uppercase().replace(" ", "")
                val lenBytes = cleanValue.length / 2
                sb.append(tag)
                sb.append(String.format("%02X", lenBytes))
                sb.append(cleanValue)
            }
        }

        // 9F26 - Application Cryptogram
        addTlv("9F26", auth.applicationCryptogram)
        // 9F27 - CID
        addTlv("9F27", auth.cryptogramInformationData)
        // 9F10 - IAD
        addTlv("9F10", auth.issuerApplicationData)
        // 9F37 - Unpredictable Number
        addTlv("9F37", auth.unpredictableNumber)
        // 9F36 - ATC
        addTlv("9F36", auth.atc.padStart(4, '0'))
        // 95 - TVR
        addTlv("95", auth.terminalVerificationResults.padStart(10, '0'))
        // 9A - Transaction Date
        addTlv("9A", auth.transactionDate)
        // 9C - Transaction Type
        addTlv("9C", auth.transactionType.padStart(2, '0'))
        // 9F02 - Amount Authorized
        addTlv("9F02", auth.amountAuthorized.padStart(12, '0'))
        // 5F2A - Transaction Currency Code
        addTlv("5F2A", auth.transactionCurrencyCode.padStart(4, '0'))
        // 82 - AIP
        addTlv("82", auth.applicationInterchangeProfile.padStart(4, '0'))
        // 9F1A - Terminal Country Code
        addTlv("9F1A", auth.terminalCountryCode.padStart(4, '0'))
        // 9F34 - CVM Results
        addTlv("9F34", auth.cvmResults.padStart(6, '0'))
        // 9F33 - Terminal Capabilities
        addTlv("9F33", auth.terminalCapabilities)
        // 9F35 - Terminal Type
        addTlv("9F35", auth.terminalType)
        // 9F1E - IFD Serial Number (8 bytes)
        addTlv("9F1E", "545450303031303031") // "TTP001001" in hex
        // 9F53 - Transaction Category Code
        addTlv("9F53", "52")
        // 84 - DF Name / AID
        addTlv("84", auth.aid)
        // 9F09 - Application Version Number
        addTlv("9F09", "0002")
        // 9F41 - Transaction Sequence Counter
        addTlv("9F41", "00000001")
        // 9F03 - Amount Other
        addTlv("9F03", auth.amountOther.padStart(12, '0'))
        // 5F34 - PAN Sequence Number
        val panSeq = auth.panSequenceNumber.ifEmpty { "01" }
        addTlv("5F34", panSeq.padStart(2, '0'))

        return sb.toString()
    }

    private class IsoDepTransceiver(private val isoDep: IsoDep) : CardTransceiver {
        override suspend fun transceive(command: CommandApdu): ResponseApdu {
            val response = isoDep.transceive(command.encode())
            return ResponseApdu.parse(response)
        }
    }
}

/**
 * Status updates during payment processing.
 */
sealed class PaymentStatus {
    object WaitingForCard : PaymentStatus()
    object CardDetected : PaymentStatus()
    object ReadingCard : PaymentStatus()
    object Processing : PaymentStatus()
}

/**
 * Result of a payment transaction.
 */
sealed class PaymentResult {
    data class Approved(
        val authCode: String,
        val last4: String,
        val cardNetwork: String,
        val cryptogram: String
    ) : PaymentResult()

    data class OnlineRequired(
        val arqc: String,
        val last4: String,
        val cardNetwork: String,
        val iccData: String = ""
    ) : PaymentResult()

    data class Declined(val reason: String) : PaymentResult()

    data class Error(val message: String) : PaymentResult()
}
