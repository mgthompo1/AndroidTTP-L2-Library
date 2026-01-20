package com.atlas.softpos

import android.app.Activity
import android.nfc.Tag
import com.atlas.softpos.kernel.common.*
import com.atlas.softpos.kernel.visa.VisaContactlessKernel
import com.atlas.softpos.kernel.visa.VisaKernelConfig
import com.atlas.softpos.kernel.visa.VisaKernelOutcome
import com.atlas.softpos.kernel.visa.VisaTransactionParams
import com.atlas.softpos.kernel.mastercard.MastercardContactlessKernel
import com.atlas.softpos.kernel.mastercard.MastercardKernelConfig
import com.atlas.softpos.kernel.mastercard.MastercardKernelOutcome
import com.atlas.softpos.kernel.mastercard.MastercardTransactionParams
import com.atlas.softpos.kernel.amex.AmexKernel
import com.atlas.softpos.kernel.amex.AmexKernelConfig
import com.atlas.softpos.kernel.amex.AmexKernelResult
import com.atlas.softpos.kernel.amex.AmexTransaction
import com.atlas.softpos.kernel.discover.DiscoverKernel
import com.atlas.softpos.kernel.discover.DiscoverKernelConfig
import com.atlas.softpos.kernel.discover.DiscoverKernelResult
import com.atlas.softpos.kernel.discover.DiscoverTransaction
import com.atlas.softpos.kernel.jcb.JcbKernel
import com.atlas.softpos.kernel.jcb.JcbKernelConfig
import com.atlas.softpos.kernel.jcb.JcbKernelResult
import com.atlas.softpos.kernel.jcb.JcbTransaction
import com.atlas.softpos.kernel.unionpay.UnionPayKernel
import com.atlas.softpos.kernel.unionpay.UnionPayKernelConfig
import com.atlas.softpos.kernel.unionpay.UnionPayKernelResult
import com.atlas.softpos.kernel.unionpay.UnionPayTransaction
import com.atlas.softpos.nfc.NfcCardReader
import com.atlas.softpos.nfc.NfcStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * Atlas SoftPOS SDK
 *
 * Main entry point for contactless payment acceptance supporting all major card networks:
 * - Visa (payWave / qVSDC)
 * - Mastercard (PayPass / M/Chip)
 * - American Express (ExpressPay)
 * - Discover (D-PAS)
 * - JCB (J/Speedy)
 * - UnionPay (QuickPass / qPBOC)
 *
 * ## Usage
 *
 * ```kotlin
 * // Initialize
 * val softPos = AtlasSoftPos.Builder(activity)
 *     .setMerchantId("MERCHANT123")
 *     .setTerminalId("TERM001")
 *     .build()
 *
 * // Start accepting payments
 * softPos.startTransaction(
 *     amount = 1000,  // $10.00
 *     callback = object : TransactionCallback {
 *         override fun onWaitingForCard() { showUI("Tap card") }
 *         override fun onCardDetected() { showUI("Processing...") }
 *         override fun onResult(result: TransactionResult) {
 *             when (result) {
 *                 is TransactionResult.OnlineRequired -> {
 *                     // Send to acquirer for authorization
 *                     sendToAcquirer(result.authorizationData)
 *                 }
 *                 is TransactionResult.Approved -> showUI("Approved")
 *                 is TransactionResult.Declined -> showUI("Declined")
 *                 is TransactionResult.Error -> showUI("Error")
 *             }
 *         }
 *         override fun onError(error: TransactionError) { handleError(error) }
 *         override fun onCancelled() { showUI("Cancelled") }
 *     }
 * )
 * ```
 */
class AtlasSoftPos private constructor(
    private val activity: Activity,
    private val config: SoftPosConfig
) {
    private val nfcReader = NfcCardReader(activity)

    private val entryPointConfig = EntryPointConfiguration(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        additionalTerminalCapabilities = config.additionalTerminalCapabilities
    )

    // Kernel configurations
    private val visaConfig = VisaKernelConfig(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        additionalTerminalCapabilities = config.additionalTerminalCapabilities,
        terminalCountryCode = config.countryCode,
        transactionCurrencyCode = config.currencyCode,
        merchantCategoryCode = config.mcc,
        merchantIdentifier = config.merchantId,
        terminalIdentification = config.terminalId,
        acquirerIdentifier = config.acquirerId,
        cvmRequiredLimit = config.cvmRequiredLimit,
        contactlessTransactionLimit = config.contactlessTransactionLimit
    )

    private val mastercardConfig = MastercardKernelConfig(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        additionalTerminalCapabilities = config.additionalTerminalCapabilities,
        terminalCountryCode = config.countryCode,
        transactionCurrencyCode = config.currencyCode,
        merchantCategoryCode = config.mcc,
        merchantIdentifier = config.merchantId,
        terminalIdentification = config.terminalId,
        acquirerIdentifier = config.acquirerId,
        cvmRequiredLimit = config.cvmRequiredLimit,
        contactlessTransactionLimitOnDeviceCvm = config.contactlessTransactionLimit,
        contactlessTransactionLimitNoCvm = config.contactlessTransactionLimit / 4
    )

    private val amexConfig = AmexKernelConfig(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        terminalCountryCode = config.countryCode,
        transactionCurrencyCode = config.currencyCode,
        merchantIdentifier = config.merchantId,
        terminalIdentification = config.terminalId,
        cvmRequiredLimit = config.cvmRequiredLimit,
        contactlessTransactionLimit = config.contactlessTransactionLimit
    )

    private val discoverConfig = DiscoverKernelConfig(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        terminalCountryCode = config.countryCode,
        transactionCurrencyCode = config.currencyCode,
        merchantIdentifier = config.merchantId,
        terminalIdentification = config.terminalId,
        cvmRequiredLimit = config.cvmRequiredLimit,
        contactlessTransactionLimit = config.contactlessTransactionLimit
    )

    private val jcbConfig = JcbKernelConfig(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        terminalCountryCode = config.countryCode,
        transactionCurrencyCode = config.currencyCode,
        merchantIdentifier = config.merchantId,
        terminalIdentification = config.terminalId,
        cvmRequiredLimit = config.cvmRequiredLimit,
        contactlessTransactionLimit = config.contactlessTransactionLimit
    )

    private val unionPayConfig = UnionPayKernelConfig(
        terminalType = config.terminalType,
        terminalCapabilities = config.terminalCapabilities,
        additionalTerminalCapabilities = config.additionalTerminalCapabilities,
        terminalCountryCode = config.countryCode,
        transactionCurrencyCode = config.currencyCode,
        merchantIdentifier = config.merchantId,
        terminalIdentification = config.terminalId,
        cvmRequiredLimit = config.cvmRequiredLimit,
        contactlessTransactionLimit = config.contactlessTransactionLimit
    )

    // Transaction state
    private var isTransactionInProgress = false
    private var currentTransactionCallback: TransactionCallback? = null

    /**
     * Check NFC availability
     */
    fun checkNfc(): NfcStatus = nfcReader.checkNfcStatus()

    /**
     * Get supported card networks
     */
    fun getSupportedNetworks(): List<CardNetwork> = listOf(
        CardNetwork.VISA,
        CardNetwork.MASTERCARD,
        CardNetwork.AMEX,
        CardNetwork.DISCOVER,
        CardNetwork.JCB,
        CardNetwork.UNIONPAY
    )

    /**
     * Start a new transaction
     *
     * @param amount Transaction amount in smallest currency unit (cents)
     * @param type Transaction type (default: Purchase)
     * @param cashbackAmount Optional cashback amount
     * @param callback Transaction result callback
     */
    fun startTransaction(
        amount: Long,
        type: TransactionType = TransactionType.PURCHASE,
        cashbackAmount: Long? = null,
        callback: TransactionCallback
    ) {
        if (isTransactionInProgress) {
            callback.onError(TransactionError.TransactionInProgress)
            return
        }

        when (checkNfc()) {
            NfcStatus.NOT_AVAILABLE -> {
                callback.onError(TransactionError.NfcNotAvailable)
                return
            }
            NfcStatus.DISABLED -> {
                callback.onError(TransactionError.NfcDisabled)
                return
            }
            NfcStatus.ENABLED -> { /* Continue */ }
        }

        isTransactionInProgress = true
        currentTransactionCallback = callback

        callback.onWaitingForCard()

        nfcReader.startReading(
            onTagDiscovered = { tag ->
                callback.onCardDetected()
                processTag(tag, amount, type, cashbackAmount, callback)
            },
            onError = { error ->
                isTransactionInProgress = false
                callback.onError(TransactionError.NfcError(error.toString()))
            }
        )
    }

    /**
     * Cancel the current transaction
     */
    fun cancelTransaction() {
        nfcReader.stopReading()
        isTransactionInProgress = false
        currentTransactionCallback?.onCancelled()
        currentTransactionCallback = null
    }

    /**
     * Call in Activity.onResume()
     */
    fun onResume() {
        if (isTransactionInProgress) {
            currentTransactionCallback?.let { callback ->
                nfcReader.startReading(
                    onTagDiscovered = { /* Already handled */ },
                    onError = { error ->
                        callback.onError(TransactionError.NfcError(error.toString()))
                    }
                )
            }
        }
    }

    /**
     * Call in Activity.onPause()
     */
    fun onPause() {
        nfcReader.stopReading()
    }

    /**
     * Process a discovered tag
     */
    private fun processTag(
        tag: Tag,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?,
        callback: TransactionCallback
    ) {
        kotlinx.coroutines.GlobalScope.launch(Dispatchers.Main) {
            try {
                val result = withContext(Dispatchers.IO) {
                    processTransaction(tag, amount, type, cashbackAmount)
                }
                isTransactionInProgress = false
                callback.onResult(result)
            } catch (e: Exception) {
                isTransactionInProgress = false
                Timber.e(e, "Transaction processing error")
                callback.onError(TransactionError.ProcessingError(e.message ?: "Unknown error"))
            } finally {
                nfcReader.stopReading()
            }
        }
    }

    /**
     * Process the full transaction
     */
    private suspend fun processTransaction(
        tag: Tag,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val transceiver = nfcReader.connect(tag)

        try {
            // Entry Point - Application Selection
            val entryPoint = EntryPoint(transceiver, entryPointConfig)
            val entryPointResult = entryPoint.start()

            when (entryPointResult) {
                is EntryPointResult.Error -> {
                    return TransactionResult.Error(entryPointResult.message)
                }
                is EntryPointResult.NoSupportedApplications -> {
                    return TransactionResult.Error("No supported payment applications on card")
                }
                is EntryPointResult.ApplicationSelectionFailed -> {
                    return TransactionResult.Error("Application selection failed")
                }
                is EntryPointResult.Success -> {
                    Timber.d("Selected: ${entryPointResult.selectedApplication.label}")
                    Timber.d("Kernel: ${entryPointResult.kernelId}")

                    // Activate appropriate kernel
                    return when (entryPointResult.kernelId) {
                        KernelId.VISA -> processVisaTransaction(
                            transceiver, entryPointResult.selectedApplication,
                            amount, type, cashbackAmount
                        )

                        KernelId.MASTERCARD -> processMastercardTransaction(
                            transceiver, entryPointResult.selectedApplication,
                            amount, type, cashbackAmount
                        )

                        KernelId.AMEX -> processAmexTransaction(
                            transceiver, entryPointResult.selectedApplication,
                            amount, type, cashbackAmount
                        )

                        KernelId.DISCOVER -> processDiscoverTransaction(
                            transceiver, entryPointResult.selectedApplication,
                            amount, type, cashbackAmount
                        )

                        KernelId.JCB -> processJcbTransaction(
                            transceiver, entryPointResult.selectedApplication,
                            amount, type, cashbackAmount
                        )

                        KernelId.UNIONPAY -> processUnionPayTransaction(
                            transceiver, entryPointResult.selectedApplication,
                            amount, type, cashbackAmount
                        )

                        KernelId.INTERAC -> {
                            TransactionResult.Error("Interac not yet supported")
                        }

                        KernelId.UNKNOWN -> {
                            TransactionResult.Error("Unknown card type")
                        }
                    }
                }
            }
        } finally {
            transceiver.close()
        }
    }

    // Visa transaction processing
    private suspend fun processVisaTransaction(
        transceiver: CardTransceiver,
        application: SelectedApplication,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val kernel = VisaContactlessKernel(transceiver, visaConfig)
        val transaction = VisaTransactionParams(amount, cashbackAmount, type.code)

        return when (val result = kernel.processTransaction(application, transaction)) {
            is VisaKernelOutcome.OnlineRequest -> {
                TransactionResult.OnlineRequired(
                    cardNetwork = CardNetwork.VISA,
                    authorizationData = AuthorizationData.fromVisaNew(result.authorizationData)
                )
            }
            is VisaKernelOutcome.Approved -> TransactionResult.Approved(CardNetwork.VISA)
            is VisaKernelOutcome.Declined -> TransactionResult.Declined(CardNetwork.VISA, result.reason)
            is VisaKernelOutcome.TryAnotherInterface -> TransactionResult.Error("Try another interface: ${result.reason}")
            is VisaKernelOutcome.EndApplication -> TransactionResult.Error("Error: ${result.error}")
        }
    }

    // Mastercard transaction processing
    private suspend fun processMastercardTransaction(
        transceiver: CardTransceiver,
        application: SelectedApplication,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val kernel = MastercardContactlessKernel(transceiver, mastercardConfig)
        val transaction = MastercardTransactionParams(amount, cashbackAmount, type.code)

        return when (val result = kernel.processTransaction(application, transaction)) {
            is MastercardKernelOutcome.OnlineRequest -> {
                TransactionResult.OnlineRequired(
                    cardNetwork = CardNetwork.MASTERCARD,
                    authorizationData = AuthorizationData.fromMastercardNew(result.authorizationData)
                )
            }
            is MastercardKernelOutcome.Approved -> TransactionResult.Approved(CardNetwork.MASTERCARD)
            is MastercardKernelOutcome.Declined -> TransactionResult.Declined(CardNetwork.MASTERCARD, result.reason)
            is MastercardKernelOutcome.TryAnotherInterface -> TransactionResult.Error("Try another interface: ${result.reason}")
            is MastercardKernelOutcome.EndApplication -> TransactionResult.Error("Error: ${result.error}")
        }
    }

    // Amex transaction processing
    private suspend fun processAmexTransaction(
        transceiver: CardTransceiver,
        application: SelectedApplication,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val kernel = AmexKernel(transceiver, amexConfig)
        val transaction = AmexTransaction(amount, cashbackAmount, type.code)

        return when (val result = kernel.processTransaction(application, transaction)) {
            is AmexKernelResult.OnlineRequired -> {
                TransactionResult.OnlineRequired(
                    cardNetwork = CardNetwork.AMEX,
                    authorizationData = AuthorizationData.fromAmex(result.authRequest)
                )
            }
            is AmexKernelResult.Approved -> TransactionResult.Approved(CardNetwork.AMEX)
            is AmexKernelResult.Declined -> TransactionResult.Declined(CardNetwork.AMEX, result.reason)
            is AmexKernelResult.Error -> TransactionResult.Error(result.message)
        }
    }

    // Discover transaction processing
    private suspend fun processDiscoverTransaction(
        transceiver: CardTransceiver,
        application: SelectedApplication,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val kernel = DiscoverKernel(transceiver, discoverConfig)
        val transaction = DiscoverTransaction(amount, cashbackAmount, type.code)

        return when (val result = kernel.processTransaction(application, transaction)) {
            is DiscoverKernelResult.OnlineRequired -> {
                TransactionResult.OnlineRequired(
                    cardNetwork = CardNetwork.DISCOVER,
                    authorizationData = AuthorizationData.fromDiscover(result.authRequest)
                )
            }
            is DiscoverKernelResult.Approved -> TransactionResult.Approved(CardNetwork.DISCOVER)
            is DiscoverKernelResult.Declined -> TransactionResult.Declined(CardNetwork.DISCOVER, result.reason)
            is DiscoverKernelResult.Error -> TransactionResult.Error(result.message)
        }
    }

    // JCB transaction processing
    private suspend fun processJcbTransaction(
        transceiver: CardTransceiver,
        application: SelectedApplication,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val kernel = JcbKernel(transceiver, jcbConfig)
        val transaction = JcbTransaction(amount, cashbackAmount, type.code)

        return when (val result = kernel.processTransaction(application, transaction)) {
            is JcbKernelResult.OnlineRequired -> {
                TransactionResult.OnlineRequired(
                    cardNetwork = CardNetwork.JCB,
                    authorizationData = AuthorizationData.fromJcb(result.authRequest)
                )
            }
            is JcbKernelResult.Approved -> TransactionResult.Approved(CardNetwork.JCB)
            is JcbKernelResult.Declined -> TransactionResult.Declined(CardNetwork.JCB, result.reason)
            is JcbKernelResult.Error -> TransactionResult.Error(result.message)
        }
    }

    // UnionPay transaction processing
    private suspend fun processUnionPayTransaction(
        transceiver: CardTransceiver,
        application: SelectedApplication,
        amount: Long,
        type: TransactionType,
        cashbackAmount: Long?
    ): TransactionResult {
        val kernel = UnionPayKernel(transceiver, unionPayConfig)
        val transaction = UnionPayTransaction(amount, cashbackAmount, type.code)

        return when (val result = kernel.processTransaction(application, transaction)) {
            is UnionPayKernelResult.OnlineRequired -> {
                TransactionResult.OnlineRequired(
                    cardNetwork = CardNetwork.UNIONPAY,
                    authorizationData = AuthorizationData.fromUnionPay(result.authRequest)
                )
            }
            is UnionPayKernelResult.Approved -> TransactionResult.Approved(CardNetwork.UNIONPAY)
            is UnionPayKernelResult.Declined -> TransactionResult.Declined(CardNetwork.UNIONPAY, result.reason)
            is UnionPayKernelResult.Error -> TransactionResult.Error(result.message)
        }
    }

    /**
     * Builder for AtlasSoftPos
     */
    class Builder(private val activity: Activity) {
        private var merchantId: String = "ATLASMERCHANT"
        private var terminalId: String = "ATLAS001"
        private var countryCode: ByteArray = byteArrayOf(0x08, 0x40)  // USA
        private var currencyCode: ByteArray = byteArrayOf(0x08, 0x40)  // USD
        private var mcc: ByteArray = byteArrayOf(0x00, 0x00)
        private var acquirerId: ByteArray = byteArrayOf(0, 0, 0, 0, 0, 1)
        private var cvmRequiredLimit: Long = 2500  // $25.00
        private var contactlessTransactionLimit: Long = 100000  // $1000.00
        private var terminalType: Byte = 0x22
        private var terminalCapabilities: ByteArray = byteArrayOf(
            0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()
        )
        private var additionalTerminalCapabilities: ByteArray = byteArrayOf(
            0xFF.toByte(), 0x00, 0xF0.toByte(), 0xA0.toByte(), 0x01
        )

        fun setMerchantId(merchantId: String) = apply { this.merchantId = merchantId }
        fun setTerminalId(terminalId: String) = apply { this.terminalId = terminalId }
        fun setCountryCode(code: ByteArray) = apply { this.countryCode = code }
        fun setCurrencyCode(code: ByteArray) = apply { this.currencyCode = code }
        fun setMcc(mcc: ByteArray) = apply { this.mcc = mcc }
        fun setAcquirerId(id: ByteArray) = apply { this.acquirerId = id }
        fun setCvmRequiredLimit(limit: Long) = apply { this.cvmRequiredLimit = limit }
        fun setContactlessTransactionLimit(limit: Long) = apply { this.contactlessTransactionLimit = limit }
        fun setTerminalType(type: Byte) = apply { this.terminalType = type }
        fun setTerminalCapabilities(caps: ByteArray) = apply { this.terminalCapabilities = caps }
        fun setAdditionalTerminalCapabilities(caps: ByteArray) = apply { this.additionalTerminalCapabilities = caps }

        fun build(): AtlasSoftPos {
            val config = SoftPosConfig(
                merchantId = merchantId,
                terminalId = terminalId,
                countryCode = countryCode,
                currencyCode = currencyCode,
                mcc = mcc,
                acquirerId = acquirerId,
                cvmRequiredLimit = cvmRequiredLimit,
                contactlessTransactionLimit = contactlessTransactionLimit,
                terminalType = terminalType,
                terminalCapabilities = terminalCapabilities,
                additionalTerminalCapabilities = additionalTerminalCapabilities
            )
            return AtlasSoftPos(activity, config)
        }
    }
}

/**
 * SDK Configuration
 */
data class SoftPosConfig(
    val merchantId: String,
    val terminalId: String,
    val countryCode: ByteArray,
    val currencyCode: ByteArray,
    val mcc: ByteArray,
    val acquirerId: ByteArray,
    val cvmRequiredLimit: Long,
    val contactlessTransactionLimit: Long,
    val terminalType: Byte,
    val terminalCapabilities: ByteArray,
    val additionalTerminalCapabilities: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SoftPosConfig) return false
        return merchantId == other.merchantId && terminalId == other.terminalId
    }

    override fun hashCode(): Int {
        var result = merchantId.hashCode()
        result = 31 * result + terminalId.hashCode()
        return result
    }
}

/**
 * Supported card networks
 */
enum class CardNetwork(val displayName: String) {
    VISA("Visa"),
    MASTERCARD("Mastercard"),
    AMEX("American Express"),
    DISCOVER("Discover"),
    JCB("JCB"),
    UNIONPAY("UnionPay"),
    INTERAC("Interac")
}

/**
 * Transaction types
 */
enum class TransactionType(val code: Byte) {
    PURCHASE(0x00),
    CASH_ADVANCE(0x01),
    PURCHASE_WITH_CASHBACK(0x09),
    REFUND(0x20),
    BALANCE_INQUIRY(0x31)
}

/**
 * Transaction callback interface
 */
interface TransactionCallback {
    fun onWaitingForCard()
    fun onCardDetected()
    fun onResult(result: TransactionResult)
    fun onError(error: TransactionError)
    fun onCancelled()
}

/**
 * Transaction result
 */
sealed class TransactionResult {
    data class OnlineRequired(
        val cardNetwork: CardNetwork,
        val authorizationData: AuthorizationData
    ) : TransactionResult()

    data class Approved(val cardNetwork: CardNetwork) : TransactionResult()

    data class Declined(val cardNetwork: CardNetwork, val reason: String) : TransactionResult()

    data class Error(val message: String) : TransactionResult()
}

/**
 * Unified authorization data for all card networks
 */
data class AuthorizationData(
    val cardNetwork: CardNetwork,
    val pan: String,
    val maskedPan: String,
    val expiryDate: String,
    val track2Equivalent: String,
    val panSequenceNumber: String,
    val applicationCryptogram: String,
    val cryptogramType: String,  // "ARQC", "TC", "AAC"
    val atc: String,
    val issuerApplicationData: String,
    val terminalVerificationResults: String,
    val cvmResults: String,
    val amountAuthorized: String,
    val transactionDate: String,
    val transactionType: String,
    val unpredictableNumber: String,
    val aip: String,
    val aid: String,
    val cardholderName: String,
    val rawData: String
) {
    companion object {
        fun fromVisaNew(req: com.atlas.softpos.kernel.visa.VisaAuthorizationData) = AuthorizationData(
            cardNetwork = CardNetwork.VISA,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = req.cryptogramType.name,
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.tvr,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName ?: "",
            rawData = ""
        )

        fun fromMastercardNew(req: com.atlas.softpos.kernel.mastercard.MastercardAuthorizationData) = AuthorizationData(
            cardNetwork = CardNetwork.MASTERCARD,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = req.cryptogramType.name,
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.tvr,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName ?: "",
            rawData = ""
        )

        fun fromVisa(req: com.atlas.softpos.kernel.visa.AuthorizationRequest) = AuthorizationData(
            cardNetwork = CardNetwork.VISA,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = getCryptogramType(req.cryptogramInfoData),
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.terminalVerificationResults,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName,
            rawData = req.rawCryptogramData
        )

        fun fromMastercard(req: com.atlas.softpos.kernel.mastercard.MastercardAuthorizationRequest) = AuthorizationData(
            cardNetwork = CardNetwork.MASTERCARD,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = getCryptogramType(req.cryptogramInfoData),
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.terminalVerificationResults,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName,
            rawData = req.rawCryptogramData
        )

        fun fromAmex(req: com.atlas.softpos.kernel.amex.AmexAuthorizationRequest) = AuthorizationData(
            cardNetwork = CardNetwork.AMEX,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = getCryptogramType(req.cryptogramInfoData),
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.terminalVerificationResults,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName,
            rawData = req.rawCryptogramData
        )

        fun fromDiscover(req: com.atlas.softpos.kernel.discover.DiscoverAuthorizationRequest) = AuthorizationData(
            cardNetwork = CardNetwork.DISCOVER,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = getCryptogramType(req.cryptogramInfoData),
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.terminalVerificationResults,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName,
            rawData = req.rawCryptogramData
        )

        fun fromJcb(req: com.atlas.softpos.kernel.jcb.JcbAuthorizationRequest) = AuthorizationData(
            cardNetwork = CardNetwork.JCB,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = getCryptogramType(req.cryptogramInfoData),
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.terminalVerificationResults,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName,
            rawData = req.rawCryptogramData
        )

        fun fromUnionPay(req: com.atlas.softpos.kernel.unionpay.UnionPayAuthorizationRequest) = AuthorizationData(
            cardNetwork = CardNetwork.UNIONPAY,
            pan = req.pan,
            maskedPan = maskPan(req.pan),
            expiryDate = req.expiryDate,
            track2Equivalent = req.track2Equivalent,
            panSequenceNumber = req.panSequenceNumber,
            applicationCryptogram = req.applicationCryptogram,
            cryptogramType = getCryptogramType(req.cryptogramInfoData),
            atc = req.atc,
            issuerApplicationData = req.issuerApplicationData,
            terminalVerificationResults = req.terminalVerificationResults,
            cvmResults = req.cvmResults,
            amountAuthorized = req.amountAuthorized,
            transactionDate = req.transactionDate,
            transactionType = req.transactionType,
            unpredictableNumber = req.unpredictableNumber,
            aip = req.aip,
            aid = req.aid,
            cardholderName = req.cardholderName,
            rawData = req.rawCryptogramData
        )

        private fun maskPan(pan: String): String {
            if (pan.length < 8) return pan
            val firstFour = pan.take(4)
            val lastFour = pan.takeLast(4)
            val middle = "*".repeat(pan.length - 8)
            return "$firstFour$middle$lastFour"
        }

        private fun getCryptogramType(cid: String): String {
            return when {
                cid.isEmpty() -> "UNKNOWN"
                cid.startsWith("80") || cid.startsWith("8") -> "ARQC"
                cid.startsWith("40") || cid.startsWith("4") -> "TC"
                cid.startsWith("00") || cid.startsWith("0") -> "AAC"
                else -> "UNKNOWN"
            }
        }
    }
}

/**
 * Transaction errors
 */
sealed class TransactionError {
    object NfcNotAvailable : TransactionError()
    object NfcDisabled : TransactionError()
    object TransactionInProgress : TransactionError()
    data class NfcError(val message: String) : TransactionError()
    data class ProcessingError(val message: String) : TransactionError()
}

// Coroutine helper
private fun kotlinx.coroutines.GlobalScope.launch(
    context: kotlinx.coroutines.CoroutineContext,
    block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit
) = kotlinx.coroutines.GlobalScope.launch(context) { block() }
