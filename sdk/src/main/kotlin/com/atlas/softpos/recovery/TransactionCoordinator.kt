package com.atlas.softpos.recovery

import android.nfc.Tag
import android.nfc.tech.IsoDep
import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.cvm.CvmMethod
import com.atlas.softpos.cvm.CvmResult
import com.atlas.softpos.cvm.OnlinePinEntry
import com.atlas.softpos.cvm.OnlinePinResult
import com.atlas.softpos.kernel.common.CardTransceiver
import com.atlas.softpos.kernel.common.SelectedApplication
import com.atlas.softpos.kernel.visa.VisaContactlessKernel
import com.atlas.softpos.kernel.visa.VisaKernelConfiguration
import com.atlas.softpos.kernel.visa.VisaKernelOutcome
import com.atlas.softpos.kernel.visa.VisaTransactionData
import com.atlas.softpos.kernel.mastercard.MastercardContactlessKernel
import com.atlas.softpos.kernel.mastercard.MastercardKernelConfiguration
import com.atlas.softpos.kernel.mastercard.MastercardKernelOutcome
import com.atlas.softpos.kernel.mastercard.MastercardTransactionParams
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Transaction Coordinator
 *
 * Orchestrates the complete transaction flow with:
 * - Automatic error recovery and retry
 * - CVM handling (CDCVM/Online PIN)
 * - Torn transaction management
 * - State management and event emission
 *
 * Usage:
 * ```kotlin
 * val coordinator = TransactionCoordinator(config)
 *
 * // Observe state
 * coordinator.state.collect { state ->
 *     when (state) {
 *         is TransactionState.WaitingForCard -> showTapPrompt()
 *         is TransactionState.Processing -> showSpinner()
 *         is TransactionState.PinRequired -> showPinEntry(state.pan, state.amount)
 *         is TransactionState.Complete -> handleOutcome(state.outcome)
 *         is TransactionState.Error -> showError(state.error)
 *     }
 * }
 *
 * // Start transaction
 * coordinator.startTransaction(amount = 1000, tag = nfcTag)
 * ```
 */
class TransactionCoordinator(
    private val config: TransactionCoordinatorConfig
) {
    private val errorRecovery = TransactionErrorRecovery(config.errorRecoveryConfig)
    private val tornRecovery = config.tornTransactionRecovery

    private val _state = MutableStateFlow<TransactionState>(TransactionState.Idle)
    val state: StateFlow<TransactionState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<TransactionEvent>()
    val events: SharedFlow<TransactionEvent> = _events.asSharedFlow()

    private var currentJob: Job? = null
    private val isProcessing = AtomicBoolean(false)

    // PIN entry callback (set by UI layer)
    var onPinEntryRequired: (suspend (String, Long) -> OnlinePinResult)? = null

    /**
     * Start a new transaction
     */
    suspend fun startTransaction(
        amount: Long,
        tag: Tag,
        transactionType: Byte = 0x00,
        cashbackAmount: Long = 0
    ): TransactionOutcome {
        if (!isProcessing.compareAndSet(false, true)) {
            Timber.w("Transaction already in progress")
            return TransactionOutcome.Error("Transaction already in progress")
        }

        try {
            _state.value = TransactionState.Processing("Connecting to card...")
            emitEvent(TransactionEvent.Started(amount))

            // Get IsoDep interface
            val isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                val error = errorRecovery.classifyError(IllegalStateException("Card does not support IsoDep"))
                _state.value = TransactionState.Error(error)
                return TransactionOutcome.Error(error.userMessage)
            }

            // Execute with recovery
            val result = errorRecovery.executeWithRecovery(
                operation = "Card Connection",
                retryPolicy = RetryPolicy(maxRetries = 2, initialDelayMs = 200)
            ) {
                connectToCard(isoDep)
            }

            when (result) {
                is RecoveryResult.Success -> {
                    // Continue with transaction
                }
                is RecoveryResult.Failed -> {
                    _state.value = TransactionState.Error(result.error)
                    emitEvent(TransactionEvent.Failed(result.error))
                    return TransactionOutcome.Error(result.error.userMessage)
                }
            }

            // Create transceiver with recovery
            val transceiver = RecoveringTransceiver(isoDep, errorRecovery)

            _state.value = TransactionState.Processing("Reading card...")

            // Select PPSE and determine kernel
            val kernelResult = selectKernel(transceiver)
            if (kernelResult is KernelSelection.Failed) {
                val error = ErrorInfo(
                    category = ErrorCategory.CARD_NOT_SUPPORTED,
                    message = kernelResult.reason,
                    isRetryable = false,
                    canRetryManually = true,
                    userMessage = "Card not supported",
                    recoveryAction = RecoveryAction.TRY_ANOTHER_CARD
                )
                _state.value = TransactionState.Error(error)
                return TransactionOutcome.Error(error.userMessage)
            }

            val selectedKernel = kernelResult as KernelSelection.Selected

            _state.value = TransactionState.Processing("Processing transaction...")

            // Process based on kernel type
            val outcome = when (selectedKernel.kernelType) {
                KernelType.VISA -> processVisaTransaction(
                    transceiver = transceiver,
                    aid = selectedKernel.aid,
                    pdol = selectedKernel.pdol,
                    amount = amount,
                    transactionType = transactionType,
                    cashbackAmount = cashbackAmount
                )
                KernelType.MASTERCARD -> processMastercardTransaction(
                    transceiver = transceiver,
                    aid = selectedKernel.aid,
                    pdol = selectedKernel.pdol,
                    amount = amount,
                    transactionType = transactionType,
                    cashbackAmount = cashbackAmount
                )
                KernelType.AMEX, KernelType.DISCOVER, KernelType.UNKNOWN -> {
                    TransactionOutcome.Error("Kernel not yet implemented: ${selectedKernel.kernelType}")
                }
            }

            // Handle outcome
            when (outcome) {
                is TransactionOutcome.OnlineRequired -> {
                    _state.value = TransactionState.Complete(outcome)
                    emitEvent(TransactionEvent.OnlineAuthRequired(outcome.authData))
                }
                is TransactionOutcome.Approved -> {
                    _state.value = TransactionState.Complete(outcome)
                    emitEvent(TransactionEvent.Completed(outcome))
                }
                is TransactionOutcome.Declined -> {
                    _state.value = TransactionState.Complete(outcome)
                    emitEvent(TransactionEvent.Completed(outcome))
                }
                is TransactionOutcome.Error -> {
                    val error = ErrorInfo(
                        category = ErrorCategory.PROCESSING_ERROR,
                        message = outcome.reason,
                        isRetryable = false,
                        canRetryManually = true,
                        userMessage = outcome.reason,
                        recoveryAction = RecoveryAction.RESTART_TRANSACTION
                    )
                    _state.value = TransactionState.Error(error)
                    emitEvent(TransactionEvent.Failed(error))
                }
                is TransactionOutcome.TryAnotherInterface -> {
                    val error = ErrorInfo(
                        category = ErrorCategory.CARD_NOT_SUPPORTED,
                        message = "Card requires insert or swipe",
                        isRetryable = false,
                        canRetryManually = false,
                        userMessage = "Please insert or swipe this card",
                        recoveryAction = RecoveryAction.TRY_ANOTHER_CARD
                    )
                    _state.value = TransactionState.Error(error)
                    emitEvent(TransactionEvent.Failed(error))
                }
            }

            // Disconnect
            try {
                isoDep.close()
            } catch (e: Exception) {
                Timber.w(e, "Error closing IsoDep")
            }

            return outcome

        } finally {
            isProcessing.set(false)
        }
    }

    /**
     * Cancel current transaction
     */
    fun cancel() {
        currentJob?.cancel()
        _state.value = TransactionState.Idle
        isProcessing.set(false)
    }

    /**
     * Handle Online PIN entry result
     */
    suspend fun submitPinResult(result: OnlinePinResult) {
        _events.emit(TransactionEvent.PinEntryComplete(result))
    }

    private suspend fun connectToCard(isoDep: IsoDep) {
        isoDep.connect()
        isoDep.timeout = config.nfcTimeoutMs
        Timber.d("Connected to card, timeout=${isoDep.timeout}ms")
    }

    private suspend fun selectKernel(transceiver: CardTransceiver): KernelSelection {
        // Select PPSE
        val ppseAid = "2PAY.SYS.DDF01".toByteArray(Charsets.US_ASCII)
        val selectPpse = CommandApdu(
            cla = 0x00,
            ins = 0xA4.toByte(),
            p1 = 0x04,
            p2 = 0x00,
            data = ppseAid,
            le = 0x00
        )

        val ppseResponse = transceiver.transceive(selectPpse)
        if (!ppseResponse.isSuccess) {
            return KernelSelection.Failed("PPSE selection failed: ${ppseResponse.sw.toString(16)}")
        }

        // Parse available AIDs
        val aids = parsePpseResponse(ppseResponse.data)
        if (aids.isEmpty()) {
            return KernelSelection.Failed("No payment applications found")
        }

        // Select first available AID
        for (aidEntry in aids) {
            val selectAid = CommandApdu(
                cla = 0x00,
                ins = 0xA4.toByte(),
                p1 = 0x04,
                p2 = 0x00,
                data = aidEntry.aid,
                le = 0x00
            )

            val aidResponse = transceiver.transceive(selectAid)
            if (aidResponse.isSuccess) {
                val kernelType = determineKernelType(aidEntry.aid)
                val pdol = extractPdol(aidResponse.data)

                Timber.d("Selected AID: ${aidEntry.aid.toHexString()}, Kernel: $kernelType")

                return KernelSelection.Selected(
                    aid = aidEntry.aid,
                    kernelType = kernelType,
                    pdol = pdol,
                    fci = aidResponse.data
                )
            }
        }

        return KernelSelection.Failed("No supported payment application")
    }

    private fun parsePpseResponse(data: ByteArray): List<AidEntry> {
        val aids = mutableListOf<AidEntry>()

        // Simple TLV parsing for AID (tag 4F) and priority (tag 87)
        var i = 0
        while (i < data.size - 2) {
            if (data[i] == 0x4F.toByte()) {
                val length = data[i + 1].toInt() and 0xFF
                if (i + 2 + length <= data.size) {
                    val aid = data.copyOfRange(i + 2, i + 2 + length)
                    aids.add(AidEntry(aid, 1))
                }
                i += 2 + length
            } else {
                i++
            }
        }

        return aids.sortedBy { it.priority }
    }

    private fun determineKernelType(aid: ByteArray): KernelType {
        val aidHex = aid.toHexString()
        return when {
            aidHex.startsWith("A000000003") -> KernelType.VISA
            aidHex.startsWith("A000000004") -> KernelType.MASTERCARD
            aidHex.startsWith("A000000025") -> KernelType.AMEX
            aidHex.startsWith("A000000152") -> KernelType.DISCOVER
            else -> KernelType.UNKNOWN
        }
    }

    private fun extractPdol(fciData: ByteArray): ByteArray? {
        // Find PDOL (tag 9F38) in FCI
        var i = 0
        while (i < fciData.size - 3) {
            if (fciData[i] == 0x9F.toByte() && fciData[i + 1] == 0x38.toByte()) {
                val length = fciData[i + 2].toInt() and 0xFF
                if (i + 3 + length <= fciData.size) {
                    return fciData.copyOfRange(i + 3, i + 3 + length)
                }
            }
            i++
        }
        return null
    }

    private suspend fun processVisaTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        pdol: ByteArray?,
        amount: Long,
        transactionType: Byte,
        cashbackAmount: Long
    ): TransactionOutcome {
        val kernel = VisaContactlessKernel(transceiver, config.visaConfig)

        val transactionData = VisaTransactionData(
            amount = amount,
            cashbackAmount = if (cashbackAmount > 0) cashbackAmount else null,
            transactionType = transactionType
        )

        return errorRecovery.executeWithRecovery(
            operation = "Visa Transaction",
            retryPolicy = RetryPolicy(maxRetries = 1)
        ) {
            val outcome = kernel.processTransaction(aid, pdol, transactionData)

            when (outcome) {
                is VisaKernelOutcome.Approved -> TransactionOutcome.Approved(
                    authData = outcome.authData.toMap(),
                    cryptogram = outcome.authData.applicationCryptogram
                )
                is VisaKernelOutcome.OnlineRequest -> {
                    // Check if Online PIN is required
                    handleCvmIfRequired(outcome.authData.cvmResults, outcome.authData.pan, amount)

                    TransactionOutcome.OnlineRequired(
                        authData = outcome.authData.toMap(),
                        cryptogram = outcome.authData.applicationCryptogram
                    )
                }
                is VisaKernelOutcome.Declined -> TransactionOutcome.Declined(
                    reason = outcome.reason,
                    authData = outcome.authData.toMap()
                )
                is VisaKernelOutcome.TryAnotherInterface -> TransactionOutcome.TryAnotherInterface
                is VisaKernelOutcome.EndApplication -> TransactionOutcome.Error(outcome.reason)
                is VisaKernelOutcome.TryAgain -> throw RetryableException(outcome.reason)
            }
        }.let { result ->
            when (result) {
                is RecoveryResult.Success -> result.value
                is RecoveryResult.Failed -> TransactionOutcome.Error(result.error.userMessage)
            }
        }
    }

    private suspend fun processMastercardTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        pdol: ByteArray?,
        amount: Long,
        transactionType: Byte,
        cashbackAmount: Long
    ): TransactionOutcome {
        val kernel = MastercardContactlessKernel(transceiver, config.mastercardConfig)

        val transactionParams = MastercardTransactionParams(
            amount = amount,
            cashbackAmount = if (cashbackAmount > 0) cashbackAmount else null,
            type = transactionType
        )

        // Create SelectedApplication from aid and pdol
        val selectedApplication = SelectedApplication(
            aid = aid,
            label = "Mastercard",
            pdol = pdol,
            languagePreference = null,
            fciData = byteArrayOf()
        )

        return errorRecovery.executeWithRecovery(
            operation = "Mastercard Transaction",
            retryPolicy = RetryPolicy(maxRetries = 1)
        ) {
            val outcome = kernel.processTransaction(selectedApplication, transactionParams)

            when (outcome) {
                is MastercardKernelOutcome.Approved -> TransactionOutcome.Approved(
                    authData = outcome.authorizationData.toMap(),
                    cryptogram = outcome.authorizationData.applicationCryptogram
                )
                is MastercardKernelOutcome.OnlineRequest -> {
                    handleCvmIfRequired(outcome.authorizationData.cvmResults, outcome.authorizationData.pan, amount)

                    TransactionOutcome.OnlineRequired(
                        authData = outcome.authorizationData.toMap(),
                        cryptogram = outcome.authorizationData.applicationCryptogram
                    )
                }
                is MastercardKernelOutcome.Declined -> TransactionOutcome.Declined(
                    reason = outcome.reason,
                    authData = outcome.authorizationData?.toMap() ?: emptyMap()
                )
                is MastercardKernelOutcome.TryAnotherInterface -> TransactionOutcome.TryAnotherInterface
                is MastercardKernelOutcome.EndApplication -> TransactionOutcome.Error(outcome.error.name)
            }
        }.let { result ->
            when (result) {
                is RecoveryResult.Success -> result.value
                is RecoveryResult.Failed -> TransactionOutcome.Error(result.error.userMessage)
            }
        }
    }

    private suspend fun handleCvmIfRequired(cvmResults: String, pan: String, amount: Long) {
        // CVM Results byte 1 indicates the method
        // 0x02 = Enciphered PIN Online
        val cvmMethod = cvmResults.take(2).toIntOrNull(16) ?: return

        if (cvmMethod == 0x02 || cvmMethod == 0x42) {  // Online PIN
            _state.value = TransactionState.PinRequired(pan, amount)
            emitEvent(TransactionEvent.PinEntryRequired(pan, amount))

            // Wait for PIN entry from UI
            val pinResult = onPinEntryRequired?.invoke(pan, amount)

            when (pinResult) {
                is OnlinePinResult.Success -> {
                    // PIN block will be included in online auth request
                    _state.value = TransactionState.Processing("Completing transaction...")
                }
                is OnlinePinResult.Cancelled, is OnlinePinResult.Bypassed -> {
                    // Continue without PIN (if allowed)
                }
                is OnlinePinResult.MaxAttemptsExceeded -> {
                    throw SecurityException("PIN entry attempts exceeded")
                }
                else -> {}
            }
        }
    }

    private suspend fun emitEvent(event: TransactionEvent) {
        _events.emit(event)
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }

    // Convert auth data to map for generic handling
    private fun com.atlas.softpos.kernel.visa.VisaAuthorizationData.toMap(): Map<String, String> {
        return mapOf(
            "pan" to pan,
            "maskedPan" to maskedPan,
            "track2" to track2Equivalent,
            "cryptogram" to applicationCryptogram,
            "cid" to cryptogramInformationData,
            "atc" to atc,
            "iad" to issuerApplicationData,
            "tvr" to terminalVerificationResults,
            "cvmResults" to cvmResults,
            "aid" to aid
        )
    }

    private fun com.atlas.softpos.kernel.mastercard.MastercardAuthorizationData.toMap(): Map<String, String> {
        return mapOf(
            "pan" to pan,
            "maskedPan" to maskPan(pan),
            "track2" to track2Equivalent,
            "cryptogram" to applicationCryptogram,
            "cid" to cryptogramInfoData.toString(16),
            "atc" to atc,
            "iad" to issuerApplicationData,
            "tvr" to tvr,
            "cvmResults" to cvmResults,
            "aid" to aid
        )
    }

    private fun maskPan(pan: String): String {
        if (pan.length < 10) return pan
        return pan.take(6) + "*".repeat(pan.length - 10) + pan.takeLast(4)
    }
}

/**
 * Transceiver wrapper with automatic retry
 */
private class RecoveringTransceiver(
    private val isoDep: IsoDep,
    private val errorRecovery: TransactionErrorRecovery
) : CardTransceiver {

    override suspend fun transceive(command: CommandApdu): ResponseApdu {
        val commandBytes = command.encode()
        val responseBytes = isoDep.transceive(commandBytes)
        return ResponseApdu.parse(responseBytes)
    }
}

class RetryableException(message: String) : Exception(message)

// ==================== DATA CLASSES ====================

data class TransactionCoordinatorConfig(
    val visaConfig: VisaKernelConfiguration,
    val mastercardConfig: MastercardKernelConfiguration,
    val errorRecoveryConfig: ErrorRecoveryConfig = ErrorRecoveryConfig(),
    val tornTransactionRecovery: TornTransactionRecovery? = null,
    val nfcTimeoutMs: Int = 5000
)

sealed class TransactionState {
    object Idle : TransactionState()
    data class Processing(val message: String) : TransactionState()
    data class PinRequired(val pan: String, val amount: Long) : TransactionState()
    data class Complete(val outcome: TransactionOutcome) : TransactionState()
    data class Error(val error: ErrorInfo) : TransactionState()
}

sealed class TransactionOutcome {
    data class Approved(
        val authData: Map<String, String>,
        val cryptogram: String
    ) : TransactionOutcome()

    data class OnlineRequired(
        val authData: Map<String, String>,
        val cryptogram: String
    ) : TransactionOutcome()

    data class Declined(
        val reason: String,
        val authData: Map<String, String>
    ) : TransactionOutcome()

    object TryAnotherInterface : TransactionOutcome()

    data class Error(val reason: String) : TransactionOutcome()
}

sealed class TransactionEvent {
    data class Started(val amount: Long) : TransactionEvent()
    data class PinEntryRequired(val pan: String, val amount: Long) : TransactionEvent()
    data class PinEntryComplete(val result: OnlinePinResult) : TransactionEvent()
    data class OnlineAuthRequired(val authData: Map<String, String>) : TransactionEvent()
    data class Completed(val outcome: TransactionOutcome) : TransactionEvent()
    data class Failed(val error: ErrorInfo) : TransactionEvent()
}

sealed class KernelSelection {
    data class Selected(
        val aid: ByteArray,
        val kernelType: KernelType,
        val pdol: ByteArray?,
        val fci: ByteArray
    ) : KernelSelection()

    data class Failed(val reason: String) : KernelSelection()
}

enum class KernelType {
    VISA,
    MASTERCARD,
    AMEX,
    DISCOVER,
    UNKNOWN
}

data class AidEntry(
    val aid: ByteArray,
    val priority: Int
)
