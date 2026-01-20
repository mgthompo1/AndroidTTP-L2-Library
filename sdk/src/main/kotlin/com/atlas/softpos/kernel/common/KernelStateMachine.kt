package com.atlas.softpos.kernel.common

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Kernel State Machine
 *
 * Manages EMV kernel state transitions with comprehensive error handling.
 * Implements EMV Contactless Book A - Kernel State Machine requirements.
 *
 * State Transitions:
 * IDLE → WAITING_FOR_CARD → CARD_DETECTED → PROCESSING → [OUTCOME]
 *
 * Outcomes:
 * - APPROVED: Offline approval (TC generated)
 * - DECLINED: Offline decline (AAC generated)
 * - ONLINE_REQUEST: Online authorization required (ARQC generated)
 * - END_APPLICATION: Application error
 * - TRY_ANOTHER_INTERFACE: Card requests chip/magstripe
 * - TRY_AGAIN: Collision or read error, retry
 * - SELECT_NEXT: Try next application in candidate list
 */
class KernelStateMachine(
    private val config: KernelTimeoutConfig = KernelTimeoutConfig()
) {
    private val _state = MutableStateFlow<KernelState>(KernelState.Idle)
    val state: StateFlow<KernelState> = _state.asStateFlow()

    private val _outcome = MutableStateFlow<KernelOutcome?>(null)
    val outcome: StateFlow<KernelOutcome?> = _outcome.asStateFlow()

    private var transactionScope: CoroutineScope? = null
    private var overallTimeoutJob: Job? = null
    private var commandTimeoutJob: Job? = null

    private val isAborted = AtomicBoolean(false)
    private val isCardRemoved = AtomicBoolean(false)

    // Transaction data for recovery
    private var transactionData: TransactionStateData? = null

    /**
     * Start a new transaction
     */
    fun startTransaction(data: TransactionStateData) {
        require(_state.value == KernelState.Idle) { "Transaction already in progress" }

        isAborted.set(false)
        isCardRemoved.set(false)
        transactionData = data
        _outcome.value = null

        transactionScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

        transition(KernelState.WaitingForCard)
        startOverallTimeout()
    }

    /**
     * Card detected - start processing
     */
    fun onCardDetected() {
        if (_state.value != KernelState.WaitingForCard) {
            Timber.w("Card detected in unexpected state: ${_state.value}")
            return
        }
        transition(KernelState.CardDetected)
    }

    /**
     * Begin kernel processing
     */
    fun beginProcessing() {
        if (_state.value != KernelState.CardDetected) {
            Timber.w("Cannot begin processing in state: ${_state.value}")
            return
        }
        transition(KernelState.SelectingApplication)
    }

    /**
     * Application selected successfully
     */
    fun onApplicationSelected(aid: ByteArray, label: String) {
        transactionData = transactionData?.copy(selectedAid = aid, applicationLabel = label)
        transition(KernelState.InitiatingApplication)
    }

    /**
     * GPO sent, processing response
     */
    fun onGpoSent() {
        transition(KernelState.ReadingApplicationData)
    }

    /**
     * Application data read complete
     */
    fun onDataReadComplete() {
        transition(KernelState.OfflineDataAuthentication)
    }

    /**
     * ODA complete, processing restrictions
     */
    fun onOdaComplete(success: Boolean) {
        transactionData = transactionData?.copy(odaPerformed = true, odaSuccessful = success)
        transition(KernelState.ProcessingRestrictions)
    }

    /**
     * CVM processing
     */
    fun onRestrictionsProcessed() {
        transition(KernelState.CardholderVerification)
    }

    /**
     * CVM complete
     */
    fun onCvmComplete(method: String, successful: Boolean) {
        transactionData = transactionData?.copy(
            cvmPerformed = true,
            cvmMethod = method,
            cvmSuccessful = successful
        )
        transition(KernelState.TerminalRiskManagement)
    }

    /**
     * Terminal risk management complete, generating cryptogram
     */
    fun onRiskManagementComplete() {
        transition(KernelState.TerminalActionAnalysis)
    }

    /**
     * Cryptogram requested
     */
    fun onCryptogramRequested(type: CryptogramType) {
        transactionData = transactionData?.copy(
            cryptogramRequested = true,
            requestedCryptogramType = type
        )
        transition(KernelState.GeneratingCryptogram)
    }

    /**
     * Cryptogram received - determine outcome
     */
    fun onCryptogramReceived(type: CryptogramType, cryptogram: ByteArray) {
        transactionData = transactionData?.copy(
            cryptogramGenerated = true,
            actualCryptogramType = type,
            cryptogram = cryptogram
        )

        val finalOutcome = when (type) {
            CryptogramType.TC -> KernelOutcome.Approved(transactionData!!)
            CryptogramType.ARQC -> KernelOutcome.OnlineRequest(transactionData!!)
            CryptogramType.AAC -> KernelOutcome.Declined(transactionData!!, "Card declined offline")
            CryptogramType.AAR -> KernelOutcome.Declined(transactionData!!, "Application authentication referral")
        }

        setOutcome(finalOutcome)
    }

    /**
     * Card removed during transaction
     */
    fun onCardRemoved() {
        isCardRemoved.set(true)

        val currentState = _state.value
        Timber.w("Card removed in state: $currentState")

        when (currentState) {
            is KernelState.Idle,
            is KernelState.WaitingForCard -> {
                // No issue - not processing yet
            }

            is KernelState.CardDetected,
            is KernelState.SelectingApplication,
            is KernelState.InitiatingApplication,
            is KernelState.ReadingApplicationData -> {
                // Card removed before critical point - can retry
                setOutcome(KernelOutcome.TryAgain("Card removed, please try again"))
            }

            is KernelState.OfflineDataAuthentication,
            is KernelState.ProcessingRestrictions,
            is KernelState.CardholderVerification,
            is KernelState.TerminalRiskManagement,
            is KernelState.TerminalActionAnalysis -> {
                // Card removed before cryptogram - end application
                setOutcome(KernelOutcome.EndApplication("Card removed before completion"))
            }

            is KernelState.GeneratingCryptogram -> {
                // CRITICAL: Card removed after requesting cryptogram
                // May need reversal if we got partial response
                handleCriticalCardRemoval()
            }

            is KernelState.Complete,
            is KernelState.Error -> {
                // Already complete
            }
        }
    }

    /**
     * Handle card removal during critical cryptogram phase
     */
    private fun handleCriticalCardRemoval() {
        val data = transactionData

        if (data?.cryptogramGenerated == true) {
            // We got the cryptogram - transaction can proceed
            Timber.w("Card removed after cryptogram - proceeding with authorization")
            setOutcome(KernelOutcome.OnlineRequest(data))
        } else if (data?.cryptogramRequested == true) {
            // Requested but didn't receive - torn transaction
            Timber.e("TORN TRANSACTION: Cryptogram requested but not received")
            setOutcome(KernelOutcome.TornTransaction(data))
        } else {
            setOutcome(KernelOutcome.EndApplication("Card removed"))
        }
    }

    /**
     * Command timeout occurred
     */
    fun onCommandTimeout() {
        val currentState = _state.value
        Timber.w("Command timeout in state: $currentState")

        when (currentState) {
            is KernelState.SelectingApplication,
            is KernelState.InitiatingApplication,
            is KernelState.ReadingApplicationData -> {
                // Can retry
                setOutcome(KernelOutcome.TryAgain("Communication timeout"))
            }

            is KernelState.GeneratingCryptogram -> {
                // Critical timeout
                handleCriticalTimeout()
            }

            else -> {
                setOutcome(KernelOutcome.EndApplication("Communication timeout"))
            }
        }
    }

    /**
     * Handle timeout during critical phase
     */
    private fun handleCriticalTimeout() {
        val data = transactionData

        if (data?.cryptogramRequested == true && data.cryptogramGenerated != true) {
            // Torn transaction - may need reversal
            Timber.e("TORN TRANSACTION: Timeout waiting for cryptogram")
            setOutcome(KernelOutcome.TornTransaction(data))
        } else {
            setOutcome(KernelOutcome.EndApplication("Critical timeout"))
        }
    }

    /**
     * Overall transaction timeout
     */
    private fun onOverallTimeout() {
        Timber.w("Overall transaction timeout")
        abort("Transaction timeout")
    }

    /**
     * Protocol error occurred
     */
    fun onProtocolError(error: String) {
        Timber.e("Protocol error: $error")
        setOutcome(KernelOutcome.EndApplication("Protocol error: $error"))
    }

    /**
     * Card requests different interface
     */
    fun onTryAnotherInterface() {
        setOutcome(KernelOutcome.TryAnotherInterface)
    }

    /**
     * Multiple applications - try next one
     */
    fun onSelectNext() {
        setOutcome(KernelOutcome.SelectNext)
    }

    /**
     * Collision detected
     */
    fun onCollision() {
        Timber.w("Card collision detected")
        setOutcome(KernelOutcome.TryAgain("Multiple cards detected, please present only one card"))
    }

    /**
     * Abort transaction
     */
    fun abort(reason: String) {
        if (isAborted.getAndSet(true)) return

        Timber.w("Transaction aborted: $reason")
        cancelTimeouts()

        val data = transactionData
        if (data?.cryptogramRequested == true && data.cryptogramGenerated != true) {
            // May need reversal
            setOutcome(KernelOutcome.TornTransaction(data))
        } else {
            setOutcome(KernelOutcome.EndApplication("Aborted: $reason"))
        }
    }

    /**
     * Reset state machine
     */
    fun reset() {
        cancelTimeouts()
        transactionScope?.cancel()
        transactionScope = null

        isAborted.set(false)
        isCardRemoved.set(false)
        transactionData = null

        _state.value = KernelState.Idle
        _outcome.value = null
    }

    /**
     * Start command timeout
     */
    fun startCommandTimeout() {
        commandTimeoutJob?.cancel()
        commandTimeoutJob = transactionScope?.launch {
            delay(config.commandTimeoutMs)
            if (!isAborted.get()) {
                onCommandTimeout()
            }
        }
    }

    /**
     * Cancel command timeout (command completed successfully)
     */
    fun cancelCommandTimeout() {
        commandTimeoutJob?.cancel()
        commandTimeoutJob = null
    }

    private fun startOverallTimeout() {
        overallTimeoutJob = transactionScope?.launch {
            delay(config.overallTimeoutMs)
            if (!isAborted.get()) {
                onOverallTimeout()
            }
        }
    }

    private fun cancelTimeouts() {
        overallTimeoutJob?.cancel()
        commandTimeoutJob?.cancel()
        overallTimeoutJob = null
        commandTimeoutJob = null
    }

    private fun transition(newState: KernelState) {
        val oldState = _state.value
        Timber.d("State transition: $oldState → $newState")
        _state.value = newState
    }

    private fun setOutcome(outcome: KernelOutcome) {
        cancelTimeouts()
        _outcome.value = outcome
        transition(
            when (outcome) {
                is KernelOutcome.Approved,
                is KernelOutcome.Declined,
                is KernelOutcome.OnlineRequest -> KernelState.Complete

                else -> KernelState.Error
            }
        )
    }
}

/**
 * Kernel states
 */
sealed class KernelState {
    object Idle : KernelState()
    object WaitingForCard : KernelState()
    object CardDetected : KernelState()
    object SelectingApplication : KernelState()
    object InitiatingApplication : KernelState()
    object ReadingApplicationData : KernelState()
    object OfflineDataAuthentication : KernelState()
    object ProcessingRestrictions : KernelState()
    object CardholderVerification : KernelState()
    object TerminalRiskManagement : KernelState()
    object TerminalActionAnalysis : KernelState()
    object GeneratingCryptogram : KernelState()
    object Complete : KernelState()
    object Error : KernelState()

    override fun toString(): String = this::class.simpleName ?: "Unknown"
}

/**
 * Kernel outcomes (EMVCo defined)
 */
sealed class KernelOutcome {
    data class Approved(val data: TransactionStateData) : KernelOutcome()
    data class Declined(val data: TransactionStateData, val reason: String) : KernelOutcome()
    data class OnlineRequest(val data: TransactionStateData) : KernelOutcome()
    data class EndApplication(val reason: String) : KernelOutcome()
    object TryAnotherInterface : KernelOutcome()
    data class TryAgain(val reason: String) : KernelOutcome()
    object SelectNext : KernelOutcome()
    data class TornTransaction(val data: TransactionStateData) : KernelOutcome()
}

/**
 * Cryptogram types
 */
enum class CryptogramType {
    TC,     // Transaction Certificate (offline approved)
    ARQC,   // Authorization Request Cryptogram (online required)
    AAC,    // Application Authentication Cryptogram (declined)
    AAR     // Application Authentication Referral
}

/**
 * Transaction state data for recovery
 */
data class TransactionStateData(
    val transactionId: String,
    val amount: Long,
    val currencyCode: String,
    val transactionType: Byte,
    val timestamp: Long = System.currentTimeMillis(),

    // Application selection
    val selectedAid: ByteArray? = null,
    val applicationLabel: String? = null,

    // ODA
    val odaPerformed: Boolean = false,
    val odaSuccessful: Boolean = false,

    // CVM
    val cvmPerformed: Boolean = false,
    val cvmMethod: String? = null,
    val cvmSuccessful: Boolean = false,

    // Cryptogram
    val cryptogramRequested: Boolean = false,
    val requestedCryptogramType: CryptogramType? = null,
    val cryptogramGenerated: Boolean = false,
    val actualCryptogramType: CryptogramType? = null,
    val cryptogram: ByteArray? = null,

    // Card data
    val pan: String? = null,
    val panSequenceNumber: String? = null,
    val track2Equivalent: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransactionStateData) return false
        return transactionId == other.transactionId
    }

    override fun hashCode(): Int = transactionId.hashCode()
}

/**
 * Timeout configuration
 */
data class KernelTimeoutConfig(
    val waitForCardTimeoutMs: Long = 60_000,      // 60 seconds
    val commandTimeoutMs: Long = 1_000,            // 1 second per command
    val overallTimeoutMs: Long = 30_000,           // 30 seconds total
    val onlineResponseTimeoutMs: Long = 45_000     // 45 seconds for online response
)
