package com.atlas.softpos.kernel.common

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Kernel State Machine
 *
 * Manages EMV kernel state transitions with comprehensive error handling.
 * Implements EMV Contactless Book A - Kernel State Machine requirements.
 *
 * This is a PASSIVE state machine - external code (kernels) must drive it
 * by calling the appropriate onX() methods. The state machine tracks state,
 * manages timeouts, and determines outcomes.
 *
 * State Transitions:
 * IDLE → WAITING_FOR_CARD → CARD_DETECTED → PROCESSING → [OUTCOME]
 *
 * For online transactions:
 * ... → ONLINE_AUTHORIZATION → ISSUER_SCRIPT_PROCESSING → SECOND_GENERATE_AC → [OUTCOME]
 *
 * Outcomes:
 * - APPROVED: Offline approval (TC generated)
 * - DECLINED: Offline decline (AAC generated)
 * - ONLINE_REQUEST: Online authorization required (ARQC generated)
 * - END_APPLICATION: Application error
 * - TRY_ANOTHER_INTERFACE: Card requests chip/magstripe
 * - TRY_AGAIN: Collision or read error, retry (up to max attempts)
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
    private var waitForCardTimeoutJob: Job? = null
    private var processingTimeoutJob: Job? = null
    private var commandTimeoutJob: Job? = null
    private var onlineTimeoutJob: Job? = null

    private val isAborted = AtomicBoolean(false)
    private val isCardRemoved = AtomicBoolean(false)

    // Command timeout sequence to prevent race conditions
    private val commandSequence = AtomicInteger(0)

    // Retry counter for TryAgain outcomes
    private val tryAgainCount = AtomicInteger(0)

    // Transaction data for recovery
    private var transactionData: TransactionStateData? = null

    /**
     * Valid state transitions map for validation
     */
    private val validTransitions: Map<KernelState, Set<KernelState>> = mapOf(
        KernelState.Idle to setOf(KernelState.WaitingForCard),
        KernelState.WaitingForCard to setOf(KernelState.CardDetected, KernelState.TerminalOutcome),
        KernelState.CardDetected to setOf(KernelState.SelectingApplication, KernelState.TerminalOutcome),
        KernelState.SelectingApplication to setOf(KernelState.InitiatingApplication, KernelState.TerminalOutcome),
        KernelState.InitiatingApplication to setOf(KernelState.ReadingApplicationData, KernelState.TerminalOutcome),
        KernelState.ReadingApplicationData to setOf(KernelState.OfflineDataAuthentication, KernelState.TerminalOutcome),
        KernelState.OfflineDataAuthentication to setOf(KernelState.ProcessingRestrictions, KernelState.TerminalOutcome),
        KernelState.ProcessingRestrictions to setOf(KernelState.CardholderVerification, KernelState.TerminalOutcome),
        KernelState.CardholderVerification to setOf(KernelState.TerminalRiskManagement, KernelState.TerminalOutcome),
        KernelState.TerminalRiskManagement to setOf(KernelState.TerminalActionAnalysis, KernelState.TerminalOutcome),
        KernelState.TerminalActionAnalysis to setOf(KernelState.GeneratingCryptogram, KernelState.TerminalOutcome),
        KernelState.GeneratingCryptogram to setOf(KernelState.Complete, KernelState.OnlineAuthorization, KernelState.TerminalOutcome),
        KernelState.OnlineAuthorization to setOf(KernelState.IssuerScriptProcessing, KernelState.Complete, KernelState.TerminalOutcome),
        KernelState.IssuerScriptProcessing to setOf(KernelState.SecondGenerateAc, KernelState.Complete, KernelState.TerminalOutcome),
        KernelState.SecondGenerateAc to setOf(KernelState.Complete, KernelState.TerminalOutcome),
        KernelState.Complete to setOf(KernelState.Idle),
        KernelState.TerminalOutcome to setOf(KernelState.Idle)
    )

    /**
     * Start a new transaction
     */
    fun startTransaction(data: TransactionStateData) {
        require(_state.value == KernelState.Idle) { "Transaction already in progress" }

        isAborted.set(false)
        isCardRemoved.set(false)
        tryAgainCount.set(0)
        commandSequence.set(0)
        transactionData = data
        _outcome.value = null

        transactionScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

        transition(KernelState.WaitingForCard)
        startWaitForCardTimeout()
    }

    /**
     * Card detected - start processing
     */
    fun onCardDetected() {
        if (_state.value != KernelState.WaitingForCard) {
            Timber.w("Card detected in unexpected state: ${_state.value}")
            return
        }

        // Cancel wait-for-card timeout, start processing timeout
        cancelWaitForCardTimeout()
        startProcessingTimeout()

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

        val data = transactionData
        if (data == null) {
            Timber.e("Transaction data is null when cryptogram received")
            setOutcome(KernelOutcome.EndApplication("Missing transaction context"))
            return
        }

        val finalOutcome = when (type) {
            CryptogramType.TC -> KernelOutcome.Approved(data)
            CryptogramType.ARQC -> KernelOutcome.OnlineRequest(data)
            CryptogramType.AAC -> KernelOutcome.Declined(data, "Card declined offline")
            CryptogramType.AAR -> KernelOutcome.Declined(data, "Application authentication referral")
        }

        setOutcome(finalOutcome)
    }

    // ==================== Online Authorization Flow ====================

    /**
     * Start online authorization phase
     * Called after receiving ARQC and sending to host
     */
    fun startOnlineAuthorization() {
        if (_state.value != KernelState.GeneratingCryptogram &&
            _outcome.value !is KernelOutcome.OnlineRequest) {
            Timber.w("Cannot start online auth in state: ${_state.value}")
            return
        }

        cancelProcessingTimeout()
        startOnlineTimeout()
        _state.value = KernelState.OnlineAuthorization
    }

    /**
     * Online response received from host
     *
     * @param approved True if host approved, false if declined
     * @param authCode Authorization code if approved
     * @param issuerAuthData Tag 91 data from host
     * @param scripts Issuer scripts (tags 71/72) if any
     */
    fun onOnlineResponseReceived(
        approved: Boolean,
        authCode: String?,
        issuerAuthData: ByteArray?,
        scripts: List<ByteArray>?
    ) {
        cancelOnlineTimeout()

        transactionData = transactionData?.copy(
            onlineResponseReceived = true,
            onlineApproved = approved,
            authorizationCode = authCode,
            issuerAuthData = issuerAuthData
        )

        if (scripts.isNullOrEmpty()) {
            // No scripts - proceed to 2nd GEN AC or completion
            if (approved) {
                transition(KernelState.SecondGenerateAc)
            } else {
                setOutcome(KernelOutcome.Declined(
                    transactionData ?: createFallbackData(),
                    "Declined by issuer"
                ))
            }
        } else {
            // Process scripts first
            transition(KernelState.IssuerScriptProcessing)
        }
    }

    /**
     * Issuer scripts processed
     */
    fun onIssuerScriptsProcessed(success: Boolean) {
        transactionData = transactionData?.copy(issuerScriptsProcessed = true)
        transition(KernelState.SecondGenerateAc)
    }

    /**
     * Second cryptogram received (after online)
     */
    fun onSecondCryptogramReceived(type: CryptogramType, cryptogram: ByteArray) {
        transactionData = transactionData?.copy(
            secondCryptogramType = type,
            secondCryptogram = cryptogram
        )

        val data = transactionData ?: createFallbackData()

        val finalOutcome = when (type) {
            CryptogramType.TC -> KernelOutcome.Approved(data)
            CryptogramType.AAC -> KernelOutcome.Declined(data, "Card declined after online")
            else -> KernelOutcome.Declined(data, "Unexpected cryptogram type")
        }

        setOutcome(finalOutcome)
    }

    // ==================== Error Handling ====================

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
            is KernelState.ReadingApplicationData,
            is KernelState.OfflineDataAuthentication,
            is KernelState.ProcessingRestrictions,
            is KernelState.CardholderVerification,
            is KernelState.TerminalRiskManagement,
            is KernelState.TerminalActionAnalysis -> {
                // Card removed before cryptogram - can retry
                handleTryAgain("Card removed, please try again")
            }

            is KernelState.GeneratingCryptogram -> {
                // CRITICAL: Card removed after requesting cryptogram
                handleCriticalCardRemoval()
            }

            is KernelState.OnlineAuthorization,
            is KernelState.IssuerScriptProcessing,
            is KernelState.SecondGenerateAc -> {
                // Card removed during online phase - may need reversal
                handleCriticalCardRemoval()
            }

            is KernelState.Complete,
            is KernelState.TerminalOutcome -> {
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
     * Handle TryAgain with retry counter
     */
    private fun handleTryAgain(reason: String) {
        val attempts = tryAgainCount.incrementAndGet()

        if (attempts > config.maxTryAgainAttempts) {
            Timber.w("Max retry attempts ($attempts) exceeded")
            setOutcome(KernelOutcome.EndApplication("Unable to read card after $attempts attempts"))
        } else {
            Timber.d("TryAgain attempt $attempts of ${config.maxTryAgainAttempts}")
            setOutcome(KernelOutcome.TryAgain(reason))
        }
    }

    /**
     * Command timeout occurred
     */
    private fun onCommandTimeout(expectedSeq: Int) {
        // Check if this timeout is still valid (not from a stale command)
        if (commandSequence.get() != expectedSeq) {
            Timber.d("Ignoring stale command timeout (seq $expectedSeq, current ${commandSequence.get()})")
            return
        }

        val currentState = _state.value
        Timber.w("Command timeout in state: $currentState")

        when (currentState) {
            is KernelState.SelectingApplication,
            is KernelState.InitiatingApplication,
            is KernelState.ReadingApplicationData -> {
                // Can retry
                handleTryAgain("Communication timeout")
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
     * Wait-for-card timeout
     */
    private fun onWaitForCardTimeout() {
        Timber.w("Wait for card timeout")
        setOutcome(KernelOutcome.EndApplication("Timeout waiting for card"))
    }

    /**
     * Overall processing timeout
     */
    private fun onProcessingTimeout() {
        Timber.w("Processing timeout")
        abort("Processing timeout")
    }

    /**
     * Online response timeout
     */
    private fun onOnlineTimeout() {
        Timber.w("Online response timeout")
        val data = transactionData
        if (data != null) {
            setOutcome(KernelOutcome.TornTransaction(data))
        } else {
            setOutcome(KernelOutcome.EndApplication("Online timeout"))
        }
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
        handleTryAgain("Multiple cards detected, please present only one card")
    }

    /**
     * Abort transaction
     */
    fun abort(reason: String) {
        if (isAborted.getAndSet(true)) return

        Timber.w("Transaction aborted: $reason")
        cancelAllTimeouts()

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
        cancelAllTimeouts()
        transactionScope?.cancel()
        transactionScope = null

        isAborted.set(false)
        isCardRemoved.set(false)
        tryAgainCount.set(0)
        commandSequence.set(0)
        transactionData = null

        _state.value = KernelState.Idle
        _outcome.value = null
    }

    // ==================== Timeout Management ====================

    /**
     * Start command timeout with sequence ID to prevent races
     *
     * @return The command sequence ID for this timeout
     */
    fun startCommandTimeout(): Int {
        val seq = commandSequence.incrementAndGet()
        commandTimeoutJob?.cancel()
        commandTimeoutJob = transactionScope?.launch {
            delay(config.commandTimeoutMs)
            if (!isAborted.get()) {
                onCommandTimeout(seq)
            }
        }
        return seq
    }

    /**
     * Cancel command timeout (command completed successfully)
     */
    fun cancelCommandTimeout() {
        commandSequence.incrementAndGet()  // Invalidate any pending timeout
        commandTimeoutJob?.cancel()
        commandTimeoutJob = null
    }

    private fun startWaitForCardTimeout() {
        waitForCardTimeoutJob = transactionScope?.launch {
            delay(config.waitForCardTimeoutMs)
            if (!isAborted.get() && _state.value == KernelState.WaitingForCard) {
                onWaitForCardTimeout()
            }
        }
    }

    private fun cancelWaitForCardTimeout() {
        waitForCardTimeoutJob?.cancel()
        waitForCardTimeoutJob = null
    }

    private fun startProcessingTimeout() {
        processingTimeoutJob = transactionScope?.launch {
            delay(config.overallTimeoutMs)
            if (!isAborted.get()) {
                onProcessingTimeout()
            }
        }
    }

    private fun cancelProcessingTimeout() {
        processingTimeoutJob?.cancel()
        processingTimeoutJob = null
    }

    private fun startOnlineTimeout() {
        onlineTimeoutJob = transactionScope?.launch {
            delay(config.onlineResponseTimeoutMs)
            if (!isAborted.get()) {
                onOnlineTimeout()
            }
        }
    }

    private fun cancelOnlineTimeout() {
        onlineTimeoutJob?.cancel()
        onlineTimeoutJob = null
    }

    private fun cancelAllTimeouts() {
        cancelWaitForCardTimeout()
        cancelProcessingTimeout()
        cancelCommandTimeout()
        cancelOnlineTimeout()
    }

    // ==================== State Transition ====================

    private fun transition(newState: KernelState) {
        val oldState = _state.value

        // Validate transition
        val validTargets = validTransitions[oldState]
        if (validTargets != null && newState !in validTargets) {
            Timber.e("Invalid state transition: $oldState → $newState (allowed: $validTargets)")
            // Allow the transition but log the error for debugging
        }

        Timber.d("State transition: $oldState → $newState")
        _state.value = newState
    }

    private fun setOutcome(outcome: KernelOutcome) {
        cancelAllTimeouts()
        _outcome.value = outcome

        // Determine terminal state based on outcome type
        val terminalState = when (outcome) {
            is KernelOutcome.Approved,
            is KernelOutcome.Declined,
            is KernelOutcome.OnlineRequest -> KernelState.Complete

            is KernelOutcome.EndApplication,
            is KernelOutcome.TryAnotherInterface,
            is KernelOutcome.TryAgain,
            is KernelOutcome.SelectNext,
            is KernelOutcome.TornTransaction -> KernelState.TerminalOutcome
        }

        transition(terminalState)
    }

    /**
     * Create fallback transaction data if original is null
     */
    private fun createFallbackData(): TransactionStateData {
        return TransactionStateData(
            transactionId = "UNKNOWN",
            amount = 0,
            currencyCode = "000",
            transactionType = 0x00
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

    // Online authorization states
    object OnlineAuthorization : KernelState()
    object IssuerScriptProcessing : KernelState()
    object SecondGenerateAc : KernelState()

    // Terminal states
    object Complete : KernelState()          // Successful completion (Approved/Declined/OnlineRequest)
    object TerminalOutcome : KernelState()   // Terminal outcome (TryAgain/SelectNext/EndApplication/etc)

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

    // First Cryptogram
    val cryptogramRequested: Boolean = false,
    val requestedCryptogramType: CryptogramType? = null,
    val cryptogramGenerated: Boolean = false,
    val actualCryptogramType: CryptogramType? = null,
    val cryptogram: ByteArray? = null,

    // Online response
    val onlineResponseReceived: Boolean = false,
    val onlineApproved: Boolean = false,
    val authorizationCode: String? = null,
    val issuerAuthData: ByteArray? = null,
    val issuerScriptsProcessed: Boolean = false,

    // Second Cryptogram (after online)
    val secondCryptogramType: CryptogramType? = null,
    val secondCryptogram: ByteArray? = null,

    // Card data
    val pan: String? = null,
    val panSequenceNumber: String? = null,
    val track2Equivalent: ByteArray? = null,

    // For torn transaction recovery
    val atc: ByteArray? = null,
    val unpredictableNumber: ByteArray? = null
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
    val waitForCardTimeoutMs: Long = 60_000,       // 60 seconds to tap card
    val commandTimeoutMs: Long = 3_000,            // 3 seconds per APDU (increased from 1s)
    val overallTimeoutMs: Long = 30_000,           // 30 seconds for entire transaction
    val onlineResponseTimeoutMs: Long = 45_000,    // 45 seconds for online response
    val maxTryAgainAttempts: Int = 3               // Max retry attempts before failure
)
