package com.atlas.softpos.kernel.common

import com.atlas.softpos.security.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber
import java.util.concurrent.atomic.AtomicReference

/**
 * EMV Transaction State Machine
 *
 * Manages transaction state transitions with fail-safe behavior:
 * - Enforces valid state transitions
 * - Automatic cleanup on failure
 * - Memory clearing on state exit
 * - Transaction logging for debugging
 *
 * Reference: EMV Contactless Book A, Section 7 - Transaction Flow
 */
class TransactionStateMachine {

    private val currentState = AtomicReference(TransactionState.IDLE)
    private val mutex = Mutex()
    private val stateHistory = mutableListOf<StateTransition>()
    private val sensitiveDataScope = SensitiveDataScope()

    // Transaction context
    private var transactionId: String? = null
    private val transactionTimer = TransactionTimer()
    private var lastError: TransactionError? = null

    /**
     * Transaction states per EMV flow
     */
    enum class TransactionState {
        IDLE,                       // No transaction in progress
        AWAITING_CARD,             // Waiting for card tap
        CARD_DETECTED,             // Card in field, not yet selected
        APPLICATION_SELECTION,      // SELECT command in progress
        INITIATE_APPLICATION,       // GPO in progress
        READ_APPLICATION_DATA,      // Reading records
        OFFLINE_DATA_AUTH,          // ODA processing
        PROCESS_RESTRICTIONS,       // Checking restrictions
        CARDHOLDER_VERIFICATION,    // CVM processing
        TERMINAL_RISK_MANAGEMENT,   // Risk checks
        TERMINAL_ACTION_ANALYSIS,   // TAA
        FIRST_GENERATE_AC,          // First GENERATE AC
        ONLINE_PROCESSING,          // Waiting for online response
        ISSUER_AUTHENTICATION,      // Processing issuer auth
        SECOND_GENERATE_AC,         // Second GENERATE AC (if needed)
        COMPLETION,                 // Transaction complete
        ERROR,                      // Error state
        CANCELLED                   // Transaction cancelled
    }

    /**
     * Valid state transitions
     */
    private val validTransitions = mapOf(
        TransactionState.IDLE to setOf(
            TransactionState.AWAITING_CARD
        ),
        TransactionState.AWAITING_CARD to setOf(
            TransactionState.CARD_DETECTED,
            TransactionState.CANCELLED,
            TransactionState.ERROR
        ),
        TransactionState.CARD_DETECTED to setOf(
            TransactionState.APPLICATION_SELECTION,
            TransactionState.ERROR
        ),
        TransactionState.APPLICATION_SELECTION to setOf(
            TransactionState.INITIATE_APPLICATION,
            TransactionState.CARD_DETECTED,  // Try different app
            TransactionState.ERROR
        ),
        TransactionState.INITIATE_APPLICATION to setOf(
            TransactionState.READ_APPLICATION_DATA,
            TransactionState.FIRST_GENERATE_AC,  // No ODA needed
            TransactionState.ERROR
        ),
        TransactionState.READ_APPLICATION_DATA to setOf(
            TransactionState.OFFLINE_DATA_AUTH,
            TransactionState.PROCESS_RESTRICTIONS,  // No ODA
            TransactionState.ERROR
        ),
        TransactionState.OFFLINE_DATA_AUTH to setOf(
            TransactionState.PROCESS_RESTRICTIONS,
            TransactionState.ERROR
        ),
        TransactionState.PROCESS_RESTRICTIONS to setOf(
            TransactionState.CARDHOLDER_VERIFICATION,
            TransactionState.TERMINAL_RISK_MANAGEMENT,  // No CVM needed
            TransactionState.ERROR
        ),
        TransactionState.CARDHOLDER_VERIFICATION to setOf(
            TransactionState.TERMINAL_RISK_MANAGEMENT,
            TransactionState.ERROR
        ),
        TransactionState.TERMINAL_RISK_MANAGEMENT to setOf(
            TransactionState.TERMINAL_ACTION_ANALYSIS,
            TransactionState.ERROR
        ),
        TransactionState.TERMINAL_ACTION_ANALYSIS to setOf(
            TransactionState.FIRST_GENERATE_AC,
            TransactionState.ERROR
        ),
        TransactionState.FIRST_GENERATE_AC to setOf(
            TransactionState.COMPLETION,  // Offline approved/declined
            TransactionState.ONLINE_PROCESSING,  // Online required
            TransactionState.ERROR
        ),
        TransactionState.ONLINE_PROCESSING to setOf(
            TransactionState.ISSUER_AUTHENTICATION,
            TransactionState.COMPLETION,  // Online result received
            TransactionState.ERROR
        ),
        TransactionState.ISSUER_AUTHENTICATION to setOf(
            TransactionState.SECOND_GENERATE_AC,
            TransactionState.COMPLETION,
            TransactionState.ERROR
        ),
        TransactionState.SECOND_GENERATE_AC to setOf(
            TransactionState.COMPLETION,
            TransactionState.ERROR
        ),
        TransactionState.COMPLETION to setOf(
            TransactionState.IDLE  // Reset for next transaction
        ),
        TransactionState.ERROR to setOf(
            TransactionState.IDLE  // Reset for next transaction
        ),
        TransactionState.CANCELLED to setOf(
            TransactionState.IDLE  // Reset for next transaction
        )
    )

    /**
     * Get current state
     */
    fun getState(): TransactionState = currentState.get()

    /**
     * Get transaction ID
     */
    fun getTransactionId(): String? = transactionId

    /**
     * Start a new transaction
     */
    suspend fun startTransaction(txnId: String = generateTransactionId()): Result<Unit> = mutex.withLock {
        val current = currentState.get()
        if (current != TransactionState.IDLE) {
            return Result.failure(IllegalStateException("Cannot start transaction from state: $current"))
        }

        transactionId = txnId
        transactionTimer.start()
        lastError = null
        stateHistory.clear()

        transition(TransactionState.AWAITING_CARD)
        Timber.i("Transaction started: $txnId")

        return Result.success(Unit)
    }

    /**
     * Transition to a new state
     */
    suspend fun transition(newState: TransactionState): Result<Unit> = mutex.withLock {
        val current = currentState.get()
        val validNext = validTransitions[current] ?: emptySet()

        if (newState !in validNext) {
            Timber.e("Invalid state transition: $current -> $newState")
            return Result.failure(
                IllegalStateException("Invalid transition from $current to $newState")
            )
        }

        // Record transition
        stateHistory.add(StateTransition(
            from = current,
            to = newState,
            timestamp = System.currentTimeMillis()
        ))

        // Update timer phase
        transactionTimer.enterPhase(mapStateToTimerPhase(newState))

        // Perform any cleanup for exiting state
        onExitState(current)

        // Update state
        currentState.set(newState)
        Timber.d("State transition: $current -> $newState")

        // Perform any initialization for entering state
        onEnterState(newState)

        return Result.success(Unit)
    }

    /**
     * Register sensitive data for automatic cleanup
     */
    fun <T : Clearable> registerSensitiveData(data: T): T {
        return sensitiveDataScope.register(data)
    }

    /**
     * Force transition to error state with error details
     */
    suspend fun setError(error: TransactionError): Result<Unit> {
        lastError = error
        return transition(TransactionState.ERROR)
    }

    /**
     * Cancel the current transaction
     * Uses mutex to prevent race conditions with state transitions
     */
    suspend fun cancel(): Result<Unit> = mutex.withLock {
        val current = currentState.get()
        if (current == TransactionState.IDLE) {
            return Result.success(Unit)
        }

        // Force transition to cancelled
        stateHistory.add(StateTransition(
            from = current,
            to = TransactionState.CANCELLED,
            timestamp = System.currentTimeMillis()
        ))

        cleanupTransaction()
        currentState.set(TransactionState.CANCELLED)
        Timber.i("Transaction cancelled from state: $current")

        return Result.success(Unit)
    }

    /**
     * Reset to idle state
     */
    suspend fun reset(): Result<Unit> = mutex.withLock {
        cleanupTransaction()
        currentState.set(TransactionState.IDLE)
        Timber.i("Transaction state machine reset")
        return Result.success(Unit)
    }

    /**
     * Get transaction summary
     */
    fun getTransactionSummary(): TransactionSummary {
        return TransactionSummary(
            transactionId = transactionId,
            finalState = currentState.get(),
            timing = transactionTimer.getTimingSummary(),
            stateHistory = stateHistory.toList(),
            error = lastError
        )
    }

    /**
     * Check if transaction is in progress
     */
    fun isTransactionInProgress(): Boolean {
        val state = currentState.get()
        return state != TransactionState.IDLE &&
                state != TransactionState.COMPLETION &&
                state != TransactionState.ERROR &&
                state != TransactionState.CANCELLED
    }

    /**
     * Check if transaction completed successfully
     */
    fun isTransactionComplete(): Boolean {
        return currentState.get() == TransactionState.COMPLETION
    }

    /**
     * Check if transaction failed
     */
    fun isTransactionFailed(): Boolean {
        val state = currentState.get()
        return state == TransactionState.ERROR || state == TransactionState.CANCELLED
    }

    private fun onExitState(state: TransactionState) {
        // Perform cleanup when leaving certain states
        when (state) {
            TransactionState.CARDHOLDER_VERIFICATION -> {
                // Clear any PIN data
                Timber.d("Clearing CVM data on exit")
            }
            TransactionState.FIRST_GENERATE_AC,
            TransactionState.SECOND_GENERATE_AC -> {
                // Clear cryptogram working data
                Timber.d("Clearing AC working data on exit")
            }
            else -> { /* No special cleanup */ }
        }
    }

    private fun onEnterState(state: TransactionState) {
        when (state) {
            TransactionState.COMPLETION -> {
                val summary = transactionTimer.stop()
                Timber.i("Transaction complete: $summary")
            }
            TransactionState.ERROR -> {
                Timber.e("Transaction error: $lastError")
                cleanupTransaction()
            }
            TransactionState.CANCELLED -> {
                Timber.w("Transaction cancelled")
                cleanupTransaction()
            }
            else -> { /* No special initialization */ }
        }
    }

    private fun cleanupTransaction() {
        // Clear all sensitive data
        sensitiveDataScope.close()

        // Clear transaction context
        transactionId = null
        lastError = null
    }

    private fun mapStateToTimerPhase(state: TransactionState): TransactionTimer.TransactionPhase {
        return when (state) {
            TransactionState.IDLE -> TransactionTimer.TransactionPhase.IDLE
            TransactionState.AWAITING_CARD -> TransactionTimer.TransactionPhase.CARD_DETECTION
            TransactionState.CARD_DETECTED,
            TransactionState.APPLICATION_SELECTION -> TransactionTimer.TransactionPhase.APPLICATION_SELECTION
            TransactionState.INITIATE_APPLICATION -> TransactionTimer.TransactionPhase.GPO_PROCESSING
            TransactionState.READ_APPLICATION_DATA -> TransactionTimer.TransactionPhase.READ_RECORDS
            TransactionState.OFFLINE_DATA_AUTH -> TransactionTimer.TransactionPhase.ODA_PROCESSING
            TransactionState.PROCESS_RESTRICTIONS,
            TransactionState.CARDHOLDER_VERIFICATION -> TransactionTimer.TransactionPhase.CVM_PROCESSING
            TransactionState.TERMINAL_RISK_MANAGEMENT,
            TransactionState.TERMINAL_ACTION_ANALYSIS -> TransactionTimer.TransactionPhase.TERMINAL_ACTION
            TransactionState.FIRST_GENERATE_AC -> TransactionTimer.TransactionPhase.FIRST_GENERATE_AC
            TransactionState.ONLINE_PROCESSING,
            TransactionState.ISSUER_AUTHENTICATION -> TransactionTimer.TransactionPhase.ONLINE_PROCESSING
            TransactionState.SECOND_GENERATE_AC -> TransactionTimer.TransactionPhase.SECOND_GENERATE_AC
            TransactionState.COMPLETION,
            TransactionState.ERROR,
            TransactionState.CANCELLED -> TransactionTimer.TransactionPhase.COMPLETION
        }
    }

    private fun generateTransactionId(): String {
        return "TXN-${System.currentTimeMillis()}-${(Math.random() * 10000).toInt()}"
    }

    data class StateTransition(
        val from: TransactionState,
        val to: TransactionState,
        val timestamp: Long
    )

    data class TransactionSummary(
        val transactionId: String?,
        val finalState: TransactionState,
        val timing: TransactionTimer.TimingSummary,
        val stateHistory: List<StateTransition>,
        val error: TransactionError?
    ) {
        override fun toString(): String {
            return buildString {
                append("Transaction Summary\n")
                append("==================\n")
                append("ID: $transactionId\n")
                append("Final State: $finalState\n")
                append(timing)
                if (error != null) {
                    append("Error: $error\n")
                }
                append("\nState History:\n")
                stateHistory.forEachIndexed { index, transition ->
                    append("  $index: ${transition.from} -> ${transition.to}\n")
                }
            }
        }
    }
}

/**
 * Transaction context holder for passing data between states
 */
class TransactionContext : Clearable {

    private var cleared = false

    // Card data
    var aid: SensitiveByteArray? = null
    var pan: SensitivePan? = null
    var track2: SensitiveTrack2? = null
    var expiryDate: ByteArray? = null
    var panSequenceNumber: ByteArray? = null

    // Application data
    var aip: ByteArray? = null
    var afl: ByteArray? = null
    var applicationLabel: String? = null
    var preferredName: String? = null

    // Cryptographic data
    var atc: ByteArray? = null
    var cryptogram: SensitiveCryptogram? = null
    var issuerApplicationData: ByteArray? = null
    var cvmResults: ByteArray? = null

    // Terminal verification results
    var tvr: ByteArray = ByteArray(5)
    var tsi: ByteArray = ByteArray(2)

    // Transaction data
    var amount: Long = 0
    var currencyCode: Int = 0
    var transactionType: Byte = 0
    var unpredictableNumber: ByteArray? = null

    // Processing results
    var odaResult: OdaResult? = null
    var cvmResult: CvmResult? = null
    var terminalDecision: TerminalDecision? = null
    var onlineResult: OnlineResult? = null

    override fun clear() {
        if (cleared) return
        cleared = true

        // Clear sensitive data
        aid?.clear()
        pan?.clear()
        track2?.clear()
        cryptogram?.clear()

        // Clear byte arrays
        expiryDate?.let { SecureMemory.clear(it) }
        panSequenceNumber?.let { SecureMemory.clear(it) }
        aip?.let { SecureMemory.clear(it) }
        afl?.let { SecureMemory.clear(it) }
        atc?.let { SecureMemory.clear(it) }
        issuerApplicationData?.let { SecureMemory.clear(it) }
        cvmResults?.let { SecureMemory.clear(it) }
        SecureMemory.clear(tvr)
        SecureMemory.clear(tsi)
        unpredictableNumber?.let { SecureMemory.clear(it) }

        // Clear references
        aid = null
        pan = null
        track2 = null
        expiryDate = null
        panSequenceNumber = null
        aip = null
        afl = null
        atc = null
        cryptogram = null
        issuerApplicationData = null
        cvmResults = null
        unpredictableNumber = null
        odaResult = null
        cvmResult = null
        terminalDecision = null
        onlineResult = null
    }

    override fun isCleared(): Boolean = cleared

    enum class OdaResult {
        NOT_PERFORMED,
        SDA_SUCCESS,
        DDA_SUCCESS,
        CDA_SUCCESS,
        FAILED
    }

    enum class CvmResult {
        NOT_PERFORMED,
        NO_CVM,
        CDCVM_SUCCESS,
        SIGNATURE_REQUIRED,
        ONLINE_PIN_REQUIRED,
        FAILED
    }

    enum class TerminalDecision {
        APPROVE_OFFLINE,
        DECLINE_OFFLINE,
        GO_ONLINE,
        REQUEST_ONLINE_PIN
    }

    enum class OnlineResult {
        APPROVED,
        DECLINED,
        UNABLE_TO_GO_ONLINE,
        REFERRAL
    }
}

/**
 * Retry policy for recoverable operations
 */
class RetryPolicy(
    private val maxRetries: Int = 3,
    private val initialDelayMs: Long = 100,
    private val maxDelayMs: Long = 1000,
    private val backoffMultiplier: Double = 2.0
) {
    private var attemptCount = 0
    private var currentDelay = initialDelayMs

    /**
     * Check if retry is allowed
     */
    fun canRetry(): Boolean = attemptCount < maxRetries

    /**
     * Record a retry attempt and get delay before next try
     */
    fun recordRetry(): Long {
        attemptCount++
        val delay = currentDelay
        currentDelay = minOf((currentDelay * backoffMultiplier).toLong(), maxDelayMs)
        return delay
    }

    /**
     * Reset for new operation
     */
    fun reset() {
        attemptCount = 0
        currentDelay = initialDelayMs
    }

    /**
     * Get remaining retries
     */
    fun remainingRetries(): Int = maxRetries - attemptCount
}
