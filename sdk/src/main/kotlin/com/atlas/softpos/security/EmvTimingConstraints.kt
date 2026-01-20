package com.atlas.softpos.security

import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber
import java.util.concurrent.atomic.AtomicLong

/**
 * EMV Timing Constraints and Transaction Timing Management
 *
 * Implements timing requirements per:
 * - EMV Contactless Book A: Architecture and General Requirements
 * - EMV Contactless Book B: Entry Point Specification
 * - EMVCo Contactless Terminal Level 2 Type Approval
 *
 * Key timing requirements:
 * - Total transaction time: Target < 500ms for tap-and-go
 * - Card response timeouts per command
 * - Processing time limits
 */
object EmvTimingConstraints {

    // ==================== CARD COMMUNICATION TIMEOUTS ====================

    /**
     * Frame Waiting Time (FWT) - Maximum time for card response
     * EMV Contactless Book D, Section 5.2.3
     * Default FWT is ~20ms, but can be extended via FWI
     */
    const val DEFAULT_FRAME_WAITING_TIME_MS = 20L

    /**
     * Maximum FWT after extension (FWTINT)
     * Per EMVCo Level 1 specification
     */
    const val MAX_FRAME_WAITING_TIME_MS = 500L

    /**
     * SELECT command timeout
     * Should complete within 100ms
     */
    const val SELECT_TIMEOUT_MS = 100L

    /**
     * GET PROCESSING OPTIONS timeout
     * Card may need to perform cryptographic operations
     */
    const val GPO_TIMEOUT_MS = 250L

    /**
     * READ RECORD timeout
     * Multiple records may need to be read
     */
    const val READ_RECORD_TIMEOUT_MS = 100L

    /**
     * GENERATE AC timeout
     * Card performs cryptogram generation
     */
    const val GENERATE_AC_TIMEOUT_MS = 250L

    /**
     * COMPUTE CRYPTOGRAPHIC CHECKSUM timeout
     * For mag stripe mode CVC3 generation
     */
    const val COMPUTE_CHECKSUM_TIMEOUT_MS = 150L

    /**
     * VERIFY PIN timeout
     */
    const val VERIFY_PIN_TIMEOUT_MS = 150L

    /**
     * GET DATA timeout
     */
    const val GET_DATA_TIMEOUT_MS = 100L

    // ==================== TRANSACTION PROCESSING TIMES ====================

    /**
     * Target total contactless transaction time
     * EMV tap-and-go should complete within 500ms
     */
    const val TARGET_TRANSACTION_TIME_MS = 500L

    /**
     * Maximum allowed transaction processing time
     * Before terminal should abort
     */
    const val MAX_TRANSACTION_TIME_MS = 1000L

    /**
     * Time allowed for ODA (Offline Data Authentication)
     * RSA operations can be slow
     */
    const val ODA_PROCESSING_TIME_MS = 200L

    /**
     * Time allowed for cryptogram verification
     */
    const val CRYPTOGRAM_VERIFICATION_TIME_MS = 100L

    /**
     * Time allowed for CVM processing
     */
    const val CVM_PROCESSING_TIME_MS = 100L

    // ==================== USER INTERACTION TIMEOUTS ====================

    /**
     * Maximum time to wait for card tap
     */
    const val CARD_DETECTION_TIMEOUT_MS = 30000L

    /**
     * Maximum time for PIN entry
     */
    const val PIN_ENTRY_TIMEOUT_MS = 60000L

    /**
     * Maximum time for user confirmation prompt
     */
    const val USER_CONFIRMATION_TIMEOUT_MS = 30000L

    /**
     * Display message minimum time (for user to read)
     */
    const val MIN_MESSAGE_DISPLAY_TIME_MS = 2000L

    // ==================== RETRY AND RECOVERY TIMEOUTS ====================

    /**
     * Time to wait between retry attempts
     */
    const val RETRY_DELAY_MS = 100L

    /**
     * Maximum time for single retry sequence
     */
    const val RETRY_SEQUENCE_TIMEOUT_MS = 3000L

    /**
     * Time to wait for card removal after decline
     */
    const val CARD_REMOVAL_TIMEOUT_MS = 3000L

    // ==================== ANTI-TEARING TIMEOUTS ====================

    /**
     * Maximum time to detect card removal (anti-tearing)
     * If card is removed during GENERATE AC, transaction must fail
     */
    const val ANTI_TEARING_DETECTION_MS = 50L

    // ==================== POLLING INTERVALS ====================

    /**
     * NFC polling interval during card detection
     */
    const val NFC_POLL_INTERVAL_MS = 50L

    /**
     * Status check interval during processing
     */
    const val PROCESSING_POLL_INTERVAL_MS = 10L
}

/**
 * Transaction timer for tracking EMV timing compliance
 */
class TransactionTimer {

    private val startTime = AtomicLong(0)
    private val phaseStartTime = AtomicLong(0)

    private var currentPhase: TransactionPhase = TransactionPhase.IDLE
    private val phaseTimes = mutableMapOf<TransactionPhase, Long>()

    enum class TransactionPhase {
        IDLE,
        CARD_DETECTION,
        APPLICATION_SELECTION,
        GPO_PROCESSING,
        READ_RECORDS,
        ODA_PROCESSING,
        CVM_PROCESSING,
        TERMINAL_ACTION,
        FIRST_GENERATE_AC,
        ONLINE_PROCESSING,
        SECOND_GENERATE_AC,
        COMPLETION
    }

    /**
     * Start the transaction timer
     */
    fun start() {
        val now = System.currentTimeMillis()
        startTime.set(now)
        phaseStartTime.set(now)
        currentPhase = TransactionPhase.CARD_DETECTION
    }

    /**
     * Move to the next transaction phase
     */
    fun enterPhase(phase: TransactionPhase) {
        val now = System.currentTimeMillis()
        val previousPhaseDuration = now - phaseStartTime.get()

        // Record previous phase duration
        phaseTimes[currentPhase] = previousPhaseDuration

        // Start new phase
        currentPhase = phase
        phaseStartTime.set(now)

        Timber.d("Transaction phase: $phase (previous: ${previousPhaseDuration}ms)")
    }

    /**
     * Get elapsed time since transaction start
     */
    fun getElapsedTime(): Long {
        return System.currentTimeMillis() - startTime.get()
    }

    /**
     * Get elapsed time in current phase
     */
    fun getPhaseElapsedTime(): Long {
        return System.currentTimeMillis() - phaseStartTime.get()
    }

    /**
     * Check if transaction is within target time
     */
    fun isWithinTargetTime(): Boolean {
        return getElapsedTime() <= EmvTimingConstraints.TARGET_TRANSACTION_TIME_MS
    }

    /**
     * Check if transaction has exceeded maximum time
     */
    fun hasExceededMaxTime(): Boolean {
        return getElapsedTime() > EmvTimingConstraints.MAX_TRANSACTION_TIME_MS
    }

    /**
     * Get remaining time before target exceeded
     */
    fun getRemainingTargetTime(): Long {
        return maxOf(0, EmvTimingConstraints.TARGET_TRANSACTION_TIME_MS - getElapsedTime())
    }

    /**
     * Get timing summary for the transaction
     */
    fun getTimingSummary(): TimingSummary {
        val totalTime = getElapsedTime()
        return TimingSummary(
            totalTimeMs = totalTime,
            withinTarget = totalTime <= EmvTimingConstraints.TARGET_TRANSACTION_TIME_MS,
            phaseTimes = phaseTimes.toMap(),
            currentPhase = currentPhase
        )
    }

    /**
     * Stop the timer and finalize
     */
    fun stop(): TimingSummary {
        enterPhase(TransactionPhase.COMPLETION)
        return getTimingSummary()
    }

    data class TimingSummary(
        val totalTimeMs: Long,
        val withinTarget: Boolean,
        val phaseTimes: Map<TransactionPhase, Long>,
        val currentPhase: TransactionPhase
    ) {
        override fun toString(): String {
            return buildString {
                append("Transaction Timing: ${totalTimeMs}ms")
                append(if (withinTarget) " [OK]" else " [SLOW]")
                append("\n")
                phaseTimes.forEach { (phase, time) ->
                    append("  $phase: ${time}ms\n")
                }
            }
        }
    }
}

/**
 * Command timer for individual APDU commands
 */
class CommandTimer(
    private val commandName: String,
    private val timeoutMs: Long
) {
    private val startTime = System.currentTimeMillis()

    /**
     * Get elapsed time
     */
    fun elapsed(): Long = System.currentTimeMillis() - startTime

    /**
     * Check if timeout has been exceeded
     */
    fun hasTimedOut(): Boolean = elapsed() > timeoutMs

    /**
     * Get remaining time before timeout
     */
    fun remaining(): Long = maxOf(0, timeoutMs - elapsed())

    /**
     * Log timing information
     */
    fun log() {
        val elapsedTime = elapsed()
        if (elapsedTime > timeoutMs * 0.8) {
            Timber.w("$commandName took ${elapsedTime}ms (timeout: ${timeoutMs}ms) - SLOW")
        } else {
            Timber.d("$commandName completed in ${elapsedTime}ms")
        }
    }
}

/**
 * Extension function to run a suspend block with EMV timing
 */
suspend fun <T> withEmvTimeout(
    timeoutMs: Long,
    commandName: String,
    block: suspend () -> T
): T {
    val timer = CommandTimer(commandName, timeoutMs)
    return try {
        withTimeout(timeoutMs) {
            block()
        }
    } finally {
        timer.log()
    }
}

/**
 * Extension function to run a suspend block with timeout, returning null on timeout
 */
suspend fun <T> withEmvTimeoutOrNull(
    timeoutMs: Long,
    commandName: String,
    block: suspend () -> T
): T? {
    val timer = CommandTimer(commandName, timeoutMs)
    return try {
        withTimeoutOrNull(timeoutMs) {
            block()
        }
    } finally {
        timer.log()
    }
}

/**
 * Timing compliance checker
 */
object TimingCompliance {

    /**
     * Check if a command response time is compliant
     */
    fun isCommandTimeCompliant(
        commandName: String,
        actualTimeMs: Long,
        maxTimeMs: Long
    ): ComplianceResult {
        return when {
            actualTimeMs <= maxTimeMs * 0.5 -> ComplianceResult.EXCELLENT
            actualTimeMs <= maxTimeMs * 0.8 -> ComplianceResult.GOOD
            actualTimeMs <= maxTimeMs -> ComplianceResult.ACCEPTABLE
            else -> ComplianceResult.NON_COMPLIANT
        }
    }

    /**
     * Check overall transaction timing compliance
     */
    fun isTransactionTimeCompliant(summary: TransactionTimer.TimingSummary): ComplianceResult {
        return when {
            summary.totalTimeMs <= 300 -> ComplianceResult.EXCELLENT
            summary.totalTimeMs <= 500 -> ComplianceResult.GOOD
            summary.totalTimeMs <= 1000 -> ComplianceResult.ACCEPTABLE
            else -> ComplianceResult.NON_COMPLIANT
        }
    }

    enum class ComplianceResult {
        EXCELLENT,    // Well within requirements
        GOOD,         // Comfortable margin
        ACCEPTABLE,   // Meets requirements
        NON_COMPLIANT // Exceeds allowed time
    }
}

/**
 * Rate limiter for transaction attempts
 * Prevents rapid-fire transaction attempts that could indicate fraud
 */
class TransactionRateLimiter(
    private val maxTransactionsPerMinute: Int = 10,
    private val minIntervalMs: Long = 1000
) {
    private val transactionTimes = mutableListOf<Long>()
    private var lastTransactionTime = 0L

    /**
     * Check if a new transaction is allowed
     */
    @Synchronized
    fun isAllowed(): Boolean {
        val now = System.currentTimeMillis()

        // Check minimum interval
        if (now - lastTransactionTime < minIntervalMs) {
            return false
        }

        // Clean up old entries
        transactionTimes.removeAll { now - it > 60000 }

        // Check rate
        return transactionTimes.size < maxTransactionsPerMinute
    }

    /**
     * Record a transaction attempt
     */
    @Synchronized
    fun recordTransaction() {
        val now = System.currentTimeMillis()
        transactionTimes.add(now)
        lastTransactionTime = now
    }

    /**
     * Get time until next transaction is allowed
     */
    @Synchronized
    fun getWaitTimeMs(): Long {
        val now = System.currentTimeMillis()
        return maxOf(0, minIntervalMs - (now - lastTransactionTime))
    }
}
