package com.atlas.softpos.recovery

import android.nfc.TagLostException
import com.atlas.softpos.core.apdu.ResponseApdu
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import timber.log.Timber
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLException

/**
 * Comprehensive Transaction Error Recovery Framework
 *
 * Handles all failure scenarios in EMV contactless transactions:
 *
 * 1. NFC Communication Errors
 *    - Tag lost (card removed too early)
 *    - Transceive failed (communication error)
 *    - Timeout during card communication
 *
 * 2. Card Response Errors
 *    - SW1/SW2 error codes
 *    - Malformed responses
 *    - Missing mandatory data
 *
 * 3. Processing Errors
 *    - ODA failures
 *    - CVM failures
 *    - Cryptogram generation failures
 *
 * 4. Network Errors (for online authorization)
 *    - Connection timeout
 *    - SSL/TLS errors
 *    - Host unreachable
 *
 * 5. System Errors
 *    - Out of memory
 *    - Crypto failures
 *    - Internal exceptions
 */
class TransactionErrorRecovery(
    private val config: ErrorRecoveryConfig = ErrorRecoveryConfig()
) {
    private val retryCount = AtomicInteger(0)
    private val errorHistory = mutableListOf<RecoveredError>()

    /**
     * Execute an operation with automatic retry and recovery
     */
    suspend fun <T> executeWithRecovery(
        operation: String,
        retryPolicy: RetryPolicy = config.defaultRetryPolicy,
        block: suspend () -> T
    ): RecoveryResult<T> {
        var lastError: Throwable? = null
        var attempt = 0

        while (attempt <= retryPolicy.maxRetries) {
            try {
                val result = block()
                if (attempt > 0) {
                    Timber.d("$operation succeeded after $attempt retries")
                }
                return RecoveryResult.Success(result)
            } catch (e: CancellationException) {
                // Don't retry cancellation
                throw e
            } catch (e: Exception) {
                lastError = e
                val errorInfo = classifyError(e)

                Timber.w("$operation failed (attempt ${attempt + 1}): ${errorInfo.category} - ${e.message}")

                recordError(operation, errorInfo, attempt)

                if (!errorInfo.isRetryable || attempt >= retryPolicy.maxRetries) {
                    return RecoveryResult.Failed(
                        error = errorInfo,
                        attempts = attempt + 1,
                        canRetryManually = errorInfo.canRetryManually
                    )
                }

                // Apply backoff before retry
                val backoffMs = calculateBackoff(attempt, retryPolicy)
                Timber.d("Retrying $operation in ${backoffMs}ms...")
                delay(backoffMs)

                attempt++
                retryCount.incrementAndGet()
            }
        }

        return RecoveryResult.Failed(
            error = classifyError(lastError ?: Exception("Unknown error")),
            attempts = attempt,
            canRetryManually = true
        )
    }

    /**
     * Handle a card response and determine if recovery is possible
     */
    fun handleCardResponse(response: ResponseApdu, context: String): CardResponseRecovery {
        val sw1 = response.sw1.toInt() and 0xFF
        val sw2 = response.sw2.toInt() and 0xFF

        return when {
            // Success
            sw1 == 0x90 && sw2 == 0x00 -> CardResponseRecovery.Success

            // Successful with warning
            sw1 == 0x62 || sw1 == 0x63 -> {
                Timber.w("$context: Warning SW=${response.statusWord}")
                CardResponseRecovery.SuccessWithWarning(parseWarning(sw1, sw2))
            }

            // Retryable errors
            sw1 == 0x69 && sw2 == 0x85 -> {
                // Conditions not satisfied - may be transient
                CardResponseRecovery.Retry("Conditions not satisfied")
            }

            sw1 == 0x69 && sw2 == 0x88 -> {
                // SM data objects incorrect
                CardResponseRecovery.Retry("Secure messaging error")
            }

            // Try another interface
            sw1 == 0x69 && sw2 == 0x84 -> {
                CardResponseRecovery.TryAnotherInterface("Reference data not usable")
            }

            sw1 == 0x69 && sw2 == 0x86 -> {
                CardResponseRecovery.TryAnotherInterface("Command not allowed (no EF selected)")
            }

            // Fatal card errors
            sw1 == 0x6A && sw2 == 0x81 -> {
                CardResponseRecovery.Fatal("Function not supported")
            }

            sw1 == 0x6A && sw2 == 0x82 -> {
                CardResponseRecovery.Fatal("File or application not found")
            }

            sw1 == 0x6A && sw2 == 0x83 -> {
                CardResponseRecovery.Fatal("Record not found")
            }

            sw1 == 0x67 && sw2 == 0x00 -> {
                CardResponseRecovery.Fatal("Wrong length")
            }

            sw1 == 0x6E && sw2 == 0x00 -> {
                CardResponseRecovery.Fatal("Class not supported")
            }

            sw1 == 0x6D && sw2 == 0x00 -> {
                CardResponseRecovery.Fatal("Instruction not supported")
            }

            // Data available (response chaining)
            sw1 == 0x61 -> {
                CardResponseRecovery.GetMoreData(sw2)
            }

            // Blocked/locked
            sw1 == 0x69 && sw2 == 0x83 -> {
                CardResponseRecovery.Fatal("Authentication method blocked")
            }

            sw1 == 0x69 && sw2 == 0x84 -> {
                CardResponseRecovery.Fatal("Referenced data invalidated")
            }

            // Application specific
            sw1 == 0x6F -> {
                CardResponseRecovery.Fatal("No precise diagnosis (internal error)")
            }

            else -> {
                Timber.w("$context: Unhandled SW=$sw1$sw2")
                CardResponseRecovery.Unknown(sw1, sw2)
            }
        }
    }

    /**
     * Classify an exception into an error category
     */
    fun classifyError(error: Throwable): ErrorInfo {
        return when (error) {
            // NFC Errors
            is TagLostException -> ErrorInfo(
                category = ErrorCategory.NFC_TAG_LOST,
                message = "Card removed too early",
                isRetryable = true,
                canRetryManually = true,
                userMessage = "Please hold card still until transaction completes",
                recoveryAction = RecoveryAction.TAP_AGAIN
            )

            is IOException -> when {
                error.message?.contains("Tag was lost", ignoreCase = true) == true -> ErrorInfo(
                    category = ErrorCategory.NFC_TAG_LOST,
                    message = "Card connection lost",
                    isRetryable = true,
                    canRetryManually = true,
                    userMessage = "Card removed during transaction. Please tap again.",
                    recoveryAction = RecoveryAction.TAP_AGAIN
                )

                error.message?.contains("Transceive failed", ignoreCase = true) == true -> ErrorInfo(
                    category = ErrorCategory.NFC_TRANSCEIVE_FAILED,
                    message = "Communication with card failed",
                    isRetryable = true,
                    canRetryManually = true,
                    userMessage = "Unable to read card. Please tap again.",
                    recoveryAction = RecoveryAction.TAP_AGAIN
                )

                error is SocketTimeoutException -> ErrorInfo(
                    category = ErrorCategory.NETWORK_TIMEOUT,
                    message = "Network request timed out",
                    isRetryable = true,
                    canRetryManually = true,
                    userMessage = "Connection timed out. Please try again.",
                    recoveryAction = RecoveryAction.RETRY_NETWORK
                )

                error is UnknownHostException -> ErrorInfo(
                    category = ErrorCategory.NETWORK_UNREACHABLE,
                    message = "Unable to reach server",
                    isRetryable = false,
                    canRetryManually = true,
                    userMessage = "No network connection. Please check your internet.",
                    recoveryAction = RecoveryAction.CHECK_NETWORK
                )

                else -> ErrorInfo(
                    category = ErrorCategory.IO_ERROR,
                    message = error.message ?: "I/O error",
                    isRetryable = true,
                    canRetryManually = true,
                    userMessage = "Communication error. Please try again.",
                    recoveryAction = RecoveryAction.TAP_AGAIN
                )
            }

            is SSLException -> ErrorInfo(
                category = ErrorCategory.NETWORK_SSL_ERROR,
                message = "Secure connection failed: ${error.message}",
                isRetryable = false,
                canRetryManually = false,
                userMessage = "Secure connection error. Please contact support.",
                recoveryAction = RecoveryAction.CONTACT_SUPPORT
            )

            is SecurityException -> ErrorInfo(
                category = ErrorCategory.SECURITY_ERROR,
                message = "Security violation: ${error.message}",
                isRetryable = false,
                canRetryManually = false,
                userMessage = "Security error. Transaction cancelled.",
                recoveryAction = RecoveryAction.ABORT
            )

            is OutOfMemoryError -> ErrorInfo(
                category = ErrorCategory.SYSTEM_ERROR,
                message = "Out of memory",
                isRetryable = false,
                canRetryManually = false,
                userMessage = "System error. Please restart the app.",
                recoveryAction = RecoveryAction.RESTART_APP
            )

            is IllegalStateException -> ErrorInfo(
                category = ErrorCategory.PROCESSING_ERROR,
                message = error.message ?: "Invalid state",
                isRetryable = false,
                canRetryManually = true,
                userMessage = "Transaction error. Please try again.",
                recoveryAction = RecoveryAction.RESTART_TRANSACTION
            )

            is IllegalArgumentException -> ErrorInfo(
                category = ErrorCategory.PROCESSING_ERROR,
                message = error.message ?: "Invalid data",
                isRetryable = false,
                canRetryManually = true,
                userMessage = "Invalid transaction data. Please try again.",
                recoveryAction = RecoveryAction.RESTART_TRANSACTION
            )

            else -> ErrorInfo(
                category = ErrorCategory.UNKNOWN,
                message = error.message ?: "Unknown error",
                isRetryable = false,
                canRetryManually = true,
                userMessage = "An error occurred. Please try again.",
                recoveryAction = RecoveryAction.RESTART_TRANSACTION
            )
        }
    }

    /**
     * Get recovery suggestion for a specific error
     */
    fun getRecoverySuggestion(error: ErrorInfo): RecoverySuggestion {
        return when (error.recoveryAction) {
            RecoveryAction.TAP_AGAIN -> RecoverySuggestion(
                title = "Tap Card Again",
                description = "Hold the card steady on the device until the transaction completes.",
                steps = listOf(
                    "Ensure the card is contactless-enabled (look for the wave symbol)",
                    "Hold the card flat against the back of the device",
                    "Keep the card in place until you see confirmation",
                    "Try different positions if it doesn't work"
                ),
                canAutoRetry = true
            )

            RecoveryAction.RETRY_NETWORK -> RecoverySuggestion(
                title = "Retry Connection",
                description = "The connection timed out. We'll try again.",
                steps = listOf(
                    "Ensure you have a stable internet connection",
                    "Wait a moment and try again",
                    "If problem persists, check your network settings"
                ),
                canAutoRetry = true
            )

            RecoveryAction.CHECK_NETWORK -> RecoverySuggestion(
                title = "Check Network",
                description = "Unable to connect to the server.",
                steps = listOf(
                    "Check that Wi-Fi or mobile data is enabled",
                    "Ensure you have internet access",
                    "Try again once connected"
                ),
                canAutoRetry = false
            )

            RecoveryAction.TRY_ANOTHER_CARD -> RecoverySuggestion(
                title = "Try Another Card",
                description = "This card cannot be used for this transaction.",
                steps = listOf(
                    "Try a different payment card",
                    "Ensure the card is not expired",
                    "Contact your bank if the issue persists"
                ),
                canAutoRetry = false
            )

            RecoveryAction.CONTACT_SUPPORT -> RecoverySuggestion(
                title = "Contact Support",
                description = "A technical error occurred that requires assistance.",
                steps = listOf(
                    "Note the error code for reference",
                    "Contact technical support",
                    "Do not retry until advised"
                ),
                canAutoRetry = false
            )

            RecoveryAction.RESTART_TRANSACTION -> RecoverySuggestion(
                title = "Start New Transaction",
                description = "Please start a new transaction.",
                steps = listOf(
                    "Cancel the current transaction",
                    "Begin a new transaction",
                    "Tap the card when prompted"
                ),
                canAutoRetry = false
            )

            RecoveryAction.RESTART_APP -> RecoverySuggestion(
                title = "Restart Application",
                description = "A system error occurred.",
                steps = listOf(
                    "Close the application completely",
                    "Reopen the application",
                    "Try the transaction again"
                ),
                canAutoRetry = false
            )

            RecoveryAction.ABORT -> RecoverySuggestion(
                title = "Transaction Cancelled",
                description = "The transaction has been cancelled for security reasons.",
                steps = listOf(
                    "Do not retry this transaction",
                    "If you believe this is an error, contact support"
                ),
                canAutoRetry = false
            )
        }
    }

    /**
     * Calculate exponential backoff delay
     */
    private fun calculateBackoff(attempt: Int, policy: RetryPolicy): Long {
        val baseDelay = policy.initialDelayMs
        val exponentialDelay = baseDelay * (1 shl attempt)
        val cappedDelay = minOf(exponentialDelay, policy.maxDelayMs)

        // Add jitter to prevent thundering herd
        val jitter = (cappedDelay * 0.2 * Math.random()).toLong()

        return cappedDelay + jitter
    }

    private fun parseWarning(sw1: Int, sw2: Int): String {
        return when {
            sw1 == 0x62 && sw2 == 0x83 -> "Selected file invalidated"
            sw1 == 0x62 && sw2 == 0x84 -> "File control information incorrect"
            sw1 == 0x63 && (sw2 and 0xF0) == 0xC0 -> "Counter: ${sw2 and 0x0F} retries remaining"
            else -> "Warning: ${"%02X%02X".format(sw1, sw2)}"
        }
    }

    private fun recordError(operation: String, error: ErrorInfo, attempt: Int) {
        errorHistory.add(RecoveredError(
            operation = operation,
            error = error,
            attempt = attempt,
            timestamp = System.currentTimeMillis()
        ))

        // Keep only last 100 errors
        while (errorHistory.size > 100) {
            errorHistory.removeAt(0)
        }
    }

    /**
     * Get error statistics for diagnostics
     */
    fun getErrorStatistics(): ErrorStatistics {
        val now = System.currentTimeMillis()
        val last24h = errorHistory.filter { now - it.timestamp < 24 * 60 * 60 * 1000 }

        return ErrorStatistics(
            totalErrors = errorHistory.size,
            errorsLast24h = last24h.size,
            totalRetries = retryCount.get(),
            errorsByCategory = last24h.groupBy { it.error.category }.mapValues { it.value.size },
            mostCommonError = last24h.groupBy { it.error.category }
                .maxByOrNull { it.value.size }?.key
        )
    }

    /**
     * Clear error history
     */
    fun clearHistory() {
        errorHistory.clear()
        retryCount.set(0)
    }
}

// ==================== DATA CLASSES ====================

/**
 * Error recovery configuration
 */
data class ErrorRecoveryConfig(
    val defaultRetryPolicy: RetryPolicy = RetryPolicy(),
    val enableAutoRetry: Boolean = true,
    val logErrorsToAnalytics: Boolean = true
)

/**
 * Retry policy configuration
 */
data class RetryPolicy(
    val maxRetries: Int = 3,
    val initialDelayMs: Long = 100,
    val maxDelayMs: Long = 2000,
    val retryOnNetworkError: Boolean = true,
    val retryOnNfcError: Boolean = true
)

/**
 * Classified error information
 */
data class ErrorInfo(
    val category: ErrorCategory,
    val message: String,
    val isRetryable: Boolean,
    val canRetryManually: Boolean,
    val userMessage: String,
    val recoveryAction: RecoveryAction
)

/**
 * Error categories
 */
enum class ErrorCategory {
    // NFC Errors
    NFC_TAG_LOST,
    NFC_TRANSCEIVE_FAILED,
    NFC_TIMEOUT,
    NFC_NOT_SUPPORTED,

    // Card Response Errors
    CARD_ERROR,
    CARD_BLOCKED,
    CARD_NOT_SUPPORTED,

    // Processing Errors
    PROCESSING_ERROR,
    ODA_FAILED,
    CVM_FAILED,
    CRYPTOGRAM_FAILED,

    // Network Errors
    NETWORK_TIMEOUT,
    NETWORK_UNREACHABLE,
    NETWORK_SSL_ERROR,

    // Security Errors
    SECURITY_ERROR,

    // System Errors
    SYSTEM_ERROR,
    IO_ERROR,

    // Unknown
    UNKNOWN
}

/**
 * Recovery actions
 */
enum class RecoveryAction {
    TAP_AGAIN,
    RETRY_NETWORK,
    CHECK_NETWORK,
    TRY_ANOTHER_CARD,
    CONTACT_SUPPORT,
    RESTART_TRANSACTION,
    RESTART_APP,
    ABORT
}

/**
 * Recovery result
 */
sealed class RecoveryResult<out T> {
    data class Success<T>(val value: T) : RecoveryResult<T>()
    data class Failed(
        val error: ErrorInfo,
        val attempts: Int,
        val canRetryManually: Boolean
    ) : RecoveryResult<Nothing>()
}

/**
 * Card response recovery action
 */
sealed class CardResponseRecovery {
    object Success : CardResponseRecovery()
    data class SuccessWithWarning(val warning: String) : CardResponseRecovery()
    data class Retry(val reason: String) : CardResponseRecovery()
    data class TryAnotherInterface(val reason: String) : CardResponseRecovery()
    data class Fatal(val reason: String) : CardResponseRecovery()
    data class GetMoreData(val remaining: Int) : CardResponseRecovery()
    data class Unknown(val sw1: Int, val sw2: Int) : CardResponseRecovery()
}

/**
 * Recovery suggestion for user
 */
data class RecoverySuggestion(
    val title: String,
    val description: String,
    val steps: List<String>,
    val canAutoRetry: Boolean
)

/**
 * Recorded error for diagnostics
 */
data class RecoveredError(
    val operation: String,
    val error: ErrorInfo,
    val attempt: Int,
    val timestamp: Long
)

/**
 * Error statistics for diagnostics
 */
data class ErrorStatistics(
    val totalErrors: Int,
    val errorsLast24h: Int,
    val totalRetries: Int,
    val errorsByCategory: Map<ErrorCategory, Int>,
    val mostCommonError: ErrorCategory?
)
