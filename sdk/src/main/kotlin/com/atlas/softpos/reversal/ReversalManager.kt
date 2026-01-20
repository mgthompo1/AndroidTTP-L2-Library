package com.atlas.softpos.reversal

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.atlas.softpos.kernel.common.TransactionStateData
import kotlinx.coroutines.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Reversal Manager
 *
 * Manages transaction reversals for torn transactions and timeout scenarios.
 * Reversals are persisted securely and retried until confirmed.
 *
 * EMV Requirements:
 * - Reversals must be stored persistently
 * - Reversals must be retried until successful or manually cleared
 * - Reversal queue must survive app restart
 * - Maximum reversal age before escalation (configurable)
 *
 * PCI Requirements:
 * - Reversal data must be encrypted at rest
 * - PAN must be masked in logs
 * - Sensitive data cleared after successful reversal
 */
class ReversalManager(
    private val context: Context,
    private val config: ReversalConfig = ReversalConfig()
) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val encryptedPrefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            "atlas_reversal_store",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val pendingReversals = ConcurrentHashMap<String, ReversalRecord>()
    private var retryJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Callback for sending reversals to acquirer
    private var reversalSender: ReversalSender? = null

    /**
     * Initialize reversal manager and load pending reversals
     */
    fun initialize() {
        loadPendingReversals()
        startRetryLoop()
        Timber.d("ReversalManager initialized. Pending reversals: ${pendingReversals.size}")
    }

    /**
     * Set the reversal sender callback
     */
    fun setReversalSender(sender: ReversalSender) {
        this.reversalSender = sender
    }

    /**
     * Queue a reversal for a torn transaction
     */
    fun queueReversal(
        transactionData: TransactionStateData,
        reason: ReversalReason
    ): String {
        val reversalId = UUID.randomUUID().toString()

        val record = ReversalRecord(
            reversalId = reversalId,
            originalTransactionId = transactionData.transactionId,
            amount = transactionData.amount,
            currencyCode = transactionData.currencyCode,
            pan = transactionData.pan?.let { maskPan(it) },
            panSequenceNumber = transactionData.panSequenceNumber,
            cryptogram = transactionData.cryptogram?.toHexString(),
            cryptogramType = transactionData.actualCryptogramType?.name,
            reason = reason,
            createdAt = System.currentTimeMillis(),
            attemptCount = 0,
            lastAttemptAt = null,
            status = ReversalStatus.PENDING
        )

        pendingReversals[reversalId] = record
        persistReversal(record)

        Timber.i("Reversal queued: $reversalId for transaction ${transactionData.transactionId}")

        // Attempt immediate send
        scope.launch {
            attemptReversal(record)
        }

        return reversalId
    }

    /**
     * Queue reversal from raw data (for timeout scenarios)
     */
    fun queueReversal(
        originalTransactionId: String,
        amount: Long,
        currencyCode: String,
        maskedPan: String?,
        reason: ReversalReason
    ): String {
        val reversalId = UUID.randomUUID().toString()

        val record = ReversalRecord(
            reversalId = reversalId,
            originalTransactionId = originalTransactionId,
            amount = amount,
            currencyCode = currencyCode,
            pan = maskedPan,
            panSequenceNumber = null,
            cryptogram = null,
            cryptogramType = null,
            reason = reason,
            createdAt = System.currentTimeMillis(),
            attemptCount = 0,
            lastAttemptAt = null,
            status = ReversalStatus.PENDING
        )

        pendingReversals[reversalId] = record
        persistReversal(record)

        Timber.i("Reversal queued: $reversalId")

        scope.launch {
            attemptReversal(record)
        }

        return reversalId
    }

    /**
     * Attempt to send a reversal
     */
    private suspend fun attemptReversal(record: ReversalRecord) {
        val sender = reversalSender
        if (sender == null) {
            Timber.w("No reversal sender configured")
            return
        }

        val updatedRecord = record.copy(
            attemptCount = record.attemptCount + 1,
            lastAttemptAt = System.currentTimeMillis(),
            status = ReversalStatus.IN_PROGRESS
        )
        pendingReversals[record.reversalId] = updatedRecord
        persistReversal(updatedRecord)

        try {
            Timber.d("Attempting reversal ${record.reversalId} (attempt ${updatedRecord.attemptCount})")

            val result = sender.sendReversal(updatedRecord)

            when (result) {
                is ReversalResult.Success -> {
                    Timber.i("Reversal ${record.reversalId} successful")
                    markReversalComplete(record.reversalId)
                }

                is ReversalResult.Duplicate -> {
                    Timber.i("Reversal ${record.reversalId} already processed (duplicate)")
                    markReversalComplete(record.reversalId)
                }

                is ReversalResult.Failed -> {
                    Timber.w("Reversal ${record.reversalId} failed: ${result.reason}")
                    val failedRecord = updatedRecord.copy(
                        status = ReversalStatus.PENDING,
                        lastError = result.reason
                    )
                    pendingReversals[record.reversalId] = failedRecord
                    persistReversal(failedRecord)
                }

                is ReversalResult.PermanentFailure -> {
                    Timber.e("Reversal ${record.reversalId} permanently failed: ${result.reason}")
                    markReversalFailed(record.reversalId, result.reason)
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Exception during reversal ${record.reversalId}")
            val errorRecord = updatedRecord.copy(
                status = ReversalStatus.PENDING,
                lastError = e.message
            )
            pendingReversals[record.reversalId] = errorRecord
            persistReversal(errorRecord)
        }
    }

    /**
     * Mark reversal as complete
     */
    private fun markReversalComplete(reversalId: String) {
        val record = pendingReversals.remove(reversalId)
        if (record != null) {
            val completedRecord = record.copy(
                status = ReversalStatus.COMPLETED,
                completedAt = System.currentTimeMillis()
            )
            // Keep completed record for audit trail
            persistReversal(completedRecord)

            // Remove from pending after retention period
            scope.launch {
                delay(config.completedRetentionMs)
                removeReversal(reversalId)
            }
        }
    }

    /**
     * Mark reversal as permanently failed
     */
    private fun markReversalFailed(reversalId: String, reason: String) {
        val record = pendingReversals[reversalId] ?: return
        val failedRecord = record.copy(
            status = ReversalStatus.FAILED,
            lastError = reason,
            completedAt = System.currentTimeMillis()
        )
        pendingReversals[reversalId] = failedRecord
        persistReversal(failedRecord)

        // Notify for manual intervention
        Timber.e("REVERSAL REQUIRES MANUAL INTERVENTION: $reversalId - $reason")
    }

    /**
     * Get all pending reversals
     */
    fun getPendingReversals(): List<ReversalRecord> {
        return pendingReversals.values
            .filter { it.status == ReversalStatus.PENDING || it.status == ReversalStatus.IN_PROGRESS }
            .toList()
    }

    /**
     * Get all reversals (including completed/failed)
     */
    fun getAllReversals(): List<ReversalRecord> {
        return pendingReversals.values.toList()
    }

    /**
     * Manually retry a specific reversal
     */
    suspend fun retryReversal(reversalId: String): Boolean {
        val record = pendingReversals[reversalId] ?: return false
        attemptReversal(record)
        return true
    }

    /**
     * Manually clear a reversal (use with caution)
     */
    fun clearReversal(reversalId: String, manualClearReason: String) {
        Timber.w("Manual reversal clear: $reversalId - $manualClearReason")
        val record = pendingReversals.remove(reversalId)
        if (record != null) {
            val clearedRecord = record.copy(
                status = ReversalStatus.MANUALLY_CLEARED,
                lastError = "Manually cleared: $manualClearReason",
                completedAt = System.currentTimeMillis()
            )
            persistReversal(clearedRecord)
        }
    }

    /**
     * Check if there are any pending reversals
     */
    fun hasPendingReversals(): Boolean {
        return pendingReversals.values.any {
            it.status == ReversalStatus.PENDING || it.status == ReversalStatus.IN_PROGRESS
        }
    }

    /**
     * Start retry loop for pending reversals
     */
    private fun startRetryLoop() {
        retryJob?.cancel()
        retryJob = scope.launch {
            while (isActive) {
                delay(config.retryIntervalMs)

                val pending = getPendingReversals()
                for (record in pending) {
                    // Check if enough time has passed since last attempt
                    val timeSinceLastAttempt = System.currentTimeMillis() - (record.lastAttemptAt ?: 0)
                    val backoffTime = calculateBackoff(record.attemptCount)

                    if (timeSinceLastAttempt >= backoffTime) {
                        // Check max attempts
                        if (record.attemptCount >= config.maxAttempts) {
                            Timber.w("Reversal ${record.reversalId} exceeded max attempts")
                            markReversalFailed(record.reversalId, "Max attempts exceeded")
                        } else {
                            attemptReversal(record)
                        }
                    }
                }

                // Check for aged reversals requiring escalation
                checkAgedReversals()
            }
        }
    }

    /**
     * Calculate exponential backoff time
     */
    private fun calculateBackoff(attemptCount: Int): Long {
        val baseBackoff = config.baseBackoffMs
        val maxBackoff = config.maxBackoffMs
        val backoff = (baseBackoff * Math.pow(2.0, attemptCount.toDouble())).toLong()
        return minOf(backoff, maxBackoff)
    }

    /**
     * Check for aged reversals requiring escalation
     */
    private fun checkAgedReversals() {
        val now = System.currentTimeMillis()
        for (record in pendingReversals.values) {
            if (record.status != ReversalStatus.PENDING) continue

            val age = now - record.createdAt
            if (age > config.escalationThresholdMs) {
                Timber.e("AGED REVERSAL REQUIRES ATTENTION: ${record.reversalId} - age: ${age / 1000}s")
                // Could trigger notification, alert, etc.
            }
        }
    }

    /**
     * Load pending reversals from storage
     */
    private fun loadPendingReversals() {
        val allKeys = encryptedPrefs.all.keys.filter { it.startsWith("reversal_") }
        for (key in allKeys) {
            try {
                val jsonStr = encryptedPrefs.getString(key, null) ?: continue
                val record = json.decodeFromString<ReversalRecord>(jsonStr)
                pendingReversals[record.reversalId] = record
            } catch (e: Exception) {
                Timber.e(e, "Failed to load reversal: $key")
            }
        }
    }

    /**
     * Persist reversal to encrypted storage
     */
    private fun persistReversal(record: ReversalRecord) {
        try {
            val jsonStr = json.encodeToString(record)
            encryptedPrefs.edit()
                .putString("reversal_${record.reversalId}", jsonStr)
                .apply()
        } catch (e: Exception) {
            Timber.e(e, "Failed to persist reversal: ${record.reversalId}")
        }
    }

    /**
     * Remove reversal from storage
     */
    private fun removeReversal(reversalId: String) {
        pendingReversals.remove(reversalId)
        encryptedPrefs.edit()
            .remove("reversal_$reversalId")
            .apply()
    }

    /**
     * Shutdown
     */
    fun shutdown() {
        retryJob?.cancel()
        scope.cancel()
    }

    private fun maskPan(pan: String): String {
        if (pan.length < 10) return pan
        return pan.take(6) + "*".repeat(pan.length - 10) + pan.takeLast(4)
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02X".format(it) }
    }
}

/**
 * Reversal record
 */
@Serializable
data class ReversalRecord(
    val reversalId: String,
    val originalTransactionId: String,
    val amount: Long,
    val currencyCode: String,
    val pan: String?,
    val panSequenceNumber: String?,
    val cryptogram: String?,
    val cryptogramType: String?,
    val reason: ReversalReason,
    val createdAt: Long,
    val attemptCount: Int,
    val lastAttemptAt: Long?,
    val lastError: String? = null,
    val status: ReversalStatus,
    val completedAt: Long? = null
)

/**
 * Reversal status
 */
@Serializable
enum class ReversalStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    MANUALLY_CLEARED
}

/**
 * Reversal reason
 */
@Serializable
enum class ReversalReason {
    TIMEOUT,                    // Transaction timed out
    CARD_REMOVED,              // Card removed during critical phase
    COMMUNICATION_ERROR,       // Lost connection to card
    USER_CANCELLED,            // User cancelled after cryptogram
    PARTIAL_COMPLETION,        // Transaction partially completed
    DUPLICATE_TRANSACTION,     // Duplicate detected
    SYSTEM_ERROR               // Internal error
}

/**
 * Reversal result
 */
sealed class ReversalResult {
    object Success : ReversalResult()
    object Duplicate : ReversalResult()
    data class Failed(val reason: String) : ReversalResult()
    data class PermanentFailure(val reason: String) : ReversalResult()
}

/**
 * Interface for sending reversals to acquirer
 */
interface ReversalSender {
    suspend fun sendReversal(record: ReversalRecord): ReversalResult
}

/**
 * Reversal configuration
 */
data class ReversalConfig(
    val retryIntervalMs: Long = 30_000,           // Check every 30 seconds
    val baseBackoffMs: Long = 5_000,              // Initial backoff 5 seconds
    val maxBackoffMs: Long = 300_000,             // Max backoff 5 minutes
    val maxAttempts: Int = 100,                   // Max retry attempts
    val escalationThresholdMs: Long = 3600_000,  // Escalate after 1 hour
    val completedRetentionMs: Long = 86400_000   // Keep completed for 24 hours
)
