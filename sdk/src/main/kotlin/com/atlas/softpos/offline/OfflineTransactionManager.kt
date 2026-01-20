package com.atlas.softpos.offline

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Offline Transaction Manager
 *
 * Manages offline transaction limits, store-and-forward queue, and
 * offline cumulative tracking per PAN.
 *
 * EMV Offline Requirements:
 * - Track cumulative offline amounts per card
 * - Enforce terminal floor limits
 * - Manage consecutive offline transaction limits
 * - Force online after threshold
 * - Store and forward queue for offline approved transactions
 *
 * This enables the terminal to:
 * - Accept transactions when online connectivity is unavailable
 * - Track offline risk per card
 * - Batch submit offline transactions when connectivity returns
 */
class OfflineTransactionManager(
    private val context: Context,
    private val config: OfflineConfig = OfflineConfig()
) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val encryptedPrefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            "atlas_offline_store",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // In-memory caches
    private val cardOfflineData = ConcurrentHashMap<String, CardOfflineData>()
    private val pendingOfflineTransactions = ConcurrentHashMap<String, OfflineTransaction>()

    // Callback for submitting offline transactions
    private var offlineSubmitter: OfflineTransactionSubmitter? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var syncJob: Job? = null

    /**
     * Initialize and load persisted data
     */
    fun initialize() {
        loadCardOfflineData()
        loadPendingTransactions()
        startSyncLoop()
        Timber.d("OfflineTransactionManager initialized. Pending: ${pendingOfflineTransactions.size}")
    }

    /**
     * Set the submitter for offline transactions
     */
    fun setSubmitter(submitter: OfflineTransactionSubmitter) {
        this.offlineSubmitter = submitter
    }

    /**
     * Check if transaction should be forced online
     *
     * @param panHash Hash of PAN (for privacy)
     * @param amount Transaction amount
     * @return Decision on whether to force online
     */
    fun shouldForceOnline(panHash: String, amount: Long): OfflineDecision {
        val cardData = cardOfflineData[panHash]

        // Check terminal floor limit
        if (amount > config.terminalFloorLimit) {
            return OfflineDecision.ForceOnline(
                reason = "Amount exceeds floor limit",
                floorLimitExceeded = true
            )
        }

        // Check if we have card-specific data
        if (cardData == null) {
            // First transaction for this card
            return if (amount <= config.terminalFloorLimit && config.allowFirstOffline) {
                OfflineDecision.AllowOffline
            } else {
                OfflineDecision.ForceOnline(reason = "First transaction must be online")
            }
        }

        // Check cumulative offline limit
        val newCumulative = cardData.cumulativeOfflineAmount + amount
        if (newCumulative > config.cumulativeOfflineLimit) {
            return OfflineDecision.ForceOnline(
                reason = "Cumulative offline limit exceeded",
                cumulativeLimitExceeded = true
            )
        }

        // Check consecutive offline count
        if (cardData.consecutiveOfflineCount >= config.maxConsecutiveOffline) {
            return OfflineDecision.ForceOnline(
                reason = "Consecutive offline limit exceeded",
                consecutiveLimitExceeded = true
            )
        }

        // Check if we should randomly force online (velocity check)
        if (shouldRandomlyForceOnline(cardData)) {
            return OfflineDecision.ForceOnline(reason = "Random online selection")
        }

        // Check time since last online
        val timeSinceOnline = System.currentTimeMillis() - cardData.lastOnlineTimestamp
        if (timeSinceOnline > config.maxTimeBetweenOnlineMs) {
            return OfflineDecision.ForceOnline(
                reason = "Time since last online exceeded",
                timeLimitExceeded = true
            )
        }

        return OfflineDecision.AllowOffline
    }

    /**
     * Random transaction selection for online
     * EMV Book 4, Section 6.4
     */
    private fun shouldRandomlyForceOnline(cardData: CardOfflineData): Boolean {
        if (config.randomSelectionThreshold <= 0) return false

        val random = Random().nextInt(100)
        val probability = calculateRandomSelectionProbability(cardData)

        return random < probability
    }

    /**
     * Calculate random selection probability based on offline activity
     */
    private fun calculateRandomSelectionProbability(cardData: CardOfflineData): Int {
        // Higher probability if more offline transactions
        val baseProbability = config.randomSelectionThreshold
        val offlineBonus = (cardData.consecutiveOfflineCount * 5).coerceAtMost(30)
        val amountBonus = ((cardData.cumulativeOfflineAmount / config.cumulativeOfflineLimit.toFloat()) * 20).toInt()

        return (baseProbability + offlineBonus + amountBonus).coerceAtMost(100)
    }

    /**
     * Record an offline transaction
     */
    fun recordOfflineTransaction(
        transactionId: String,
        panHash: String,
        amount: Long,
        cryptogram: ByteArray,
        authorizationData: Map<String, String>
    ) {
        // Update card offline data
        val cardData = cardOfflineData.getOrPut(panHash) {
            CardOfflineData(
                panHash = panHash,
                cumulativeOfflineAmount = 0,
                consecutiveOfflineCount = 0,
                lastOnlineTimestamp = System.currentTimeMillis(),
                lastOfflineTimestamp = 0
            )
        }

        val updatedCardData = cardData.copy(
            cumulativeOfflineAmount = cardData.cumulativeOfflineAmount + amount,
            consecutiveOfflineCount = cardData.consecutiveOfflineCount + 1,
            lastOfflineTimestamp = System.currentTimeMillis()
        )
        cardOfflineData[panHash] = updatedCardData
        persistCardData(updatedCardData)

        // Queue transaction for store-and-forward
        val offlineTxn = OfflineTransaction(
            transactionId = transactionId,
            panHash = panHash,
            amount = amount,
            currencyCode = config.currencyCode,
            cryptogram = cryptogram.toHexString(),
            authorizationData = authorizationData,
            timestamp = System.currentTimeMillis(),
            status = OfflineTransactionStatus.PENDING,
            attemptCount = 0
        )
        pendingOfflineTransactions[transactionId] = offlineTxn
        persistTransaction(offlineTxn)

        Timber.d("Offline transaction recorded: $transactionId")
    }

    /**
     * Record that a transaction went online
     * Resets consecutive offline counter
     */
    fun recordOnlineTransaction(panHash: String, successful: Boolean) {
        val cardData = cardOfflineData[panHash] ?: return

        val updatedData = if (successful) {
            cardData.copy(
                consecutiveOfflineCount = 0,
                lastOnlineTimestamp = System.currentTimeMillis(),
                // Reset cumulative after successful online
                cumulativeOfflineAmount = 0
            )
        } else {
            // Failed online doesn't reset counters
            cardData
        }

        cardOfflineData[panHash] = updatedData
        persistCardData(updatedData)
    }

    /**
     * Get pending offline transactions count
     */
    fun getPendingCount(): Int {
        return pendingOfflineTransactions.values.count {
            it.status == OfflineTransactionStatus.PENDING
        }
    }

    /**
     * Get all pending offline transactions
     */
    fun getPendingTransactions(): List<OfflineTransaction> {
        return pendingOfflineTransactions.values
            .filter { it.status == OfflineTransactionStatus.PENDING }
            .sortedBy { it.timestamp }
    }

    /**
     * Submit all pending offline transactions
     */
    suspend fun submitPendingTransactions(): SubmitResult {
        val submitter = offlineSubmitter ?: return SubmitResult(
            submitted = 0,
            successful = 0,
            failed = 0,
            errors = listOf("No submitter configured")
        )

        val pending = getPendingTransactions()
        if (pending.isEmpty()) {
            return SubmitResult(0, 0, 0, emptyList())
        }

        var successful = 0
        var failed = 0
        val errors = mutableListOf<String>()

        for (txn in pending) {
            val result = submitTransaction(txn, submitter)
            when (result) {
                is SubmissionResult.Success -> successful++
                is SubmissionResult.Failed -> {
                    failed++
                    errors.add("${txn.transactionId}: ${result.reason}")
                }
            }
        }

        return SubmitResult(
            submitted = pending.size,
            successful = successful,
            failed = failed,
            errors = errors
        )
    }

    /**
     * Submit a single offline transaction
     */
    private suspend fun submitTransaction(
        txn: OfflineTransaction,
        submitter: OfflineTransactionSubmitter
    ): SubmissionResult {
        val updatedTxn = txn.copy(
            attemptCount = txn.attemptCount + 1,
            lastAttemptTimestamp = System.currentTimeMillis()
        )
        pendingOfflineTransactions[txn.transactionId] = updatedTxn
        persistTransaction(updatedTxn)

        return try {
            val response = submitter.submitOfflineTransaction(txn)

            when (response) {
                is OfflineSubmitResponse.Approved -> {
                    markTransactionSubmitted(txn.transactionId)
                    SubmissionResult.Success
                }

                is OfflineSubmitResponse.Declined -> {
                    // Declined but submitted successfully
                    markTransactionSubmitted(txn.transactionId, declined = true)
                    SubmissionResult.Success
                }

                is OfflineSubmitResponse.Error -> {
                    // Keep for retry
                    SubmissionResult.Failed(response.reason)
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to submit offline transaction: ${txn.transactionId}")
            SubmissionResult.Failed(e.message ?: "Unknown error")
        }
    }

    /**
     * Mark transaction as submitted
     */
    private fun markTransactionSubmitted(transactionId: String, declined: Boolean = false) {
        val txn = pendingOfflineTransactions[transactionId] ?: return
        val submittedTxn = txn.copy(
            status = if (declined) OfflineTransactionStatus.DECLINED else OfflineTransactionStatus.SUBMITTED,
            submittedTimestamp = System.currentTimeMillis()
        )
        pendingOfflineTransactions[transactionId] = submittedTxn
        persistTransaction(submittedTxn)

        // Remove after retention period
        scope.launch {
            delay(config.submittedRetentionMs)
            removeTransaction(transactionId)
        }
    }

    /**
     * Start sync loop
     */
    private fun startSyncLoop() {
        syncJob?.cancel()
        syncJob = scope.launch {
            while (isActive) {
                delay(config.syncIntervalMs)

                if (offlineSubmitter != null && getPendingCount() > 0) {
                    Timber.d("Auto-syncing ${getPendingCount()} offline transactions")
                    submitPendingTransactions()
                }
            }
        }
    }

    /**
     * Load card offline data from storage
     */
    private fun loadCardOfflineData() {
        val keys = encryptedPrefs.all.keys.filter { it.startsWith("card_") }
        for (key in keys) {
            try {
                val jsonStr = encryptedPrefs.getString(key, null) ?: continue
                val data = json.decodeFromString<CardOfflineData>(jsonStr)
                cardOfflineData[data.panHash] = data
            } catch (e: Exception) {
                Timber.e(e, "Failed to load card data: $key")
            }
        }
    }

    /**
     * Load pending transactions from storage
     */
    private fun loadPendingTransactions() {
        val keys = encryptedPrefs.all.keys.filter { it.startsWith("txn_") }
        for (key in keys) {
            try {
                val jsonStr = encryptedPrefs.getString(key, null) ?: continue
                val txn = json.decodeFromString<OfflineTransaction>(jsonStr)
                pendingOfflineTransactions[txn.transactionId] = txn
            } catch (e: Exception) {
                Timber.e(e, "Failed to load transaction: $key")
            }
        }
    }

    private fun persistCardData(data: CardOfflineData) {
        encryptedPrefs.edit()
            .putString("card_${data.panHash}", json.encodeToString(data))
            .apply()
    }

    private fun persistTransaction(txn: OfflineTransaction) {
        encryptedPrefs.edit()
            .putString("txn_${txn.transactionId}", json.encodeToString(txn))
            .apply()
    }

    private fun removeTransaction(transactionId: String) {
        pendingOfflineTransactions.remove(transactionId)
        encryptedPrefs.edit()
            .remove("txn_$transactionId")
            .apply()
    }

    /**
     * Clear all card data (for testing/reset)
     */
    fun clearAllCardData() {
        cardOfflineData.clear()
        encryptedPrefs.all.keys
            .filter { it.startsWith("card_") }
            .forEach { encryptedPrefs.edit().remove(it).apply() }
    }

    fun shutdown() {
        syncJob?.cancel()
        scope.cancel()
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
}

/**
 * Card-specific offline tracking data
 */
@Serializable
data class CardOfflineData(
    val panHash: String,
    val cumulativeOfflineAmount: Long,
    val consecutiveOfflineCount: Int,
    val lastOnlineTimestamp: Long,
    val lastOfflineTimestamp: Long
)

/**
 * Offline transaction record
 */
@Serializable
data class OfflineTransaction(
    val transactionId: String,
    val panHash: String,
    val amount: Long,
    val currencyCode: String,
    val cryptogram: String,
    val authorizationData: Map<String, String>,
    val timestamp: Long,
    val status: OfflineTransactionStatus,
    val attemptCount: Int,
    val lastAttemptTimestamp: Long? = null,
    val submittedTimestamp: Long? = null
)

@Serializable
enum class OfflineTransactionStatus {
    PENDING,
    SUBMITTED,
    DECLINED,
    FAILED
}

/**
 * Offline decision
 */
sealed class OfflineDecision {
    object AllowOffline : OfflineDecision()
    data class ForceOnline(
        val reason: String,
        val floorLimitExceeded: Boolean = false,
        val cumulativeLimitExceeded: Boolean = false,
        val consecutiveLimitExceeded: Boolean = false,
        val timeLimitExceeded: Boolean = false
    ) : OfflineDecision()
}

/**
 * Submission results
 */
data class SubmitResult(
    val submitted: Int,
    val successful: Int,
    val failed: Int,
    val errors: List<String>
)

sealed class SubmissionResult {
    object Success : SubmissionResult()
    data class Failed(val reason: String) : SubmissionResult()
}

/**
 * Interface for submitting offline transactions
 */
interface OfflineTransactionSubmitter {
    suspend fun submitOfflineTransaction(txn: OfflineTransaction): OfflineSubmitResponse
}

sealed class OfflineSubmitResponse {
    data class Approved(val authCode: String) : OfflineSubmitResponse()
    data class Declined(val reason: String) : OfflineSubmitResponse()
    data class Error(val reason: String) : OfflineSubmitResponse()
}

/**
 * Offline configuration
 */
data class OfflineConfig(
    val terminalFloorLimit: Long = 0,              // Amount above which online is required
    val cumulativeOfflineLimit: Long = 10000,     // Max cumulative offline per card ($100)
    val maxConsecutiveOffline: Int = 3,            // Max consecutive offline
    val maxTimeBetweenOnlineMs: Long = 86400000,  // Force online after 24 hours
    val randomSelectionThreshold: Int = 10,        // Base % chance of random online
    val allowFirstOffline: Boolean = false,        // Allow first transaction offline
    val syncIntervalMs: Long = 60000,              // Auto-sync every 60 seconds
    val submittedRetentionMs: Long = 86400000,    // Keep submitted for 24 hours
    val currencyCode: String = "840"               // USD
)
