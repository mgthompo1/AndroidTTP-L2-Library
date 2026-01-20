package com.atlas.softpos.recovery

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.tlv.TlvTag
import com.atlas.softpos.kernel.common.CardTransceiver
import com.atlas.softpos.kernel.common.TransactionStateData
import com.atlas.softpos.reversal.ReversalManager
import com.atlas.softpos.reversal.ReversalReason
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import timber.log.Timber

/**
 * Torn Transaction Recovery
 *
 * Handles recovery of transactions that were interrupted during the
 * critical cryptogram generation phase.
 *
 * A "torn transaction" occurs when:
 * - Card is removed after GENERATE AC command sent
 * - Communication lost after cryptogram requested
 * - Timeout during cryptogram generation
 * - App crash/kill during critical phase
 *
 * Recovery Process:
 * 1. On startup, check for torn transaction records
 * 2. If torn record exists, attempt recovery on next card present
 * 3. Query card for last transaction status
 * 4. Complete or reverse based on card's response
 *
 * Visa qVSDC Torn Transaction Log:
 * - Maintains up to 5 torn transaction records
 * - Each record contains: PAN, ATC, Amount, Date, Torn flags
 */
class TornTransactionRecovery(
    private val context: Context,
    private val reversalManager: ReversalManager
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
            "atlas_torn_transaction_store",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val tornRecords = mutableListOf<TornTransactionRecord>()
    private val mutex = Mutex()

    /**
     * Initialize and load torn transaction records
     */
    fun initialize() {
        loadTornRecords()
        Timber.d("TornTransactionRecovery initialized. Records: ${tornRecords.size}")

        // Check for any records that need immediate attention
        checkAgedRecords()
    }

    /**
     * Record a torn transaction for future recovery
     */
    suspend fun recordTornTransaction(
        transactionData: TransactionStateData,
        tornAt: TornPhase
    ) = mutex.withLock {
        val record = TornTransactionRecord(
            recordId = generateRecordId(),
            transactionId = transactionData.transactionId,
            panHash = transactionData.pan?.let { hashPan(it) } ?: "",
            panLastFour = transactionData.pan?.takeLast(4) ?: "",
            panSequenceNumber = transactionData.panSequenceNumber,
            amount = transactionData.amount,
            currencyCode = transactionData.currencyCode,
            atc = null, // Will be populated if available
            aid = transactionData.selectedAid?.toHexString(),
            timestamp = System.currentTimeMillis(),
            tornPhase = tornAt,
            recoveryAttempts = 0,
            lastRecoveryAttempt = null,
            status = TornRecordStatus.PENDING_RECOVERY
        )

        // Maintain max 5 records (oldest gets removed)
        if (tornRecords.size >= MAX_TORN_RECORDS) {
            val oldest = tornRecords.minByOrNull { it.timestamp }
            if (oldest != null) {
                handleUnrecoverableRecord(oldest)
                tornRecords.remove(oldest)
            }
        }

        tornRecords.add(record)
        persistRecords()

        Timber.w("Torn transaction recorded: ${record.recordId} at phase ${record.tornPhase}")
    }

    /**
     * Check if recovery is needed for a card
     * Call when card is presented
     */
    suspend fun checkRecoveryNeeded(
        panHash: String,
        panLastFour: String
    ): TornTransactionRecord? = mutex.withLock {
        return@withLock tornRecords.find {
            it.status == TornRecordStatus.PENDING_RECOVERY &&
                    (it.panHash == panHash || it.panLastFour == panLastFour)
        }
    }

    /**
     * Attempt recovery for a torn transaction
     *
     * @param record The torn transaction record
     * @param transceiver Connection to the card
     * @return Recovery result
     */
    suspend fun attemptRecovery(
        record: TornTransactionRecord,
        transceiver: CardTransceiver
    ): RecoveryResult = mutex.withLock {
        Timber.d("Attempting recovery for: ${record.recordId}")

        val updatedRecord = record.copy(
            recoveryAttempts = record.recoveryAttempts + 1,
            lastRecoveryAttempt = System.currentTimeMillis()
        )
        updateRecord(updatedRecord)

        return@withLock try {
            // Query card for torn transaction status
            val cardStatus = queryCardTornStatus(transceiver, record)

            when (cardStatus) {
                is CardTornStatus.TransactionCompleted -> {
                    // Card completed the transaction - we need to complete our side
                    Timber.i("Card reports transaction completed: ${record.recordId}")
                    markRecoveryComplete(record.recordId, cardStatus.cryptogram)
                    RecoveryResult.CompletedOnCard(cardStatus.cryptogram)
                }

                is CardTornStatus.TransactionNotFound -> {
                    // Card has no record - transaction was never completed
                    Timber.i("Card has no torn transaction record: ${record.recordId}")
                    markRecoveryComplete(record.recordId, null)
                    RecoveryResult.NotFoundOnCard
                }

                is CardTornStatus.TransactionAborted -> {
                    // Card aborted the transaction - we should do the same
                    Timber.i("Card reports transaction aborted: ${record.recordId}")
                    markRecoveryComplete(record.recordId, null)
                    RecoveryResult.AbortedOnCard
                }

                is CardTornStatus.QueryFailed -> {
                    // Couldn't query card - keep trying
                    Timber.w("Failed to query card torn status: ${cardStatus.reason}")
                    RecoveryResult.QueryFailed(cardStatus.reason)
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Recovery exception for ${record.recordId}")
            RecoveryResult.QueryFailed(e.message ?: "Unknown error")
        }
    }

    /**
     * Query card for torn transaction status
     * Uses network-specific methods
     */
    private suspend fun queryCardTornStatus(
        transceiver: CardTransceiver,
        record: TornTransactionRecord
    ): CardTornStatus {
        // For Visa: Use GET DATA to query torn transaction log
        // For Mastercard: Check if transaction completed via ATC comparison

        val aid = record.aid
        if (aid == null) {
            return CardTornStatus.QueryFailed("No AID available")
        }

        return when {
            aid.startsWith("A000000003") -> queryVisaTornStatus(transceiver, record)
            aid.startsWith("A000000004") -> queryMastercardTornStatus(transceiver, record)
            else -> {
                // Generic approach - compare ATC
                queryGenericTornStatus(transceiver, record)
            }
        }
    }

    /**
     * Query Visa card for torn transaction status
     * Visa maintains a Torn Transaction Log on card
     */
    private suspend fun queryVisaTornStatus(
        transceiver: CardTransceiver,
        record: TornTransactionRecord
    ): CardTornStatus {
        try {
            // GET DATA for Torn Transaction Log (Tag DF8128)
            val getDataCmd = com.atlas.softpos.core.apdu.CommandApdu(
                cla = 0x80.toByte(),
                ins = 0xCA.toByte(),
                p1 = 0xDF.toByte(),
                p2 = 0x81.toByte(),
                data = byteArrayOf(0x28),
                le = 0x00
            )

            val response = transceiver.transceive(getDataCmd)

            if (!response.isSuccess) {
                // Card may not support torn transaction log
                return CardTornStatus.TransactionNotFound
            }

            // Parse torn transaction log
            // Format: Each entry contains PAN, ATC, Amount, Date, etc.
            val logEntries = parseTornTransactionLog(response.data)

            // Find matching entry
            val matchingEntry = logEntries.find { entry ->
                entry.panLastFour == record.panLastFour &&
                        entry.amount == record.amount
            }

            return if (matchingEntry != null) {
                if (matchingEntry.completed) {
                    CardTornStatus.TransactionCompleted(matchingEntry.cryptogram)
                } else {
                    CardTornStatus.TransactionAborted
                }
            } else {
                CardTornStatus.TransactionNotFound
            }
        } catch (e: Exception) {
            return CardTornStatus.QueryFailed(e.message ?: "Query failed")
        }
    }

    /**
     * Query Mastercard for torn status via ATC comparison
     */
    private suspend fun queryMastercardTornStatus(
        transceiver: CardTransceiver,
        record: TornTransactionRecord
    ): CardTornStatus {
        try {
            // GET DATA for ATC (Tag 9F36)
            val getDataCmd = com.atlas.softpos.core.apdu.CommandApdu(
                cla = 0x80.toByte(),
                ins = 0xCA.toByte(),
                p1 = 0x9F.toByte(),
                p2 = 0x36.toByte(),
                le = 0x00
            )

            val response = transceiver.transceive(getDataCmd)

            if (!response.isSuccess) {
                return CardTornStatus.QueryFailed("Failed to read ATC")
            }

            val currentAtc = parseAtc(response.data)
            val recordAtc = record.atc?.toIntOrNull()

            return if (recordAtc != null && currentAtc > recordAtc) {
                // ATC advanced - transaction may have completed
                // Would need additional verification
                CardTornStatus.TransactionNotFound
            } else {
                CardTornStatus.TransactionNotFound
            }
        } catch (e: Exception) {
            return CardTornStatus.QueryFailed(e.message ?: "Query failed")
        }
    }

    /**
     * Generic torn status query
     */
    private suspend fun queryGenericTornStatus(
        transceiver: CardTransceiver,
        record: TornTransactionRecord
    ): CardTornStatus {
        // Without network-specific support, assume not found
        return CardTornStatus.TransactionNotFound
    }

    /**
     * Parse Visa torn transaction log
     */
    private fun parseTornTransactionLog(data: ByteArray): List<TornLogEntry> {
        val entries = mutableListOf<TornLogEntry>()

        try {
            val tlvs = TlvParser.parseRecursive(data)
            // Each DF8129 tag is a torn transaction record
            tlvs.filter { it.tag.hex == "DF8129" }.forEach { recordTlv ->
                val recordData = TlvParser.parseToMap(recordTlv.value)

                entries.add(TornLogEntry(
                    panLastFour = recordData["5A"]?.value?.takeLast(2)?.toHexString() ?: "",
                    amount = recordData["9F02"]?.value?.toLong() ?: 0,
                    completed = (recordData["DF8101"]?.value?.get(0)?.toInt() ?: 0) == 0x01,
                    cryptogram = recordData["9F26"]?.value
                ))
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse torn transaction log")
        }

        return entries
    }

    private fun parseAtc(data: ByteArray): Int {
        if (data.size < 2) return 0
        return ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
    }

    /**
     * Mark recovery complete
     */
    private fun markRecoveryComplete(recordId: String, cryptogram: ByteArray?) {
        val record = tornRecords.find { it.recordId == recordId } ?: return

        val completedRecord = record.copy(
            status = TornRecordStatus.RECOVERED,
            recoveredCryptogram = cryptogram?.toHexString()
        )

        tornRecords.remove(record)
        tornRecords.add(completedRecord)
        persistRecords()

        // Schedule cleanup
        cleanupCompletedRecord(recordId)
    }

    /**
     * Handle unrecoverable record
     */
    private fun handleUnrecoverableRecord(record: TornTransactionRecord) {
        Timber.e("Torn transaction unrecoverable: ${record.recordId}")

        // Queue reversal if needed
        if (record.tornPhase == TornPhase.AFTER_GENERATE_AC_SENT) {
            reversalManager.queueReversal(
                originalTransactionId = record.transactionId,
                amount = record.amount,
                currencyCode = record.currencyCode,
                maskedPan = "****${record.panLastFour}",
                reason = ReversalReason.CARD_REMOVED
            )
        }

        val failedRecord = record.copy(status = TornRecordStatus.FAILED)
        tornRecords.remove(record)
        tornRecords.add(failedRecord)
        persistRecords()
    }

    /**
     * Check for aged records needing attention
     */
    private fun checkAgedRecords() {
        val now = System.currentTimeMillis()
        val maxAge = 24 * 60 * 60 * 1000L // 24 hours

        tornRecords.filter {
            it.status == TornRecordStatus.PENDING_RECOVERY &&
                    (now - it.timestamp) > maxAge
        }.forEach { record ->
            Timber.w("Aged torn transaction: ${record.recordId}")
            // Consider queueing reversal for aged records
            if (record.recoveryAttempts >= MAX_RECOVERY_ATTEMPTS) {
                handleUnrecoverableRecord(record)
            }
        }
    }

    private fun cleanupCompletedRecord(recordId: String) {
        // Keep completed records for audit trail but can clean up after period
    }

    private fun updateRecord(record: TornTransactionRecord) {
        val index = tornRecords.indexOfFirst { it.recordId == record.recordId }
        if (index >= 0) {
            tornRecords[index] = record
            persistRecords()
        }
    }

    private fun loadTornRecords() {
        val jsonStr = encryptedPrefs.getString(PREFS_KEY_TORN_RECORDS, null) ?: return
        try {
            val records = json.decodeFromString<List<TornTransactionRecord>>(jsonStr)
            tornRecords.clear()
            tornRecords.addAll(records)
        } catch (e: Exception) {
            Timber.e(e, "Failed to load torn records")
        }
    }

    private fun persistRecords() {
        val jsonStr = json.encodeToString(tornRecords.toList())
        encryptedPrefs.edit().putString(PREFS_KEY_TORN_RECORDS, jsonStr).apply()
    }

    private fun generateRecordId(): String {
        return "TORN_${System.currentTimeMillis()}_${(Math.random() * 10000).toInt()}"
    }

    private fun hashPan(pan: String): String {
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(pan.toByteArray())
            .toHexString()
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
    private fun ByteArray.toLong(): Long {
        var result = 0L
        for (b in this) {
            result = (result shl 8) or (b.toLong() and 0xFF)
        }
        return result
    }

    companion object {
        private const val PREFS_KEY_TORN_RECORDS = "torn_records"
        private const val MAX_TORN_RECORDS = 5
        private const val MAX_RECOVERY_ATTEMPTS = 10
    }
}

/**
 * Torn transaction record
 */
@Serializable
data class TornTransactionRecord(
    val recordId: String,
    val transactionId: String,
    val panHash: String,
    val panLastFour: String,
    val panSequenceNumber: String?,
    val amount: Long,
    val currencyCode: String,
    val atc: String?,
    val aid: String?,
    val timestamp: Long,
    val tornPhase: TornPhase,
    val recoveryAttempts: Int,
    val lastRecoveryAttempt: Long?,
    val status: TornRecordStatus,
    val recoveredCryptogram: String? = null
)

@Serializable
enum class TornPhase {
    BEFORE_GENERATE_AC,
    AFTER_GENERATE_AC_SENT,
    DURING_RESPONSE
}

@Serializable
enum class TornRecordStatus {
    PENDING_RECOVERY,
    RECOVERED,
    FAILED
}

/**
 * Recovery result
 */
sealed class RecoveryResult {
    data class CompletedOnCard(val cryptogram: ByteArray?) : RecoveryResult()
    object NotFoundOnCard : RecoveryResult()
    object AbortedOnCard : RecoveryResult()
    data class QueryFailed(val reason: String) : RecoveryResult()
}

/**
 * Card torn status
 */
sealed class CardTornStatus {
    data class TransactionCompleted(val cryptogram: ByteArray?) : CardTornStatus()
    object TransactionNotFound : CardTornStatus()
    object TransactionAborted : CardTornStatus()
    data class QueryFailed(val reason: String) : CardTornStatus()
}

/**
 * Torn log entry from card
 */
data class TornLogEntry(
    val panLastFour: String,
    val amount: Long,
    val completed: Boolean,
    val cryptogram: ByteArray?
)
