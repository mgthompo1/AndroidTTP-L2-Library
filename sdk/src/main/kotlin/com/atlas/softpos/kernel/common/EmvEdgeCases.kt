package com.atlas.softpos.kernel.common

import timber.log.Timber
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * EMV Edge Case Handling
 *
 * Handles various edge cases and error conditions in EMV transactions:
 * - Torn transactions (card removed during processing)
 * - Card collision (multiple cards in field)
 * - Protocol errors (malformed responses)
 * - Data validation failures
 * - Recovery procedures
 *
 * Reference: EMV Contactless Book A, Section 9 - Error Handling
 */
object EmvEdgeCases {

    /**
     * Validate TLV data structure
     *
     * @param data The TLV data to validate
     * @return ValidationResult indicating success or specific failure
     */
    fun validateTlvStructure(data: ByteArray): TlvValidationResult {
        if (data.isEmpty()) {
            return TlvValidationResult.Empty
        }

        var offset = 0
        var tagCount = 0

        while (offset < data.size) {
            // Check minimum bytes for tag
            if (offset >= data.size) {
                return TlvValidationResult.TruncatedData(offset)
            }

            // Parse tag
            val tagStart = offset
            var tag = data[offset].toInt() and 0xFF
            offset++

            // Multi-byte tag
            if ((tag and 0x1F) == 0x1F) {
                if (offset >= data.size) {
                    return TlvValidationResult.TruncatedData(offset)
                }
                do {
                    tag = (tag shl 8) or (data[offset].toInt() and 0xFF)
                    offset++
                } while (offset < data.size && (data[offset - 1].toInt() and 0x80) != 0)
            }

            // Check for length byte
            if (offset >= data.size) {
                return TlvValidationResult.TruncatedData(offset)
            }

            // Parse length
            val lengthByte = data[offset].toInt() and 0xFF
            offset++

            val length: Int
            when {
                lengthByte <= 0x7F -> {
                    length = lengthByte
                }
                lengthByte == 0x81 -> {
                    if (offset >= data.size) {
                        return TlvValidationResult.TruncatedData(offset)
                    }
                    length = data[offset].toInt() and 0xFF
                    offset++
                }
                lengthByte == 0x82 -> {
                    if (offset + 1 >= data.size) {
                        return TlvValidationResult.TruncatedData(offset)
                    }
                    length = ((data[offset].toInt() and 0xFF) shl 8) or
                            (data[offset + 1].toInt() and 0xFF)
                    offset += 2
                }
                else -> {
                    return TlvValidationResult.InvalidLength(offset - 1, lengthByte)
                }
            }

            // Validate length doesn't exceed remaining data
            if (offset + length > data.size) {
                return TlvValidationResult.LengthExceedsData(
                    tagOffset = tagStart,
                    tag = tag,
                    declaredLength = length,
                    availableLength = data.size - offset
                )
            }

            offset += length
            tagCount++

            // Sanity check for infinite loops
            if (tagCount > 1000) {
                return TlvValidationResult.TooManyTags(tagCount)
            }
        }

        return TlvValidationResult.Valid(tagCount)
    }

    /**
     * Validate PAN format
     */
    fun validatePan(pan: ByteArray): PanValidationResult {
        // Convert to string, removing padding F's
        val panString = pan.joinToString("") { "%02X".format(it) }
            .trimEnd('F')

        // Check length (13-19 digits)
        if (panString.length < 13) {
            return PanValidationResult.TooShort(panString.length)
        }
        if (panString.length > 19) {
            return PanValidationResult.TooLong(panString.length)
        }

        // Check all digits
        if (!panString.all { it.isDigit() }) {
            return PanValidationResult.InvalidCharacters
        }

        // Luhn check
        if (!passesLuhnCheck(panString)) {
            return PanValidationResult.LuhnCheckFailed
        }

        return PanValidationResult.Valid
    }

    /**
     * Luhn algorithm check
     */
    private fun passesLuhnCheck(pan: String): Boolean {
        var sum = 0
        var alternate = false

        for (i in pan.length - 1 downTo 0) {
            var digit = pan[i].digitToInt()

            if (alternate) {
                digit *= 2
                if (digit > 9) {
                    digit -= 9
                }
            }

            sum += digit
            alternate = !alternate
        }

        return sum % 10 == 0
    }

    /**
     * Validate expiry date
     */
    fun validateExpiryDate(expiry: ByteArray): ExpiryValidationResult {
        if (expiry.size < 3) {
            return ExpiryValidationResult.InvalidFormat
        }

        // Format: YYMMDD (BCD)
        val hex = expiry.joinToString("") { "%02X".format(it) }

        try {
            val year = hex.substring(0, 2).toInt()
            val month = hex.substring(2, 4).toInt()

            if (month < 1 || month > 12) {
                return ExpiryValidationResult.InvalidMonth(month)
            }

            // Check if expired (assuming 2000-2099 century)
            val currentYear = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR) % 100
            val currentMonth = java.util.Calendar.getInstance().get(java.util.Calendar.MONTH) + 1

            if (year < currentYear || (year == currentYear && month < currentMonth)) {
                return ExpiryValidationResult.Expired(year, month)
            }

            return ExpiryValidationResult.Valid(year, month)
        } catch (e: Exception) {
            return ExpiryValidationResult.InvalidFormat
        }
    }

    /**
     * Validate AFL (Application File Locator)
     */
    fun validateAfl(afl: ByteArray): AflValidationResult {
        // AFL must be multiple of 4 bytes
        if (afl.size % 4 != 0) {
            return AflValidationResult.InvalidLength(afl.size)
        }

        if (afl.isEmpty()) {
            return AflValidationResult.Empty
        }

        val entries = mutableListOf<AflEntry>()

        for (i in afl.indices step 4) {
            val sfi = (afl[i].toInt() and 0xF8) shr 3
            val firstRecord = afl[i + 1].toInt() and 0xFF
            val lastRecord = afl[i + 2].toInt() and 0xFF
            val signedRecords = afl[i + 3].toInt() and 0xFF

            // Validate SFI (1-30)
            if (sfi < 1 || sfi > 30) {
                return AflValidationResult.InvalidSfi(sfi)
            }

            // Validate record range
            if (firstRecord < 1 || firstRecord > lastRecord) {
                return AflValidationResult.InvalidRecordRange(firstRecord, lastRecord)
            }

            // Signed records cannot exceed range
            if (signedRecords > (lastRecord - firstRecord + 1)) {
                return AflValidationResult.SignedRecordsExceedRange(signedRecords, lastRecord - firstRecord + 1)
            }

            entries.add(AflEntry(sfi, firstRecord, lastRecord, signedRecords))
        }

        return AflValidationResult.Valid(entries)
    }

    /**
     * Validate ATC (Application Transaction Counter)
     */
    fun validateAtc(atc: ByteArray, previousAtc: ByteArray?): AtcValidationResult {
        if (atc.size != 2) {
            return AtcValidationResult.InvalidLength(atc.size)
        }

        val atcValue = ((atc[0].toInt() and 0xFF) shl 8) or (atc[1].toInt() and 0xFF)

        // Check for zero ATC
        if (atcValue == 0) {
            return AtcValidationResult.ZeroValue
        }

        // Check for max value (potential wrap-around)
        if (atcValue == 0xFFFF) {
            return AtcValidationResult.MaxValue
        }

        // Check for decreasing ATC (replay attack indicator)
        if (previousAtc != null && previousAtc.size == 2) {
            val prevValue = ((previousAtc[0].toInt() and 0xFF) shl 8) or
                    (previousAtc[1].toInt() and 0xFF)
            if (atcValue <= prevValue) {
                return AtcValidationResult.Decreasing(atcValue, prevValue)
            }
        }

        return AtcValidationResult.Valid(atcValue)
    }

    /**
     * Detect and handle card collision (multiple cards)
     */
    fun detectCardCollision(responses: List<ByteArray>): Boolean {
        if (responses.size < 2) return false

        // Check for different AIDs in responses
        val aids = responses.mapNotNull { extractAidFromResponse(it) }
        return aids.toSet().size > 1
    }

    private fun extractAidFromResponse(response: ByteArray): ByteArray? {
        // Simple AID extraction - look for tag 4F or 84
        for (i in 0 until response.size - 2) {
            if (response[i] == 0x4F.toByte() || response[i] == 0x84.toByte()) {
                val length = response[i + 1].toInt() and 0xFF
                if (i + 2 + length <= response.size) {
                    return response.copyOfRange(i + 2, i + 2 + length)
                }
            }
        }
        return null
    }

    /**
     * Determine appropriate recovery action for an error
     */
    fun determineRecoveryAction(error: TransactionError): RecoveryAction {
        return when (error) {
            // Recoverable errors - can retry
            is TransactionError.CommunicationError -> RecoveryAction.RetryCommand(maxRetries = 3)
            is TransactionError.TemporaryCardError -> RecoveryAction.RetryAfterDelay(delayMs = 100)

            // Card errors - prompt for different card
            is TransactionError.CardBlocked -> RecoveryAction.TryDifferentCard("Card is blocked")
            is TransactionError.InvalidCard -> RecoveryAction.TryDifferentCard("Card not supported")

            // User action required
            is TransactionError.PinBlocked -> RecoveryAction.TryDifferentCard("PIN blocked")
            is TransactionError.CardRemoved -> RecoveryAction.PresentCardAgain

            // Fatal errors - abort transaction
            is TransactionError.SecurityViolation -> RecoveryAction.AbortTransaction("Security violation")
            is TransactionError.InternalError -> RecoveryAction.AbortTransaction("Internal error")

            // Protocol errors - may need restart
            is TransactionError.ProtocolError -> RecoveryAction.RestartTransaction
        }
    }
}

/**
 * TLV validation results
 */
sealed class TlvValidationResult {
    data class Valid(val tagCount: Int) : TlvValidationResult()
    object Empty : TlvValidationResult()
    data class TruncatedData(val offset: Int) : TlvValidationResult()
    data class InvalidLength(val offset: Int, val lengthByte: Int) : TlvValidationResult()
    data class LengthExceedsData(
        val tagOffset: Int,
        val tag: Int,
        val declaredLength: Int,
        val availableLength: Int
    ) : TlvValidationResult()
    data class TooManyTags(val count: Int) : TlvValidationResult()

    fun isValid() = this is Valid
}

/**
 * PAN validation results
 */
sealed class PanValidationResult {
    object Valid : PanValidationResult()
    data class TooShort(val length: Int) : PanValidationResult()
    data class TooLong(val length: Int) : PanValidationResult()
    object InvalidCharacters : PanValidationResult()
    object LuhnCheckFailed : PanValidationResult()

    fun isValid() = this is Valid
}

/**
 * Expiry date validation results
 */
sealed class ExpiryValidationResult {
    data class Valid(val year: Int, val month: Int) : ExpiryValidationResult()
    object InvalidFormat : ExpiryValidationResult()
    data class InvalidMonth(val month: Int) : ExpiryValidationResult()
    data class Expired(val year: Int, val month: Int) : ExpiryValidationResult()

    fun isValid() = this is Valid
}

/**
 * AFL validation results
 */
sealed class AflValidationResult {
    data class Valid(val entries: List<AflEntry>) : AflValidationResult()
    object Empty : AflValidationResult()
    data class InvalidLength(val length: Int) : AflValidationResult()
    data class InvalidSfi(val sfi: Int) : AflValidationResult()
    data class InvalidRecordRange(val first: Int, val last: Int) : AflValidationResult()
    data class SignedRecordsExceedRange(val signed: Int, val total: Int) : AflValidationResult()

    fun isValid() = this is Valid
}

data class AflEntry(
    val sfi: Int,
    val firstRecord: Int,
    val lastRecord: Int,
    val signedRecords: Int
)

/**
 * ATC validation results
 */
sealed class AtcValidationResult {
    data class Valid(val value: Int) : AtcValidationResult()
    data class InvalidLength(val length: Int) : AtcValidationResult()
    object ZeroValue : AtcValidationResult()
    object MaxValue : AtcValidationResult()
    data class Decreasing(val current: Int, val previous: Int) : AtcValidationResult()

    fun isValid() = this is Valid
}

/**
 * Transaction errors
 */
sealed class TransactionError {
    data class CommunicationError(val message: String) : TransactionError()
    data class TemporaryCardError(val sw: Int) : TransactionError()
    data class CardBlocked(val reason: String) : TransactionError()
    data class InvalidCard(val reason: String) : TransactionError()
    data class PinBlocked(val remainingTries: Int) : TransactionError()
    object CardRemoved : TransactionError()
    data class SecurityViolation(val reason: String) : TransactionError()
    data class InternalError(val exception: Exception) : TransactionError()
    data class ProtocolError(val message: String) : TransactionError()
}

/**
 * Recovery actions
 */
sealed class RecoveryAction {
    data class RetryCommand(val maxRetries: Int) : RecoveryAction()
    data class RetryAfterDelay(val delayMs: Long) : RecoveryAction()
    data class TryDifferentCard(val reason: String) : RecoveryAction()
    object PresentCardAgain : RecoveryAction()
    object RestartTransaction : RecoveryAction()
    data class AbortTransaction(val reason: String) : RecoveryAction()
}

/**
 * Torn transaction handler
 *
 * Manages detection and recovery from transactions where the card
 * was removed before completion (anti-tearing)
 */
class TornTransactionHandler {

    private val tornTransactions = mutableMapOf<String, TornTransaction>()

    /**
     * Record a potential torn transaction
     */
    @Synchronized
    fun recordTornTransaction(
        pan: ByteArray,
        atc: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ) {
        val key = pan.joinToString("") { "%02X".format(it) }
        tornTransactions[key] = TornTransaction(
            panHash = key.hashCode(),
            atc = atc.copyOf(),
            timestamp = timestamp
        )
        Timber.w("Recorded torn transaction for PAN hash: ${key.hashCode()}")

        // Clean up old entries (older than 24 hours)
        cleanupOldEntries()
    }

    /**
     * Check if this is a potentially repeated torn transaction
     */
    @Synchronized
    fun checkForTornTransaction(pan: ByteArray, atc: ByteArray): TornTransactionCheck {
        val key = pan.joinToString("") { "%02X".format(it) }
        val existing = tornTransactions[key] ?: return TornTransactionCheck.NotFound

        // Check if ATC matches (same transaction)
        if (existing.atc.contentEquals(atc)) {
            return TornTransactionCheck.Duplicate(existing)
        }

        // Check if ATC is close (possible recovery attempt)
        val existingAtcValue = ((existing.atc[0].toInt() and 0xFF) shl 8) or
                (existing.atc[1].toInt() and 0xFF)
        val newAtcValue = ((atc[0].toInt() and 0xFF) shl 8) or
                (atc[1].toInt() and 0xFF)

        if (newAtcValue == existingAtcValue + 1) {
            return TornTransactionCheck.RecoveryAttempt(existing)
        }

        return TornTransactionCheck.DifferentTransaction
    }

    /**
     * Clear a torn transaction record (e.g., after successful completion)
     */
    @Synchronized
    fun clearTornTransaction(pan: ByteArray) {
        val key = pan.joinToString("") { "%02X".format(it) }
        tornTransactions.remove(key)
    }

    private fun cleanupOldEntries() {
        val cutoff = System.currentTimeMillis() - 24 * 60 * 60 * 1000
        tornTransactions.entries.removeAll { it.value.timestamp < cutoff }
    }

    data class TornTransaction(
        val panHash: Int,
        val atc: ByteArray,
        val timestamp: Long
    )

    sealed class TornTransactionCheck {
        object NotFound : TornTransactionCheck()
        object DifferentTransaction : TornTransactionCheck()
        data class Duplicate(val existing: TornTransaction) : TornTransactionCheck()
        data class RecoveryAttempt(val existing: TornTransaction) : TornTransactionCheck()
    }
}

/**
 * Card removal detector for anti-tearing
 */
class CardRemovalDetector(
    private val checkIntervalMs: Long = 50
) {
    private val cardPresent = AtomicReference(true)
    private val checkCount = AtomicInteger(0)

    /**
     * Update card presence status
     */
    fun updateCardPresence(present: Boolean) {
        cardPresent.set(present)
        if (!present) {
            checkCount.incrementAndGet()
        }
    }

    /**
     * Check if card is still present
     */
    fun isCardPresent(): Boolean = cardPresent.get()

    /**
     * Check if card was removed at any point
     */
    fun wasCardRemoved(): Boolean = checkCount.get() > 0

    /**
     * Reset detector for new transaction
     */
    fun reset() {
        cardPresent.set(true)
        checkCount.set(0)
    }
}

/**
 * Status word handler for APDU responses
 */
object StatusWordHandler {

    /**
     * Interpret status word and determine appropriate action
     */
    fun interpret(sw1: Int, sw2: Int): StatusWordInterpretation {
        val sw = (sw1 shl 8) or sw2

        return when {
            // Success
            sw == 0x9000 -> StatusWordInterpretation.Success

            // Processing warning - data may be incomplete
            sw1 == 0x62 -> StatusWordInterpretation.Warning("State unchanged", canContinue = true)
            sw1 == 0x63 -> when (sw2 and 0xF0) {
                0xC0 -> StatusWordInterpretation.PinWrong(remainingTries = sw2 and 0x0F)
                else -> StatusWordInterpretation.Warning("State changed", canContinue = true)
            }

            // Execution error
            sw1 == 0x64 -> StatusWordInterpretation.Error("Memory unchanged", canRetry = true)
            sw1 == 0x65 -> StatusWordInterpretation.Error("Memory changed", canRetry = false)
            sw == 0x6700 -> StatusWordInterpretation.Error("Wrong length", canRetry = false)

            // Security errors
            sw == 0x6982 -> StatusWordInterpretation.SecurityError("Security status not satisfied")
            sw == 0x6983 -> StatusWordInterpretation.SecurityError("Authentication method blocked")
            sw == 0x6984 -> StatusWordInterpretation.SecurityError("Reference data invalidated")
            sw == 0x6985 -> StatusWordInterpretation.SecurityError("Conditions of use not satisfied")

            // Not found
            sw == 0x6A81 -> StatusWordInterpretation.NotSupported("Function not supported")
            sw == 0x6A82 -> StatusWordInterpretation.NotFound("File not found")
            sw == 0x6A83 -> StatusWordInterpretation.NotFound("Record not found")
            sw == 0x6A88 -> StatusWordInterpretation.NotFound("Referenced data not found")

            // Wrong parameters
            sw1 == 0x6A -> StatusWordInterpretation.WrongParameters("P1/P2 incorrect")
            sw == 0x6B00 -> StatusWordInterpretation.WrongParameters("Wrong P1/P2")
            sw == 0x6D00 -> StatusWordInterpretation.NotSupported("INS not supported")
            sw == 0x6E00 -> StatusWordInterpretation.NotSupported("CLA not supported")

            // Response available
            sw1 == 0x61 -> StatusWordInterpretation.MoreDataAvailable(sw2)
            sw1 == 0x6C -> StatusWordInterpretation.WrongLength(sw2)

            else -> StatusWordInterpretation.Unknown(sw)
        }
    }

    sealed class StatusWordInterpretation {
        object Success : StatusWordInterpretation()
        data class Warning(val message: String, val canContinue: Boolean) : StatusWordInterpretation()
        data class Error(val message: String, val canRetry: Boolean) : StatusWordInterpretation()
        data class SecurityError(val message: String) : StatusWordInterpretation()
        data class NotFound(val message: String) : StatusWordInterpretation()
        data class NotSupported(val message: String) : StatusWordInterpretation()
        data class WrongParameters(val message: String) : StatusWordInterpretation()
        data class PinWrong(val remainingTries: Int) : StatusWordInterpretation()
        data class MoreDataAvailable(val length: Int) : StatusWordInterpretation()
        data class WrongLength(val correctLength: Int) : StatusWordInterpretation()
        data class Unknown(val sw: Int) : StatusWordInterpretation()

        fun isSuccess() = this is Success
        fun isError() = this is Error || this is SecurityError
    }
}
