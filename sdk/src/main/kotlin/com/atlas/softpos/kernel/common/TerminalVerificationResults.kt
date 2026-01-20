package com.atlas.softpos.kernel.common

/**
 * Terminal Verification Results (TVR) - Tag 95
 *
 * 5 bytes containing flags set by terminal during transaction processing.
 * Used for Terminal Action Analysis to determine transaction outcome.
 *
 * Reference: EMV Book 3, Annex C3
 */
class TerminalVerificationResults {
    private val bytes = ByteArray(5)

    // ==================== BYTE 1 ====================

    /** Offline data authentication was not performed */
    var odaNotPerformed: Boolean
        get() = getBit(0, 7)
        set(value) = setBit(0, 7, value)

    /** SDA failed */
    var sdaFailed: Boolean
        get() = getBit(0, 6)
        set(value) = setBit(0, 6, value)

    /** ICC data missing */
    var iccDataMissing: Boolean
        get() = getBit(0, 5)
        set(value) = setBit(0, 5, value)

    /** Card appears on terminal exception file */
    var cardOnExceptionFile: Boolean
        get() = getBit(0, 4)
        set(value) = setBit(0, 4, value)

    /** DDA failed */
    var ddaFailed: Boolean
        get() = getBit(0, 3)
        set(value) = setBit(0, 3, value)

    /** CDA failed */
    var cdaFailed: Boolean
        get() = getBit(0, 2)
        set(value) = setBit(0, 2, value)

    /** SDA selected (for contactless) */
    var sdaSelected: Boolean
        get() = getBit(0, 1)
        set(value) = setBit(0, 1, value)

    // Bit 0 RFU

    // ==================== BYTE 2 ====================

    /** ICC and terminal have different application versions */
    var appVersionsDiffer: Boolean
        get() = getBit(1, 7)
        set(value) = setBit(1, 7, value)

    /** Expired application */
    var expiredApplication: Boolean
        get() = getBit(1, 6)
        set(value) = setBit(1, 6, value)

    /** Application not yet effective */
    var applicationNotYetEffective: Boolean
        get() = getBit(1, 5)
        set(value) = setBit(1, 5, value)

    /** Requested service not allowed for card product */
    var serviceNotAllowed: Boolean
        get() = getBit(1, 4)
        set(value) = setBit(1, 4, value)

    /** New card */
    var newCard: Boolean
        get() = getBit(1, 3)
        set(value) = setBit(1, 3, value)

    // Bits 2-0 RFU

    // ==================== BYTE 3 ====================

    /** Cardholder verification was not successful */
    var cvmNotSuccessful: Boolean
        get() = getBit(2, 7)
        set(value) = setBit(2, 7, value)

    /** Unrecognised CVM */
    var unrecognisedCvm: Boolean
        get() = getBit(2, 6)
        set(value) = setBit(2, 6, value)

    /** PIN try limit exceeded */
    var pinTryLimitExceeded: Boolean
        get() = getBit(2, 5)
        set(value) = setBit(2, 5, value)

    /** PIN entry required and PIN pad not present or not working */
    var pinPadNotWorking: Boolean
        get() = getBit(2, 4)
        set(value) = setBit(2, 4, value)

    /** PIN entry required, PIN pad present but PIN was not entered */
    var pinNotEntered: Boolean
        get() = getBit(2, 3)
        set(value) = setBit(2, 3, value)

    /** Online PIN entered */
    var onlinePinEntered: Boolean
        get() = getBit(2, 2)
        set(value) = setBit(2, 2, value)

    // Bits 1-0 RFU

    // ==================== BYTE 4 ====================

    /** Transaction exceeds floor limit */
    var floorLimitExceeded: Boolean
        get() = getBit(3, 7)
        set(value) = setBit(3, 7, value)

    /** Lower consecutive offline limit exceeded */
    var lcolExceeded: Boolean
        get() = getBit(3, 6)
        set(value) = setBit(3, 6, value)

    /** Upper consecutive offline limit exceeded */
    var ucolExceeded: Boolean
        get() = getBit(3, 5)
        set(value) = setBit(3, 5, value)

    /** Transaction selected randomly for online processing */
    var randomlySelectedOnline: Boolean
        get() = getBit(3, 4)
        set(value) = setBit(3, 4, value)

    /** Merchant forced transaction online */
    var merchantForcedOnline: Boolean
        get() = getBit(3, 3)
        set(value) = setBit(3, 3, value)

    // Bits 2-0 RFU

    // ==================== BYTE 5 ====================

    /** Default TDOL used */
    var defaultTdolUsed: Boolean
        get() = getBit(4, 7)
        set(value) = setBit(4, 7, value)

    /** Issuer authentication failed */
    var issuerAuthFailed: Boolean
        get() = getBit(4, 6)
        set(value) = setBit(4, 6, value)

    /** Script processing failed before final GENERATE AC */
    var scriptFailedBeforeAc: Boolean
        get() = getBit(4, 5)
        set(value) = setBit(4, 5, value)

    /** Script processing failed after final GENERATE AC */
    var scriptFailedAfterAc: Boolean
        get() = getBit(4, 4)
        set(value) = setBit(4, 4, value)

    // Bits 3-0 RFU

    // ==================== CONTACTLESS SPECIFIC (Visa qVSDC) ====================

    /** Relay resistance threshold exceeded (Byte 4, Bit 2) */
    var relayResistanceThresholdExceeded: Boolean
        get() = getBit(3, 2)
        set(value) = setBit(3, 2, value)

    /** Relay resistance time limits exceeded (Byte 4, Bit 1) */
    var relayResistanceTimeLimitsExceeded: Boolean
        get() = getBit(3, 1)
        set(value) = setBit(3, 1, value)

    // ==================== METHODS ====================

    private fun getBit(byteIndex: Int, bitIndex: Int): Boolean {
        return (bytes[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    private fun setBit(byteIndex: Int, bitIndex: Int, value: Boolean) {
        bytes[byteIndex] = if (value) {
            (bytes[byteIndex].toInt() or (1 shl bitIndex)).toByte()
        } else {
            (bytes[byteIndex].toInt() and (1 shl bitIndex).inv()).toByte()
        }
    }

    /**
     * Get raw bytes
     */
    fun toBytes(): ByteArray = bytes.copyOf()

    /**
     * Set from raw bytes
     */
    fun fromBytes(data: ByteArray) {
        require(data.size >= 5) { "TVR must be 5 bytes" }
        System.arraycopy(data, 0, bytes, 0, 5)
    }

    /**
     * Check if any ODA failure flags are set
     */
    fun hasOdaFailure(): Boolean {
        return sdaFailed || ddaFailed || cdaFailed
    }

    /**
     * Check if any CVM failure flags are set
     */
    fun hasCvmFailure(): Boolean {
        return cvmNotSuccessful || unrecognisedCvm || pinTryLimitExceeded
    }

    /**
     * Check if transaction should go online based on TVR
     */
    fun requiresOnline(): Boolean {
        return floorLimitExceeded || lcolExceeded || ucolExceeded ||
                randomlySelectedOnline || merchantForcedOnline
    }

    /**
     * Reset all flags
     */
    fun reset() {
        for (i in bytes.indices) {
            bytes[i] = 0
        }
    }

    /**
     * Perform AND operation with IAC/TAC
     */
    fun matchesActionCode(actionCode: ByteArray): Boolean {
        require(actionCode.size == 5) { "Action code must be 5 bytes" }
        for (i in 0 until 5) {
            if ((bytes[i].toInt() and actionCode[i].toInt()) != 0) {
                return true
            }
        }
        return false
    }

    override fun toString(): String {
        return buildString {
            append("TVR[")
            if (odaNotPerformed) append("ODA_NOT_PERFORMED ")
            if (sdaFailed) append("SDA_FAILED ")
            if (ddaFailed) append("DDA_FAILED ")
            if (cdaFailed) append("CDA_FAILED ")
            if (iccDataMissing) append("ICC_DATA_MISSING ")
            if (expiredApplication) append("EXPIRED ")
            if (cvmNotSuccessful) append("CVM_FAILED ")
            if (pinTryLimitExceeded) append("PIN_TRIES_EXCEEDED ")
            if (floorLimitExceeded) append("FLOOR_LIMIT ")
            if (lcolExceeded) append("LCOL ")
            if (ucolExceeded) append("UCOL ")
            if (randomlySelectedOnline) append("RANDOM_ONLINE ")
            if (merchantForcedOnline) append("MERCHANT_ONLINE ")
            if (issuerAuthFailed) append("ISSUER_AUTH_FAILED ")
            append("]")
        }
    }

    companion object {
        fun fromBytes(data: ByteArray): TerminalVerificationResults {
            return TerminalVerificationResults().apply { fromBytes(data) }
        }
    }
}

/**
 * Transaction Status Information (TSI) - Tag 9B
 *
 * 2 bytes indicating functions performed during transaction
 */
class TransactionStatusInformation {
    private val bytes = ByteArray(2)

    // ==================== BYTE 1 ====================

    /** Offline data authentication was performed */
    var odaPerformed: Boolean
        get() = getBit(0, 7)
        set(value) = setBit(0, 7, value)

    /** Cardholder verification was performed */
    var cvmPerformed: Boolean
        get() = getBit(0, 6)
        set(value) = setBit(0, 6, value)

    /** Card risk management was performed */
    var cardRiskManagementPerformed: Boolean
        get() = getBit(0, 5)
        set(value) = setBit(0, 5, value)

    /** Issuer authentication was performed */
    var issuerAuthPerformed: Boolean
        get() = getBit(0, 4)
        set(value) = setBit(0, 4, value)

    /** Terminal risk management was performed */
    var terminalRiskManagementPerformed: Boolean
        get() = getBit(0, 3)
        set(value) = setBit(0, 3, value)

    /** Script processing was performed */
    var scriptProcessingPerformed: Boolean
        get() = getBit(0, 2)
        set(value) = setBit(0, 2, value)

    // Bits 1-0 RFU

    // ==================== BYTE 2 ====================
    // All bits RFU

    private fun getBit(byteIndex: Int, bitIndex: Int): Boolean {
        return (bytes[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    private fun setBit(byteIndex: Int, bitIndex: Int, value: Boolean) {
        bytes[byteIndex] = if (value) {
            (bytes[byteIndex].toInt() or (1 shl bitIndex)).toByte()
        } else {
            (bytes[byteIndex].toInt() and (1 shl bitIndex).inv()).toByte()
        }
    }

    fun toBytes(): ByteArray = bytes.copyOf()

    fun fromBytes(data: ByteArray) {
        require(data.size >= 2) { "TSI must be 2 bytes" }
        System.arraycopy(data, 0, bytes, 0, 2)
    }

    fun reset() {
        bytes[0] = 0
        bytes[1] = 0
    }
}

/**
 * Card Verification Results (CVR) - Network specific
 * Used in Issuer Application Data interpretation
 */
class CardVerificationResults {
    var byte1: Byte = 0
    var byte2: Byte = 0
    var byte3: Byte = 0
    var byte4: Byte = 0

    // Visa CVR Byte 1
    val acReturnedInSecondGenerateAc: Boolean get() = (byte1.toInt() and 0x10) != 0
    val acReturnedInFirstGenerateAc: Boolean get() = (byte1.toInt() and 0x08) != 0

    // Visa CVR Byte 2
    val offlinePinVerificationPerformed: Boolean get() = (byte2.toInt() and 0x80) != 0
    val offlinePinVerificationFailed: Boolean get() = (byte2.toInt() and 0x40) != 0
    val pinTryLimitExceeded: Boolean get() = (byte2.toInt() and 0x20) != 0
    val lastOnlineTxnNotCompleted: Boolean get() = (byte2.toInt() and 0x10) != 0
    val lowerOfflineTransactionCountLimitExceeded: Boolean get() = (byte2.toInt() and 0x08) != 0
    val upperOfflineTransactionCountLimitExceeded: Boolean get() = (byte2.toInt() and 0x04) != 0
    val lowerCumulativeOfflineAmountLimitExceeded: Boolean get() = (byte2.toInt() and 0x02) != 0
    val upperCumulativeOfflineAmountLimitExceeded: Boolean get() = (byte2.toInt() and 0x01) != 0

    fun toBytes(): ByteArray = byteArrayOf(byte1, byte2, byte3, byte4)

    companion object {
        fun fromIad(iad: ByteArray): CardVerificationResults? {
            if (iad.size < 4) return null
            return CardVerificationResults().apply {
                // CVR is typically at offset 3 in IAD for Visa
                // Format varies by network
                if (iad.size >= 7) {
                    byte1 = iad[3]
                    byte2 = iad[4]
                    byte3 = if (iad.size > 5) iad[5] else 0
                    byte4 = if (iad.size > 6) iad[6] else 0
                }
            }
        }
    }
}
