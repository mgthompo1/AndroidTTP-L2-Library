package com.atlas.softpos.core.dol

import com.atlas.softpos.core.tlv.EmvTags
import com.atlas.softpos.core.tlv.Tag
import com.atlas.softpos.core.types.hexToByteArray
import com.atlas.softpos.core.types.toHexString
import timber.log.Timber

/**
 * Data Object List (DOL) Parser and Builder
 *
 * Handles PDOL, CDOL1, CDOL2, DDOL, TDOL parsing and data construction.
 * DOLs specify which data elements the card expects from the terminal.
 *
 * DOL Format: Tag1 | Length1 | Tag2 | Length2 | ... | TagN | LengthN
 * Built Data: Value1 | Value2 | ... | ValueN (concatenated, no delimiters)
 */
object DolParser {

    /**
     * Parse a DOL into a list of requested tags with lengths
     */
    fun parse(dol: ByteArray): List<DolEntry> {
        val entries = mutableListOf<DolEntry>()
        var offset = 0

        while (offset < dol.size) {
            // Parse tag (1 or 2 bytes)
            val tagStart = offset
            val firstByte = dol[offset].toInt() and 0xFF

            val tagValue: Int
            val tagLength: Int

            if ((firstByte and 0x1F) == 0x1F) {
                // Two-byte tag
                if (offset + 1 >= dol.size) break
                tagValue = (firstByte shl 8) or (dol[offset + 1].toInt() and 0xFF)
                tagLength = 2
            } else {
                // One-byte tag
                tagValue = firstByte
                tagLength = 1
            }
            offset += tagLength

            // Parse length (1 byte in DOL - always simple form)
            if (offset >= dol.size) break
            val length = dol[offset].toInt() and 0xFF
            offset++

            val tag = EmvTags.get(tagValue)
            entries.add(DolEntry(
                tagValue = tagValue,
                tagHex = "%0${tagLength * 2}X".format(tagValue),
                length = length,
                tag = tag
            ))
        }

        return entries
    }

    /**
     * Build DOL data from terminal data store
     *
     * @param dol The DOL bytes from card
     * @param dataStore Map of tag hex -> value bytes
     * @return Concatenated DOL data
     */
    fun buildDolData(dol: ByteArray, dataStore: DataStore): ByteArray {
        val entries = parse(dol)
        return buildDolData(entries, dataStore)
    }

    /**
     * Build DOL data from parsed entries
     */
    fun buildDolData(entries: List<DolEntry>, dataStore: DataStore): ByteArray {
        val result = mutableListOf<Byte>()

        for (entry in entries) {
            val value = dataStore.get(entry.tagValue) ?: dataStore.get(entry.tagHex)
            val data = formatValue(value, entry.length, entry.tagValue)
            result.addAll(data.toList())

            Timber.v("DOL entry ${entry.tagHex}: requested=${entry.length}, provided=${data.size}, value=${data.toHexString()}")
        }

        return result.toByteArray()
    }

    /**
     * Format a value to the required length
     * - If value is null, return zeros (or spaces for alphanumeric)
     * - If value is shorter, left-pad with zeros (for numeric) or right-pad with spaces (for alpha)
     * - If value is longer, truncate
     */
    private fun formatValue(value: ByteArray?, requestedLength: Int, tagValue: Int = 0): ByteArray {
        val isAlphanumeric = isAlphanumericTag(tagValue)

        if (value == null) {
            return if (isAlphanumeric) {
                ByteArray(requestedLength) { 0x20 }  // Space padding for AN fields
            } else {
                ByteArray(requestedLength)  // Zero padding for numeric fields
            }
        }

        return when {
            value.size == requestedLength -> value
            value.size > requestedLength -> value.copyOfRange(0, requestedLength)
            else -> {
                val padded = ByteArray(requestedLength)
                if (isAlphanumeric) {
                    // Right-pad with spaces for alphanumeric fields
                    padded.fill(0x20)  // Fill with spaces
                    System.arraycopy(value, 0, padded, 0, value.size)
                } else {
                    // Left-pad with zeros for numeric fields
                    System.arraycopy(value, 0, padded, requestedLength - value.size, value.size)
                }
                padded
            }
        }
    }

    /**
     * Check if tag is alphanumeric (AN/ANS format) - these need right-padding with spaces
     */
    private fun isAlphanumericTag(tagValue: Int): Boolean {
        return tagValue in listOf(
            0x9F1C,  // Terminal Identification (8 bytes AN)
            0x9F16,  // Merchant Identifier (15 bytes AN)
            0x9F1E,  // IFD Serial Number (8 bytes AN)
            0x5F20,  // Cardholder Name (2-26 bytes ANS)
            0x50,    // Application Label (1-16 bytes ANS)
            0x9F12,  // Application Preferred Name (1-16 bytes ANS)
            0x5F2D,  // Language Preference (2-8 bytes AN)
            0x9F4E   // Merchant Name and Location (var ANS)
        )
    }

    /**
     * Check if all required DOL entries can be satisfied
     */
    fun canSatisfy(dol: ByteArray, dataStore: DataStore): Pair<Boolean, List<String>> {
        val entries = parse(dol)
        val missing = mutableListOf<String>()

        for (entry in entries) {
            val value = dataStore.get(entry.tagValue) ?: dataStore.get(entry.tagHex)
            if (value == null) {
                // Check if it's a critical tag
                if (isCriticalTag(entry.tagValue)) {
                    missing.add(entry.tagHex)
                }
            }
        }

        return Pair(missing.isEmpty(), missing)
    }

    /**
     * Tags that must be present (not just filled with zeros)
     */
    private fun isCriticalTag(tagValue: Int): Boolean {
        return tagValue in listOf(
            0x9F02,  // Amount Authorized
            0x9F03,  // Amount Other
            0x9F1A,  // Terminal Country Code
            0x5F2A,  // Transaction Currency Code
            0x9A,    // Transaction Date
            0x9C,    // Transaction Type
            0x9F37,  // Unpredictable Number
            0x9F66   // TTQ (for Visa)
        )
    }
}

/**
 * DOL Entry
 */
data class DolEntry(
    val tagValue: Int,
    val tagHex: String,
    val length: Int,
    val tag: Tag?
) {
    val name: String get() = tag?.name ?: "Unknown"
}

/**
 * Terminal Data Store
 * Manages terminal data elements for DOL construction
 */
class DataStore {
    private val data = mutableMapOf<Int, ByteArray>()
    private val dataByHex = mutableMapOf<String, ByteArray>()

    fun set(tagValue: Int, value: ByteArray) {
        data[tagValue] = value
        // Use consistent hex formatting: 2 digits for 1-byte tags, 4 digits for 2-byte tags
        val hexKey = if (tagValue > 0xFF) "%04X".format(tagValue) else "%02X".format(tagValue)
        dataByHex[hexKey] = value
    }

    fun set(tagHex: String, value: ByteArray) {
        val tagValue = tagHex.toIntOrNull(16)
        if (tagValue != null) {
            data[tagValue] = value
        }
        dataByHex[tagHex.uppercase()] = value
    }

    fun get(tagValue: Int): ByteArray? = data[tagValue]

    fun get(tagHex: String): ByteArray? = dataByHex[tagHex.uppercase()]

    fun contains(tagValue: Int): Boolean = data.containsKey(tagValue)

    fun contains(tagHex: String): Boolean = dataByHex.containsKey(tagHex.uppercase())

    fun clear() {
        data.clear()
        dataByHex.clear()
    }

    fun all(): Map<Int, ByteArray> = data.toMap()

    /**
     * Populate standard terminal data
     */
    fun populateTerminalData(config: TerminalConfiguration, transaction: TransactionData) {
        // Transaction data
        set(0x9F02, transaction.amountAuthorized.toAmount())
        set(0x9F03, transaction.amountOther.toAmount())
        set(0x5F2A, config.currencyCode)
        set(0x9A, transaction.date)
        set(0x9F21, transaction.time)
        set(0x9C, byteArrayOf(transaction.type))
        set(0x9F37, transaction.unpredictableNumber)

        // Terminal configuration
        set(0x9F1A, config.countryCode)
        set(0x9F33, config.terminalCapabilities)
        set(0x9F35, byteArrayOf(config.terminalType))
        set(0x9F40, config.additionalTerminalCapabilities)
        set(0x9F1E, config.ifdSerialNumber)
        set(0x9F15, config.mcc)

        // Contactless specific
        set(0x9F66, config.ttq)
        set(0x95, ByteArray(5))  // TVR - initialized to zeros
        set(0x9F34, ByteArray(3))  // CVM Results - initialized
        set(0x9F09, config.applicationVersion)

        // Optional
        config.acquirerId?.let { set(0x9F01, it) }
        config.terminalId?.let { set(0x9F1C, it) }
        config.merchantId?.let { set(0x9F16, it) }
        transaction.sequenceNumber?.let { set(0x9F41, it) }
    }

    private fun Long.toAmount(): ByteArray {
        // BCD encoded, 6 bytes - amounts must be non-negative
        require(this >= 0) { "Amount cannot be negative: $this" }
        val str = "%012d".format(this)
        return str.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}

/**
 * Terminal configuration for DOL population
 */
data class TerminalConfiguration(
    val countryCode: ByteArray,
    val currencyCode: ByteArray,
    val terminalCapabilities: ByteArray,
    val terminalType: Byte,
    val additionalTerminalCapabilities: ByteArray,
    val ifdSerialNumber: ByteArray,
    val mcc: ByteArray,
    val ttq: ByteArray,
    val applicationVersion: ByteArray = byteArrayOf(0x00, 0x02),
    val acquirerId: ByteArray? = null,
    val terminalId: ByteArray? = null,
    val merchantId: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TerminalConfiguration) return false
        return terminalType == other.terminalType
    }

    override fun hashCode(): Int = terminalType.hashCode()
}

/**
 * Transaction data for DOL population
 */
data class TransactionData(
    val amountAuthorized: Long,
    val amountOther: Long = 0,
    val date: ByteArray,  // YYMMDD BCD
    val time: ByteArray,  // HHMMSS BCD
    val type: Byte,       // 0x00 = purchase
    val unpredictableNumber: ByteArray,
    val sequenceNumber: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransactionData) return false
        return unpredictableNumber.contentEquals(other.unpredictableNumber)
    }

    override fun hashCode(): Int = unpredictableNumber.contentHashCode()
}

// Extension functions
private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
