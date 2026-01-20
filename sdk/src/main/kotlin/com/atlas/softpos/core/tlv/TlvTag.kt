package com.atlas.softpos.core.tlv

import com.atlas.softpos.core.types.hexToByteArray
import com.atlas.softpos.core.types.toHexString

/**
 * Represents an EMV TLV Tag.
 *
 * EMV tags follow BER-TLV encoding rules:
 * - First byte determines tag class and constructed/primitive
 * - If first byte ends in 0x1F, tag continues to next byte(s)
 * - Multi-byte tags continue while high bit (0x80) is set
 */
@JvmInline
value class TlvTag(val bytes: ByteArray) {

    val hex: String get() = bytes.toHexString()

    /**
     * Tag class: Universal (00), Application (01), Context-specific (10), Private (11)
     */
    val tagClass: TagClass
        get() = when ((bytes[0].toInt() and 0xC0) shr 6) {
            0 -> TagClass.UNIVERSAL
            1 -> TagClass.APPLICATION
            2 -> TagClass.CONTEXT_SPECIFIC
            3 -> TagClass.PRIVATE
            else -> TagClass.UNIVERSAL
        }

    /**
     * Whether this tag is constructed (contains other TLVs) or primitive (contains data)
     */
    val isConstructed: Boolean
        get() = (bytes[0].toInt() and 0x20) != 0

    /**
     * Tag number (for single-byte tags with number < 31)
     */
    val tagNumber: Int
        get() {
            if (bytes.size == 1) {
                return bytes[0].toInt() and 0x1F
            }
            // Multi-byte tag number calculation
            var number = 0
            for (i in 1 until bytes.size) {
                number = (number shl 7) or (bytes[i].toInt() and 0x7F)
            }
            return number
        }

    override fun toString(): String = hex

    companion object {
        fun fromHex(hex: String): TlvTag = TlvTag(hex.hexToByteArray())

        fun fromBytes(bytes: ByteArray): TlvTag = TlvTag(bytes.copyOf())

        /**
         * Parse tag from byte array at given offset, returning tag and bytes consumed
         */
        fun parse(data: ByteArray, offset: Int): Pair<TlvTag, Int> {
            var pos = offset
            val tagBytes = mutableListOf<Byte>()

            // First byte
            val firstByte = data[pos++]
            tagBytes.add(firstByte)

            // Check if multi-byte tag (first byte ends in 0x1F)
            if ((firstByte.toInt() and 0x1F) == 0x1F) {
                // Read subsequent bytes while high bit is set
                do {
                    val nextByte = data[pos++]
                    tagBytes.add(nextByte)
                } while ((tagBytes.last().toInt() and 0x80) != 0)
            }

            return TlvTag(tagBytes.toByteArray()) to (pos - offset)
        }
    }

    enum class TagClass {
        UNIVERSAL,      // Standard ASN.1 types
        APPLICATION,    // EMV-specific tags
        CONTEXT_SPECIFIC,
        PRIVATE
    }
}

/**
 * Common EMV Tags used in contactless transactions
 */
object EmvTags {
    // Template Tags (Constructed)
    val FCI_TEMPLATE = TlvTag.fromHex("6F")
    val FCI_PROPRIETARY = TlvTag.fromHex("A5")
    val FCI_ISSUER_DISCRETIONARY = TlvTag.fromHex("BF0C")
    val RESPONSE_TEMPLATE_1 = TlvTag.fromHex("80")
    val RESPONSE_TEMPLATE_2 = TlvTag.fromHex("77")
    val RECORD_TEMPLATE = TlvTag.fromHex("70")

    // Application Selection
    val DF_NAME = TlvTag.fromHex("84")
    val APPLICATION_LABEL = TlvTag.fromHex("50")
    val APPLICATION_PRIORITY = TlvTag.fromHex("87")
    val PDOL = TlvTag.fromHex("9F38")
    val LANGUAGE_PREFERENCE = TlvTag.fromHex("5F2D")
    val ISSUER_CODE_TABLE_INDEX = TlvTag.fromHex("9F11")
    val APPLICATION_PREFERRED_NAME = TlvTag.fromHex("9F12")
    val SFI = TlvTag.fromHex("88")
    val APPLICATION_DIRECTORY_ENTRY = TlvTag.fromHex("61")

    // Card Data
    val PAN = TlvTag.fromHex("5A")
    val TRACK2_EQUIVALENT = TlvTag.fromHex("57")
    val CARDHOLDER_NAME = TlvTag.fromHex("5F20")
    val EXPIRY_DATE = TlvTag.fromHex("5F24")
    val EFFECTIVE_DATE = TlvTag.fromHex("5F25")
    val PAN_SEQUENCE_NUMBER = TlvTag.fromHex("5F34")
    val SERVICE_CODE = TlvTag.fromHex("5F30")

    // Transaction Data
    val AMOUNT_AUTHORIZED = TlvTag.fromHex("9F02")
    val AMOUNT_OTHER = TlvTag.fromHex("9F03")
    val TERMINAL_COUNTRY_CODE = TlvTag.fromHex("9F1A")
    val TRANSACTION_CURRENCY_CODE = TlvTag.fromHex("5F2A")
    val TRANSACTION_DATE = TlvTag.fromHex("9A")
    val TRANSACTION_TIME = TlvTag.fromHex("9F21")
    val TRANSACTION_TYPE = TlvTag.fromHex("9C")
    val UNPREDICTABLE_NUMBER = TlvTag.fromHex("9F37")
    val TERMINAL_TYPE = TlvTag.fromHex("9F35")
    val TERMINAL_CAPABILITIES = TlvTag.fromHex("9F33")
    val ADDITIONAL_TERMINAL_CAPABILITIES = TlvTag.fromHex("9F40")
    val IFD_SERIAL_NUMBER = TlvTag.fromHex("9F1E")
    val MERCHANT_CATEGORY_CODE = TlvTag.fromHex("9F15")
    val MERCHANT_IDENTIFIER = TlvTag.fromHex("9F16")
    val TERMINAL_IDENTIFICATION = TlvTag.fromHex("9F1C")
    val ACQUIRER_IDENTIFIER = TlvTag.fromHex("9F01")

    // Cryptographic Data
    val APPLICATION_CRYPTOGRAM = TlvTag.fromHex("9F26")
    val CRYPTOGRAM_INFO_DATA = TlvTag.fromHex("9F27")
    val APPLICATION_TRANSACTION_COUNTER = TlvTag.fromHex("9F36")
    val ISSUER_APPLICATION_DATA = TlvTag.fromHex("9F10")
    val CVM_RESULTS = TlvTag.fromHex("9F34")
    val TERMINAL_VERIFICATION_RESULTS = TlvTag.fromHex("95")
    val TRANSACTION_STATUS_INFO = TlvTag.fromHex("9B")
    val CDOL1 = TlvTag.fromHex("8C")
    val CDOL2 = TlvTag.fromHex("8D")

    // Application Interchange Profile & Capabilities
    val AIP = TlvTag.fromHex("82")
    val AFL = TlvTag.fromHex("94")
    val AID = TlvTag.fromHex("4F")
    val APPLICATION_VERSION_NUMBER = TlvTag.fromHex("9F08")
    val APPLICATION_VERSION_NUMBER_TERMINAL = TlvTag.fromHex("9F09")

    // Visa Specific
    val VISA_FORM_FACTOR_INDICATOR = TlvTag.fromHex("9F6E")
    val VISA_CARD_TRANSACTION_QUALIFIERS = TlvTag.fromHex("9F6C")
    val VISA_CUSTOMER_EXCLUSIVE_DATA = TlvTag.fromHex("9F7C")

    // CVM (Cardholder Verification Method)
    val CVM_LIST = TlvTag.fromHex("8E")

    // Risk Management
    val LOWER_CONSECUTIVE_OFFLINE_LIMIT = TlvTag.fromHex("9F14")
    val UPPER_CONSECUTIVE_OFFLINE_LIMIT = TlvTag.fromHex("9F23")
    val LAST_ONLINE_ATC_REGISTER = TlvTag.fromHex("9F13")

    // PPSE (Proximity Payment System Environment)
    val DIRECTORY_DISCRETIONARY_TEMPLATE = TlvTag.fromHex("73")
}
