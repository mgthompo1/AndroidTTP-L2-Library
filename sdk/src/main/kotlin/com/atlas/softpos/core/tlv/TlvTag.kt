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
     * Integer representation of the tag (for use as map keys, etc.)
     */
    val value: Int
        get() {
            var result = 0
            for (b in bytes) {
                result = (result shl 8) or (b.toInt() and 0xFF)
            }
            return result
        }

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

        // ==================== COMMON EMV TAG CONSTANTS ====================
        // These provide convenient access to commonly used tags as TlvTag instances

        val AID = fromHex("4F")
        val PAN = fromHex("5A")
        val DF_NAME = fromHex("84")
        val CA_PUBLIC_KEY_INDEX = fromHex("8F")
        val ISSUER_PUBLIC_KEY_CERTIFICATE = fromHex("90")
        val ISSUER_PUBLIC_KEY_REMAINDER = fromHex("92")
        val SIGNED_STATIC_APPLICATION_DATA = fromHex("93")
        val AFL = fromHex("94")
        val CDOL1 = fromHex("8C")
        val CDOL2 = fromHex("8D")
        val ISSUER_PUBLIC_KEY_EXPONENT = fromHex("9F32")
        val ICC_PUBLIC_KEY_CERTIFICATE = fromHex("9F46")
        val ICC_PUBLIC_KEY_EXPONENT = fromHex("9F47")
        val ICC_PUBLIC_KEY_REMAINDER = fromHex("9F48")
        val DDOL = fromHex("9F49")
        val STATIC_DATA_AUTHENTICATION_TAG_LIST = fromHex("9F4A")
        val SDAD = fromHex("9F4B")

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

// Note: EmvTags object is defined in EmvTags.kt - use that for tag definitions
