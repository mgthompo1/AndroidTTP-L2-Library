package com.atlas.softpos.core.tlv

import com.atlas.softpos.core.types.hexToByteArray
import com.atlas.softpos.core.types.toHexString

/**
 * Represents a single TLV (Tag-Length-Value) data object.
 *
 * EMV uses BER-TLV encoding:
 * - Tag: 1-3 bytes identifying the data element
 * - Length: 1-3 bytes indicating value length
 * - Value: The actual data (or nested TLVs if constructed)
 */
data class Tlv(
    val tag: TlvTag,
    val value: ByteArray
) {
    val length: Int get() = value.size

    /**
     * For constructed tags, parse the value as nested TLVs
     */
    fun getChildren(): List<Tlv> {
        if (!tag.isConstructed) return emptyList()
        return TlvParser.parse(value)
    }

    /**
     * Encode this TLV to bytes
     */
    fun encode(): ByteArray {
        val tagBytes = tag.bytes
        val lengthBytes = encodeLength(value.size)
        return tagBytes + lengthBytes + value
    }

    /**
     * Get value as hex string
     */
    fun valueHex(): String = value.toHexString()

    /**
     * Get value as ASCII string (for text fields like cardholder name)
     */
    fun valueAscii(): String = String(value, Charsets.US_ASCII)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Tlv) return false
        return tag.hex == other.tag.hex && value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }

    override fun toString(): String {
        return if (tag.isConstructed) {
            "Tlv(${tag.hex}, constructed, ${getChildren().size} children)"
        } else {
            "Tlv(${tag.hex}, ${value.toHexString()})"
        }
    }

    companion object {
        fun fromHex(tagHex: String, valueHex: String): Tlv {
            return Tlv(TlvTag.fromHex(tagHex), valueHex.hexToByteArray())
        }

        /**
         * Encode length according to BER-TLV rules:
         * - 0-127: Single byte
         * - 128-255: 0x81 followed by length byte
         * - 256-65535: 0x82 followed by 2 length bytes
         */
        fun encodeLength(length: Int): ByteArray {
            return when {
                length < 128 -> byteArrayOf(length.toByte())
                length < 256 -> byteArrayOf(0x81.toByte(), length.toByte())
                length < 65536 -> byteArrayOf(
                    0x82.toByte(),
                    (length shr 8).toByte(),
                    length.toByte()
                )
                else -> throw IllegalArgumentException("Length too large: $length")
            }
        }

        /**
         * Parse length from byte array, returning length value and bytes consumed
         */
        fun parseLength(data: ByteArray, offset: Int): Pair<Int, Int> {
            val firstByte = data[offset].toInt() and 0xFF

            return when {
                // Short form: single byte, high bit not set
                firstByte < 128 -> firstByte to 1

                // Long form: first byte indicates number of length bytes
                firstByte == 0x81 -> {
                    (data[offset + 1].toInt() and 0xFF) to 2
                }

                firstByte == 0x82 -> {
                    val len = ((data[offset + 1].toInt() and 0xFF) shl 8) or
                            (data[offset + 2].toInt() and 0xFF)
                    len to 3
                }

                firstByte == 0x83 -> {
                    val len = ((data[offset + 1].toInt() and 0xFF) shl 16) or
                            ((data[offset + 2].toInt() and 0xFF) shl 8) or
                            (data[offset + 3].toInt() and 0xFF)
                    len to 4
                }

                else -> throw IllegalArgumentException(
                    "Unsupported length encoding: ${firstByte.toString(16)}"
                )
            }
        }
    }
}

/**
 * Parser for BER-TLV encoded data
 */
object TlvParser {
    /**
     * Operator invoke to allow TlvParser() syntax for backward compatibility
     * Returns the singleton object itself
     */
    operator fun invoke(): TlvParser = this

    /**
     * Parse a byte array containing one or more TLV objects
     */
    fun parse(data: ByteArray): List<Tlv> {
        val result = mutableListOf<Tlv>()
        var offset = 0

        while (offset < data.size) {
            // Skip padding bytes (0x00 or 0xFF)
            if (data[offset] == 0x00.toByte() || data[offset] == 0xFF.toByte()) {
                offset++
                continue
            }

            // Parse tag
            val (tag, tagLength) = TlvTag.parse(data, offset)
            offset += tagLength

            // Parse length
            if (offset >= data.size) break
            val (length, lengthBytes) = Tlv.parseLength(data, offset)
            offset += lengthBytes

            // Bounds check before extracting value
            if (offset + length > data.size) {
                throw IllegalArgumentException(
                    "TLV length exceeds data bounds: offset=$offset, length=$length, dataSize=${data.size}"
                )
            }

            // Extract value
            val value = data.copyOfRange(offset, offset + length)
            offset += length

            result.add(Tlv(tag, value))
        }

        return result
    }

    /**
     * Parse and return a map for easy lookup by tag
     */
    fun parseToMap(data: ByteArray): Map<String, Tlv> {
        return parse(data).associateBy { it.tag.hex }
    }

    /**
     * Recursively parse all TLVs including nested ones
     */
    fun parseRecursive(data: ByteArray): List<Tlv> {
        val result = mutableListOf<Tlv>()

        for (tlv in parse(data)) {
            result.add(tlv)
            if (tlv.tag.isConstructed) {
                result.addAll(parseRecursive(tlv.value))
            }
        }

        return result
    }

    /**
     * Find a specific tag in the data (searches recursively)
     */
    fun findTag(data: ByteArray, targetTag: TlvTag): Tlv? {
        return parseRecursive(data).find { it.tag.hex == targetTag.hex }
    }

    /**
     * Find a specific tag by hex string
     */
    fun findTag(data: ByteArray, tagHex: String): Tlv? {
        return findTag(data, TlvTag.fromHex(tagHex))
    }

    /**
     * Find a specific tag by EmvTags.Tag
     */
    fun findTag(data: ByteArray, tag: Tag): Tlv? {
        return findTag(data, tag.hex)
    }
}

/**
 * Builder for constructing TLV data
 */
class TlvBuilder {
    private val tlvs = mutableListOf<Tlv>()

    fun add(tag: TlvTag, value: ByteArray): TlvBuilder {
        tlvs.add(Tlv(tag, value))
        return this
    }

    fun add(tagHex: String, value: ByteArray): TlvBuilder {
        return add(TlvTag.fromHex(tagHex), value)
    }

    fun add(tagHex: String, valueHex: String): TlvBuilder {
        return add(TlvTag.fromHex(tagHex), valueHex.hexToByteArray())
    }

    fun add(tag: Tag, value: ByteArray): TlvBuilder {
        return add(TlvTag.fromHex(tag.hex), value)
    }

    fun add(tlv: Tlv): TlvBuilder {
        tlvs.add(tlv)
        return this
    }

    fun addAll(tlvs: List<Tlv>): TlvBuilder {
        this.tlvs.addAll(tlvs)
        return this
    }

    /**
     * Add a constructed (template) TLV containing other TLVs
     */
    fun addConstructed(tagHex: String, builder: TlvBuilder.() -> Unit): TlvBuilder {
        val innerBuilder = TlvBuilder()
        innerBuilder.builder()
        val innerData = innerBuilder.build()
        return add(tagHex, innerData)
    }

    fun build(): ByteArray {
        if (tlvs.isEmpty()) return byteArrayOf()
        return tlvs.map { it.encode() }.reduce { acc, bytes -> acc + bytes }
    }

    fun toList(): List<Tlv> = tlvs.toList()
}

/**
 * DSL function for building TLV data
 */
fun buildTlv(builder: TlvBuilder.() -> Unit): ByteArray {
    return TlvBuilder().apply(builder).build()
}

/**
 * Type alias for backward compatibility - TlvObject is the same as Tlv
 */
typealias TlvObject = Tlv
