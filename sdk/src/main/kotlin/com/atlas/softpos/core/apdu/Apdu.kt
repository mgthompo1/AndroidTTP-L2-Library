package com.atlas.softpos.core.apdu

import com.atlas.softpos.core.types.hexToByteArray
import com.atlas.softpos.core.types.toHexString

/**
 * Command APDU (Application Protocol Data Unit)
 *
 * Structure:
 * | CLA | INS | P1 | P2 | Lc | Data | Le |
 *
 * - CLA: Class byte (instruction class)
 * - INS: Instruction byte
 * - P1, P2: Parameter bytes
 * - Lc: Length of command data (optional)
 * - Data: Command data (optional)
 * - Le: Expected response length (optional)
 */
data class CommandApdu(
    val cla: Byte,
    val ins: Byte,
    val p1: Byte,
    val p2: Byte,
    val data: ByteArray? = null,
    val le: Int? = null  // null = no Le, 0 = 256, 1-255 = that value
) {
    /**
     * Encode to byte array for transmission
     */
    fun encode(): ByteArray {
        val result = mutableListOf<Byte>()

        // Header
        result.add(cla)
        result.add(ins)
        result.add(p1)
        result.add(p2)

        // Lc and Data
        if (data != null && data.isNotEmpty()) {
            if (data.size <= 255) {
                // Short APDU: single byte Lc
                result.add(data.size.toByte())
            } else {
                // Extended APDU: 3-byte Lc (0x00 + 2 bytes big-endian)
                result.add(0x00)
                result.add((data.size shr 8).toByte())
                result.add((data.size and 0xFF).toByte())
            }
            result.addAll(data.toList())
        }

        // Le
        if (le != null) {
            if (data != null && data.size > 255) {
                // Extended Le: 2 bytes
                if (le == 65536 || le == 0) {
                    result.add(0x00)
                    result.add(0x00)
                } else {
                    result.add((le shr 8).toByte())
                    result.add((le and 0xFF).toByte())
                }
            } else {
                // Short Le: single byte (0x00 = 256)
                result.add(if (le == 256) 0x00.toByte() else le.toByte())
            }
        }

        return result.toByteArray()
    }

    fun toHexString(): String = encode().toHexString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CommandApdu) return false
        return cla == other.cla && ins == other.ins &&
                p1 == other.p1 && p2 == other.p2 &&
                data.contentEquals(other.data) && le == other.le
    }

    override fun hashCode(): Int {
        var result = cla.toInt()
        result = 31 * result + ins.toInt()
        result = 31 * result + p1.toInt()
        result = 31 * result + p2.toInt()
        result = 31 * result + (data?.contentHashCode() ?: 0)
        result = 31 * result + (le ?: 0)
        return result
    }

    companion object {
        fun fromHex(hex: String): CommandApdu {
            val bytes = hex.hexToByteArray()
            require(bytes.size >= 4) { "APDU must be at least 4 bytes" }

            val cla = bytes[0]
            val ins = bytes[1]
            val p1 = bytes[2]
            val p2 = bytes[3]

            return when (bytes.size) {
                4 -> CommandApdu(cla, ins, p1, p2)
                5 -> CommandApdu(cla, ins, p1, p2, le = bytes[4].toInt() and 0xFF)
                else -> {
                    val lc = bytes[4].toInt() and 0xFF
                    val data = bytes.copyOfRange(5, 5 + lc)
                    val le = if (bytes.size > 5 + lc) {
                        bytes[5 + lc].toInt() and 0xFF
                    } else null
                    CommandApdu(cla, ins, p1, p2, data, le)
                }
            }
        }
    }
}

/**
 * Response APDU from the card
 *
 * Structure:
 * | Data | SW1 | SW2 |
 *
 * - Data: Response data (optional)
 * - SW1, SW2: Status words
 */
data class ResponseApdu(
    val data: ByteArray,
    val sw1: Byte,
    val sw2: Byte
) {
    /**
     * Combined status word (SW1 << 8 | SW2)
     */
    val sw: Int get() = ((sw1.toInt() and 0xFF) shl 8) or (sw2.toInt() and 0xFF)

    /**
     * Check if response indicates success (9000)
     */
    val isSuccess: Boolean get() = sw == 0x9000

    /**
     * Check if more data is available (61XX)
     */
    val hasMoreData: Boolean get() = (sw1.toInt() and 0xFF) == 0x61

    /**
     * Get the number of additional bytes available (from 61XX response)
     */
    val additionalDataLength: Int
        get() = if (hasMoreData) sw2.toInt() and 0xFF else 0

    /**
     * Check if warning (62XX or 63XX)
     */
    val isWarning: Boolean
        get() {
            val sw1Int = sw1.toInt() and 0xFF
            return sw1Int == 0x62 || sw1Int == 0x63
        }

    /**
     * Check if error
     */
    val isError: Boolean
        get() = !isSuccess && !hasMoreData && !isWarning

    /**
     * Get human-readable status description
     */
    val statusDescription: String
        get() = when (sw) {
            0x9000 -> "Success"
            0x6283 -> "Selected file invalidated"
            0x6700 -> "Wrong length"
            0x6882 -> "Secure messaging not supported"
            0x6982 -> "Security status not satisfied"
            0x6983 -> "Authentication method blocked"
            0x6984 -> "Reference data not usable"
            0x6985 -> "Conditions of use not satisfied"
            0x6A80 -> "Incorrect parameters in data field"
            0x6A81 -> "Function not supported"
            0x6A82 -> "File or application not found"
            0x6A83 -> "Record not found"
            0x6A86 -> "Incorrect P1-P2"
            0x6A88 -> "Referenced data not found"
            0x6B00 -> "Wrong parameters P1-P2"
            0x6C00 -> "Wrong Le field"
            0x6D00 -> "Instruction not supported"
            0x6E00 -> "Class not supported"
            0x6F00 -> "Unknown error"
            else -> {
                if (hasMoreData) {
                    "$additionalDataLength more bytes available"
                } else {
                    "Unknown status: ${sw.toString(16).uppercase()}"
                }
            }
        }

    fun dataHex(): String = data.toHexString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ResponseApdu) return false
        return data.contentEquals(other.data) && sw1 == other.sw1 && sw2 == other.sw2
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1.toInt()
        result = 31 * result + sw2.toInt()
        return result
    }

    override fun toString(): String {
        return "ResponseApdu(data=${data.toHexString()}, sw=${sw.toString(16).uppercase()}, $statusDescription)"
    }

    companion object {
        /**
         * Parse a byte array into a ResponseApdu.
         * Alias for fromBytes for backward compatibility.
         */
        fun parse(bytes: ByteArray): ResponseApdu = fromBytes(bytes)

        fun fromBytes(bytes: ByteArray): ResponseApdu {
            require(bytes.size >= 2) { "Response must be at least 2 bytes (status word)" }

            val data = if (bytes.size > 2) {
                bytes.copyOfRange(0, bytes.size - 2)
            } else {
                ByteArray(0)
            }

            return ResponseApdu(
                data = data,
                sw1 = bytes[bytes.size - 2],
                sw2 = bytes[bytes.size - 1]
            )
        }

        fun success(data: ByteArray = ByteArray(0)): ResponseApdu {
            return ResponseApdu(data, 0x90.toByte(), 0x00.toByte())
        }

        fun error(sw: Int): ResponseApdu {
            return ResponseApdu(
                ByteArray(0),
                (sw shr 8).toByte(),
                sw.toByte()
            )
        }
    }
}
