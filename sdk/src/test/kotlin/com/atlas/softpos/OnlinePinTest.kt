package com.atlas.softpos

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for Online PIN block building
 *
 * Tests PIN block formats per ISO 9564-1
 */
class OnlinePinTest {

    // ==================== ISO FORMAT 0 TESTS ====================

    @Test
    fun `test ISO Format 0 PIN block structure`() {
        val pin = "1234"
        val pan = "4111111111111111"

        val pinBlock = buildIsoFormat0PinBlock(pin, pan)

        assertEquals(8, pinBlock.size)
    }

    @Test
    fun `test ISO Format 0 with 4-digit PIN`() {
        val pin = "1234"
        val pan = "4111111111111111"

        val pinBlock = buildIsoFormat0PinBlock(pin, pan)

        // PIN field: 0 | 4 | 1234 | FFFFFFFFFF
        // PAN field: 0000 | 111111111111
        // Result is XOR of these

        // Verify it's 8 bytes
        assertEquals(8, pinBlock.size)

        // Verify it can be decrypted (reversible XOR)
        val pinFieldRecovered = xorWithPanField(pinBlock, pan)
        assertEquals("04", pinFieldRecovered.substring(0, 2))
    }

    @Test
    fun `test ISO Format 0 with 6-digit PIN`() {
        val pin = "123456"
        val pan = "4111111111111111"

        val pinBlock = buildIsoFormat0PinBlock(pin, pan)

        assertEquals(8, pinBlock.size)

        val pinFieldRecovered = xorWithPanField(pinBlock, pan)
        assertEquals("06", pinFieldRecovered.substring(0, 2)) // Length = 6
    }

    @Test
    fun `test ISO Format 0 different PANs produce different blocks`() {
        val pin = "1234"
        val pan1 = "4111111111111111"
        val pan2 = "5500000000000004"

        val block1 = buildIsoFormat0PinBlock(pin, pan1)
        val block2 = buildIsoFormat0PinBlock(pin, pan2)

        assertFalse(block1.contentEquals(block2))
    }

    @Test
    fun `test ISO Format 0 different PINs produce different blocks`() {
        val pan = "4111111111111111"
        val pin1 = "1234"
        val pin2 = "5678"

        val block1 = buildIsoFormat0PinBlock(pin1, pan)
        val block2 = buildIsoFormat0PinBlock(pin2, pan)

        assertFalse(block1.contentEquals(block2))
    }

    @Test
    fun `test ISO Format 0 with short PAN`() {
        val pin = "1234"
        val pan = "4111111111111" // 13 digits

        val pinBlock = buildIsoFormat0PinBlock(pin, pan)

        assertEquals(8, pinBlock.size)
    }

    // ==================== PIN FIELD TESTS ====================

    @Test
    fun `test PIN field construction`() {
        // PIN field format: 0 | PIN Length | PIN | F padding

        // 4-digit PIN
        var pinField = buildPinField("1234")
        assertEquals("041234FFFFFFFFFF", pinField)

        // 5-digit PIN
        pinField = buildPinField("12345")
        assertEquals("0512345FFFFFFFFF", pinField)

        // 6-digit PIN
        pinField = buildPinField("123456")
        assertEquals("06123456FFFFFFFF", pinField)
    }

    // ==================== PAN FIELD TESTS ====================

    @Test
    fun `test PAN field construction`() {
        // PAN field format: 0000 | 12 rightmost digits (excluding check digit)

        // 16-digit PAN
        var panField = buildPanField("4111111111111111")
        assertEquals("0000111111111111", panField)

        // Different PAN
        panField = buildPanField("5500000000000004")
        assertEquals("0000000000000000", panField)
    }

    @Test
    fun `test PAN field with 15-digit PAN`() {
        val panField = buildPanField("371449635398431") // AmEx 15 digits
        assertEquals(16, panField.length)
    }

    // ==================== XOR TESTS ====================

    @Test
    fun `test XOR operation is reversible`() {
        val a = hexToBytes("0412345FFFFFFFFF")
        val b = hexToBytes("0000111111111111")

        val xored = xorBytes(a, b)
        val recovered = xorBytes(xored, b)

        assertArrayEquals(a, recovered)
    }

    // ==================== HELPER METHODS ====================

    private fun buildIsoFormat0PinBlock(pin: String, pan: String): ByteArray {
        val pinField = buildPinField(pin)
        val panField = buildPanField(pan)

        val pinBytes = hexToBytes(pinField)
        val panBytes = hexToBytes(panField)

        return xorBytes(pinBytes, panBytes)
    }

    private fun buildPinField(pin: String): String {
        val sb = StringBuilder()
        sb.append("0")
        sb.append(pin.length.toString(16).uppercase())
        sb.append(pin)
        while (sb.length < 16) {
            sb.append("F")
        }
        return sb.toString()
    }

    private fun buildPanField(pan: String): String {
        val panDigits = pan.replace("[^0-9]".toRegex(), "")
        val panForBlock = if (panDigits.length >= 13) {
            panDigits.substring(panDigits.length - 13, panDigits.length - 1)
        } else {
            panDigits.dropLast(1).padStart(12, '0')
        }
        return "0000$panForBlock"
    }

    private fun xorWithPanField(pinBlock: ByteArray, pan: String): String {
        val panField = buildPanField(pan)
        val panBytes = hexToBytes(panField)
        val result = xorBytes(pinBlock, panBytes)
        return result.toHexString()
    }

    private fun xorBytes(a: ByteArray, b: ByteArray): ByteArray {
        val result = ByteArray(minOf(a.size, b.size))
        for (i in result.indices) {
            result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return result
    }

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in result.indices) {
            result[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02X".format(it) }
    }
}
