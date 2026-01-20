package com.atlas.softpos

import com.atlas.softpos.crypto.EmvCrypto
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for EMV cryptographic operations
 *
 * Tests SHA-1, SHA-256, 3DES, and RSA operations
 * per EMV Book 2 specifications.
 */
class EmvCryptoTest {

    // ==================== SHA-1 TESTS ====================

    @Test
    fun `SHA1 produces correct hash for empty input`() {
        val result = EmvCrypto.sha1(byteArrayOf())

        assertEquals(20, result.size)
        // Known SHA-1 of empty string: DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
        assertArrayEquals(
            hexToBytes("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
            result
        )
    }

    @Test
    fun `SHA1 produces correct hash for known input`() {
        val input = "test".toByteArray(Charsets.US_ASCII)
        val result = EmvCrypto.sha1(input)

        assertEquals(20, result.size)
        // Known SHA-1 of "test": A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
        assertArrayEquals(
            hexToBytes("A94A8FE5CCB19BA61C4C0873D391E987982FBBD3"),
            result
        )
    }

    @Test
    fun `SHA1 produces consistent results`() {
        val input = byteArrayOf(0x01, 0x02, 0x03, 0x04)

        val result1 = EmvCrypto.sha1(input)
        val result2 = EmvCrypto.sha1(input)

        assertArrayEquals(result1, result2)
    }

    // ==================== SHA-256 TESTS ====================

    @Test
    fun `SHA256 produces correct hash for empty input`() {
        val result = EmvCrypto.sha256(byteArrayOf())

        assertEquals(32, result.size)
        // Known SHA-256 of empty string
        assertArrayEquals(
            hexToBytes("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
            result
        )
    }

    @Test
    fun `SHA256 produces correct hash for known input`() {
        val input = "test".toByteArray(Charsets.US_ASCII)
        val result = EmvCrypto.sha256(input)

        assertEquals(32, result.size)
        // Known SHA-256 of "test"
        assertArrayEquals(
            hexToBytes("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"),
            result
        )
    }

    @Test
    fun `SHA256 produces consistent results`() {
        val input = byteArrayOf(0x01, 0x02, 0x03, 0x04)

        val result1 = EmvCrypto.sha256(input)
        val result2 = EmvCrypto.sha256(input)

        assertArrayEquals(result1, result2)
    }

    // ==================== 3DES TESTS ====================

    @Test
    fun `3DES encrypt produces correct length output`() {
        val key = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val data = hexToBytes("0000000000000000")

        val result = EmvCrypto.tripleDesEncrypt(data, key)

        assertEquals(8, result.size)
    }

    @Test
    fun `3DES decrypt reverses encrypt`() {
        val key = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val plaintext = hexToBytes("1234567890ABCDEF")

        val encrypted = EmvCrypto.tripleDesEncrypt(plaintext, key)
        val decrypted = EmvCrypto.tripleDesDecrypt(encrypted, key)

        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun `3DES with different keys produces different results`() {
        val key1 = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val key2 = hexToBytes("FEDCBA9876543210FEDCBA9876543210")
        val data = hexToBytes("0000000000000000")

        val result1 = EmvCrypto.tripleDesEncrypt(data, key1)
        val result2 = EmvCrypto.tripleDesEncrypt(data, key2)

        assertFalse(result1.contentEquals(result2))
    }

    // ==================== MAC TESTS ====================

    @Test
    fun `MAC generation produces 8 byte result`() {
        val key = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val data = hexToBytes("0102030405060708090A0B0C0D0E0F10")

        val result = EmvCrypto.generateMac(data, key)

        assertEquals(8, result.size)
    }

    @Test
    fun `MAC is consistent for same input`() {
        val key = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val data = hexToBytes("0102030405060708090A0B0C0D0E0F10")

        val result1 = EmvCrypto.generateMac(data, key)
        val result2 = EmvCrypto.generateMac(data, key)

        assertArrayEquals(result1, result2)
    }

    @Test
    fun `MAC differs for different data`() {
        val key = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val data1 = hexToBytes("0102030405060708090A0B0C0D0E0F10")
        val data2 = hexToBytes("1112131415161718191A1B1C1D1E1F20")

        val result1 = EmvCrypto.generateMac(data1, key)
        val result2 = EmvCrypto.generateMac(data2, key)

        assertFalse(result1.contentEquals(result2))
    }

    // ==================== SESSION KEY DERIVATION TESTS ====================

    @Test
    fun `Session key derivation produces 16 byte key`() {
        val masterKey = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val pan = "4000000000000001"
        val psn = "00"

        val result = EmvCrypto.deriveSessionKey(masterKey, pan, psn)

        assertEquals(16, result.size)
    }

    @Test
    fun `Session key derivation is consistent`() {
        val masterKey = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val pan = "4000000000000001"
        val psn = "00"

        val result1 = EmvCrypto.deriveSessionKey(masterKey, pan, psn)
        val result2 = EmvCrypto.deriveSessionKey(masterKey, pan, psn)

        assertArrayEquals(result1, result2)
    }

    @Test
    fun `Session key differs for different PAN`() {
        val masterKey = hexToBytes("0123456789ABCDEF0123456789ABCDEF")
        val pan1 = "4000000000000001"
        val pan2 = "4000000000000002"
        val psn = "00"

        val result1 = EmvCrypto.deriveSessionKey(masterKey, pan1, psn)
        val result2 = EmvCrypto.deriveSessionKey(masterKey, pan2, psn)

        assertFalse(result1.contentEquals(result2))
    }

    // ==================== RSA RECOVERY TESTS ====================

    @Test
    fun `RSA recovery produces non-empty result for valid input`() {
        // Small test values
        val data = ByteArray(128) { 0x00 }
        data[0] = 0x01
        val modulus = ByteArray(128) { 0xFF.toByte() }
        modulus[0] = 0x00  // Make it a valid number
        val exponent = byteArrayOf(0x03)

        val result = EmvCrypto.rsaRecover(data, modulus, exponent)

        assertTrue(result.isNotEmpty())
    }

    @Test
    fun `RSA recovery output size matches modulus size`() {
        // Test with controlled size
        val modulusSize = 128
        val data = ByteArray(modulusSize)
        val modulus = ByteArray(modulusSize)
        val exponent = byteArrayOf(0x01, 0x00, 0x01)  // 65537

        // Fill with test data
        for (i in data.indices) {
            data[i] = i.toByte()
        }
        for (i in modulus.indices) {
            modulus[i] = (0xFF - i).toByte()
        }
        modulus[0] = 0x00  // Ensure positive

        val result = EmvCrypto.rsaRecover(data, modulus, exponent)

        assertEquals(modulusSize, result.size)
    }

    // ==================== XOR TESTS ====================

    @Test
    fun `XOR produces correct result`() {
        val a = byteArrayOf(0xFF.toByte(), 0x00, 0xAA.toByte())
        val b = byteArrayOf(0x0F, 0xF0.toByte(), 0x55)

        val result = EmvCrypto.xor(a, b)

        assertArrayEquals(byteArrayOf(0xF0.toByte(), 0xF0.toByte(), 0xFF.toByte()), result)
    }

    @Test
    fun `XOR with self produces zeros`() {
        val a = byteArrayOf(0x12, 0x34, 0x56, 0x78)

        val result = EmvCrypto.xor(a, a)

        assertTrue(result.all { it == 0x00.toByte() })
    }

    @Test
    fun `XOR handles different length arrays`() {
        val a = byteArrayOf(0xFF.toByte(), 0xFF.toByte())
        val b = byteArrayOf(0x00, 0x00, 0xFF.toByte())

        val result = EmvCrypto.xor(a, b)

        // Should use shorter length
        assertEquals(2, result.size)
    }

    // ==================== HELPER FUNCTIONS ====================

    private fun hexToBytes(hex: String): ByteArray {
        check(hex.length % 2 == 0) { "Hex string must have even length" }
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02X".format(it) }
    }
}
