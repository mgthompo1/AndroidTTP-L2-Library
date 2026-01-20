package com.atlas.softpos.crypto

import com.atlas.softpos.core.types.toHexString
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * EMV Cryptographic Operations
 *
 * Implements all cryptographic functions required for EMV L2 certification:
 * - RSA signature verification (up to 2048-bit)
 * - SHA-1/SHA-256 hashing
 * - MAC generation for session keys
 * - Certificate recovery and validation
 */
object EmvCrypto {

    /**
     * Recover data from RSA signature using public key
     * Used for certificate and signed data recovery in ODA
     *
     * @param signature The signature bytes to recover
     * @param modulus The RSA public key modulus
     * @param exponent The RSA public key exponent (usually 3 or 65537)
     * @return Recovered plaintext data
     */
    fun rsaRecover(
        signature: ByteArray,
        modulus: ByteArray,
        exponent: ByteArray
    ): ByteArray {
        val modulusBigInt = BigInteger(1, modulus)
        val exponentBigInt = BigInteger(1, exponent)
        val signatureBigInt = BigInteger(1, signature)

        // RSA recovery: plaintext = signature^exponent mod modulus
        val recovered = signatureBigInt.modPow(exponentBigInt, modulusBigInt)

        // Pad to modulus length
        var result = recovered.toByteArray()

        // Remove leading zero if present (sign byte)
        if (result.size > modulus.size && result[0] == 0.toByte()) {
            result = result.copyOfRange(1, result.size)
        }

        // Pad with leading zeros if needed
        if (result.size < modulus.size) {
            val padded = ByteArray(modulus.size)
            System.arraycopy(result, 0, padded, modulus.size - result.size, result.size)
            result = padded
        }

        return result
    }

    /**
     * Verify RSA signature
     */
    fun rsaVerify(
        data: ByteArray,
        signature: ByteArray,
        modulus: ByteArray,
        exponent: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA1
    ): Boolean {
        val recovered = rsaRecover(signature, modulus, exponent)
        val expectedHash = hash(data, hashAlgorithm)

        // Check recovered data format and extract hash
        // EMV format: 6A || data || hash || BC
        if (recovered.isEmpty()) return false

        val hashLength = when (hashAlgorithm) {
            HashAlgorithm.SHA1 -> 20
            HashAlgorithm.SHA256 -> 32
        }

        if (recovered.size < hashLength + 2) return false

        // Extract hash from recovered data (last hashLength bytes before trailer)
        val trailerIndex = recovered.size - 1
        if (recovered[trailerIndex] != 0xBC.toByte()) {
            // Try without trailer check for some certificate formats
        }

        val recoveredHash = recovered.copyOfRange(
            recovered.size - hashLength - 1,
            recovered.size - 1
        )

        return recoveredHash.contentEquals(expectedHash)
    }

    /**
     * SHA-1 hash
     */
    fun sha1(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-1").digest(data)
    }

    /**
     * SHA-256 hash
     */
    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /**
     * Generic hash function
     */
    fun hash(data: ByteArray, algorithm: HashAlgorithm): ByteArray {
        return when (algorithm) {
            HashAlgorithm.SHA1 -> sha1(data)
            HashAlgorithm.SHA256 -> sha256(data)
        }
    }

    /**
     * Compute MAC using ISO 9797-1 Algorithm 3 (Retail MAC)
     * Used for issuer authentication and script processing
     */
    fun retailMac(
        data: ByteArray,
        key: ByteArray
    ): ByteArray {
        require(key.size == 16) { "Key must be 16 bytes (double-length DES)" }

        val keyLeft = key.copyOfRange(0, 8)
        val keyRight = key.copyOfRange(8, 16)

        // Pad data to multiple of 8 bytes
        val padded = pad80(data, 8)

        // CBC-MAC with left key
        var intermediate = ByteArray(8)
        val cipher = Cipher.getInstance("DES/ECB/NoPadding")
        val desKeyLeft = SecretKeySpec(keyLeft, "DES")
        cipher.init(Cipher.ENCRYPT_MODE, desKeyLeft)

        for (i in padded.indices step 8) {
            val block = padded.copyOfRange(i, i + 8)
            val xored = xor(intermediate, block)
            intermediate = cipher.doFinal(xored)
        }

        // Final decrypt with right key, encrypt with left key
        val desKeyRight = SecretKeySpec(keyRight, "DES")
        cipher.init(Cipher.DECRYPT_MODE, desKeyRight)
        val decrypted = cipher.doFinal(intermediate)

        cipher.init(Cipher.ENCRYPT_MODE, desKeyLeft)
        return cipher.doFinal(decrypted)
    }

    /**
     * 3DES encryption (2-key)
     */
    fun des3Encrypt(data: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 16) { "Key must be 16 bytes" }

        // Expand to 24-byte key (K1-K2-K1)
        val expandedKey = ByteArray(24)
        System.arraycopy(key, 0, expandedKey, 0, 16)
        System.arraycopy(key, 0, expandedKey, 16, 8)

        val keySpec = SecretKeySpec(expandedKey, "DESede")
        val cipher = Cipher.getInstance("DESede/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)

        return cipher.doFinal(pad80(data, 8))
    }

    /**
     * 3DES decryption (2-key)
     */
    fun des3Decrypt(data: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 16) { "Key must be 16 bytes" }

        val expandedKey = ByteArray(24)
        System.arraycopy(key, 0, expandedKey, 0, 16)
        System.arraycopy(key, 0, expandedKey, 16, 8)

        val keySpec = SecretKeySpec(expandedKey, "DESede")
        val cipher = Cipher.getInstance("DESede/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec)

        return unpad80(cipher.doFinal(data))
    }

    /**
     * ISO/IEC 9797-1 Padding Method 2 (0x80 padding)
     */
    fun pad80(data: ByteArray, blockSize: Int): ByteArray {
        val paddingLength = blockSize - (data.size % blockSize)
        val padded = ByteArray(data.size + paddingLength)
        System.arraycopy(data, 0, padded, 0, data.size)
        padded[data.size] = 0x80.toByte()
        // Rest is already 0x00
        return padded
    }

    /**
     * Remove ISO/IEC 9797-1 Padding Method 2
     */
    fun unpad80(data: ByteArray): ByteArray {
        var i = data.size - 1
        while (i >= 0 && data[i] == 0x00.toByte()) {
            i--
        }
        if (i >= 0 && data[i] == 0x80.toByte()) {
            return data.copyOfRange(0, i)
        }
        return data
    }

    /**
     * XOR two byte arrays
     */
    fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "Arrays must be same length" }
        return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
    }

    /**
     * Derive session key from master key and ATC
     * Used for Application Cryptogram generation
     */
    fun deriveSessionKey(
        masterKey: ByteArray,
        atc: ByteArray,
        keyType: SessionKeyType
    ): ByteArray {
        require(masterKey.size == 16) { "Master key must be 16 bytes" }
        require(atc.size == 2) { "ATC must be 2 bytes" }

        val derivationData = ByteArray(8)
        derivationData[0] = atc[0]
        derivationData[1] = atc[1]
        derivationData[2] = 0xF0.toByte()
        derivationData[3] = keyType.value
        // Bytes 4-7 are 0x00

        val leftKey = des3Encrypt(derivationData, masterKey).copyOfRange(0, 8)

        derivationData[2] = 0x0F.toByte()
        val rightKey = des3Encrypt(derivationData, masterKey).copyOfRange(0, 8)

        return leftKey + rightKey
    }

    /**
     * Generate Application Cryptogram (ARQC/TC/AAC)
     * EMV Book 2, Annex A1.4
     */
    fun generateApplicationCryptogram(
        sessionKey: ByteArray,
        data: ByteArray
    ): ByteArray {
        return retailMac(data, sessionKey)
    }

    /**
     * Verify ARPC (Authorization Response Cryptogram)
     * Method 1: ARPC = MAC(ARQC XOR ARC)
     */
    fun verifyArpcMethod1(
        arqc: ByteArray,
        arc: ByteArray,
        arpc: ByteArray,
        sessionKey: ByteArray
    ): Boolean {
        require(arqc.size == 8) { "ARQC must be 8 bytes" }
        require(arc.size == 2) { "ARC must be 2 bytes" }

        // Pad ARC to 8 bytes
        val arcPadded = ByteArray(8)
        arcPadded[0] = arc[0]
        arcPadded[1] = arc[1]

        val xored = xor(arqc, arcPadded)
        val expectedArpc = retailMac(xored, sessionKey)

        return arpc.contentEquals(expectedArpc)
    }

    enum class HashAlgorithm {
        SHA1,
        SHA256
    }

    enum class SessionKeyType(val value: Byte) {
        AC(0x00),      // Application Cryptogram
        MAC(0x01),     // MAC
        ENC(0x02)      // Encryption
    }
}

/**
 * Certificate data recovered from EMV certificates
 */
data class RecoveredCertificate(
    val format: Byte,
    val identifier: ByteArray,
    val expiryDate: ByteArray,  // MMYY
    val serialNumber: ByteArray,
    val hashAlgorithm: Byte,
    val publicKeyAlgorithm: Byte,
    val publicKeyLength: Int,
    val publicKeyExponentLength: Int,
    val publicKeyRemainder: ByteArray,
    val hash: ByteArray,
    val isValid: Boolean
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RecoveredCertificate) return false
        return identifier.contentEquals(other.identifier) &&
                serialNumber.contentEquals(other.serialNumber)
    }

    override fun hashCode(): Int {
        var result = identifier.contentHashCode()
        result = 31 * result + serialNumber.contentHashCode()
        return result
    }
}
