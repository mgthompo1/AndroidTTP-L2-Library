package com.atlas.softpos.crypto

import timber.log.Timber
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * EMV Session Key Derivation per EMV Book 2 Annex A1.3
 *
 * Implements the complete key derivation hierarchy:
 * 1. Issuer Master Key (IMK) - provided by issuer
 * 2. ICC Master Key (MK_ICC) - derived from IMK + PAN + PSN
 * 3. Session Keys (SK) - derived from MK_ICC + ATC
 *
 * Reference: EMV Book 2 v4.3, Annex A1.3 - Session Key Derivation
 */
object EmvSessionKeyDerivation {

    /**
     * Derive ICC Master Key from Issuer Master Key
     * EMV Book 2 Annex A1.3.1 - Master Key Derivation
     *
     * Option A (Common): MK_ICC = 3DES(IMK, PAN || PSN padded)
     *
     * @param issuerMasterKey 16-byte Issuer Master Key (IMK_AC, IMK_SMC, or IMK_SMI)
     * @param pan Primary Account Number (up to 16 digits as bytes, BCD encoded)
     * @param panSequenceNumber PAN Sequence Number (1 byte), default 0x00
     * @return 16-byte ICC Master Key
     */
    fun deriveIccMasterKey(
        issuerMasterKey: ByteArray,
        pan: ByteArray,
        panSequenceNumber: Byte = 0x00
    ): ByteArray {
        require(issuerMasterKey.size == 16) { "Issuer Master Key must be 16 bytes" }
        require(pan.isNotEmpty() && pan.size <= 10) { "PAN must be 1-10 bytes (BCD)" }

        // Build derivation data: rightmost 16 digits of PAN || PSN, left-padded with zeros
        // Per EMV Book 2 A1.3.1: Use decimal digits of PAN
        val derivationInput = buildDerivationInput(pan, panSequenceNumber)

        // Derive left half: 3DES encrypt derivation data
        val leftHalf = des3EncryptBlock(derivationInput, issuerMasterKey)

        // Derive right half: 3DES encrypt (derivation data XOR FFFFFFFFFFFFFFFF)
        val invertedInput = derivationInput.map { (it.toInt() xor 0xFF).toByte() }.toByteArray()
        val rightHalf = des3EncryptBlock(invertedInput, issuerMasterKey)

        val masterKey = leftHalf + rightHalf
        Timber.d("Derived ICC Master Key from PAN ending ...${pan.takeLast(2).toByteArray().toHexString()}")

        return masterKey
    }

    /**
     * Derive Session Key from ICC Master Key
     * EMV Book 2 Annex A1.3.1 - Session Key Derivation
     *
     * SK = 3DES(MK_ICC, ATC || 0xF0 || 0x00...) || 3DES(MK_ICC, ATC || 0x0F || 0x00...)
     *
     * @param iccMasterKey 16-byte ICC Master Key
     * @param atc 2-byte Application Transaction Counter
     * @param keyType Type of session key to derive (AC, MAC, or ENC)
     * @return 16-byte Session Key
     */
    fun deriveSessionKey(
        iccMasterKey: ByteArray,
        atc: ByteArray,
        keyType: SessionKeyType
    ): ByteArray {
        require(iccMasterKey.size == 16) { "ICC Master Key must be 16 bytes" }
        require(atc.size == 2) { "ATC must be 2 bytes" }

        // Build derivation data for left key half
        // Format: ATC (2) || F0 (1) || 00 (5) for left, ATC || 0F || 00... for right
        val leftInput = ByteArray(8).apply {
            this[0] = atc[0]
            this[1] = atc[1]
            this[2] = 0xF0.toByte()
            this[3] = keyType.derivationConstant
            // Bytes 4-7 are 0x00
        }

        val rightInput = ByteArray(8).apply {
            this[0] = atc[0]
            this[1] = atc[1]
            this[2] = 0x0F.toByte()
            this[3] = keyType.derivationConstant
            // Bytes 4-7 are 0x00
        }

        val leftHalf = des3EncryptBlock(leftInput, iccMasterKey)
        val rightHalf = des3EncryptBlock(rightInput, iccMasterKey)

        return leftHalf + rightHalf
    }

    /**
     * Complete session key derivation from Issuer Master Key
     * Combines IMK -> MK_ICC -> SK derivation in one call
     *
     * @param issuerMasterKey 16-byte Issuer Master Key
     * @param pan PAN in BCD format
     * @param panSequenceNumber PSN (default 0x00)
     * @param atc 2-byte Application Transaction Counter
     * @param keyType Type of session key
     * @return 16-byte Session Key
     */
    fun deriveSessionKeyFromImk(
        issuerMasterKey: ByteArray,
        pan: ByteArray,
        panSequenceNumber: Byte = 0x00,
        atc: ByteArray,
        keyType: SessionKeyType
    ): ByteArray {
        val iccMasterKey = deriveIccMasterKey(issuerMasterKey, pan, panSequenceNumber)
        return deriveSessionKey(iccMasterKey, atc, keyType)
    }

    /**
     * Visa-specific session key derivation (CVN 10, 17, 18)
     * Uses different derivation method based on Cryptogram Version Number
     *
     * @param iccMasterKey ICC Master Key for AC generation
     * @param atc Application Transaction Counter
     * @param cvn Cryptogram Version Number (determines derivation method)
     * @return 16-byte Session Key
     */
    fun deriveVisaSessionKey(
        iccMasterKey: ByteArray,
        atc: ByteArray,
        cvn: Int
    ): ByteArray {
        require(iccMasterKey.size == 16) { "ICC Master Key must be 16 bytes" }
        require(atc.size == 2) { "ATC must be 2 bytes" }

        return when (cvn) {
            10 -> {
                // CVN 10: SK = MK_AC (no derivation, use master key directly)
                iccMasterKey.copyOf()
            }
            17, 18 -> {
                // CVN 17/18: Standard EMV session key derivation
                deriveSessionKey(iccMasterKey, atc, SessionKeyType.AC)
            }
            else -> {
                Timber.w("Unknown CVN $cvn, using standard derivation")
                deriveSessionKey(iccMasterKey, atc, SessionKeyType.AC)
            }
        }
    }

    /**
     * Mastercard-specific session key derivation
     * Supports M/Chip 4 and M/Chip Advance
     *
     * @param iccMasterKey ICC Master Key
     * @param atc Application Transaction Counter
     * @param unpredictableNumber 4-byte UN (used in some derivation methods)
     * @param cid Cryptogram Information Data (indicates derivation method)
     * @return 16-byte Session Key
     */
    fun deriveMastercardSessionKey(
        iccMasterKey: ByteArray,
        atc: ByteArray,
        unpredictableNumber: ByteArray? = null,
        cid: Byte = 0x80.toByte()
    ): ByteArray {
        require(iccMasterKey.size == 16) { "ICC Master Key must be 16 bytes" }
        require(atc.size == 2) { "ATC must be 2 bytes" }

        // M/Chip uses standard EMV derivation with ATC
        // The CID upper nibble indicates AC type, not derivation method
        return deriveSessionKey(iccMasterKey, atc, SessionKeyType.AC)
    }

    /**
     * Generate Application Cryptogram using derived session key
     * EMV Book 2 Annex A1.4.1
     *
     * @param sessionKey 16-byte session key
     * @param transactionData Data to MAC (CDOL1 data for first AC)
     * @return 8-byte Application Cryptogram (ARQC, TC, or AAC)
     */
    fun generateApplicationCryptogram(
        sessionKey: ByteArray,
        transactionData: ByteArray
    ): ByteArray {
        require(sessionKey.size == 16) { "Session key must be 16 bytes" }

        // AC = Retail MAC over transaction data
        return EmvCrypto.retailMac(transactionData, sessionKey)
    }

    /**
     * Verify ARPC (Authorization Response Cryptogram) Method 1
     * EMV Book 2 Annex A1.4.2
     *
     * ARPC = MAC(ARQC XOR (ARC || 0x00...))
     *
     * @param arqc 8-byte ARQC from card
     * @param arc 2-byte Authorization Response Code
     * @param arpc 8-byte ARPC from issuer
     * @param sessionKey 16-byte session key
     * @return true if ARPC is valid
     */
    fun verifyArpcMethod1(
        arqc: ByteArray,
        arc: ByteArray,
        arpc: ByteArray,
        sessionKey: ByteArray
    ): Boolean {
        require(arqc.size == 8) { "ARQC must be 8 bytes" }
        require(arc.size == 2) { "ARC must be 2 bytes" }
        require(arpc.size == 8) { "ARPC must be 8 bytes" }
        require(sessionKey.size == 16) { "Session key must be 16 bytes" }

        // XOR ARQC with padded ARC
        val arcPadded = ByteArray(8).apply {
            this[0] = arc[0]
            this[1] = arc[1]
        }
        val xored = EmvCrypto.xor(arqc, arcPadded)

        // Compute expected ARPC
        val expectedArpc = EmvCrypto.retailMac(xored, sessionKey)

        // Constant-time comparison
        return constantTimeEquals(arpc, expectedArpc)
    }

    /**
     * Verify ARPC Method 2 (used by some issuers)
     * ARPC = 3DES(SK, ARQC) XOR (CSU || Prop Auth Data || padding)
     *
     * @param arqc 8-byte ARQC
     * @param csu 4-byte Card Status Update
     * @param proprietaryAuthData Optional proprietary data
     * @param arpc 4-byte ARPC (Method 2 uses 4 bytes)
     * @param sessionKey 16-byte session key
     * @return true if ARPC is valid
     */
    fun verifyArpcMethod2(
        arqc: ByteArray,
        csu: ByteArray,
        proprietaryAuthData: ByteArray?,
        arpc: ByteArray,
        sessionKey: ByteArray
    ): Boolean {
        require(arqc.size == 8) { "ARQC must be 8 bytes" }
        require(csu.size == 4) { "CSU must be 4 bytes" }
        require(arpc.size == 4) { "ARPC (Method 2) must be 4 bytes" }
        require(sessionKey.size == 16) { "Session key must be 16 bytes" }

        // Encrypt ARQC with session key
        val encryptedArqc = des3EncryptBlock(arqc, sessionKey)

        // Build CSU data block: CSU || Prop Data || padding
        val csuBlock = ByteArray(8).apply {
            System.arraycopy(csu, 0, this, 0, 4)
            proprietaryAuthData?.let { pad ->
                System.arraycopy(pad, 0, this, 4, minOf(4, pad.size))
            }
        }

        // XOR first 4 bytes of encrypted ARQC with first 4 bytes of CSU block
        val expectedArpc = ByteArray(4)
        for (i in 0 until 4) {
            expectedArpc[i] = (encryptedArqc[i].toInt() xor csuBlock[i].toInt()).toByte()
        }

        return constantTimeEquals(arpc, expectedArpc)
    }

    // ==================== Private Helper Functions ====================

    private fun buildDerivationInput(pan: ByteArray, psn: Byte): ByteArray {
        // Convert PAN to decimal string, take rightmost 16 digits, append PSN
        val panHex = pan.toHexString()
        val panDigits = panHex.filter { it.isDigit() }

        // Take rightmost 16-1=15 digits of PAN, append 1 digit PSN
        val derivationString = if (panDigits.length >= 16) {
            panDigits.takeLast(16)
        } else {
            panDigits.padStart(16, '0')
        }

        // Replace last 2 characters with PSN (as 2 hex digits)
        val withPsn = derivationString.dropLast(2) + "%02X".format(psn.toInt() and 0xFF)

        // Convert back to bytes (8 bytes of BCD)
        return withPsn.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun des3EncryptBlock(data: ByteArray, key: ByteArray): ByteArray {
        require(data.size == 8) { "Data must be 8 bytes" }
        require(key.size == 16) { "Key must be 16 bytes" }

        // Expand 16-byte key to 24-byte (K1-K2-K1)
        val expandedKey = ByteArray(24)
        System.arraycopy(key, 0, expandedKey, 0, 16)
        System.arraycopy(key, 0, expandedKey, 16, 8)

        val keySpec = SecretKeySpec(expandedKey, "DESede")
        val cipher = Cipher.getInstance("DESede/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)

        return cipher.doFinal(data)
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02X".format(it) }

    /**
     * Session key types per EMV Book 2
     */
    enum class SessionKeyType(val derivationConstant: Byte) {
        /** Application Cryptogram generation */
        AC(0x00),
        /** Secure Messaging for Confidentiality (encryption) */
        SMC(0x01),
        /** Secure Messaging for Integrity (MAC) */
        SMI(0x02)
    }
}

/**
 * Result of session key derivation with metadata
 */
data class DerivedSessionKey(
    val key: ByteArray,
    val keyType: EmvSessionKeyDerivation.SessionKeyType,
    val atc: ByteArray,
    val derivationMethod: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DerivedSessionKey) return false
        return key.contentEquals(other.key) &&
                keyType == other.keyType &&
                atc.contentEquals(other.atc)
    }

    override fun hashCode(): Int {
        var result = key.contentHashCode()
        result = 31 * result + keyType.hashCode()
        result = 31 * result + atc.contentHashCode()
        return result
    }

    fun clear() {
        key.fill(0)
        atc.fill(0)
    }
}
