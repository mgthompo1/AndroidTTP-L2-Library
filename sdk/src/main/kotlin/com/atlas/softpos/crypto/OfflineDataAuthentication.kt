package com.atlas.softpos.crypto

import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.tlv.Tlv
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.tlv.TlvTag
import com.atlas.softpos.core.types.hexToByteArray
import com.atlas.softpos.core.types.toHexString
import com.atlas.softpos.kernel.common.CardTransceiver
import timber.log.Timber

/**
 * Offline Data Authentication (ODA)
 *
 * Implements EMV Book 2 Chapter 6 - Offline Data Authentication
 * Supports:
 * - SDA (Static Data Authentication) - verifies signed static data
 * - DDA (Dynamic Data Authentication) - verifies card's RSA signature
 * - CDA (Combined DDA/Application Cryptogram) - verifies cryptogram signature
 * - fDDA (Fast DDA) - Visa-specific optimized DDA
 */
class OfflineDataAuthentication(
    private val transceiver: CardTransceiver,
    private val cardData: Map<String, Tlv>
) {
    private var issuerPublicKey: RecoveredPublicKey? = null
    private var iccPublicKey: RecoveredPublicKey? = null

    /**
     * Perform ODA based on card capabilities (AIP)
     */
    suspend fun performOda(
        aip: ByteArray,
        staticDataToAuthenticate: ByteArray
    ): OdaResult {
        // Check AIP for supported ODA methods
        val supportsCda = (aip[0].toInt() and 0x01) != 0
        val supportsDda = (aip[0].toInt() and 0x20) != 0
        val supportsSda = (aip[0].toInt() and 0x40) != 0

        Timber.d("ODA capabilities - CDA: $supportsCda, DDA: $supportsDda, SDA: $supportsSda")

        return when {
            supportsCda -> {
                // CDA is performed during GENERATE AC, prepare keys here
                prepareForCda()
            }
            supportsDda -> {
                performDda(staticDataToAuthenticate)
            }
            supportsSda -> {
                performSda(staticDataToAuthenticate)
            }
            else -> {
                OdaResult.NotSupported
            }
        }
    }

    /**
     * Prepare keys for CDA (actual verification happens in GENERATE AC)
     */
    private fun prepareForCda(): OdaResult {
        // Recover issuer public key
        val issuerKeyResult = recoverIssuerPublicKey()
        if (issuerKeyResult !is IssuerKeyResult.Success) {
            return OdaResult.Failed(OdaFailureReason.ISSUER_KEY_RECOVERY_FAILED)
        }
        issuerPublicKey = issuerKeyResult.publicKey

        // Recover ICC public key
        val iccKeyResult = recoverIccPublicKey(issuerKeyResult.publicKey)
        if (iccKeyResult !is IccKeyResult.Success) {
            return OdaResult.Failed(OdaFailureReason.ICC_KEY_RECOVERY_FAILED)
        }
        iccPublicKey = iccKeyResult.publicKey

        return OdaResult.CdaPrepared(iccKeyResult.publicKey)
    }

    /**
     * Perform Static Data Authentication (SDA)
     * EMV Book 2, Section 6.3
     */
    private fun performSda(staticDataToAuthenticate: ByteArray): OdaResult {
        Timber.d("Performing SDA")

        // 1. Recover Issuer Public Key
        val issuerKeyResult = recoverIssuerPublicKey()
        if (issuerKeyResult !is IssuerKeyResult.Success) {
            return OdaResult.Failed(OdaFailureReason.ISSUER_KEY_RECOVERY_FAILED)
        }

        // 2. Get Signed Static Application Data (Tag 93)
        val ssad = cardData[TlvTag.SIGNED_STATIC_APPLICATION_DATA.hex]?.value
            ?: return OdaResult.Failed(OdaFailureReason.MISSING_SSAD)

        // 3. Verify SSAD
        val recovered = EmvCrypto.rsaRecover(
            ssad,
            issuerKeyResult.publicKey.modulus,
            issuerKeyResult.publicKey.exponent
        )

        // 4. Validate recovered data format
        // Format: 6A || 03 || Hash Algorithm || Data Auth Code || Pad || Hash || BC
        if (recovered.isEmpty() || recovered[0] != 0x6A.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_SSAD_FORMAT)
        }

        if (recovered[1] != 0x03.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_SSAD_FORMAT)
        }

        if (recovered[recovered.size - 1] != 0xBC.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_SSAD_FORMAT)
        }

        // 5. Verify hash
        val hashAlgorithm = recovered[2]
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32

        // Data to hash: recovered data (excluding header and hash) + static data to authenticate
        val dataToHash = recovered.copyOfRange(1, recovered.size - hashLength - 1) +
                staticDataToAuthenticate

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(recovered.size - hashLength - 1, recovered.size - 1)

        if (!expectedHash.contentEquals(actualHash)) {
            return OdaResult.Failed(OdaFailureReason.HASH_MISMATCH)
        }

        // 6. Extract Data Authentication Code (Tag 9F45)
        val dataAuthCode = recovered.copyOfRange(3, 5)

        Timber.d("SDA successful. Data Auth Code: ${dataAuthCode.toHexString()}")
        return OdaResult.SdaSuccess(dataAuthCode)
    }

    /**
     * Perform Dynamic Data Authentication (DDA)
     * EMV Book 2, Section 6.5
     */
    private suspend fun performDda(staticDataToAuthenticate: ByteArray): OdaResult {
        Timber.d("Performing DDA")

        // 1. Recover Issuer Public Key
        val issuerKeyResult = recoverIssuerPublicKey()
        if (issuerKeyResult !is IssuerKeyResult.Success) {
            return OdaResult.Failed(OdaFailureReason.ISSUER_KEY_RECOVERY_FAILED)
        }
        issuerPublicKey = issuerKeyResult.publicKey

        // 2. Recover ICC Public Key
        val iccKeyResult = recoverIccPublicKey(issuerKeyResult.publicKey)
        if (iccKeyResult !is IccKeyResult.Success) {
            return OdaResult.Failed(OdaFailureReason.ICC_KEY_RECOVERY_FAILED)
        }
        iccPublicKey = iccKeyResult.publicKey

        // 3. Generate unpredictable number
        val unpredictableNumber = generateUnpredictableNumber()

        // 4. Send INTERNAL AUTHENTICATE command
        val ddol = cardData[TlvTag.DDOL.hex]?.value
        val authData = buildDdolData(ddol, unpredictableNumber)

        val response = transceiver.transceive(
            CommandApdu(
                cla = 0x00,
                ins = 0x88.toByte(),  // INTERNAL AUTHENTICATE
                p1 = 0x00,
                p2 = 0x00,
                data = authData,
                le = 0x00
            )
        )

        if (!response.isSuccess) {
            return OdaResult.Failed(OdaFailureReason.INTERNAL_AUTHENTICATE_FAILED)
        }

        // 5. Parse response - may be raw or TLV encoded
        val signedDynamicData = parseInternalAuthenticateResponse(response.data)
            ?: return OdaResult.Failed(OdaFailureReason.INVALID_DDA_RESPONSE)

        // 6. Verify signature
        val verifyResult = verifyDdaSignature(
            signedDynamicData,
            iccKeyResult.publicKey,
            unpredictableNumber,
            staticDataToAuthenticate
        )

        return if (verifyResult) {
            Timber.d("DDA successful")
            OdaResult.DdaSuccess
        } else {
            OdaResult.Failed(OdaFailureReason.DDA_SIGNATURE_INVALID)
        }
    }

    /**
     * Verify CDA signature from GENERATE AC response
     * Called after receiving cryptogram with signed data
     */
    fun verifyCdaSignature(
        signedDynamicApplicationData: ByteArray,
        transactionDataHash: ByteArray
    ): CdaResult {
        val iccKey = iccPublicKey ?: return CdaResult.Failed("ICC public key not available")

        // Recover signed data
        val recovered = EmvCrypto.rsaRecover(
            signedDynamicApplicationData,
            iccKey.modulus,
            iccKey.exponent
        )

        // Validate format: 6A || 05 || ...
        if (recovered.isEmpty() || recovered[0] != 0x6A.toByte()) {
            return CdaResult.Failed("Invalid CDA format - wrong header")
        }

        if (recovered[1] != 0x05.toByte()) {
            return CdaResult.Failed("Invalid CDA certificate type")
        }

        if (recovered[recovered.size - 1] != 0xBC.toByte()) {
            return CdaResult.Failed("Invalid CDA format - wrong trailer")
        }

        // Extract fields
        val hashAlgorithm = recovered[2]
        val iccDynamicDataLength = recovered[3].toInt() and 0xFF

        // ICC Dynamic Data starts at offset 4
        val iccDynamicData = recovered.copyOfRange(4, 4 + iccDynamicDataLength)

        // Extract cryptogram from ICC Dynamic Data
        // Format: ICC Dynamic Number Length || ICC Dynamic Number || Cryptogram Info || Cryptogram
        if (iccDynamicData.size < 10) {
            return CdaResult.Failed("ICC Dynamic Data too short")
        }

        val iccDynamicNumberLength = iccDynamicData[0].toInt() and 0xFF
        val cryptogramInfo = iccDynamicData[1 + iccDynamicNumberLength]
        val cryptogram = iccDynamicData.copyOfRange(
            2 + iccDynamicNumberLength,
            2 + iccDynamicNumberLength + 8
        )

        // Verify hash
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32
        val paddingStart = 4 + iccDynamicDataLength
        val hashStart = recovered.size - hashLength - 1

        val dataToHash = recovered.copyOfRange(1, hashStart) + transactionDataHash

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(hashStart, recovered.size - 1)

        if (!expectedHash.contentEquals(actualHash)) {
            return CdaResult.Failed("CDA hash mismatch")
        }

        Timber.d("CDA verification successful")
        return CdaResult.Success(
            cryptogramType = cryptogramInfo,
            cryptogram = cryptogram
        )
    }

    /**
     * Perform fDDA (Fast DDA) - Visa specific
     * Uses data from GPO response instead of INTERNAL AUTHENTICATE
     */
    fun performFdda(
        signedDynamicApplicationData: ByteArray,
        iccDynamicNumber: ByteArray,
        unpredictableNumber: ByteArray
    ): OdaResult {
        val iccKey = iccPublicKey
            ?: return OdaResult.Failed(OdaFailureReason.ICC_KEY_NOT_RECOVERED)

        val recovered = EmvCrypto.rsaRecover(
            signedDynamicApplicationData,
            iccKey.modulus,
            iccKey.exponent
        )

        // Validate format
        if (recovered.isEmpty() || recovered[0] != 0x6A.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        // Certificate type should be 0x05 for fDDA
        if (recovered[1] != 0x05.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        // Verify hash includes terminal unpredictable number
        val hashAlgorithm = recovered[2]
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32

        val hashStart = recovered.size - hashLength - 1
        val dataToHash = recovered.copyOfRange(1, hashStart) + unpredictableNumber

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(hashStart, recovered.size - 1)

        if (!expectedHash.contentEquals(actualHash)) {
            return OdaResult.Failed(OdaFailureReason.FDDA_HASH_MISMATCH)
        }

        Timber.d("fDDA successful")
        return OdaResult.FddaSuccess
    }

    // ========== KEY RECOVERY ==========

    /**
     * Recover Issuer Public Key from certificate
     * EMV Book 2, Section 6.3
     */
    private fun recoverIssuerPublicKey(): IssuerKeyResult {
        // Get required data
        val rid = cardData[TlvTag.DF_NAME.hex]?.value?.copyOfRange(0, 5)
            ?: cardData[TlvTag.AID.hex]?.value?.copyOfRange(0, 5)
            ?: return IssuerKeyResult.Failed("Missing RID")

        val caPublicKeyIndex = cardData[TlvTag.CA_PUBLIC_KEY_INDEX.hex]?.value?.get(0)
            ?: return IssuerKeyResult.Failed("Missing CA Public Key Index")

        val issuerCert = cardData[TlvTag.ISSUER_PUBLIC_KEY_CERTIFICATE.hex]?.value
            ?: return IssuerKeyResult.Failed("Missing Issuer Certificate")

        val issuerExponent = cardData[TlvTag.ISSUER_PUBLIC_KEY_EXPONENT.hex]?.value
            ?: byteArrayOf(0x03)  // Default exponent

        val issuerRemainder = cardData[TlvTag.ISSUER_PUBLIC_KEY_REMAINDER.hex]?.value
            ?: byteArrayOf()

        // Get CA Public Key
        val caKey = CaPublicKeyStore.getKey(rid, caPublicKeyIndex)
            ?: return IssuerKeyResult.Failed("CA Public Key not found: ${rid.toHexString()}:$caPublicKeyIndex")

        if (caKey.isExpired()) {
            return IssuerKeyResult.Failed("CA Public Key expired")
        }

        // Recover certificate
        val recovered = EmvCrypto.rsaRecover(issuerCert, caKey.modulus, caKey.exponent)

        // Validate format: 6A || 02 || ...
        if (recovered.isEmpty() || recovered[0] != 0x6A.toByte()) {
            return IssuerKeyResult.Failed("Invalid certificate header")
        }

        if (recovered[1] != 0x02.toByte()) {
            return IssuerKeyResult.Failed("Invalid certificate type")
        }

        if (recovered[recovered.size - 1] != 0xBC.toByte()) {
            return IssuerKeyResult.Failed("Invalid certificate trailer")
        }

        // Parse certificate fields
        // Offset 2: Issuer Identifier (4 bytes, leftmost PAN digits)
        val issuerIdentifier = recovered.copyOfRange(2, 6)

        // Offset 6: Certificate Expiration (MMYY)
        val certExpiry = recovered.copyOfRange(6, 8)

        // Check expiry
        if (isCertificateExpired(certExpiry)) {
            return IssuerKeyResult.Failed("Issuer certificate expired")
        }

        // Offset 8: Certificate Serial Number (3 bytes)
        val certSerial = recovered.copyOfRange(8, 11)

        // Offset 11: Hash Algorithm Indicator
        val hashAlgorithm = recovered[11]

        // Offset 12: Issuer Public Key Algorithm Indicator
        val pkAlgorithm = recovered[12]

        // Offset 13: Issuer Public Key Length
        val pkLength = recovered[13].toInt() and 0xFF

        // Offset 14: Issuer Public Key Exponent Length
        val pkExponentLength = recovered[14].toInt() and 0xFF

        // Offset 15: Issuer Public Key (leftmost digits) || Padding
        val pkDataLength = caKey.modulusLength - 36  // 36 = header + hash + trailer
        val pkLeftmost = recovered.copyOfRange(15, 15 + pkDataLength)

        // Construct full public key
        val fullModulus = if (pkLength <= pkDataLength) {
            pkLeftmost.copyOfRange(0, pkLength)
        } else {
            pkLeftmost + issuerRemainder
        }

        // Verify hash
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32
        val dataToHash = recovered.copyOfRange(1, recovered.size - hashLength - 1) +
                issuerRemainder + issuerExponent

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(
            recovered.size - hashLength - 1,
            recovered.size - 1
        )

        if (!expectedHash.contentEquals(actualHash)) {
            return IssuerKeyResult.Failed("Issuer certificate hash mismatch")
        }

        Timber.d("Issuer Public Key recovered. Length: ${fullModulus.size}")

        return IssuerKeyResult.Success(
            RecoveredPublicKey(
                modulus = fullModulus,
                exponent = issuerExponent,
                identifier = issuerIdentifier
            )
        )
    }

    /**
     * Recover ICC Public Key from certificate
     * EMV Book 2, Section 6.4
     */
    private fun recoverIccPublicKey(issuerKey: RecoveredPublicKey): IccKeyResult {
        val iccCert = cardData[TlvTag.ICC_PUBLIC_KEY_CERTIFICATE.hex]?.value
            ?: return IccKeyResult.Failed("Missing ICC Certificate")

        val iccExponent = cardData[TlvTag.ICC_PUBLIC_KEY_EXPONENT.hex]?.value
            ?: byteArrayOf(0x03)

        val iccRemainder = cardData[TlvTag.ICC_PUBLIC_KEY_REMAINDER.hex]?.value
            ?: byteArrayOf()

        val pan = cardData[TlvTag.PAN.hex]?.value
            ?: return IccKeyResult.Failed("Missing PAN")

        // Recover certificate
        val recovered = EmvCrypto.rsaRecover(iccCert, issuerKey.modulus, issuerKey.exponent)

        // Validate format
        if (recovered.isEmpty() || recovered[0] != 0x6A.toByte()) {
            return IccKeyResult.Failed("Invalid ICC certificate header")
        }

        if (recovered[1] != 0x04.toByte()) {
            return IccKeyResult.Failed("Invalid ICC certificate type")
        }

        if (recovered[recovered.size - 1] != 0xBC.toByte()) {
            return IccKeyResult.Failed("Invalid ICC certificate trailer")
        }

        // Offset 2: PAN (10 bytes)
        val certPan = recovered.copyOfRange(2, 12)

        // Verify PAN matches
        val paddedPan = pan.copyOf(10)
        if (!certPan.contentEquals(paddedPan) && !verifyPanMatch(certPan, pan)) {
            return IccKeyResult.Failed("ICC certificate PAN mismatch")
        }

        // Offset 12: Certificate Expiration (MMYY)
        val certExpiry = recovered.copyOfRange(12, 14)
        if (isCertificateExpired(certExpiry)) {
            return IccKeyResult.Failed("ICC certificate expired")
        }

        // Offset 14: Certificate Serial Number (3 bytes)
        val certSerial = recovered.copyOfRange(14, 17)

        // Offset 17: Hash Algorithm
        val hashAlgorithm = recovered[17]

        // Offset 18: ICC Public Key Algorithm
        val pkAlgorithm = recovered[18]

        // Offset 19: ICC Public Key Length
        val pkLength = recovered[19].toInt() and 0xFF

        // Offset 20: ICC Public Key Exponent Length
        val pkExponentLength = recovered[20].toInt() and 0xFF

        // Offset 21: ICC Public Key (leftmost) || Padding
        val pkDataLength = issuerKey.modulus.size - 42
        val pkLeftmost = recovered.copyOfRange(21, 21 + pkDataLength)

        // Construct full ICC public key
        val fullModulus = if (pkLength <= pkDataLength) {
            pkLeftmost.copyOfRange(0, pkLength)
        } else {
            pkLeftmost + iccRemainder
        }

        // Get Static Data to Authenticate for hash
        val staticData = cardData[TlvTag.STATIC_DATA_AUTHENTICATION_TAG_LIST.hex]?.value
            ?: byteArrayOf()

        // Verify hash
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32
        val dataToHash = recovered.copyOfRange(1, recovered.size - hashLength - 1) +
                iccRemainder + iccExponent + staticData

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(
            recovered.size - hashLength - 1,
            recovered.size - 1
        )

        if (!expectedHash.contentEquals(actualHash)) {
            return IccKeyResult.Failed("ICC certificate hash mismatch")
        }

        Timber.d("ICC Public Key recovered. Length: ${fullModulus.size}")

        return IccKeyResult.Success(
            RecoveredPublicKey(
                modulus = fullModulus,
                exponent = iccExponent,
                identifier = certPan
            )
        )
    }

    // ========== HELPER FUNCTIONS ==========

    private fun generateUnpredictableNumber(): ByteArray {
        return java.security.SecureRandom().let { random ->
            ByteArray(4).also { random.nextBytes(it) }
        }
    }

    private fun buildDdolData(ddol: ByteArray?, unpredictableNumber: ByteArray): ByteArray {
        // If no DDOL, use default (just unpredictable number)
        if (ddol == null || ddol.isEmpty()) {
            return unpredictableNumber
        }

        // Parse DDOL and build data
        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < ddol.size) {
            val tag = if ((ddol[offset].toInt() and 0x1F) == 0x1F) {
                // Two-byte tag
                ((ddol[offset].toInt() and 0xFF) shl 8) or (ddol[offset + 1].toInt() and 0xFF)
            } else {
                ddol[offset].toInt() and 0xFF
            }

            val tagLength = if (tag > 0xFF) 2 else 1
            val length = ddol[offset + tagLength].toInt() and 0xFF

            // Fill with data from card or terminal
            when (tag) {
                0x9F37 -> result.addAll(unpredictableNumber.toList())  // Unpredictable Number
                else -> {
                    // Try to get from card data, otherwise fill with zeros
                    val tagHex = "%02X".format(tag)
                    val value = cardData[tagHex]?.value ?: ByteArray(length)
                    result.addAll(value.copyOf(length).toList())
                }
            }

            offset += tagLength + 1
        }

        return result.toByteArray()
    }

    private fun parseInternalAuthenticateResponse(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null

        // Check if TLV encoded (Tag 80 or 77)
        return when (data[0]) {
            0x80.toByte() -> {
                // Primitive format
                TlvParser.parse(data).firstOrNull()?.value
            }
            0x77.toByte() -> {
                // Constructed format - look for Tag 9F4B
                val tlvs = TlvParser.parseRecursive(data)
                val sdad = tlvs.find { it.tag.hex == "9F4B" }
                sdad?.value
            }
            else -> {
                // Raw signed data
                data
            }
        }
    }

    private fun verifyDdaSignature(
        signedData: ByteArray,
        iccKey: RecoveredPublicKey,
        unpredictableNumber: ByteArray,
        staticData: ByteArray
    ): Boolean {
        val recovered = EmvCrypto.rsaRecover(signedData, iccKey.modulus, iccKey.exponent)

        if (recovered.isEmpty() || recovered[0] != 0x6A.toByte()) return false
        if (recovered[1] != 0x05.toByte()) return false
        if (recovered[recovered.size - 1] != 0xBC.toByte()) return false

        val hashAlgorithm = recovered[2]
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32

        val hashStart = recovered.size - hashLength - 1
        val dataToHash = recovered.copyOfRange(1, hashStart) + unpredictableNumber

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(hashStart, recovered.size - 1)

        return expectedHash.contentEquals(actualHash)
    }

    private fun isCertificateExpired(mmyy: ByteArray): Boolean {
        if (mmyy.size < 2) return true

        val month = ((mmyy[0].toInt() and 0xF0) shr 4) * 10 + (mmyy[0].toInt() and 0x0F)
        val year = 2000 + ((mmyy[1].toInt() and 0xF0) shr 4) * 10 + (mmyy[1].toInt() and 0x0F)

        val calendar = java.util.Calendar.getInstance()
        val currentYear = calendar.get(java.util.Calendar.YEAR)
        val currentMonth = calendar.get(java.util.Calendar.MONTH) + 1

        return (year < currentYear) || (year == currentYear && month < currentMonth)
    }

    private fun verifyPanMatch(certPan: ByteArray, actualPan: ByteArray): Boolean {
        // Compare digit by digit, accounting for padding (F)
        for (i in certPan.indices) {
            val certByte = certPan[i].toInt() and 0xFF
            val actualByte = if (i < actualPan.size) actualPan[i].toInt() and 0xFF else 0xFF

            val certHigh = (certByte shr 4) and 0x0F
            val certLow = certByte and 0x0F
            val actualHigh = (actualByte shr 4) and 0x0F
            val actualLow = actualByte and 0x0F

            if (certHigh != 0x0F && actualHigh != 0x0F && certHigh != actualHigh) return false
            if (certLow != 0x0F && actualLow != 0x0F && certLow != actualLow) return false
        }
        return true
    }
}

// ========== RESULT TYPES ==========

// Note: OdaResult sealed class is defined at the bottom of this file to avoid duplication

enum class OdaFailureReason {
    ISSUER_KEY_RECOVERY_FAILED,
    ICC_KEY_RECOVERY_FAILED,
    ICC_KEY_NOT_RECOVERED,
    MISSING_SSAD,
    INVALID_SSAD_FORMAT,
    HASH_MISMATCH,
    INTERNAL_AUTHENTICATE_FAILED,
    INVALID_DDA_RESPONSE,
    DDA_SIGNATURE_INVALID,
    INVALID_FDDA_FORMAT,
    FDDA_HASH_MISMATCH,
    CA_KEY_NOT_FOUND,
    CA_KEY_EXPIRED,
    CERTIFICATE_EXPIRED
}

sealed class IssuerKeyResult {
    data class Success(val publicKey: RecoveredPublicKey) : IssuerKeyResult()
    data class Failed(val reason: String) : IssuerKeyResult()
}

sealed class IccKeyResult {
    data class Success(val publicKey: RecoveredPublicKey) : IccKeyResult()
    data class Failed(val reason: String) : IccKeyResult()
}

sealed class CdaResult {
    data class Success(
        val cryptogramType: Byte,
        val cryptogram: ByteArray
    ) : CdaResult()
    data class Failed(val reason: String) : CdaResult()
}

data class RecoveredPublicKey(
    val modulus: ByteArray,
    val exponent: ByteArray,
    val identifier: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RecoveredPublicKey) return false
        return modulus.contentEquals(other.modulus) && exponent.contentEquals(other.exponent)
    }

    override fun hashCode(): Int {
        var result = modulus.contentHashCode()
        result = 31 * result + exponent.contentHashCode()
        return result
    }
}

/**
 * Standalone ODA Processor
 *
 * Provides ODA methods that can be used by kernels without requiring
 * a CardTransceiver or pre-populated card data map.
 *
 * Use this when the kernel manages its own card data and transceiver.
 */
object StandaloneOdaProcessor {

    /**
     * Perform SDA with explicit parameters
     */
    fun performSda(
        aid: ByteArray,
        issuerPkCertificate: ByteArray,
        issuerPkExponent: ByteArray,
        signedStaticData: ByteArray,
        staticDataToAuthenticate: ByteArray
    ): OdaResult {
        // Get CA public key
        val rid = aid.copyOfRange(0, minOf(5, aid.size))
        val caKeyIndex = 0x01.toByte()  // Would need to be passed in production

        // Recover issuer public key
        val issuerKeyResult = recoverIssuerPublicKey(
            rid = rid,
            caKeyIndex = caKeyIndex,
            issuerCertificate = issuerPkCertificate,
            issuerExponent = issuerPkExponent,
            issuerRemainder = byteArrayOf()
        )

        if (issuerKeyResult !is IssuerKeyResult.Success) {
            return OdaResult.Failed(OdaFailureReason.ISSUER_KEY_RECOVERY_FAILED)
        }

        // Verify signed static data
        val recovered = EmvCrypto.rsaRecover(
            signedStaticData,
            issuerKeyResult.publicKey.modulus,
            issuerKeyResult.publicKey.exponent
        )

        if (!validateSdaFormat(recovered)) {
            return OdaResult.Failed(OdaFailureReason.INVALID_SSAD_FORMAT)
        }

        // Verify hash
        val hashAlgorithm = recovered[2]
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32

        val dataToHash = recovered.copyOfRange(1, recovered.size - hashLength - 1) +
                staticDataToAuthenticate

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = recovered.copyOfRange(recovered.size - hashLength - 1, recovered.size - 1)

        if (!expectedHash.contentEquals(actualHash)) {
            return OdaResult.Failed(OdaFailureReason.HASH_MISMATCH)
        }

        val dataAuthCode = recovered.copyOfRange(3, 5)
        return OdaResult.SdaSuccess(dataAuthCode)
    }

    /**
     * Perform fDDA with explicit parameters
     */
    fun performFdda(
        aid: ByteArray,
        issuerPkCertificate: ByteArray,
        issuerPkExponent: ByteArray,
        iccPkCertificate: ByteArray,
        iccPkExponent: ByteArray,
        signedDynamicData: ByteArray,
        staticDataToAuthenticate: ByteArray,
        unpredictableNumber: ByteArray
    ): OdaResult {
        // Recover issuer public key
        val rid = aid.copyOfRange(0, minOf(5, aid.size))

        // Try to find CA key
        var caKey: CaPublicKey? = null
        for (index in 0..255) {
            caKey = CaPublicKeyStore.getKey(rid, index.toByte())
            if (caKey != null && !caKey.isExpired()) break
        }

        if (caKey == null) {
            return OdaResult.Failed(OdaFailureReason.CA_KEY_NOT_FOUND)
        }

        // Recover issuer key
        val issuerRecovered = EmvCrypto.rsaRecover(issuerPkCertificate, caKey.modulus, caKey.exponent)
        if (!validateIssuerCertFormat(issuerRecovered)) {
            return OdaResult.Failed(OdaFailureReason.ISSUER_KEY_RECOVERY_FAILED)
        }

        val issuerKeyLength = issuerRecovered[13].toInt() and 0xFF
        val issuerKeyDataLength = caKey.modulusLength - 36
        val issuerModulus = if (issuerKeyLength <= issuerKeyDataLength) {
            issuerRecovered.copyOfRange(15, 15 + issuerKeyLength)
        } else {
            issuerRecovered.copyOfRange(15, 15 + issuerKeyDataLength)
        }

        // Recover ICC key
        val iccRecovered = EmvCrypto.rsaRecover(iccPkCertificate, issuerModulus, issuerPkExponent)
        if (!validateIccCertFormat(iccRecovered)) {
            return OdaResult.Failed(OdaFailureReason.ICC_KEY_RECOVERY_FAILED)
        }

        val iccKeyLength = iccRecovered[19].toInt() and 0xFF
        val iccKeyDataLength = issuerModulus.size - 42
        val iccModulus = if (iccKeyLength <= iccKeyDataLength) {
            iccRecovered.copyOfRange(21, 21 + iccKeyLength)
        } else {
            iccRecovered.copyOfRange(21, 21 + iccKeyDataLength)
        }

        // Verify fDDA signature
        val sdadRecovered = EmvCrypto.rsaRecover(signedDynamicData, iccModulus, iccPkExponent)

        if (sdadRecovered.isEmpty() || sdadRecovered[0] != 0x6A.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        if (sdadRecovered[1] != 0x05.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        if (sdadRecovered[sdadRecovered.size - 1] != 0xBC.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        // Verify hash
        val hashAlgorithm = sdadRecovered[2]
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32

        val hashStart = sdadRecovered.size - hashLength - 1
        val dataToHash = sdadRecovered.copyOfRange(1, hashStart) + unpredictableNumber

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = sdadRecovered.copyOfRange(hashStart, sdadRecovered.size - 1)

        if (!expectedHash.contentEquals(actualHash)) {
            return OdaResult.Failed(OdaFailureReason.FDDA_HASH_MISMATCH)
        }

        return OdaResult.FddaSuccess
    }

    /**
     * Perform CDA with explicit parameters
     */
    fun performCda(
        aid: ByteArray,
        issuerPkCertificate: ByteArray,
        issuerPkExponent: ByteArray,
        iccPkCertificate: ByteArray,
        iccPkExponent: ByteArray,
        signedDynamicData: ByteArray,
        staticDataToAuthenticate: ByteArray,
        unpredictableNumber: ByteArray,
        applicationCryptogram: ByteArray
    ): OdaResult {
        // Similar to fDDA but includes cryptogram verification
        val rid = aid.copyOfRange(0, minOf(5, aid.size))

        var caKey: CaPublicKey? = null
        for (index in 0..255) {
            caKey = CaPublicKeyStore.getKey(rid, index.toByte())
            if (caKey != null && !caKey.isExpired()) break
        }

        if (caKey == null) {
            return OdaResult.Failed(OdaFailureReason.CA_KEY_NOT_FOUND)
        }

        // Recover keys (same as fDDA)
        val issuerRecovered = EmvCrypto.rsaRecover(issuerPkCertificate, caKey.modulus, caKey.exponent)
        if (!validateIssuerCertFormat(issuerRecovered)) {
            return OdaResult.Failed(OdaFailureReason.ISSUER_KEY_RECOVERY_FAILED)
        }

        val issuerKeyLength = issuerRecovered[13].toInt() and 0xFF
        val issuerKeyDataLength = caKey.modulusLength - 36
        val issuerModulus = if (issuerKeyLength <= issuerKeyDataLength) {
            issuerRecovered.copyOfRange(15, 15 + issuerKeyLength)
        } else {
            issuerRecovered.copyOfRange(15, 15 + issuerKeyDataLength)
        }

        val iccRecovered = EmvCrypto.rsaRecover(iccPkCertificate, issuerModulus, issuerPkExponent)
        if (!validateIccCertFormat(iccRecovered)) {
            return OdaResult.Failed(OdaFailureReason.ICC_KEY_RECOVERY_FAILED)
        }

        val iccKeyLength = iccRecovered[19].toInt() and 0xFF
        val iccKeyDataLength = issuerModulus.size - 42
        val iccModulus = if (iccKeyLength <= iccKeyDataLength) {
            iccRecovered.copyOfRange(21, 21 + iccKeyLength)
        } else {
            iccRecovered.copyOfRange(21, 21 + iccKeyDataLength)
        }

        // Verify CDA signature
        val sdadRecovered = EmvCrypto.rsaRecover(signedDynamicData, iccModulus, iccPkExponent)

        if (sdadRecovered.isEmpty() || sdadRecovered[0] != 0x6A.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        if (sdadRecovered[1] != 0x05.toByte()) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        // Extract ICC Dynamic Data and verify cryptogram matches
        val iccDynamicDataLength = sdadRecovered[3].toInt() and 0xFF
        val iccDynamicData = sdadRecovered.copyOfRange(4, 4 + iccDynamicDataLength)

        // ICC Dynamic Data format: IDN Length | IDN | CID | AC (8 bytes)
        if (iccDynamicData.size < 10) {
            return OdaResult.Failed(OdaFailureReason.INVALID_FDDA_FORMAT)
        }

        val idnLength = iccDynamicData[0].toInt() and 0xFF
        val extractedAc = iccDynamicData.copyOfRange(2 + idnLength, 2 + idnLength + 8)

        // Verify cryptogram matches
        if (!extractedAc.contentEquals(applicationCryptogram)) {
            return OdaResult.Failed(OdaFailureReason.HASH_MISMATCH)
        }

        // Verify hash
        val hashAlgorithm = sdadRecovered[2]
        val hashLength = if (hashAlgorithm == 0x01.toByte()) 20 else 32

        val hashStart = sdadRecovered.size - hashLength - 1
        val dataToHash = sdadRecovered.copyOfRange(1, hashStart) + unpredictableNumber

        val expectedHash = when (hashAlgorithm.toInt()) {
            0x01 -> EmvCrypto.sha1(dataToHash)
            else -> EmvCrypto.sha256(dataToHash)
        }

        val actualHash = sdadRecovered.copyOfRange(hashStart, sdadRecovered.size - 1)

        if (!expectedHash.contentEquals(actualHash)) {
            return OdaResult.Failed(OdaFailureReason.FDDA_HASH_MISMATCH)
        }

        return OdaResult.FddaSuccess  // CDA is essentially fDDA with AC verification
    }

    // Helper functions

    private fun recoverIssuerPublicKey(
        rid: ByteArray,
        caKeyIndex: Byte,
        issuerCertificate: ByteArray,
        issuerExponent: ByteArray,
        issuerRemainder: ByteArray
    ): IssuerKeyResult {
        val caKey = CaPublicKeyStore.getKey(rid, caKeyIndex)
            ?: return IssuerKeyResult.Failed("CA key not found")

        if (caKey.isExpired()) {
            return IssuerKeyResult.Failed("CA key expired")
        }

        val recovered = EmvCrypto.rsaRecover(issuerCertificate, caKey.modulus, caKey.exponent)

        if (!validateIssuerCertFormat(recovered)) {
            return IssuerKeyResult.Failed("Invalid certificate format")
        }

        val pkLength = recovered[13].toInt() and 0xFF
        val pkDataLength = caKey.modulusLength - 36
        val pkLeftmost = recovered.copyOfRange(15, 15 + pkDataLength)

        val fullModulus = if (pkLength <= pkDataLength) {
            pkLeftmost.copyOfRange(0, pkLength)
        } else {
            pkLeftmost + issuerRemainder
        }

        return IssuerKeyResult.Success(
            RecoveredPublicKey(
                modulus = fullModulus,
                exponent = issuerExponent,
                identifier = recovered.copyOfRange(2, 6)
            )
        )
    }

    private fun validateSdaFormat(recovered: ByteArray): Boolean {
        if (recovered.isEmpty()) return false
        if (recovered[0] != 0x6A.toByte()) return false
        if (recovered[1] != 0x03.toByte()) return false
        if (recovered[recovered.size - 1] != 0xBC.toByte()) return false
        return true
    }

    private fun validateIssuerCertFormat(recovered: ByteArray): Boolean {
        if (recovered.isEmpty()) return false
        if (recovered[0] != 0x6A.toByte()) return false
        if (recovered[1] != 0x02.toByte()) return false
        if (recovered[recovered.size - 1] != 0xBC.toByte()) return false
        return true
    }

    private fun validateIccCertFormat(recovered: ByteArray): Boolean {
        if (recovered.isEmpty()) return false
        if (recovered[0] != 0x6A.toByte()) return false
        if (recovered[1] != 0x04.toByte()) return false
        if (recovered[recovered.size - 1] != 0xBC.toByte()) return false
        return true
    }
}

/**
 * Simplified ODA Result for kernel usage
 */
sealed class OdaResult {
    object NotSupported : OdaResult()
    data class SdaSuccess(val dataAuthCode: ByteArray) : OdaResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is SdaSuccess) return false
            return dataAuthCode.contentEquals(other.dataAuthCode)
        }
        override fun hashCode(): Int = dataAuthCode.contentHashCode()
    }
    object DdaSuccess : OdaResult()
    object FddaSuccess : OdaResult()
    data class CdaPrepared(val iccPublicKey: RecoveredPublicKey) : OdaResult()
    data class Success(val type: String = "ODA") : OdaResult()
    data class Failure(val reason: String) : OdaResult()
    data class Failed(val failureReason: OdaFailureReason) : OdaResult()
}
