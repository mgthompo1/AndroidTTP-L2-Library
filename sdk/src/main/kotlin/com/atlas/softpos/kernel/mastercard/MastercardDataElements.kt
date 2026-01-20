package com.atlas.softpos.kernel.mastercard

import com.atlas.softpos.core.types.toHexString

/**
 * Terminal Interchange Profile (TIP) - Mastercard specific
 *
 * Used in PDOL construction for Mastercard contactless.
 * Controls transaction processing options.
 *
 * Reference: M/Chip Requirements for Contact and Contactless
 */
class TerminalInterchangeProfile {
    private val bytes = ByteArray(3)

    // ==================== BYTE 1 ====================

    /** Terminal supports ODA for Online Authorizations */
    var odaForOnlineSupported: Boolean
        get() = getBit(0, 7)
        set(value) = setBit(0, 7, value)

    /** Terminal supports Offline Only */
    var offlineOnlySupported: Boolean
        get() = getBit(0, 6)
        set(value) = setBit(0, 6, value)

    /** Terminal supports Online and Offline */
    var onlineOfflineSupported: Boolean
        get() = getBit(0, 5)
        set(value) = setBit(0, 5, value)

    /** Terminal supports Script Processing */
    var scriptProcessingSupported: Boolean
        get() = getBit(0, 4)
        set(value) = setBit(0, 4, value)

    /** Terminal supports EMV Mode */
    var emvModeSupported: Boolean
        get() = getBit(0, 3)
        set(value) = setBit(0, 3, value)

    /** Terminal supports Mag Stripe Mode */
    var magStripeModeSupported: Boolean
        get() = getBit(0, 2)
        set(value) = setBit(0, 2, value)

    // Bits 1-0: RFU

    // ==================== BYTE 2 ====================

    /** On-device cardholder verification supported */
    var onDeviceCvmSupported: Boolean
        get() = getBit(1, 7)
        set(value) = setBit(1, 7, value)

    /** CDA supported */
    var cdaSupported: Boolean
        get() = getBit(1, 6)
        set(value) = setBit(1, 6, value)

    /** DDA supported */
    var ddaSupported: Boolean
        get() = getBit(1, 5)
        set(value) = setBit(1, 5, value)

    /** Cardholder verification supported */
    var cvmSupported: Boolean
        get() = getBit(1, 4)
        set(value) = setBit(1, 4, value)

    // Bits 3-0: RFU

    // ==================== BYTE 3 ====================

    /** Relay Resistance Protocol supported */
    var relayResistanceSupported: Boolean
        get() = getBit(2, 7)
        set(value) = setBit(2, 7, value)

    // Bits 6-0: RFU

    private fun getBit(byteIndex: Int, bitIndex: Int): Boolean {
        return (bytes[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    private fun setBit(byteIndex: Int, bitIndex: Int, value: Boolean) {
        bytes[byteIndex] = if (value) {
            (bytes[byteIndex].toInt() or (1 shl bitIndex)).toByte()
        } else {
            (bytes[byteIndex].toInt() and (1 shl bitIndex).inv()).toByte()
        }
    }

    fun toBytes(): ByteArray = bytes.copyOf()

    companion object {
        /**
         * Create default TIP for SoftPOS contactless
         */
        fun forSoftPos(): TerminalInterchangeProfile {
            return TerminalInterchangeProfile().apply {
                odaForOnlineSupported = true
                offlineOnlySupported = false
                onlineOfflineSupported = true
                scriptProcessingSupported = true
                emvModeSupported = true
                magStripeModeSupported = true
                onDeviceCvmSupported = true
                cdaSupported = true
                ddaSupported = true
                cvmSupported = true
                relayResistanceSupported = false // Optional for initial certification
            }
        }
    }
}

/**
 * Mastercard Application Interchange Profile (AIP)
 *
 * Indicates card capabilities and transaction processing requirements
 */
class MastercardAIP(private val bytes: ByteArray) {

    init {
        require(bytes.size >= 2) { "AIP must be at least 2 bytes" }
    }

    // ==================== BYTE 1 ====================

    /** RFU (Bit 8) */
    val rfu1: Boolean get() = getBit(0, 7)

    /** SDA supported for offline data authentication */
    val sdaSupported: Boolean get() = getBit(0, 6)

    /** DDA supported for offline data authentication */
    val ddaSupported: Boolean get() = getBit(0, 5)

    /** Cardholder verification is supported */
    val cardholderVerificationSupported: Boolean get() = getBit(0, 4)

    /** Terminal risk management is to be performed */
    val terminalRiskManagementRequired: Boolean get() = getBit(0, 3)

    /** Issuer authentication is supported */
    val issuerAuthenticationSupported: Boolean get() = getBit(0, 2)

    /** RFU (Bit 2) */
    val rfu2: Boolean get() = getBit(0, 1)

    /** CDA supported for offline data authentication */
    val cdaSupported: Boolean get() = getBit(0, 0)

    // ==================== BYTE 2 ====================

    /** Reserved for use by the EMV Contactless Specifications (Bit 8) */
    val emvContactlessRfu: Boolean get() = getBit(1, 7)

    /** Reserved for use by the EMV Contactless Specifications (Bit 7) */
    val emvContactlessRfu2: Boolean get() = getBit(1, 6)

    /** Reserved for use by the EMV Contactless Specifications (Bit 6) */
    val emvContactlessRfu3: Boolean get() = getBit(1, 5)

    /** EMV mode supported (M/Chip) */
    val emvModeSupported: Boolean get() = getBit(1, 4)

    /** Mag Stripe mode supported */
    val magStripeModeSupported: Boolean get() = getBit(1, 3)

    /** Reserved for use by the EMV Contactless Specifications (Bit 3) */
    val emvContactlessRfu4: Boolean get() = getBit(1, 2)

    /** On-device cardholder verification supported */
    val onDeviceCvmSupported: Boolean get() = getBit(1, 1)

    /** Relay Resistance Protocol supported */
    val relayResistanceSupported: Boolean get() = getBit(1, 0)

    private fun getBit(byteIndex: Int, bitIndex: Int): Boolean {
        return (bytes[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    /** Check if any ODA method is supported */
    fun isOdaSupported(): Boolean = sdaSupported || ddaSupported || cdaSupported

    fun toBytes(): ByteArray = bytes.copyOf()

    override fun toString(): String {
        return buildString {
            append("AIP[")
            if (sdaSupported) append("SDA ")
            if (ddaSupported) append("DDA ")
            if (cdaSupported) append("CDA ")
            if (emvModeSupported) append("EMV ")
            if (magStripeModeSupported) append("MAGSTRIPE ")
            if (onDeviceCvmSupported) append("ODCVM ")
            if (relayResistanceSupported) append("RRP ")
            append("]")
        }
    }
}

/**
 * Card Transaction Qualifiers (CTQ) - Mastercard specific
 *
 * Returned in GPO response, indicates card's transaction processing requirements
 */
class CardTransactionQualifiers(private val bytes: ByteArray) {

    init {
        require(bytes.size >= 2) { "CTQ must be at least 2 bytes" }
    }

    // ==================== BYTE 1 ====================

    /** Online PIN required */
    val onlinePinRequired: Boolean get() = getBit(0, 7)

    /** Signature required */
    val signatureRequired: Boolean get() = getBit(0, 6)

    /** Go online if offline data authentication fails and Reader is online capable */
    val goOnlineIfOdaFails: Boolean get() = getBit(0, 5)

    /** Switch interface if offline data authentication fails */
    val switchInterfaceIfOdaFails: Boolean get() = getBit(0, 4)

    /** Go online if application expired */
    val goOnlineIfExpired: Boolean get() = getBit(0, 3)

    /** Switch interface for cash transactions */
    val switchInterfaceForCash: Boolean get() = getBit(0, 2)

    /** Switch interface for cashback transactions */
    val switchInterfaceForCashback: Boolean get() = getBit(0, 1)

    // Bit 0: RFU

    // ==================== BYTE 2 ====================

    /** Consumer Device CVM performed */
    val cdcvmPerformed: Boolean get() = getBit(1, 7)

    /** Card supports Issuer Update Processing at the POS */
    val issuerUpdateSupported: Boolean get() = getBit(1, 6)

    // Bits 5-0: RFU

    private fun getBit(byteIndex: Int, bitIndex: Int): Boolean {
        return (bytes[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    fun toBytes(): ByteArray = bytes.copyOf()

    override fun toString(): String {
        return buildString {
            append("CTQ[")
            if (onlinePinRequired) append("ONLINE_PIN ")
            if (signatureRequired) append("SIGNATURE ")
            if (cdcvmPerformed) append("CDCVM ")
            if (goOnlineIfOdaFails) append("ONLINE_IF_ODA_FAIL ")
            append("]")
        }
    }
}

/**
 * Third Party Data (tag 9F6E)
 *
 * Used for Mastercard contactless to carry additional terminal/transaction info
 */
class ThirdPartyData {
    var deviceType: Byte = 0x00
    var productionEnvironment: Boolean = true
    var uniqueIdentifier: ByteArray = ByteArray(5)

    fun toBytes(): ByteArray {
        val result = ByteArray(6)
        result[0] = deviceType
        System.arraycopy(uniqueIdentifier, 0, result, 1, minOf(uniqueIdentifier.size, 5))
        return result
    }

    companion object {
        const val DEVICE_TYPE_MPOS = 0x30.toByte()
        const val DEVICE_TYPE_SOFTPOS = 0x34.toByte()

        fun forSoftPos(): ThirdPartyData {
            return ThirdPartyData().apply {
                deviceType = DEVICE_TYPE_SOFTPOS
            }
        }
    }
}

/**
 * Issuer Application Data (IAD) parsing for Mastercard
 *
 * Mastercard uses specific IAD formats to carry CVR and other data
 */
class MastercardIssuerApplicationData(private val bytes: ByteArray) {

    /** Derivation Key Index */
    val derivationKeyIndex: Byte get() = if (bytes.isNotEmpty()) bytes[0] else 0

    /** Cryptogram Version Number */
    val cryptogramVersionNumber: Byte get() = if (bytes.size > 1) bytes[1] else 0

    /** Card Verification Results (4 bytes starting at offset 2) */
    val cvr: MastercardCVR? get() {
        return if (bytes.size >= 6) {
            MastercardCVR(bytes.copyOfRange(2, 6))
        } else null
    }

    /** DAC/ICC Dynamic Number */
    val dacIdn: ByteArray? get() {
        return if (bytes.size >= 8) {
            bytes.copyOfRange(6, 8)
        } else null
    }

    /** Plaintext/Encrypted Counters */
    val counters: ByteArray? get() {
        return if (bytes.size > 8) {
            bytes.copyOfRange(8, bytes.size)
        } else null
    }

    fun toBytes(): ByteArray = bytes.copyOf()
}

/**
 * Mastercard Card Verification Results (CVR)
 *
 * 4-byte structure in Issuer Application Data indicating card's verification status
 */
class MastercardCVR(private val bytes: ByteArray) {

    init {
        require(bytes.size >= 4) { "CVR must be at least 4 bytes" }
    }

    // ==================== BYTE 1 (CVR byte 2 in spec) ====================

    /** Second GENERATE AC not requested */
    val secondAcNotRequested: Boolean get() = getBit(0, 7)

    /** Second GENERATE AC returned ARQC */
    val secondAcReturnedArqc: Boolean get() = getBit(0, 6)

    /** Second GENERATE AC returned TC */
    val secondAcReturnedTc: Boolean get() = getBit(0, 5)

    /** First GENERATE AC returned ARQC */
    val firstAcReturnedArqc: Boolean get() = getBit(0, 4)

    /** First GENERATE AC returned TC */
    val firstAcReturnedTc: Boolean get() = getBit(0, 3)

    /** First GENERATE AC returned AAC */
    val firstAcReturnedAac: Boolean get() = getBit(0, 2)

    // Bits 1-0: RFU

    // ==================== BYTE 2 (CVR byte 3 in spec) ====================

    /** Offline PIN verification performed */
    val offlinePinPerformed: Boolean get() = getBit(1, 7)

    /** Offline encrypted PIN verification performed */
    val offlineEncryptedPinPerformed: Boolean get() = getBit(1, 6)

    /** Offline PIN verification successful */
    val offlinePinSuccessful: Boolean get() = getBit(1, 5)

    /** DDA returned */
    val ddaReturned: Boolean get() = getBit(1, 4)

    /** CDA performed */
    val cdaPerformed: Boolean get() = getBit(1, 3)

    /** CDA/DDA/SDAD failed */
    val odaFailed: Boolean get() = getBit(1, 2)

    /** Issuer authentication performed */
    val issuerAuthPerformed: Boolean get() = getBit(1, 1)

    /** CIAC - Default skipped on CAT3 */
    val ciacDefaultSkipped: Boolean get() = getBit(1, 0)

    // ==================== BYTE 3 (CVR byte 4 in spec) ====================

    /** Right nibble: PIN try counter */
    val pinTryCounter: Int get() = bytes[2].toInt() and 0x0F

    // ==================== BYTE 4 (CVR byte 5 in spec) ====================

    /** Last online ATC register */
    val lastOnlineAtc: Byte get() = bytes[3]

    private fun getBit(byteIndex: Int, bitIndex: Int): Boolean {
        return (bytes[byteIndex].toInt() and (1 shl bitIndex)) != 0
    }

    fun toBytes(): ByteArray = bytes.copyOf()

    override fun toString(): String {
        return buildString {
            append("CVR[")
            if (offlinePinPerformed) append("PIN_PERFORMED ")
            if (offlinePinSuccessful) append("PIN_OK ")
            if (cdaPerformed) append("CDA ")
            if (odaFailed) append("ODA_FAIL ")
            append("PIN_TRIES=$pinTryCounter")
            append("]")
        }
    }
}

/**
 * Mastercard Track 2 Data Parser
 */
object MastercardTrack2Parser {

    data class Track2Data(
        val pan: String,
        val expiryDate: String,  // YYMM
        val serviceCode: String,
        val discretionaryData: String
    )

    /**
     * Parse Track 2 Equivalent Data (tag 57)
     */
    fun parse(track2: ByteArray): Track2Data? {
        val hex = track2.toHexString()

        // Find separator 'D' (0x0D in BCD)
        val separatorIndex = hex.indexOf('D', ignoreCase = true)
        if (separatorIndex == -1 || separatorIndex < 8) return null

        val pan = hex.substring(0, separatorIndex)

        // After separator: YYMM (4 digits) + Service Code (3 digits) + discretionary data
        val afterSeparator = hex.substring(separatorIndex + 1)
        if (afterSeparator.length < 7) return null

        val expiryDate = afterSeparator.substring(0, 4)
        val serviceCode = afterSeparator.substring(4, 7)
        val discretionaryData = if (afterSeparator.length > 7) {
            afterSeparator.substring(7).trimEnd('F')
        } else ""

        return Track2Data(pan, expiryDate, serviceCode, discretionaryData)
    }

    /**
     * Parse PUNATC (Position of UN and ATC in Track 2)
     */
    fun parsePunatc(track2: ByteArray, punatc: ByteArray): Pair<Int, Int>? {
        if (punatc.size < 4) return null

        val unPosition = ((punatc[0].toInt() and 0xFF) shl 8) or (punatc[1].toInt() and 0xFF)
        val atcPosition = ((punatc[2].toInt() and 0xFF) shl 8) or (punatc[3].toInt() and 0xFF)

        return Pair(unPosition, atcPosition)
    }
}

/**
 * Mag Stripe Application Version Number Qualifier (AVN)
 *
 * Tag 9F6D - determines mag stripe mode capabilities
 */
object MagStripeVersionQualifier {
    const val VERSION_PAYPASS_MAGSTRIPE_3_0: Byte = 0x01
    const val VERSION_PAYPASS_MAGSTRIPE_3_1: Byte = 0x02

    /**
     * Check if CVC3 Track 1 is supported
     */
    fun supportsCvc3Track1(avn: ByteArray): Boolean {
        return avn.isNotEmpty() && (avn[0].toInt() and 0x80) != 0
    }

    /**
     * Check if CVC3 Track 2 is supported
     */
    fun supportsCvc3Track2(avn: ByteArray): Boolean {
        return avn.isNotEmpty() && (avn[0].toInt() and 0x40) != 0
    }
}

// Extension
private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
