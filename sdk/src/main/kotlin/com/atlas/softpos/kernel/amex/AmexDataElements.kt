package com.atlas.softpos.kernel.amex

/**
 * American Express ExpressPay Data Elements
 *
 * Per EMV Contactless Book C-4 (American Express Specification)
 */

/**
 * Enhanced Contactless Reader Capabilities (Tag 9F6E)
 *
 * 4-byte field indicating terminal capabilities for ExpressPay
 *
 * Byte 1:
 *   b8: Contact mode supported
 *   b7: Contactless MSD mode supported
 *   b6: Contactless EMV mode supported
 *   b5: Contact chip offline PIN supported
 *   b4: Contactless mobile device supported
 *   b3: Reserved
 *   b2: Online cryptogram required
 *   b1: Signature supported
 *
 * Byte 2:
 *   b8: Consumer Device CVM supported
 *   b7: Issuer Update supported
 *   b6: Mobile-CVM supported
 *   b5-b1: Reserved
 *
 * Byte 3-4: Reserved
 */
data class EnhancedContactlessReaderCapabilities(
    val bytes: ByteArray = byteArrayOf(0xD8.toByte(), 0xE0.toByte(), 0x00, 0x00)
) {
    // Byte 1 capabilities
    val contactModeSupported: Boolean
        get() = (bytes[0].toInt() and 0x80) != 0

    val contactlessMsdSupported: Boolean
        get() = (bytes[0].toInt() and 0x40) != 0

    val contactlessEmvSupported: Boolean
        get() = (bytes[0].toInt() and 0x20) != 0

    val contactChipOfflinePinSupported: Boolean
        get() = (bytes[0].toInt() and 0x10) != 0

    val contactlessMobileDeviceSupported: Boolean
        get() = (bytes[0].toInt() and 0x08) != 0

    val onlineCryptogramRequired: Boolean
        get() = (bytes[0].toInt() and 0x02) != 0

    val signatureSupported: Boolean
        get() = (bytes[0].toInt() and 0x01) != 0

    // Byte 2 capabilities
    val consumerDeviceCvmSupported: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    val issuerUpdateSupported: Boolean
        get() = (bytes[1].toInt() and 0x40) != 0

    val mobileCvmSupported: Boolean
        get() = (bytes[1].toInt() and 0x20) != 0

    companion object {
        /**
         * Build ECR capabilities for SoftPOS terminal
         */
        fun forSoftPos(
            contactlessEmv: Boolean = true,
            contactlessMsd: Boolean = true,
            mobileDevice: Boolean = true,
            onlineRequired: Boolean = true,
            cdcvm: Boolean = true,
            mobileCvm: Boolean = true
        ): EnhancedContactlessReaderCapabilities {
            var byte1 = 0x00
            var byte2 = 0x00

            if (contactlessMsd) byte1 = byte1 or 0x40
            if (contactlessEmv) byte1 = byte1 or 0x20
            if (mobileDevice) byte1 = byte1 or 0x08
            if (onlineRequired) byte1 = byte1 or 0x02

            if (cdcvm) byte2 = byte2 or 0x80
            if (mobileCvm) byte2 = byte2 or 0x20

            return EnhancedContactlessReaderCapabilities(
                byteArrayOf(byte1.toByte(), byte2.toByte(), 0x00, 0x00)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EnhancedContactlessReaderCapabilities) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * American Express Application Interchange Profile (AIP)
 *
 * 2-byte field indicating card capabilities
 *
 * Byte 1:
 *   b8: Reserved
 *   b7: SDA supported
 *   b6: DDA supported
 *   b5: EMV mode supported (Cardholder verification supported)
 *   b4: Terminal risk management required
 *   b3: Issuer authentication supported
 *   b2: Reserved
 *   b1: CDA supported
 *
 * Byte 2:
 *   b8: Mag stripe mode supported
 *   b7: Reserved
 *   b6-b1: Reserved for future use
 */
data class AmexApplicationInterchangeProfile(
    val bytes: ByteArray
) {
    init {
        require(bytes.size >= 2) { "AIP must be at least 2 bytes" }
    }

    // Byte 1
    val sdaSupported: Boolean
        get() = (bytes[0].toInt() and 0x40) != 0

    val ddaSupported: Boolean
        get() = (bytes[0].toInt() and 0x20) != 0

    val emvModeSupported: Boolean
        get() = (bytes[0].toInt() and 0x10) != 0

    val terminalRiskManagementRequired: Boolean
        get() = (bytes[0].toInt() and 0x08) != 0

    val issuerAuthenticationSupported: Boolean
        get() = (bytes[0].toInt() and 0x04) != 0

    val cdaSupported: Boolean
        get() = (bytes[0].toInt() and 0x01) != 0

    // Byte 2
    val magStripeModeSupported: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    /**
     * Determine best ODA method
     */
    fun getPreferredOdaMethod(): OdaMethod {
        return when {
            cdaSupported -> OdaMethod.CDA
            ddaSupported -> OdaMethod.DDA
            sdaSupported -> OdaMethod.SDA
            else -> OdaMethod.NONE
        }
    }

    /**
     * Check if card supports any ODA
     */
    fun supportsOda(): Boolean = sdaSupported || ddaSupported || cdaSupported

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexApplicationInterchangeProfile) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    fun toHexString(): String = bytes.joinToString("") { "%02X".format(it) }
}

enum class OdaMethod {
    NONE, SDA, DDA, CDA
}

/**
 * American Express Card Transaction Qualifiers (CTQ)
 *
 * Returned in GPO response, indicates card's transaction preferences
 *
 * Byte 1:
 *   b8: Online cryptogram required
 *   b7: CVM required
 *   b6: Offline PIN required (contact only)
 *   b5: Signature required
 *   b4-b1: Reserved
 *
 * Byte 2:
 *   b8: Consumer Device CVM performed
 *   b7: Card supports CDCVM
 *   b6-b1: Reserved
 */
data class AmexCardTransactionQualifiers(
    val bytes: ByteArray
) {
    init {
        require(bytes.size >= 2) { "CTQ must be at least 2 bytes" }
    }

    val onlineCryptogramRequired: Boolean
        get() = (bytes[0].toInt() and 0x80) != 0

    val cvmRequired: Boolean
        get() = (bytes[0].toInt() and 0x40) != 0

    val offlinePinRequired: Boolean
        get() = (bytes[0].toInt() and 0x20) != 0

    val signatureRequired: Boolean
        get() = (bytes[0].toInt() and 0x10) != 0

    val cdcvmPerformed: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    val cardSupportsCdcvm: Boolean
        get() = (bytes[1].toInt() and 0x40) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexCardTransactionQualifiers) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * American Express Issuer Application Data (IAD)
 *
 * Card-specific data in GENERATE AC response
 *
 * Format varies by card profile, typically:
 * - Bytes 1-2: Derivation Key Index
 * - Bytes 3-4: Cryptogram Version Number
 * - Bytes 5-8: Card Verification Results (CVR)
 * - Remaining: Discretionary data
 */
data class AmexIssuerApplicationData(
    val bytes: ByteArray
) {
    val derivationKeyIndex: ByteArray
        get() = if (bytes.size >= 2) bytes.copyOfRange(0, 2) else byteArrayOf()

    val cryptogramVersionNumber: ByteArray
        get() = if (bytes.size >= 4) bytes.copyOfRange(2, 4) else byteArrayOf()

    val cardVerificationResults: ByteArray
        get() = if (bytes.size >= 8) bytes.copyOfRange(4, 8) else byteArrayOf()

    val discretionaryData: ByteArray
        get() = if (bytes.size > 8) bytes.copyOfRange(8, bytes.size) else byteArrayOf()

    fun toHexString(): String = bytes.joinToString("") { "%02X".format(it) }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexIssuerApplicationData) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * American Express Card Verification Results (CVR)
 *
 * 4-byte field within IAD indicating card-level verification status
 *
 * Byte 1:
 *   b8-b5: Application Cryptogram Type (0=AAC, 1=TC, 2=ARQC)
 *   b4: Second GENERATE AC not requested
 *   b3: GENERATE AC returned in Format 1
 *   b2: Offline data auth performed
 *   b1: Issuer authentication performed
 *
 * Byte 2:
 *   b8-b5: Offline PIN verification performed counter
 *   b4: Offline PIN verification passed
 *   b3: PIN try limit exceeded
 *   b2: Last online transaction not completed
 *   b1: Lower offline limit exceeded
 *
 * Byte 3:
 *   b8: Upper offline limit exceeded
 *   b7: Script counter (MSB)
 *   b6-b1: Script counter (LSB)
 *
 * Byte 4:
 *   b8-b5: Issuer discretionary
 *   b4-b1: RFU
 */
data class AmexCardVerificationResults(
    val bytes: ByteArray
) {
    init {
        require(bytes.size >= 4) { "CVR must be at least 4 bytes" }
    }

    val cryptogramType: CryptogramType
        get() = when ((bytes[0].toInt() and 0xF0) shr 4) {
            0 -> CryptogramType.AAC
            1 -> CryptogramType.TC
            2 -> CryptogramType.ARQC
            else -> CryptogramType.UNKNOWN
        }

    val offlineDataAuthPerformed: Boolean
        get() = (bytes[0].toInt() and 0x02) != 0

    val issuerAuthPerformed: Boolean
        get() = (bytes[0].toInt() and 0x01) != 0

    val offlinePinPassed: Boolean
        get() = (bytes[1].toInt() and 0x08) != 0

    val pinTryLimitExceeded: Boolean
        get() = (bytes[1].toInt() and 0x04) != 0

    val lastOnlineNotCompleted: Boolean
        get() = (bytes[1].toInt() and 0x02) != 0

    val lowerOfflineLimitExceeded: Boolean
        get() = (bytes[1].toInt() and 0x01) != 0

    val upperOfflineLimitExceeded: Boolean
        get() = (bytes[2].toInt() and 0x80) != 0

    enum class CryptogramType {
        AAC, TC, ARQC, UNKNOWN
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexCardVerificationResults) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * American Express Track 2 Equivalent Data parser
 */
object AmexTrack2Parser {
    /**
     * Parse Track 2 Equivalent Data (Tag 57)
     *
     * Format: PAN D YYMM ServiceCode Discretionary Data F
     */
    fun parse(track2Data: ByteArray): AmexTrack2? {
        val hex = track2Data.joinToString("") { "%02X".format(it) }
        val separatorIndex = hex.indexOf('D')

        if (separatorIndex < 0) return null

        val pan = hex.substring(0, separatorIndex)
        val afterSeparator = hex.substring(separatorIndex + 1)

        if (afterSeparator.length < 7) return null

        val expiryDate = afterSeparator.substring(0, 4)  // YYMM
        val serviceCode = afterSeparator.substring(4, 7)
        val discretionaryData = afterSeparator.substring(7).trimEnd('F')

        return AmexTrack2(
            pan = pan,
            expiryDate = expiryDate,
            serviceCode = serviceCode,
            discretionaryData = discretionaryData
        )
    }
}

data class AmexTrack2(
    val pan: String,
    val expiryDate: String,  // YYMM
    val serviceCode: String,
    val discretionaryData: String
) {
    val maskedPan: String
        get() = if (pan.length >= 10) {
            "${pan.take(6)}${"*".repeat(pan.length - 10)}${pan.takeLast(4)}"
        } else pan

    val expiryFormatted: String
        get() = if (expiryDate.length == 4) {
            "${expiryDate.substring(2, 4)}/${expiryDate.substring(0, 2)}"
        } else expiryDate
}

/**
 * AmEx-specific EMV tags
 */
object AmexTags {
    // Standard EMV tags used by AmEx
    const val AID = "9F06"
    const val APPLICATION_LABEL = "50"
    const val APPLICATION_PREFERRED_NAME = "9F12"
    const val PAN = "5A"
    const val TRACK2_EQUIVALENT = "57"
    const val EXPIRY_DATE = "5F24"
    const val PAN_SEQUENCE_NUMBER = "5F34"
    const val AIP = "82"
    const val AFL = "94"
    const val CDOL1 = "8C"
    const val CDOL2 = "8D"
    const val CVM_LIST = "8E"
    const val CA_PUBLIC_KEY_INDEX = "8F"
    const val ISSUER_PUBLIC_KEY_CERTIFICATE = "90"
    const val ISSUER_PUBLIC_KEY_REMAINDER = "92"
    const val ISSUER_PUBLIC_KEY_EXPONENT = "9F32"
    const val ICC_PUBLIC_KEY_CERTIFICATE = "9F46"
    const val ICC_PUBLIC_KEY_EXPONENT = "9F47"
    const val ICC_PUBLIC_KEY_REMAINDER = "9F48"
    const val STATIC_DATA_AUTH_TAG_LIST = "9F4A"
    const val SDAD = "9F4B"
    const val ICC_DYNAMIC_NUMBER = "9F4C"
    const val APPLICATION_CRYPTOGRAM = "9F26"
    const val CRYPTOGRAM_INFO_DATA = "9F27"
    const val ISSUER_APPLICATION_DATA = "9F10"
    const val ATC = "9F36"
    const val TVR = "95"
    const val TSI = "9B"
    const val CVM_RESULTS = "9F34"
    const val UNPREDICTABLE_NUMBER = "9F37"

    // AmEx-specific tags
    const val ENHANCED_CONTACTLESS_READER_CAPABILITIES = "9F6E"
    const val CARD_TRANSACTION_QUALIFIERS = "9F6C"  // Same as MC
    const val FORM_FACTOR_INDICATOR = "9F6E"
    const val CUSTOMER_EXCLUSIVE_DATA = "9F7C"
}

/**
 * American Express AIDs
 */
object AmexAids {
    val EXPRESSPAY = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x00, 0x25.toByte(), 0x01
    )

    val EXPRESSPAY_US_DEBIT = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x00, 0x25.toByte(), 0x01, 0x07, 0x01
    )

    fun isAmexAid(aid: ByteArray): Boolean {
        if (aid.size < 5) return false
        return aid[0] == 0xA0.toByte() &&
                aid[1] == 0x00.toByte() &&
                aid[2] == 0x00.toByte() &&
                aid[3] == 0x00.toByte() &&
                aid[4] == 0x25.toByte()
    }
}
