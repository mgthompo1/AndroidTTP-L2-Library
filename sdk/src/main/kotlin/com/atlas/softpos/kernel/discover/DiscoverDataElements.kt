package com.atlas.softpos.kernel.discover

/**
 * Discover D-PAS (Discover Payment Application Specification) Data Elements
 *
 * Per EMV Contactless Book C-6 (Discover Specification)
 */

/**
 * Discover Application Interchange Profile (AIP)
 *
 * 2-byte field indicating card capabilities
 *
 * Byte 1:
 *   b8: Reserved
 *   b7: SDA supported
 *   b6: DDA supported
 *   b5: Cardholder verification supported
 *   b4: Terminal risk management required
 *   b3: Issuer authentication supported
 *   b2: Reserved
 *   b1: CDA supported
 *
 * Byte 2:
 *   b8: EMV mode supported
 *   b7: Mag stripe mode supported
 *   b6-b1: Reserved
 */
data class DiscoverApplicationInterchangeProfile(
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

    val cardholderVerificationSupported: Boolean
        get() = (bytes[0].toInt() and 0x10) != 0

    val terminalRiskManagementRequired: Boolean
        get() = (bytes[0].toInt() and 0x08) != 0

    val issuerAuthenticationSupported: Boolean
        get() = (bytes[0].toInt() and 0x04) != 0

    val cdaSupported: Boolean
        get() = (bytes[0].toInt() and 0x01) != 0

    // Byte 2
    val emvModeSupported: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    val magStripeModeSupported: Boolean
        get() = (bytes[1].toInt() and 0x40) != 0

    fun getPreferredOdaMethod(): DiscoverOdaMethod {
        return when {
            cdaSupported -> DiscoverOdaMethod.CDA
            ddaSupported -> DiscoverOdaMethod.DDA
            sdaSupported -> DiscoverOdaMethod.SDA
            else -> DiscoverOdaMethod.NONE
        }
    }

    fun supportsOda(): Boolean = sdaSupported || ddaSupported || cdaSupported

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DiscoverApplicationInterchangeProfile) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    fun toHexString(): String = bytes.joinToString("") { "%02X".format(it) }
}

enum class DiscoverOdaMethod {
    NONE, SDA, DDA, CDA
}

/**
 * Discover Card Transaction Qualifiers (CTQ)
 *
 * Returned in GPO response, indicates card's transaction preferences
 *
 * Byte 1:
 *   b8: Online cryptogram required
 *   b7: CVM required
 *   b6: Offline PIN required
 *   b5: Signature required
 *   b4: Online PIN required
 *   b3: Switch interface for cash
 *   b2: Switch interface for cashback
 *   b1: Reserved
 *
 * Byte 2:
 *   b8: Consumer Device CVM performed
 *   b7: Card supports issuer update
 *   b6-b1: Reserved
 */
data class DiscoverCardTransactionQualifiers(
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

    val onlinePinRequired: Boolean
        get() = (bytes[0].toInt() and 0x08) != 0

    val switchInterfaceForCash: Boolean
        get() = (bytes[0].toInt() and 0x04) != 0

    val switchInterfaceForCashback: Boolean
        get() = (bytes[0].toInt() and 0x02) != 0

    val cdcvmPerformed: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    val issuerUpdateSupported: Boolean
        get() = (bytes[1].toInt() and 0x40) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DiscoverCardTransactionQualifiers) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Discover Terminal Transaction Qualifiers (TTQ)
 *
 * Sent to card in PDOL to indicate terminal capabilities
 *
 * Byte 1:
 *   b8: Mag stripe mode supported
 *   b7: Reserved
 *   b6: EMV mode supported
 *   b5: EMV contact chip supported
 *   b4: Offline-only reader
 *   b3: Online PIN supported
 *   b2: Signature supported
 *   b1: Offline data authentication for online auth supported
 *
 * Byte 2:
 *   b8: Online cryptogram required
 *   b7: CVM required
 *   b6: Offline PIN supported
 *   b5-b1: Reserved
 *
 * Byte 3:
 *   b8: Issuer update processing supported
 *   b7: Consumer device CVM supported
 *   b6-b1: Reserved
 *
 * Byte 4: Reserved
 */
data class DiscoverTerminalTransactionQualifiers(
    val bytes: ByteArray = byteArrayOf(0x36, 0xC0.toByte(), 0xC0.toByte(), 0x00)
) {
    // Byte 1 capabilities
    val magStripeModeSupported: Boolean
        get() = (bytes[0].toInt() and 0x80) != 0

    val emvModeSupported: Boolean
        get() = (bytes[0].toInt() and 0x20) != 0

    val emvContactChipSupported: Boolean
        get() = (bytes[0].toInt() and 0x10) != 0

    val offlineOnlyReader: Boolean
        get() = (bytes[0].toInt() and 0x08) != 0

    val onlinePinSupported: Boolean
        get() = (bytes[0].toInt() and 0x04) != 0

    val signatureSupported: Boolean
        get() = (bytes[0].toInt() and 0x02) != 0

    val odaForOnlineSupported: Boolean
        get() = (bytes[0].toInt() and 0x01) != 0

    // Byte 2
    val onlineCryptogramRequired: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    val cvmRequired: Boolean
        get() = (bytes[1].toInt() and 0x40) != 0

    val offlinePinSupported: Boolean
        get() = (bytes[1].toInt() and 0x20) != 0

    // Byte 3
    val issuerUpdateSupported: Boolean
        get() = (bytes[2].toInt() and 0x80) != 0

    val consumerDeviceCvmSupported: Boolean
        get() = (bytes[2].toInt() and 0x40) != 0

    companion object {
        /**
         * Build TTQ for SoftPOS terminal
         */
        fun forSoftPos(
            emvMode: Boolean = true,
            magStripeMode: Boolean = true,
            onlinePin: Boolean = true,
            signature: Boolean = false,
            cdcvm: Boolean = true,
            onlineCryptogramRequired: Boolean = true
        ): DiscoverTerminalTransactionQualifiers {
            var byte1 = 0x00
            var byte2 = 0x00
            var byte3 = 0x00

            if (magStripeMode) byte1 = byte1 or 0x80
            if (emvMode) byte1 = byte1 or 0x20
            if (onlinePin) byte1 = byte1 or 0x04
            if (signature) byte1 = byte1 or 0x02

            if (onlineCryptogramRequired) byte2 = byte2 or 0x80
            byte2 = byte2 or 0x40 // CVM required for contactless

            if (cdcvm) byte3 = byte3 or 0x40

            return DiscoverTerminalTransactionQualifiers(
                byteArrayOf(byte1.toByte(), byte2.toByte(), byte3.toByte(), 0x00)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DiscoverTerminalTransactionQualifiers) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Discover Issuer Application Data (IAD)
 *
 * Card-specific data in GENERATE AC response
 */
data class DiscoverIssuerApplicationData(
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
        if (other !is DiscoverIssuerApplicationData) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Discover Card Verification Results (CVR)
 *
 * 4-byte field within IAD indicating card-level verification status
 */
data class DiscoverCardVerificationResults(
    val bytes: ByteArray
) {
    init {
        require(bytes.size >= 4) { "CVR must be at least 4 bytes" }
    }

    val cryptogramType: DiscoverCryptogramType
        get() = when ((bytes[0].toInt() and 0xF0) shr 4) {
            0 -> DiscoverCryptogramType.AAC
            1 -> DiscoverCryptogramType.TC
            2 -> DiscoverCryptogramType.ARQC
            else -> DiscoverCryptogramType.UNKNOWN
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

    enum class DiscoverCryptogramType {
        AAC, TC, ARQC, UNKNOWN
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DiscoverCardVerificationResults) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Discover Track 2 Equivalent Data parser
 */
object DiscoverTrack2Parser {
    /**
     * Parse Track 2 Equivalent Data (Tag 57)
     *
     * Format: PAN D YYMM ServiceCode Discretionary Data F
     */
    fun parse(track2Data: ByteArray): DiscoverTrack2? {
        val hex = track2Data.joinToString("") { "%02X".format(it) }
        val separatorIndex = hex.indexOf('D')

        if (separatorIndex < 0) return null

        val pan = hex.substring(0, separatorIndex)
        val afterSeparator = hex.substring(separatorIndex + 1)

        if (afterSeparator.length < 7) return null

        val expiryDate = afterSeparator.substring(0, 4)  // YYMM
        val serviceCode = afterSeparator.substring(4, 7)
        val discretionaryData = afterSeparator.substring(7).trimEnd('F')

        return DiscoverTrack2(
            pan = pan,
            expiryDate = expiryDate,
            serviceCode = serviceCode,
            discretionaryData = discretionaryData
        )
    }
}

data class DiscoverTrack2(
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
 * Discover-specific EMV tags
 */
object DiscoverTags {
    // Standard EMV tags used by Discover
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

    // Discover-specific tags
    const val TERMINAL_TRANSACTION_QUALIFIERS = "9F66"
    const val CARD_TRANSACTION_QUALIFIERS = "9F6C"
    const val FORM_FACTOR_INDICATOR = "9F6E"
}

/**
 * Discover AIDs
 */
object DiscoverAids {
    val DISCOVER_ZIP = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x01, 0x52.toByte(), 0x30, 0x10
    )

    val DISCOVER_DPAS = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x01, 0x52.toByte(), 0x10, 0x10
    )

    val DINERS_CLUB = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x01, 0x52.toByte(), 0x30, 0x10
    )

    fun isDiscoverAid(aid: ByteArray): Boolean {
        if (aid.size < 5) return false
        return aid[0] == 0xA0.toByte() &&
                aid[1] == 0x00.toByte() &&
                aid[2] == 0x00.toByte() &&
                aid[3] == 0x01.toByte() &&
                aid[4] == 0x52.toByte()
    }
}
