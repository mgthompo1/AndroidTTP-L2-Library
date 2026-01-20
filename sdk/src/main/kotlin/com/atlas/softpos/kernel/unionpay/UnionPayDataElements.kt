package com.atlas.softpos.kernel.unionpay

/**
 * UnionPay QuickPass Data Elements
 *
 * Per UnionPay Contactless Specification (UICS)
 */

/**
 * UnionPay Application Interchange Profile (AIP)
 *
 * 2-byte field indicating card capabilities
 */
data class UnionPayApplicationInterchangeProfile(
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

    val onDeviceCvmSupported: Boolean
        get() = (bytes[1].toInt() and 0x20) != 0

    fun getPreferredOdaMethod(): UnionPayOdaMethod {
        return when {
            cdaSupported -> UnionPayOdaMethod.CDA
            ddaSupported -> UnionPayOdaMethod.DDA
            sdaSupported -> UnionPayOdaMethod.SDA
            else -> UnionPayOdaMethod.NONE
        }
    }

    fun supportsOda(): Boolean = sdaSupported || ddaSupported || cdaSupported

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnionPayApplicationInterchangeProfile) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    fun toHexString(): String = bytes.joinToString("") { "%02X".format(it) }
}

enum class UnionPayOdaMethod {
    NONE, SDA, DDA, CDA
}

/**
 * UnionPay Card Transaction Qualifiers (CTQ)
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
 *   b8: On-device CVM performed
 *   b7: Card supports issuer update
 *   b6: Card supports CDCVM
 *   b5-b1: Reserved
 */
data class UnionPayCardTransactionQualifiers(
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

    val onDeviceCvmPerformed: Boolean
        get() = (bytes[1].toInt() and 0x80) != 0

    val issuerUpdateSupported: Boolean
        get() = (bytes[1].toInt() and 0x40) != 0

    val cardSupportsCdcvm: Boolean
        get() = (bytes[1].toInt() and 0x20) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnionPayCardTransactionQualifiers) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * UnionPay Terminal Transaction Qualifiers (TTQ)
 *
 * 4-byte field sent to card in PDOL
 */
data class UnionPayTerminalTransactionQualifiers(
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

    val onDeviceCvmSupported: Boolean
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
            onDeviceCvm: Boolean = true,
            onlineCryptogramRequired: Boolean = true
        ): UnionPayTerminalTransactionQualifiers {
            var byte1 = 0x00
            var byte2 = 0x00
            var byte3 = 0x00

            if (magStripeMode) byte1 = byte1 or 0x80
            if (emvMode) byte1 = byte1 or 0x20
            if (onlinePin) byte1 = byte1 or 0x04
            if (signature) byte1 = byte1 or 0x02

            if (onlineCryptogramRequired) byte2 = byte2 or 0x80
            byte2 = byte2 or 0x40 // CVM required

            if (onDeviceCvm) byte3 = byte3 or 0x40

            return UnionPayTerminalTransactionQualifiers(
                byteArrayOf(byte1.toByte(), byte2.toByte(), byte3.toByte(), 0x00)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnionPayTerminalTransactionQualifiers) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * UnionPay Issuer Application Data (IAD)
 */
data class UnionPayIssuerApplicationData(
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
        if (other !is UnionPayIssuerApplicationData) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * UnionPay Card Verification Results (CVR)
 */
data class UnionPayCardVerificationResults(
    val bytes: ByteArray
) {
    init {
        require(bytes.size >= 4) { "CVR must be at least 4 bytes" }
    }

    val cryptogramType: UnionPayCryptogramType
        get() = when ((bytes[0].toInt() and 0xF0) shr 4) {
            0 -> UnionPayCryptogramType.AAC
            1 -> UnionPayCryptogramType.TC
            2 -> UnionPayCryptogramType.ARQC
            else -> UnionPayCryptogramType.UNKNOWN
        }

    val offlineDataAuthPerformed: Boolean
        get() = (bytes[0].toInt() and 0x02) != 0

    val issuerAuthPerformed: Boolean
        get() = (bytes[0].toInt() and 0x01) != 0

    val offlinePinPassed: Boolean
        get() = (bytes[1].toInt() and 0x08) != 0

    val pinTryLimitExceeded: Boolean
        get() = (bytes[1].toInt() and 0x04) != 0

    enum class UnionPayCryptogramType {
        AAC, TC, ARQC, UNKNOWN
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnionPayCardVerificationResults) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * UnionPay Track 2 Equivalent Data parser
 */
object UnionPayTrack2Parser {
    fun parse(track2Data: ByteArray): UnionPayTrack2? {
        val hex = track2Data.joinToString("") { "%02X".format(it) }
        val separatorIndex = hex.indexOf('D')

        if (separatorIndex < 0) return null

        val pan = hex.substring(0, separatorIndex)
        val afterSeparator = hex.substring(separatorIndex + 1)

        if (afterSeparator.length < 7) return null

        val expiryDate = afterSeparator.substring(0, 4)
        val serviceCode = afterSeparator.substring(4, 7)
        val discretionaryData = afterSeparator.substring(7).trimEnd('F')

        return UnionPayTrack2(
            pan = pan,
            expiryDate = expiryDate,
            serviceCode = serviceCode,
            discretionaryData = discretionaryData
        )
    }
}

data class UnionPayTrack2(
    val pan: String,
    val expiryDate: String,
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
 * UnionPay-specific EMV tags
 */
object UnionPayTags {
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

    // UnionPay-specific tags
    const val TERMINAL_TRANSACTION_QUALIFIERS = "9F66"
    const val CARD_TRANSACTION_QUALIFIERS = "9F6C"
    const val FORM_FACTOR_INDICATOR = "9F6E"

    // UnionPay proprietary
    const val ELECTRONIC_CASH_BALANCE = "9F79"
    const val ELECTRONIC_CASH_LIMIT = "9F77"
    const val ELECTRONIC_CASH_SINGLE_LIMIT = "9F78"
}

/**
 * UnionPay AIDs
 */
object UnionPayAids {
    val QUICKPASS_DEBIT = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x03, 0x33.toByte(), 0x01, 0x01
    )

    val QUICKPASS_CREDIT = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x03, 0x33.toByte(), 0x01, 0x02
    )

    val QUICKPASS_QUASI_CREDIT = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x03, 0x33.toByte(), 0x01, 0x03
    )

    val ELECTRONIC_CASH = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x03, 0x33.toByte(), 0x01, 0x06
    )

    fun isUnionPayAid(aid: ByteArray): Boolean {
        if (aid.size < 5) return false
        return aid[0] == 0xA0.toByte() &&
                aid[1] == 0x00.toByte() &&
                aid[2] == 0x00.toByte() &&
                aid[3] == 0x03.toByte() &&
                aid[4] == 0x33.toByte()
    }
}
