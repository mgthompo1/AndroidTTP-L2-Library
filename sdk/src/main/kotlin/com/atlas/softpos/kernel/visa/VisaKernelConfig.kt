package com.atlas.softpos.kernel.visa

import com.atlas.softpos.core.types.hexToByteArray

/**
 * Visa payWave Kernel Configuration
 *
 * Based on Visa Contactless Payment Specification (VCPS) and
 * Visa Ready Tap to Phone Kernel Specification (VRTPKS)
 */
data class VisaKernelConfig(
    /**
     * Terminal Type (tag 9F35)
     * - 0x22: Attended, online only
     * - 0x21: Attended, online capable
     * - 0x11: Unattended, online only
     */
    val terminalType: Byte = 0x22,

    /**
     * Terminal Capabilities (tag 9F33) - 3 bytes
     * Byte 1: Card data input capability
     *   - bit 8: Manual key entry
     *   - bit 7: Magnetic stripe
     *   - bit 6: IC with contacts
     *   - bits 5-1: RFU
     * Byte 2: CVM capability
     *   - bit 8: Plaintext PIN for ICC verification
     *   - bit 7: Enciphered PIN for online verification
     *   - bit 6: Signature (paper)
     *   - bit 5: Enciphered PIN for offline verification
     *   - bit 4: No CVM required
     *   - bits 3-1: RFU
     * Byte 3: Security capability
     *   - bit 8: SDA
     *   - bit 7: DDA
     *   - bit 6: Card capture
     *   - bit 5: RFU
     *   - bit 4: CDA
     *   - bits 3-1: RFU
     */
    val terminalCapabilities: ByteArray = "E0F0C8".hexToByteArray(),

    /**
     * Additional Terminal Capabilities (tag 9F40) - 5 bytes
     */
    val additionalTerminalCapabilities: ByteArray = "FF00F0A001".hexToByteArray(),

    /**
     * Terminal Country Code (tag 9F1A) - 2 bytes
     * ISO 3166-1 numeric country code (e.g., 0840 for USA)
     */
    val terminalCountryCode: ByteArray = "0840".hexToByteArray(),

    /**
     * Transaction Currency Code (tag 5F2A) - 2 bytes
     * ISO 4217 numeric currency code (e.g., 0840 for USD)
     */
    val transactionCurrencyCode: ByteArray = "0840".hexToByteArray(),

    /**
     * Merchant Category Code (tag 9F15) - 2 bytes
     */
    val merchantCategoryCode: ByteArray = "0000".hexToByteArray(),

    /**
     * Merchant Identifier (tag 9F16) - 15 bytes AN
     */
    val merchantIdentifier: String = "ATLASMERCHANT01",

    /**
     * Terminal Identification (tag 9F1C) - 8 bytes AN
     */
    val terminalIdentification: String = "ATLAS001",

    /**
     * Acquirer Identifier (tag 9F01) - 6 bytes
     */
    val acquirerIdentifier: ByteArray = "000000000001".hexToByteArray(),

    /**
     * Reader Contactless Floor Limit (tag DF8123)
     * Transactions above this amount require online authorization
     */
    val contactlessFloorLimit: Long = 0,

    /**
     * Reader CVM Required Limit (tag DF8126)
     * Transactions above this amount require cardholder verification
     */
    val cvmRequiredLimit: Long = 2500,  // $25.00 in cents

    /**
     * Reader Contactless Transaction Limit (tag DF8124)
     * Maximum transaction amount for contactless
     */
    val contactlessTransactionLimit: Long = 100000,  // $1000.00 in cents

    /**
     * Terminal Floor Limit (tag 9F1B) - 4 bytes
     */
    val terminalFloorLimit: Long = 0,

    /**
     * Terminal Action Codes
     * Specify when to decline/go online based on TVR
     */
    val tacDenial: ByteArray = "0010000000".hexToByteArray(),
    val tacOnline: ByteArray = "F850ACF800".hexToByteArray(),
    val tacDefault: ByteArray = "F850ACF800".hexToByteArray(),

    /**
     * Application Version Number (tag 9F09)
     * Must match or exceed card's version
     */
    val applicationVersionNumber: ByteArray = "0002".hexToByteArray(),

    /**
     * TTQ (Terminal Transaction Qualifiers) for Visa
     * Tag 9F66 - 4 bytes
     *
     * Byte 1:
     *   - bit 8: MSD supported
     *   - bit 7: Reserved (Visa VSDC)
     *   - bit 6: qVSDC supported
     *   - bit 5: Contact chip supported
     *   - bit 4: Reader is offline only
     *   - bit 3: Online PIN supported
     *   - bit 2: Signature supported
     *   - bit 1: ODA for online auth supported
     *
     * Byte 2:
     *   - bit 8: Online cryptogram required
     *   - bit 7: CVM required
     *   - bit 6: Contact chip offline PIN supported
     *   - bits 5-1: RFU
     *
     * Byte 3:
     *   - bit 8: Issuer Update Processing supported
     *   - bit 7: Consumer Device CVM performed
     *   - bits 6-1: RFU
     *
     * Byte 4: RFU
     */
    val defaultTtq: ByteArray = "36000000".hexToByteArray()
) {
    /**
     * Build TTQ based on transaction parameters
     */
    fun buildTtq(
        amount: Long,
        isOnlineCapable: Boolean = true,
        cvmPerformed: Boolean = false
    ): ByteArray {
        var byte1 = 0x26  // qVSDC supported, ODA supported

        if (isOnlineCapable) {
            byte1 = byte1 or 0x10  // Not offline only
        }

        // Check if CVM is required based on amount
        val cvmRequired = amount > cvmRequiredLimit

        var byte2 = 0x00
        if (!isOnlineCapable || cvmRequired) {
            byte2 = byte2 or 0x80  // Online cryptogram required
        }
        if (cvmRequired) {
            byte2 = byte2 or 0x40  // CVM required
        }

        var byte3 = 0x00
        if (cvmPerformed) {
            byte3 = byte3 or 0x40  // Consumer Device CVM performed
        }

        return byteArrayOf(
            byte1.toByte(),
            byte2.toByte(),
            byte3.toByte(),
            0x00
        )
    }
}

/**
 * Transaction types (tag 9C)
 */
object TransactionType {
    const val PURCHASE: Byte = 0x00
    const val CASH_ADVANCE: Byte = 0x01
    const val PURCHASE_WITH_CASHBACK: Byte = 0x09
    const val REFUND: Byte = 0x20
    const val BALANCE_INQUIRY: Byte = 0x31
}

/**
 * CVM (Cardholder Verification Method) types
 */
enum class CvmType(val code: Byte) {
    NO_CVM(0x00),
    SIGNATURE(0x1E),
    ONLINE_PIN(0x02),
    CONSUMER_DEVICE_CVM(0x1F);

    companion object {
        fun fromCode(code: Byte): CvmType {
            return entries.find { it.code == code } ?: NO_CVM
        }
    }
}

/**
 * Outcome of kernel processing
 */
enum class KernelOutcome {
    APPROVED,           // Offline approval (TC received)
    ONLINE_REQUEST,     // Go online for authorization (ARQC received)
    DECLINED,           // Offline decline (AAC received)
    TRY_ANOTHER_INTERFACE,
    END_APPLICATION,
    SELECT_NEXT,
    TRY_AGAIN
}
