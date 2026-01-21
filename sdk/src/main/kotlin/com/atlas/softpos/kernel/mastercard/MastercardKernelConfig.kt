package com.atlas.softpos.kernel.mastercard

import com.atlas.softpos.core.types.hexToByteArray

/**
 * Mastercard PayPass Kernel Configuration
 *
 * Based on Mastercard Contactless Specifications for Payment Systems
 * (M/Chip Requirements for Contact and Contactless)
 */
data class MastercardKernelConfig(
    /**
     * Terminal Type (tag 9F35)
     */
    val terminalType: Byte = 0x22,

    /**
     * Terminal Capabilities (tag 9F33) - 3 bytes
     */
    val terminalCapabilities: ByteArray = "E0F0C8".hexToByteArray(),

    /**
     * Additional Terminal Capabilities (tag 9F40) - 5 bytes
     */
    val additionalTerminalCapabilities: ByteArray = "FF00F0A001".hexToByteArray(),

    /**
     * Terminal Country Code (tag 9F1A) - 2 bytes
     */
    val terminalCountryCode: ByteArray = "0840".hexToByteArray(),

    /**
     * Transaction Currency Code (tag 5F2A) - 2 bytes
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
     * Reader Contactless Floor Limit (DF8123)
     */
    val contactlessFloorLimit: Long = 0,

    /**
     * Reader CVM Required Limit (DF8126)
     * Transactions above this require CVM
     */
    val cvmRequiredLimit: Long = 2500,

    /**
     * Reader Contactless Transaction Limit - No On-device CVM (DF8124)
     */
    val contactlessTransactionLimitNoCvm: Long = 10000,

    /**
     * Reader Contactless Transaction Limit - On-device CVM (DF8125)
     */
    val contactlessTransactionLimitOnDeviceCvm: Long = 100000,

    /**
     * Terminal Floor Limit (9F1B) - 4 bytes
     */
    val terminalFloorLimit: Long = 0,

    /**
     * Terminal Action Codes
     */
    val tacDenial: ByteArray = "0000000000".hexToByteArray(),
    val tacOnline: ByteArray = "F850ACF800".hexToByteArray(),
    val tacDefault: ByteArray = "F850ACF800".hexToByteArray(),

    /**
     * Kernel Configuration (DF811B)
     * Bit 8: On device cardholder verification supported
     * Bit 7: Relay resistance protocol supported
     */
    val kernelConfiguration: Byte = 0x80.toByte(),

    /**
     * Mag Stripe CVM Capability - CVM Required (DF811E)
     */
    val magStripeCvmCapabilityCvmRequired: Byte = 0x10,

    /**
     * Mag Stripe CVM Capability - No CVM Required (DF812C)
     */
    val magStripeCvmCapabilityNoCvmRequired: Byte = 0x00,

    /**
     * Card Data Input Capability (DF8117)
     */
    val cardDataInputCapability: Byte = 0x60.toByte(),

    /**
     * Security Capability (DF8118)
     */
    val securityCapability: Byte = 0x08,

    /**
     * Maximum Relay Resistance Grace Period (DF8133)
     */
    val maxRelayResistanceGracePeriod: Int = 1000,

    /**
     * Minimum Relay Resistance Grace Period (DF8132)
     */
    val minRelayResistanceGracePeriod: Int = 500,

    /**
     * Terminal Expected Transmission Time for RR C-APDU (DF8134)
     */
    val terminalExpectedTransmissionTimeC: Int = 100,

    /**
     * Terminal Expected Transmission Time for RR R-APDU (DF8135)
     */
    val terminalExpectedTransmissionTimeR: Int = 100,

    /**
     * Relay Resistance Accuracy Threshold (DF8136)
     */
    val relayResistanceAccuracyThreshold: Int = 150,

    /**
     * Relay Resistance Transmission Time Mismatch Threshold (DF8137)
     */
    val relayResistanceTransmissionTimeMismatchThreshold: Int = 100
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MastercardKernelConfig) return false
        return merchantIdentifier == other.merchantIdentifier &&
                terminalIdentification == other.terminalIdentification
    }

    override fun hashCode(): Int {
        var result = merchantIdentifier.hashCode()
        result = 31 * result + terminalIdentification.hashCode()
        return result
    }
}

/**
 * Mastercard Outcome types
 */
enum class MastercardOutcome {
    APPROVED,
    DECLINED,
    ONLINE_REQUEST,
    TRY_ANOTHER_INTERFACE,
    END_APPLICATION,
    SELECT_NEXT,
    TRY_AGAIN
}

/**
 * Mastercard CVM types
 */
enum class MastercardCvmType(val code: Byte) {
    NO_CVM(0x00),
    OBTAIN_SIGNATURE(0x1E),
    ONLINE_PIN(0x02),
    CONFIRMATION_CODE_VERIFIED(0x03),
    NO_CVM_REQUIRED(0x1F);

    companion object {
        fun fromCode(code: Byte): MastercardCvmType {
            return entries.find { it.code == code } ?: NO_CVM
        }
    }
}

/**
 * Mastercard-specific tags
 */
object MastercardTags {
    const val PAYPASS_MAG_STRIPE_APP_VERSION = "9F6D"
    const val KERNEL_IDENTIFIER = "9F2A"
    const val CARD_AUTH_RELATED_DATA = "9F69"
    const val DS_SUMMARY_1 = "9F7D"
    const val DS_SUMMARY_2 = "DF8101"
    const val DS_SUMMARY_3 = "DF8102"
    const val POS_CARDHOLDER_INTERACTION_INFO = "DF4B"
    const val THIRD_PARTY_DATA = "9F6E"
    const val UDOL = "9F69"
}

/**
 * Type alias for backward compatibility with TransactionCoordinator
 */
typealias MastercardKernelConfiguration = MastercardKernelConfig
