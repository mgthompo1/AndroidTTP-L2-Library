package com.atlas.softpos.core.apdu

import com.atlas.softpos.core.tlv.TlvTag
import com.atlas.softpos.core.types.hexToByteArray

/**
 * EMV Command Set for Contactless Transactions
 *
 * Reference: EMV Contactless Book B - Entry Point Specification
 */
object EmvCommands {

    // Instruction bytes
    private const val INS_SELECT: Byte = 0xA4.toByte()
    private const val INS_READ_RECORD: Byte = 0xB2.toByte()
    private const val INS_GET_PROCESSING_OPTIONS: Byte = 0xA8.toByte()
    private const val INS_GENERATE_AC: Byte = 0xAE.toByte()
    private const val INS_GET_DATA: Byte = 0xCA.toByte()
    private const val INS_GET_RESPONSE: Byte = 0xC0.toByte()
    private const val INS_VERIFY: Byte = 0x20.toByte()
    private const val INS_COMPUTE_CRYPTOGRAPHIC_CHECKSUM: Byte = 0x2A.toByte()
    private const val INS_EXCHANGE_RELAY_RESISTANCE_DATA: Byte = 0xEA.toByte()

    /**
     * SELECT command for PPSE (Proximity Payment System Environment)
     *
     * The PPSE is the entry point for contactless payment applications.
     * Returns a list of available payment applications on the card.
     */
    fun selectPpse(): CommandApdu {
        return CommandApdu(
            cla = 0x00,
            ins = INS_SELECT,
            p1 = 0x04,  // Select by DF name
            p2 = 0x00,  // First or only occurrence
            data = "2PAY.SYS.DDF01".toByteArray(Charsets.US_ASCII),
            le = 0  // Return all available data
        )
    }

    /**
     * SELECT command for a specific Application Identifier (AID)
     *
     * @param aid The AID to select (e.g., A0000000031010 for Visa Debit)
     * @param firstOccurrence If true, select first occurrence; if false, select next
     */
    fun selectApplication(aid: ByteArray, firstOccurrence: Boolean = true): CommandApdu {
        return CommandApdu(
            cla = 0x00,
            ins = INS_SELECT,
            p1 = 0x04,  // Select by DF name
            p2 = if (firstOccurrence) 0x00 else 0x02,
            data = aid,
            le = 0
        )
    }

    fun selectApplication(aidHex: String, firstOccurrence: Boolean = true): CommandApdu {
        return selectApplication(aidHex.hexToByteArray(), firstOccurrence)
    }

    /**
     * GET PROCESSING OPTIONS (GPO) command
     *
     * Initiates the transaction by providing terminal data (PDOL) to the card.
     * Returns the Application Interchange Profile (AIP) and
     * Application File Locator (AFL).
     *
     * @param pdolData The PDOL data built according to the card's PDOL template
     */
    fun getProcessingOptions(pdolData: ByteArray): CommandApdu {
        // GPO data is wrapped in a command template (tag 83)
        val data = if (pdolData.isEmpty()) {
            byteArrayOf(0x83.toByte(), 0x00)
        } else {
            byteArrayOf(0x83.toByte(), pdolData.size.toByte()) + pdolData
        }

        return CommandApdu(
            cla = 0x80.toByte(),  // Proprietary class
            ins = INS_GET_PROCESSING_OPTIONS,
            p1 = 0x00,
            p2 = 0x00,
            data = data,
            le = 0
        )
    }

    /**
     * READ RECORD command
     *
     * Reads a record from the card's data files.
     *
     * @param recordNumber The record number (1-254)
     * @param sfi The Short File Identifier (1-30)
     */
    fun readRecord(recordNumber: Int, sfi: Int): CommandApdu {
        require(recordNumber in 1..254) { "Record number must be 1-254" }
        require(sfi in 1..30) { "SFI must be 1-30" }

        return CommandApdu(
            cla = 0x00,
            ins = INS_READ_RECORD,
            p1 = recordNumber.toByte(),
            p2 = ((sfi shl 3) or 0x04).toByte(),  // SFI in bits 8-4, 0x04 = P1 is record number
            le = 0
        )
    }

    /**
     * GENERATE APPLICATION CRYPTOGRAM (GENERATE AC) command
     *
     * Requests the card to generate a cryptogram for transaction authorization.
     *
     * @param cryptogramType The type of cryptogram requested (ARQC, TC, or AAC)
     * @param cdolData The CDOL data (Card Risk Management Data Object List)
     * @param cda If true, request Combined Data Authentication
     */
    fun generateAc(
        cryptogramType: CryptogramType,
        cdolData: ByteArray,
        cda: Boolean = false
    ): CommandApdu {
        val p1 = when (cryptogramType) {
            CryptogramType.AAC -> 0x00    // Application Authentication Cryptogram (decline)
            CryptogramType.TC -> 0x40     // Transaction Certificate (offline approval)
            CryptogramType.ARQC -> 0x80   // Authorization Request Cryptogram (online auth)
        }.let { if (cda) it or 0x10 else it }  // Set CDA bit if requested

        return CommandApdu(
            cla = 0x80.toByte(),
            ins = INS_GENERATE_AC,
            p1 = p1.toByte(),
            p2 = 0x00,
            data = cdolData,
            le = 0
        )
    }

    /**
     * GET DATA command
     *
     * Retrieves a specific data object from the card.
     *
     * @param tag The tag of the data object to retrieve
     */
    fun getData(tag: TlvTag): CommandApdu {
        val tagBytes = tag.bytes
        return when (tagBytes.size) {
            1 -> CommandApdu(
                cla = 0x80.toByte(),
                ins = INS_GET_DATA,
                p1 = 0x00,
                p2 = tagBytes[0],
                le = 0
            )
            2 -> CommandApdu(
                cla = 0x80.toByte(),
                ins = INS_GET_DATA,
                p1 = tagBytes[0],
                p2 = tagBytes[1],
                le = 0
            )
            else -> throw IllegalArgumentException("Tag must be 1 or 2 bytes")
        }
    }

    /**
     * GET RESPONSE command
     *
     * Used to retrieve additional data after a 61XX response.
     *
     * @param length The expected response length (from SW2 of 61XX response)
     */
    fun getResponse(length: Int): CommandApdu {
        return CommandApdu(
            cla = 0x00,
            ins = INS_GET_RESPONSE,
            p1 = 0x00,
            p2 = 0x00,
            le = length
        )
    }

    /**
     * VERIFY command for PIN verification (offline PIN)
     *
     * @param pinBlock The encrypted PIN block
     */
    fun verifyPin(pinBlock: ByteArray): CommandApdu {
        return CommandApdu(
            cla = 0x00,
            ins = INS_VERIFY,
            p1 = 0x00,
            p2 = 0x80.toByte(),  // Plaintext PIN
            data = pinBlock
        )
    }

    /**
     * COMPUTE CRYPTOGRAPHIC CHECKSUM command (Visa specific)
     *
     * Used for fDDA (fast Dynamic Data Authentication) in Visa contactless.
     *
     * @param data The data to compute checksum over
     */
    fun computeCryptographicChecksum(data: ByteArray): CommandApdu {
        return CommandApdu(
            cla = 0x80.toByte(),
            ins = INS_COMPUTE_CRYPTOGRAPHIC_CHECKSUM,
            p1 = 0x8E.toByte(),
            p2 = 0x80.toByte(),
            data = data,
            le = 0
        )
    }

    /**
     * EXCHANGE RELAY RESISTANCE DATA command (EMV 3.1+)
     *
     * Used for relay attack resistance timing measurements.
     */
    fun exchangeRelayResistanceData(
        terminalRelayResistanceData: ByteArray
    ): CommandApdu {
        return CommandApdu(
            cla = 0x80.toByte(),
            ins = INS_EXCHANGE_RELAY_RESISTANCE_DATA,
            p1 = 0x00,
            p2 = 0x00,
            data = terminalRelayResistanceData,
            le = 0
        )
    }

    /**
     * Types of cryptograms that can be requested via GENERATE AC
     */
    enum class CryptogramType {
        /**
         * Application Authentication Cryptogram
         * Indicates the transaction should be declined
         */
        AAC,

        /**
         * Transaction Certificate
         * Indicates the transaction is approved offline
         */
        TC,

        /**
         * Authorization Request Cryptogram
         * Indicates the transaction should go online for authorization
         */
        ARQC
    }
}

/**
 * Well-known Application Identifiers (AIDs)
 */
object KnownAids {
    // Visa
    val VISA_CREDIT = "A0000000031010".hexToByteArray()
    val VISA_DEBIT = "A0000000032010".hexToByteArray()
    val VISA_ELECTRON = "A0000000032020".hexToByteArray()
    val VISA_VPAY = "A0000000032020".hexToByteArray()
    val VISA_PLUS = "A0000000038010".hexToByteArray()
    val VISA_US_DEBIT = "A0000000980840".hexToByteArray()

    // Mastercard
    val MASTERCARD_CREDIT = "A0000000041010".hexToByteArray()
    val MASTERCARD_DEBIT = "A0000000042010".hexToByteArray()
    val MAESTRO = "A0000000043060".hexToByteArray()
    val MASTERCARD_US_DEBIT = "A0000000042203".hexToByteArray()

    // American Express
    val AMEX = "A00000002501".hexToByteArray()

    // Discover
    val DISCOVER = "A0000001523010".hexToByteArray()
    val DISCOVER_ZIP = "A0000003241010".hexToByteArray()

    // JCB
    val JCB = "A0000000651010".hexToByteArray()

    // UnionPay
    val UNIONPAY_CREDIT = "A000000333010101".hexToByteArray()
    val UNIONPAY_DEBIT = "A000000333010102".hexToByteArray()

    // Interac (Canada)
    val INTERAC = "A0000002771010".hexToByteArray()

    // EFTPOS (Australia)
    val EFTPOS = "A000000384".hexToByteArray()

    /**
     * Get the card brand name from an AID based on RID (first 5 bytes)
     */
    fun getBrandName(aid: ByteArray): String {
        if (aid.size < 5) return "Unknown"

        val rid = aid.copyOfRange(0, 5)
        return when {
            rid.contentEquals(RID_VISA) -> "Visa"
            rid.contentEquals(RID_MASTERCARD) -> "Mastercard"
            rid.contentEquals(RID_AMEX) -> "American Express"
            rid.contentEquals(RID_DISCOVER) -> "Discover"
            rid.contentEquals(RID_DISCOVER_ZIP) -> "Discover"
            rid.contentEquals(RID_JCB) -> "JCB"
            rid.contentEquals(RID_UNIONPAY) -> "UnionPay"
            rid.contentEquals(RID_INTERAC) -> "Interac"
            rid.contentEquals(RID_EFTPOS) -> "EFTPOS"
            else -> "Unknown"
        }
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }

    // Registered Application Provider Identifiers (RIDs) - 5 bytes each
    private val RID_VISA = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x03)
    private val RID_MASTERCARD = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x04)
    private val RID_AMEX = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x25)
    private val RID_DISCOVER = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x01, 0x52)
    private val RID_DISCOVER_ZIP = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x24)
    private val RID_JCB = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x65)
    private val RID_UNIONPAY = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x33)
    private val RID_INTERAC = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x02, 0x77)
    private val RID_EFTPOS = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x03, 0x84.toByte())
}
