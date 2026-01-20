package com.atlas.softpos.receipt

import java.text.SimpleDateFormat
import java.util.*

/**
 * EMV Receipt Data Builder
 *
 * Builds receipt data compliant with payment network requirements:
 * - Visa: VOP (Visa Operating Regulations)
 * - Mastercard: Chargeback Guide requirements
 * - EMVCo: Book 4 receipt requirements
 *
 * Required Receipt Fields (per card network rules):
 * - Merchant name and location
 * - Date and time
 * - Transaction amount
 * - Card type/AID
 * - Masked PAN (first 6, last 4)
 * - Authorization code (if online approved)
 * - ATC (Application Transaction Counter)
 * - TVR (Terminal Verification Results)
 * - TSI (Transaction Status Information)
 * - Cryptogram type (TC/ARQC/AAC)
 * - CVM method used
 *
 * Optional but recommended:
 * - Application label
 * - Cardholder name (if available)
 * - AID
 * - Issuer Application Data
 */
class ReceiptDataBuilder {

    private val fields = mutableMapOf<ReceiptField, String>()
    private val emvData = mutableMapOf<String, String>()

    // ==================== MERCHANT DATA ====================

    fun merchantName(name: String) = apply {
        fields[ReceiptField.MERCHANT_NAME] = name
    }

    fun merchantId(id: String) = apply {
        fields[ReceiptField.MERCHANT_ID] = id
    }

    fun merchantAddress(address: String) = apply {
        fields[ReceiptField.MERCHANT_ADDRESS] = address
    }

    fun merchantCity(city: String) = apply {
        fields[ReceiptField.MERCHANT_CITY] = city
    }

    fun merchantCountry(country: String) = apply {
        fields[ReceiptField.MERCHANT_COUNTRY] = country
    }

    fun terminalId(id: String) = apply {
        fields[ReceiptField.TERMINAL_ID] = id
    }

    // ==================== TRANSACTION DATA ====================

    fun transactionDate(date: Date) = apply {
        fields[ReceiptField.TRANSACTION_DATE] = SimpleDateFormat("MM/dd/yyyy", Locale.US).format(date)
    }

    fun transactionTime(date: Date) = apply {
        fields[ReceiptField.TRANSACTION_TIME] = SimpleDateFormat("HH:mm:ss", Locale.US).format(date)
    }

    fun transactionDateTime(date: Date) = apply {
        transactionDate(date)
        transactionTime(date)
    }

    fun transactionType(type: TransactionType) = apply {
        fields[ReceiptField.TRANSACTION_TYPE] = type.displayName
    }

    fun amount(amountCents: Long, currencySymbol: String = "$") = apply {
        val dollars = amountCents / 100
        val cents = amountCents % 100
        fields[ReceiptField.AMOUNT] = "$currencySymbol$dollars.${cents.toString().padStart(2, '0')}"
        fields[ReceiptField.AMOUNT_NUMERIC] = amountCents.toString()
    }

    fun tipAmount(amountCents: Long, currencySymbol: String = "$") = apply {
        if (amountCents > 0) {
            val dollars = amountCents / 100
            val cents = amountCents % 100
            fields[ReceiptField.TIP_AMOUNT] = "$currencySymbol$dollars.${cents.toString().padStart(2, '0')}"
        }
    }

    fun totalAmount(amountCents: Long, currencySymbol: String = "$") = apply {
        val dollars = amountCents / 100
        val cents = amountCents % 100
        fields[ReceiptField.TOTAL_AMOUNT] = "$currencySymbol$dollars.${cents.toString().padStart(2, '0')}"
    }

    fun cashbackAmount(amountCents: Long, currencySymbol: String = "$") = apply {
        if (amountCents > 0) {
            val dollars = amountCents / 100
            val cents = amountCents % 100
            fields[ReceiptField.CASHBACK_AMOUNT] = "$currencySymbol$dollars.${cents.toString().padStart(2, '0')}"
        }
    }

    fun currencyCode(code: String) = apply {
        fields[ReceiptField.CURRENCY_CODE] = code
    }

    // ==================== CARD DATA ====================

    fun maskedPan(pan: String) = apply {
        // Ensure proper masking: show first 6 and last 4
        val cleanPan = pan.replace("[^0-9*X]".toRegex(), "")
        val masked = if (cleanPan.length >= 13 && !cleanPan.contains("*") && !cleanPan.contains("X")) {
            "${cleanPan.take(6)}${"*".repeat(cleanPan.length - 10)}${cleanPan.takeLast(4)}"
        } else {
            cleanPan // Already masked
        }
        fields[ReceiptField.MASKED_PAN] = formatPanForDisplay(masked)
    }

    fun cardholderName(name: String) = apply {
        if (name.isNotBlank()) {
            fields[ReceiptField.CARDHOLDER_NAME] = name.trim()
        }
    }

    fun cardType(type: CardType) = apply {
        fields[ReceiptField.CARD_TYPE] = type.displayName
    }

    fun cardTypeFromAid(aid: String) = apply {
        val type = when {
            aid.startsWith("A000000003") -> CardType.VISA
            aid.startsWith("A000000004") -> CardType.MASTERCARD
            aid.startsWith("A000000025") -> CardType.AMEX
            aid.startsWith("A000000152") -> CardType.DISCOVER
            aid.startsWith("A000000333") -> CardType.UNIONPAY
            aid.startsWith("A000000065") -> CardType.JCB
            else -> CardType.UNKNOWN
        }
        fields[ReceiptField.CARD_TYPE] = type.displayName
    }

    fun applicationLabel(label: String) = apply {
        if (label.isNotBlank()) {
            fields[ReceiptField.APPLICATION_LABEL] = label.trim()
        }
    }

    fun expirationDate(expiry: String) = apply {
        // Format: YYMM or MMYY - display as MM/YY
        val formatted = if (expiry.length == 4) {
            "${expiry.substring(2, 4)}/${expiry.substring(0, 2)}"
        } else {
            expiry
        }
        fields[ReceiptField.EXPIRATION_DATE] = formatted
    }

    fun entryMode(mode: EntryMode) = apply {
        fields[ReceiptField.ENTRY_MODE] = mode.displayName
    }

    // ==================== AUTHORIZATION DATA ====================

    fun authorizationCode(code: String) = apply {
        if (code.isNotBlank()) {
            fields[ReceiptField.AUTHORIZATION_CODE] = code
        }
    }

    fun responseCode(code: String) = apply {
        fields[ReceiptField.RESPONSE_CODE] = code
    }

    fun approvalStatus(approved: Boolean) = apply {
        fields[ReceiptField.APPROVAL_STATUS] = if (approved) "APPROVED" else "DECLINED"
    }

    fun referenceNumber(refNum: String) = apply {
        fields[ReceiptField.REFERENCE_NUMBER] = refNum
    }

    fun invoiceNumber(invoice: String) = apply {
        fields[ReceiptField.INVOICE_NUMBER] = invoice
    }

    fun batchNumber(batch: String) = apply {
        fields[ReceiptField.BATCH_NUMBER] = batch
    }

    fun sequenceNumber(seq: String) = apply {
        fields[ReceiptField.SEQUENCE_NUMBER] = seq
    }

    // ==================== EMV DATA ====================

    fun aid(aid: String) = apply {
        emvData["AID"] = aid
        fields[ReceiptField.AID] = aid
    }

    fun applicationCryptogram(ac: String) = apply {
        emvData["AC"] = ac
    }

    fun cryptogramType(type: CryptogramType) = apply {
        emvData["CID"] = type.name
        fields[ReceiptField.CRYPTOGRAM_TYPE] = type.displayName
    }

    fun atc(atc: String) = apply {
        emvData["ATC"] = atc
        fields[ReceiptField.ATC] = atc
    }

    fun tvr(tvr: String) = apply {
        emvData["TVR"] = tvr
        fields[ReceiptField.TVR] = tvr
    }

    fun tsi(tsi: String) = apply {
        emvData["TSI"] = tsi
    }

    fun cvmResults(cvmResults: String) = apply {
        emvData["CVM_RESULTS"] = cvmResults
        fields[ReceiptField.CVM_METHOD] = parseCvmMethod(cvmResults)
    }

    fun iad(iad: String) = apply {
        emvData["IAD"] = iad
    }

    fun unpredictableNumber(un: String) = apply {
        emvData["UN"] = un
    }

    // ==================== CVM ====================

    fun cvmMethod(method: CvmMethodType) = apply {
        fields[ReceiptField.CVM_METHOD] = method.displayName
    }

    fun signatureRequired(required: Boolean) = apply {
        fields[ReceiptField.SIGNATURE_REQUIRED] = if (required) "YES" else "NO"
    }

    fun pinVerified(verified: Boolean) = apply {
        fields[ReceiptField.PIN_VERIFIED] = if (verified) "VERIFIED" else ""
    }

    // ==================== BUILD ====================

    /**
     * Build the receipt data
     */
    fun build(): ReceiptData {
        // Validate required fields
        val missingFields = REQUIRED_FIELDS.filter { !fields.containsKey(it) }
        if (missingFields.isNotEmpty()) {
            throw IllegalStateException("Missing required receipt fields: $missingFields")
        }

        return ReceiptData(
            fields = fields.toMap(),
            emvData = emvData.toMap(),
            timestamp = System.currentTimeMillis()
        )
    }

    /**
     * Build without validation (for partial receipts)
     */
    fun buildPartial(): ReceiptData {
        return ReceiptData(
            fields = fields.toMap(),
            emvData = emvData.toMap(),
            timestamp = System.currentTimeMillis()
        )
    }

    // ==================== HELPERS ====================

    private fun formatPanForDisplay(pan: String): String {
        // Format as groups of 4: **** **** **** 1234
        return pan.chunked(4).joinToString(" ")
    }

    private fun parseCvmMethod(cvmResults: String): String {
        if (cvmResults.length < 2) return "UNKNOWN"

        return when (cvmResults.substring(0, 2).uppercase()) {
            "00" -> "NO CVM"
            "01" -> "OFFLINE PIN"
            "02" -> "ONLINE PIN"
            "1E" -> "SIGNATURE"
            "1F" -> "NO CVM REQUIRED"
            "2F" -> "CDCVM"
            "42" -> "ONLINE PIN"
            else -> "OTHER"
        }
    }

    companion object {
        private val REQUIRED_FIELDS = listOf(
            ReceiptField.MERCHANT_NAME,
            ReceiptField.TRANSACTION_DATE,
            ReceiptField.TRANSACTION_TIME,
            ReceiptField.AMOUNT,
            ReceiptField.MASKED_PAN,
            ReceiptField.APPROVAL_STATUS
        )

        /**
         * Create builder from authorization data map
         */
        fun fromAuthData(authData: Map<String, String>): ReceiptDataBuilder {
            return ReceiptDataBuilder().apply {
                authData["maskedPan"]?.let { maskedPan(it) }
                authData["aid"]?.let {
                    aid(it)
                    cardTypeFromAid(it)
                }
                authData["cryptogram"]?.let { applicationCryptogram(it) }
                authData["atc"]?.let { atc(it) }
                authData["tvr"]?.let { tvr(it) }
                authData["cvmResults"]?.let { cvmResults(it) }
                authData["iad"]?.let { iad(it) }
            }
        }
    }
}

// ==================== DATA CLASSES ====================

/**
 * Built receipt data
 */
data class ReceiptData(
    val fields: Map<ReceiptField, String>,
    val emvData: Map<String, String>,
    val timestamp: Long
) {
    /**
     * Get a field value
     */
    operator fun get(field: ReceiptField): String? = fields[field]

    /**
     * Check if field exists
     */
    fun has(field: ReceiptField): Boolean = fields.containsKey(field)

    /**
     * Format as plain text receipt
     */
    fun toPlainText(width: Int = 40): String {
        val sb = StringBuilder()
        val separator = "=".repeat(width)
        val dashes = "-".repeat(width)

        // Header
        sb.appendLine(centerText(fields[ReceiptField.MERCHANT_NAME] ?: "", width))
        fields[ReceiptField.MERCHANT_ADDRESS]?.let { sb.appendLine(centerText(it, width)) }
        fields[ReceiptField.MERCHANT_CITY]?.let { sb.appendLine(centerText(it, width)) }
        sb.appendLine(separator)

        // Transaction info
        sb.appendLine("DATE: ${fields[ReceiptField.TRANSACTION_DATE]}  TIME: ${fields[ReceiptField.TRANSACTION_TIME]}")
        fields[ReceiptField.TERMINAL_ID]?.let { sb.appendLine("TERMINAL: $it") }
        fields[ReceiptField.REFERENCE_NUMBER]?.let { sb.appendLine("REF: $it") }
        sb.appendLine(dashes)

        // Card info
        sb.appendLine("CARD: ${fields[ReceiptField.MASKED_PAN]}")
        fields[ReceiptField.CARD_TYPE]?.let { sb.appendLine("TYPE: $it") }
        fields[ReceiptField.APPLICATION_LABEL]?.let { sb.appendLine("APP: $it") }
        fields[ReceiptField.ENTRY_MODE]?.let { sb.appendLine("ENTRY: $it") }
        sb.appendLine(dashes)

        // Transaction type and amounts
        fields[ReceiptField.TRANSACTION_TYPE]?.let { sb.appendLine(it) }
        sb.appendLine()
        sb.appendLine(formatAmountLine("AMOUNT:", fields[ReceiptField.AMOUNT] ?: "", width))
        fields[ReceiptField.TIP_AMOUNT]?.let { sb.appendLine(formatAmountLine("TIP:", it, width)) }
        fields[ReceiptField.CASHBACK_AMOUNT]?.let { sb.appendLine(formatAmountLine("CASHBACK:", it, width)) }
        fields[ReceiptField.TOTAL_AMOUNT]?.let {
            sb.appendLine(dashes)
            sb.appendLine(formatAmountLine("TOTAL:", it, width))
        }
        sb.appendLine(separator)

        // Status
        val status = fields[ReceiptField.APPROVAL_STATUS] ?: ""
        sb.appendLine(centerText("*** $status ***", width))
        fields[ReceiptField.AUTHORIZATION_CODE]?.let { sb.appendLine(centerText("AUTH: $it", width)) }
        sb.appendLine()

        // CVM
        fields[ReceiptField.CVM_METHOD]?.let { sb.appendLine("CVM: $it") }
        if (fields[ReceiptField.SIGNATURE_REQUIRED] == "YES") {
            sb.appendLine()
            sb.appendLine("X${" ".repeat(width - 2)}")
            sb.appendLine("-".repeat(width))
            sb.appendLine(centerText("CARDHOLDER SIGNATURE", width))
        }

        // EMV data (smaller print)
        if (emvData.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine(dashes)
            emvData["AID"]?.let { sb.appendLine("AID: $it") }
            emvData["TVR"]?.let { sb.appendLine("TVR: $it") }
            emvData["ATC"]?.let { sb.appendLine("ATC: $it") }
            fields[ReceiptField.CRYPTOGRAM_TYPE]?.let { sb.appendLine("CRYPTO: $it") }
        }

        sb.appendLine()
        sb.appendLine(centerText("THANK YOU", width))

        return sb.toString()
    }

    /**
     * Convert to JSON-like map for API transmission
     */
    fun toMap(): Map<String, Any> {
        return mapOf(
            "fields" to fields.mapKeys { it.key.name },
            "emvData" to emvData,
            "timestamp" to timestamp
        )
    }

    private fun centerText(text: String, width: Int): String {
        if (text.length >= width) return text
        val padding = (width - text.length) / 2
        return " ".repeat(padding) + text
    }

    private fun formatAmountLine(label: String, amount: String, width: Int): String {
        val spaces = width - label.length - amount.length
        return if (spaces > 0) {
            "$label${" ".repeat(spaces)}$amount"
        } else {
            "$label $amount"
        }
    }
}

/**
 * Receipt fields
 */
enum class ReceiptField {
    // Merchant
    MERCHANT_NAME,
    MERCHANT_ID,
    MERCHANT_ADDRESS,
    MERCHANT_CITY,
    MERCHANT_COUNTRY,
    TERMINAL_ID,

    // Transaction
    TRANSACTION_DATE,
    TRANSACTION_TIME,
    TRANSACTION_TYPE,
    AMOUNT,
    AMOUNT_NUMERIC,
    TIP_AMOUNT,
    TOTAL_AMOUNT,
    CASHBACK_AMOUNT,
    CURRENCY_CODE,

    // Card
    MASKED_PAN,
    CARDHOLDER_NAME,
    CARD_TYPE,
    APPLICATION_LABEL,
    EXPIRATION_DATE,
    ENTRY_MODE,

    // Authorization
    AUTHORIZATION_CODE,
    RESPONSE_CODE,
    APPROVAL_STATUS,
    REFERENCE_NUMBER,
    INVOICE_NUMBER,
    BATCH_NUMBER,
    SEQUENCE_NUMBER,

    // EMV
    AID,
    ATC,
    TVR,
    CRYPTOGRAM_TYPE,
    CVM_METHOD,

    // CVM
    SIGNATURE_REQUIRED,
    PIN_VERIFIED
}

/**
 * Transaction types
 */
enum class TransactionType(val displayName: String) {
    PURCHASE("PURCHASE"),
    REFUND("REFUND"),
    VOID("VOID"),
    PRE_AUTH("PRE-AUTHORIZATION"),
    COMPLETION("COMPLETION"),
    BALANCE_INQUIRY("BALANCE INQUIRY"),
    CASH_ADVANCE("CASH ADVANCE")
}

/**
 * Card types
 */
enum class CardType(val displayName: String) {
    VISA("VISA"),
    MASTERCARD("MASTERCARD"),
    AMEX("AMERICAN EXPRESS"),
    DISCOVER("DISCOVER"),
    UNIONPAY("UNIONPAY"),
    JCB("JCB"),
    UNKNOWN("CARD")
}

/**
 * Entry modes
 */
enum class EntryMode(val displayName: String) {
    CONTACTLESS("CONTACTLESS"),
    CHIP("CHIP"),
    SWIPE("SWIPE"),
    MANUAL("MANUAL"),
    FALLBACK("FALLBACK")
}

/**
 * Cryptogram types
 */
enum class CryptogramType(val displayName: String) {
    TC("TC (OFFLINE APPROVED)"),
    ARQC("ARQC (ONLINE)"),
    AAC("AAC (DECLINED)"),
    AAR("AAR (REFERRAL)")
}

/**
 * CVM method types
 */
enum class CvmMethodType(val displayName: String) {
    NO_CVM("NO CVM"),
    SIGNATURE("SIGNATURE"),
    ONLINE_PIN("ONLINE PIN"),
    OFFLINE_PIN("OFFLINE PIN"),
    CDCVM("MOBILE VERIFICATION"),
    FAILED("CVM FAILED")
}
