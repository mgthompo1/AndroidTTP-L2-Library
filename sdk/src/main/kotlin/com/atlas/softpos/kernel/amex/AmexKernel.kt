package com.atlas.softpos.kernel.amex

import com.atlas.softpos.core.apdu.EmvCommands
import com.atlas.softpos.core.tlv.*
import com.atlas.softpos.core.types.*
import com.atlas.softpos.kernel.common.CardTransceiver
import com.atlas.softpos.kernel.common.SelectedApplication
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * American Express ExpressPay Kernel (Kernel 4)
 *
 * Implements EMV Contactless Book C-4 - American Express Kernel Specification
 *
 * Supports:
 * - EMV mode transactions
 * - Mag Stripe mode (legacy)
 * - Enhanced Contactless Reader (ECR) capabilities
 */
class AmexKernel(
    private val transceiver: CardTransceiver,
    private val config: AmexKernelConfig = AmexKernelConfig()
) {
    private val transactionData = mutableMapOf<String, ByteArray>()
    private val cardData = mutableMapOf<String, ByteArray>()

    /**
     * Process an American Express contactless transaction
     */
    suspend fun processTransaction(
        application: SelectedApplication,
        transaction: AmexTransaction
    ): AmexKernelResult {
        try {
            initializeTransactionData(transaction)

            // GET PROCESSING OPTIONS
            val gpoResult = performGpo(application.pdol, transaction)
            if (gpoResult is AmexContactGpoResult.Error) {
                return AmexKernelResult.Error(gpoResult.message)
            }
            val gpoData = (gpoResult as AmexContactGpoResult.Success)

            // Determine path based on AIP
            val isEmvMode = gpoData.aip.isEmvModeSupported()

            return if (isEmvMode) {
                processEmvTransaction(gpoData, transaction)
            } else {
                processMagStripeTransaction(gpoData, transaction)
            }

        } catch (e: Exception) {
            return AmexKernelResult.Error("Kernel error: ${e.message}")
        }
    }

    private fun initializeTransactionData(transaction: AmexTransaction) {
        transactionData.clear()
        cardData.clear()

        transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] = transaction.amount.toBcd(6)
        transactionData[EmvTags.AMOUNT_OTHER.hex] = (transaction.cashbackAmount ?: 0L).toBcd(6)
        transactionData[EmvTags.TRANSACTION_TYPE.hex] = byteArrayOf(transaction.type)

        val date = LocalDate.now()
        transactionData[EmvTags.TRANSACTION_DATE.hex] = date.format(
            DateTimeFormatter.ofPattern("yyMMdd")
        ).hexToByteArray()

        val time = LocalTime.now()
        transactionData[EmvTags.TRANSACTION_TIME.hex] = time.format(
            DateTimeFormatter.ofPattern("HHmmss")
        ).hexToByteArray()

        val unpredictableNumber = ByteArray(4)
        SecureRandom().nextBytes(unpredictableNumber)
        transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] = unpredictableNumber

        transactionData[EmvTags.TERMINAL_COUNTRY_CODE.hex] = config.terminalCountryCode
        transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] = config.transactionCurrencyCode
        transactionData[EmvTags.TERMINAL_TYPE.hex] = byteArrayOf(config.terminalType)
        transactionData[EmvTags.TERMINAL_CAPABILITIES.hex] = config.terminalCapabilities
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = ByteArray(5)

        // Amex specific: Enhanced Contactless Reader Capabilities (9F6E)
        transactionData["9F6E"] = config.enhancedContactlessReaderCapabilities
    }

    private suspend fun performGpo(pdol: ByteArray?, transaction: AmexTransaction): AmexGpoResult {
        val pdolData = buildPdolData(pdol)
        val command = EmvCommands.getProcessingOptions(pdolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return AmexContactGpoResult.Error("GPO failed: ${response.statusDescription}")
        }

        return parseGpoResponse(response.data)
    }

    private fun buildPdolData(pdol: ByteArray?): ByteArray {
        if (pdol == null || pdol.isEmpty()) return ByteArray(0)

        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < pdol.size) {
            val (tag, tagLength) = TlvTag.parse(pdol, offset)
            offset += tagLength
            val length = pdol[offset].toInt() and 0xFF
            offset++

            val data = transactionData[tag.hex] ?: ByteArray(length)
            val paddedData = when {
                data.size == length -> data
                data.size < length -> data + ByteArray(length - data.size)
                else -> data.copyOfRange(0, length)
            }
            result.addAll(paddedData.toList())
        }

        return result.toByteArray()
    }

    private fun parseGpoResponse(data: ByteArray): AmexGpoResult {
        val tlvList = TlvParser.parse(data)
        if (tlvList.isEmpty()) return AmexContactGpoResult.Error("Empty GPO response")

        val firstTlv = tlvList[0]

        return when (firstTlv.tag.hex) {
            "80" -> {
                if (firstTlv.value.size < 2) {
                    return AmexContactGpoResult.Error("Invalid Format 1 response")
                }
                val aip = AmexAip(firstTlv.value.copyOfRange(0, 2))
                val afl = if (firstTlv.value.size > 2) {
                    firstTlv.value.copyOfRange(2, firstTlv.value.size)
                } else ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl
                AmexContactGpoResult.Success(aip, afl)
            }
            "77" -> {
                val aipTlv = TlvParser.findTag(firstTlv.value, EmvTags.AIP)
                    ?: return AmexContactGpoResult.Error("Missing AIP")
                val aflTlv = TlvParser.findTag(firstTlv.value, EmvTags.AFL)

                val aip = AmexAip(aipTlv.value)
                val afl = aflTlv?.value ?: ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl

                for (tlv in TlvParser.parse(firstTlv.value)) {
                    cardData[tlv.tag.hex] = tlv.value
                }

                AmexContactGpoResult.Success(aip, afl)
            }
            else -> AmexContactGpoResult.Error("Unknown GPO response format")
        }
    }

    private suspend fun processEmvTransaction(
        gpoData: AmexContactGpoResult.Success,
        transaction: AmexTransaction
    ): AmexKernelResult {
        // Read application data
        readApplicationData(gpoData.afl)

        // Check restrictions
        checkProcessingRestrictions()

        // CVM processing
        performCvm(transaction)

        // Terminal action analysis
        val cryptogram = generateAc(EmvCommands.CryptogramType.ARQC)
            ?: return AmexKernelResult.Error("Failed to generate ARQC")

        val authRequest = buildAuthorizationRequest(cryptogram)
        return AmexKernelResult.OnlineRequired(authRequest)
    }

    private suspend fun processMagStripeTransaction(
        gpoData: AmexContactGpoResult.Success,
        transaction: AmexTransaction
    ): AmexKernelResult {
        // Mag stripe mode - cryptogram from GPO response
        val authRequest = buildMagStripeAuthRequest()
        return AmexKernelResult.OnlineRequired(authRequest)
    }

    private suspend fun readApplicationData(afl: ByteArray) {
        if (afl.isEmpty()) return

        var offset = 0
        while (offset + 4 <= afl.size) {
            val sfi = (afl[offset].toInt() and 0xFF) shr 3
            val firstRecord = afl[offset + 1].toInt() and 0xFF
            val lastRecord = afl[offset + 2].toInt() and 0xFF
            offset += 4

            for (recordNum in firstRecord..lastRecord) {
                val command = EmvCommands.readRecord(recordNum, sfi)
                val response = transceiver.transceive(command)

                if (response.isSuccess) {
                    val recordTlvs = TlvParser.parseRecursive(response.data)
                    for (tlv in recordTlvs) {
                        if (!tlv.tag.isConstructed) {
                            cardData[tlv.tag.hex] = tlv.value
                        }
                    }
                }
            }
        }
    }

    private fun checkProcessingRestrictions() {
        val expiryDate = cardData[EmvTags.EXPIRY_DATE.hex]
        if (expiryDate != null) {
            val hex = expiryDate.toHexString()
            try {
                val year = 2000 + hex.substring(0, 2).toInt()
                val month = hex.substring(2, 4).toInt()
                val expiry = LocalDate.of(year, month, 1)
                if (expiry.isBefore(LocalDate.now())) {
                    setTvrBit(1, 0x20)  // Expired
                }
            } catch (_: Exception) {}
        }
    }

    private fun performCvm(transaction: AmexTransaction) {
        if (transaction.amount <= config.cvmRequiredLimit) {
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0000".hexToByteArray()
        } else {
            // Online PIN or CDCVM
            transactionData[EmvTags.CVM_RESULTS.hex] = "020000".hexToByteArray()
        }
    }

    private suspend fun generateAc(cryptogramType: EmvCommands.CryptogramType): ByteArray? {
        val cdol1 = cardData[EmvTags.CDOL1.hex]
        val cdolData = buildCdolData(cdol1)

        val command = EmvCommands.generateAc(cryptogramType, cdolData, cda = false)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) return null

        val tlvs = TlvParser.parseRecursive(response.data)
        for (tlv in tlvs) {
            cardData[tlv.tag.hex] = tlv.value
        }

        return response.data
    }

    private fun buildCdolData(cdol: ByteArray?): ByteArray {
        if (cdol == null || cdol.isEmpty()) {
            return (transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] ?: ByteArray(6)) +
                    (transactionData[EmvTags.AMOUNT_OTHER.hex] ?: ByteArray(6)) +
                    (transactionData[EmvTags.TERMINAL_COUNTRY_CODE.hex] ?: ByteArray(2)) +
                    (transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)) +
                    (transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] ?: ByteArray(2)) +
                    (transactionData[EmvTags.TRANSACTION_DATE.hex] ?: ByteArray(3)) +
                    (transactionData[EmvTags.TRANSACTION_TYPE.hex] ?: ByteArray(1)) +
                    (transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] ?: ByteArray(4)) +
                    (transactionData[EmvTags.TERMINAL_TYPE.hex] ?: ByteArray(1)) +
                    (transactionData[EmvTags.CVM_RESULTS.hex] ?: ByteArray(3))
        }

        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < cdol.size) {
            val (tag, tagLength) = TlvTag.parse(cdol, offset)
            offset += tagLength
            val length = cdol[offset].toInt() and 0xFF
            offset++

            val data = transactionData[tag.hex] ?: cardData[tag.hex] ?: ByteArray(length)
            val paddedData = when {
                data.size == length -> data
                data.size < length -> data + ByteArray(length - data.size)
                else -> data.copyOfRange(0, length)
            }
            result.addAll(paddedData.toList())
        }

        return result.toByteArray()
    }

    private fun buildAuthorizationRequest(cryptogramData: ByteArray): AmexAuthorizationRequest {
        val cryptogramTlvs = TlvParser.parseToMap(cryptogramData)

        return AmexAuthorizationRequest(
            pan = cardData[EmvTags.PAN.hex]?.toHexString() ?: "",
            track2Equivalent = cardData[EmvTags.TRACK2_EQUIVALENT.hex]?.toHexString() ?: "",
            expiryDate = cardData[EmvTags.EXPIRY_DATE.hex]?.toHexString() ?: "",
            panSequenceNumber = cardData[EmvTags.PAN_SEQUENCE_NUMBER.hex]?.toHexString() ?: "00",
            applicationCryptogram = cryptogramTlvs[EmvTags.APPLICATION_CRYPTOGRAM.hex]?.valueHex() ?: "",
            cryptogramInfoData = cryptogramTlvs[EmvTags.CRYPTOGRAM_INFO_DATA.hex]?.valueHex() ?: "",
            atc = cryptogramTlvs[EmvTags.APPLICATION_TRANSACTION_COUNTER.hex]?.valueHex() ?: "",
            issuerApplicationData = cryptogramTlvs[EmvTags.ISSUER_APPLICATION_DATA.hex]?.valueHex() ?: "",
            terminalVerificationResults = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex]?.toHexString() ?: "",
            cvmResults = transactionData[EmvTags.CVM_RESULTS.hex]?.toHexString() ?: "",
            amountAuthorized = transactionData[EmvTags.AMOUNT_AUTHORIZED.hex]?.toHexString() ?: "",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = transactionData[EmvTags.TRANSACTION_DATE.hex]?.toHexString() ?: "",
            transactionType = transactionData[EmvTags.TRANSACTION_TYPE.hex]?.toHexString() ?: "",
            unpredictableNumber = transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex]?.toHexString() ?: "",
            aip = cardData[EmvTags.AIP.hex]?.toHexString() ?: "",
            aid = cardData[EmvTags.AID.hex]?.toHexString() ?: "A00000002501",
            cardholderName = cardData[EmvTags.CARDHOLDER_NAME.hex]?.let { String(it) } ?: "",
            transactionMode = "EMV",
            rawCryptogramData = cryptogramData.toHexString()
        )
    }

    private fun buildMagStripeAuthRequest(): AmexAuthorizationRequest {
        return AmexAuthorizationRequest(
            pan = extractPanFromTrack2(),
            track2Equivalent = cardData[EmvTags.TRACK2_EQUIVALENT.hex]?.toHexString() ?: "",
            expiryDate = extractExpiryFromTrack2(),
            panSequenceNumber = "00",
            applicationCryptogram = cardData[EmvTags.APPLICATION_CRYPTOGRAM.hex]?.toHexString() ?: "",
            cryptogramInfoData = "80",
            atc = cardData[EmvTags.APPLICATION_TRANSACTION_COUNTER.hex]?.toHexString() ?: "",
            issuerApplicationData = "",
            terminalVerificationResults = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex]?.toHexString() ?: "",
            cvmResults = transactionData[EmvTags.CVM_RESULTS.hex]?.toHexString() ?: "",
            amountAuthorized = transactionData[EmvTags.AMOUNT_AUTHORIZED.hex]?.toHexString() ?: "",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = transactionData[EmvTags.TRANSACTION_DATE.hex]?.toHexString() ?: "",
            transactionType = transactionData[EmvTags.TRANSACTION_TYPE.hex]?.toHexString() ?: "",
            unpredictableNumber = transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex]?.toHexString() ?: "",
            aip = cardData[EmvTags.AIP.hex]?.toHexString() ?: "",
            aid = "A00000002501",
            cardholderName = "",
            transactionMode = "MAGSTRIPE",
            rawCryptogramData = ""
        )
    }

    private fun extractPanFromTrack2(): String {
        val track2 = cardData[EmvTags.TRACK2_EQUIVALENT.hex] ?: return ""
        val track2Hex = track2.toHexString()
        val separatorIndex = track2Hex.indexOf('D')
        return if (separatorIndex > 0) track2Hex.substring(0, separatorIndex) else ""
    }

    private fun extractExpiryFromTrack2(): String {
        val track2 = cardData[EmvTags.TRACK2_EQUIVALENT.hex] ?: return ""
        val track2Hex = track2.toHexString()
        val separatorIndex = track2Hex.indexOf('D')
        return if (separatorIndex > 0 && track2Hex.length > separatorIndex + 5) {
            track2Hex.substring(separatorIndex + 1, separatorIndex + 5)
        } else ""
    }

    private fun setTvrBit(byteIndex: Int, bitMask: Int) {
        val tvr = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)
        tvr[byteIndex] = (tvr[byteIndex].toInt() or bitMask).toByte()
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = tvr
    }
}

// Configuration and Data Classes

data class AmexKernelConfig(
    val terminalType: Byte = 0x22,
    val terminalCapabilities: ByteArray = "E0F0C8".hexToByteArray(),
    val terminalCountryCode: ByteArray = "0840".hexToByteArray(),
    val transactionCurrencyCode: ByteArray = "0840".hexToByteArray(),
    val merchantIdentifier: String = "ATLASMERCHANT01",
    val terminalIdentification: String = "ATLAS001",
    val cvmRequiredLimit: Long = 2500,
    val contactlessTransactionLimit: Long = 100000,
    val enhancedContactlessReaderCapabilities: ByteArray = "D8E00000".hexToByteArray(),
    val tacDenial: ByteArray = "0000000000".hexToByteArray(),
    val tacOnline: ByteArray = "F850ACF800".hexToByteArray(),
    val tacDefault: ByteArray = "F850ACF800".hexToByteArray()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexKernelConfig) return false
        return merchantIdentifier == other.merchantIdentifier
    }

    override fun hashCode(): Int = merchantIdentifier.hashCode()
}

data class AmexAip(val bytes: ByteArray) {
    fun isEmvModeSupported(): Boolean = (bytes[0].toInt() and 0x10) != 0
    fun isSdaSupported(): Boolean = (bytes[0].toInt() and 0x40) != 0
    fun isDdaSupported(): Boolean = (bytes[0].toInt() and 0x20) != 0
    fun isCdaSupported(): Boolean = (bytes[0].toInt() and 0x01) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexAip) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

data class AmexTransaction(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val type: Byte = 0x00
)

sealed class AmexContactGpoResult {
    data class Success(val aip: AmexAip, val afl: ByteArray) : AmexGpoResult()
    data class Error(val message: String) : AmexGpoResult()
}

sealed class AmexKernelResult {
    data class OnlineRequired(val authRequest: AmexAuthorizationRequest) : AmexKernelResult()
    data class Approved(val cryptogram: ByteArray) : AmexKernelResult()
    data class Declined(val reason: String) : AmexKernelResult()
    data class Error(val message: String) : AmexKernelResult()
}

data class AmexAuthorizationRequest(
    val pan: String,
    val track2Equivalent: String,
    val expiryDate: String,
    val panSequenceNumber: String,
    val applicationCryptogram: String,
    val cryptogramInfoData: String,
    val atc: String,
    val issuerApplicationData: String,
    val terminalVerificationResults: String,
    val cvmResults: String,
    val amountAuthorized: String,
    val terminalCountryCode: String,
    val transactionCurrencyCode: String,
    val transactionDate: String,
    val transactionType: String,
    val unpredictableNumber: String,
    val aip: String,
    val aid: String,
    val cardholderName: String,
    val transactionMode: String,
    val rawCryptogramData: String
)
