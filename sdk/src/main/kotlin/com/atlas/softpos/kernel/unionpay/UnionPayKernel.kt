package com.atlas.softpos.kernel.unionpay

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
 * UnionPay QuickPass Kernel (Kernel 7)
 *
 * Implements EMV Contactless Book C-7 - UnionPay Kernel Specification
 *
 * QuickPass is UnionPay's contactless payment specification with support for:
 * - qPBOC (Quick PBOC) - EMV mode
 * - MSD mode (legacy)
 * - Electronic Cash (offline stored value)
 *
 * UnionPay has specific requirements for terminals deployed in China.
 */
class UnionPayKernel(
    private val transceiver: CardTransceiver,
    private val config: UnionPayKernelConfig = UnionPayKernelConfig()
) {
    private val transactionData = mutableMapOf<String, ByteArray>()
    private val cardData = mutableMapOf<String, ByteArray>()

    /**
     * Process a UnionPay contactless transaction
     */
    suspend fun processTransaction(
        application: SelectedApplication,
        transaction: UnionPayTransaction
    ): UnionPayKernelResult {
        try {
            initializeTransactionData(transaction)

            // GET PROCESSING OPTIONS
            val gpoResult = performGpo(application.pdol, transaction)
            if (gpoResult is UnionPayGpoResult.Error) {
                return UnionPayKernelResult.Error(gpoResult.message)
            }
            val gpoData = (gpoResult as UnionPayGpoResult.Success)

            // Determine path based on AIP
            val isQpbocMode = gpoData.aip.isQpbocSupported()

            return if (isQpbocMode) {
                processQpbocTransaction(gpoData, transaction)
            } else {
                processMsdTransaction(gpoData, transaction)
            }

        } catch (e: Exception) {
            return UnionPayKernelResult.Error("Kernel error: ${e.message}")
        }
    }

    private fun initializeTransactionData(transaction: UnionPayTransaction) {
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
        transactionData[EmvTags.ADDITIONAL_TERMINAL_CAPABILITIES.hex] = config.additionalTerminalCapabilities
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = ByteArray(5)

        // UnionPay specific: Terminal Transaction Qualifiers (9F66)
        transactionData["9F66"] = config.ttq

        // UnionPay specific: Issuer Code Table Index default
        transactionData["9F11"] = byteArrayOf(0x01)  // ISO 8859-1 (Latin-1) by default
    }

    private suspend fun performGpo(pdol: ByteArray?, transaction: UnionPayTransaction): UnionPayGpoResult {
        val pdolData = buildPdolData(pdol)
        val command = EmvCommands.getProcessingOptions(pdolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return UnionPayGpoResult.Error("GPO failed: ${response.statusDescription}")
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

    private fun parseGpoResponse(data: ByteArray): UnionPayGpoResult {
        val tlvList = TlvParser.parse(data)
        if (tlvList.isEmpty()) return UnionPayGpoResult.Error("Empty GPO response")

        val firstTlv = tlvList[0]

        return when (firstTlv.tag.hex) {
            "80" -> {
                if (firstTlv.value.size < 2) {
                    return UnionPayGpoResult.Error("Invalid Format 1 response")
                }
                val aip = UnionPayAip(firstTlv.value.copyOfRange(0, 2))
                val afl = if (firstTlv.value.size > 2) {
                    firstTlv.value.copyOfRange(2, firstTlv.value.size)
                } else ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl
                UnionPayGpoResult.Success(aip, afl)
            }
            "77" -> {
                val aipTlv = TlvParser.findTag(firstTlv.value, EmvTags.AIP)
                    ?: return UnionPayGpoResult.Error("Missing AIP")
                val aflTlv = TlvParser.findTag(firstTlv.value, EmvTags.AFL)

                val aip = UnionPayAip(aipTlv.value)
                val afl = aflTlv?.value ?: ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl

                for (tlv in TlvParser.parse(firstTlv.value)) {
                    cardData[tlv.tag.hex] = tlv.value
                }

                UnionPayGpoResult.Success(aip, afl)
            }
            else -> UnionPayGpoResult.Error("Unknown GPO response format")
        }
    }

    /**
     * Process qPBOC (Quick PBOC) transaction
     */
    private suspend fun processQpbocTransaction(
        gpoData: UnionPayGpoResult.Success,
        transaction: UnionPayTransaction
    ): UnionPayKernelResult {
        // Read application data
        readApplicationData(gpoData.afl)

        // Check processing restrictions
        val restrictionsResult = checkProcessingRestrictions()
        if (restrictionsResult is ProcessingResult.Declined) {
            return UnionPayKernelResult.Declined(restrictionsResult.reason)
        }

        // CVM processing
        performCvm(transaction, gpoData.aip)

        // Terminal action analysis & Generate AC
        val cryptogram = generateAc(EmvCommands.CryptogramType.ARQC)
            ?: return UnionPayKernelResult.Error("Failed to generate ARQC")

        val authRequest = buildAuthorizationRequest(cryptogram)
        return UnionPayKernelResult.OnlineRequired(authRequest)
    }

    /**
     * Process MSD transaction (legacy mode)
     */
    private suspend fun processMsdTransaction(
        gpoData: UnionPayGpoResult.Success,
        transaction: UnionPayTransaction
    ): UnionPayKernelResult {
        // MSD mode - data already in GPO response
        val authRequest = buildMsdAuthRequest()
        return UnionPayKernelResult.OnlineRequired(authRequest)
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

    private fun checkProcessingRestrictions(): ProcessingResult {
        // Check expiry date
        val expiryDate = cardData[EmvTags.EXPIRY_DATE.hex]
        if (expiryDate != null) {
            val hex = expiryDate.toHexString()
            try {
                val year = 2000 + hex.substring(0, 2).toInt()
                val month = hex.substring(2, 4).toInt()
                val expiry = LocalDate.of(year, month, 1)
                if (expiry.isBefore(LocalDate.now())) {
                    setTvrBit(1, 0x20)
                    return ProcessingResult.Declined("Card expired")
                }
            } catch (_: Exception) {}
        }

        // Check effective date
        val effectiveDate = cardData[EmvTags.EFFECTIVE_DATE.hex]
        if (effectiveDate != null) {
            val hex = effectiveDate.toHexString()
            try {
                val year = 2000 + hex.substring(0, 2).toInt()
                val month = hex.substring(2, 4).toInt()
                val effective = LocalDate.of(year, month, 1)
                if (effective.isAfter(LocalDate.now())) {
                    setTvrBit(1, 0x10)  // Application not yet effective
                }
            } catch (_: Exception) {}
        }

        return ProcessingResult.Continue
    }

    private fun performCvm(transaction: UnionPayTransaction, aip: UnionPayAip) {
        // Check card's CTQ for CVM requirements
        val ctq = cardData["9F6C"]

        if (transaction.amount <= config.cvmRequiredLimit) {
            // No CVM required for low value transactions
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0000".hexToByteArray()
            return
        }

        // Check for CDCVM support
        if (ctq != null && (ctq[0].toInt() and 0x80) != 0) {
            // Consumer Device CVM performed
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0002".hexToByteArray()
            return
        }

        // Online PIN required
        transactionData[EmvTags.CVM_RESULTS.hex] = "020000".hexToByteArray()
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
            // Default CDOL for qPBOC
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

    private fun buildAuthorizationRequest(cryptogramData: ByteArray): UnionPayAuthorizationRequest {
        val cryptogramTlvs = TlvParser.parseToMap(cryptogramData)

        return UnionPayAuthorizationRequest(
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
            aid = cardData[EmvTags.AID.hex]?.toHexString()
                ?: cardData[EmvTags.DF_NAME.hex]?.toHexString() ?: "A000000333010101",
            cardholderName = cardData[EmvTags.CARDHOLDER_NAME.hex]?.let { String(it) } ?: "",
            transactionMode = "QPBOC",
            rawCryptogramData = cryptogramData.toHexString()
        )
    }

    private fun buildMsdAuthRequest(): UnionPayAuthorizationRequest {
        return UnionPayAuthorizationRequest(
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
            aid = "A000000333010101",
            cardholderName = "",
            transactionMode = "MSD",
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

data class UnionPayKernelConfig(
    val terminalType: Byte = 0x22,
    val terminalCapabilities: ByteArray = "E0F0C8".hexToByteArray(),
    val additionalTerminalCapabilities: ByteArray = "FF00F0A001".hexToByteArray(),
    val terminalCountryCode: ByteArray = "0156".hexToByteArray(),  // China default
    val transactionCurrencyCode: ByteArray = "0156".hexToByteArray(),  // CNY default
    val merchantIdentifier: String = "ATLASMERCHANT01",
    val terminalIdentification: String = "ATLAS001",
    val cvmRequiredLimit: Long = 10000,  // 100 CNY default
    val contactlessTransactionLimit: Long = 100000,  // 1000 CNY default
    val ttq: ByteArray = "36000000".hexToByteArray(),
    val tacDenial: ByteArray = "0000000000".hexToByteArray(),
    val tacOnline: ByteArray = "F850ACF800".hexToByteArray(),
    val tacDefault: ByteArray = "F850ACF800".hexToByteArray()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnionPayKernelConfig) return false
        return merchantIdentifier == other.merchantIdentifier
    }

    override fun hashCode(): Int = merchantIdentifier.hashCode()
}

data class UnionPayAip(val bytes: ByteArray) {
    fun isQpbocSupported(): Boolean = (bytes[0].toInt() and 0x10) != 0
    fun isSdaSupported(): Boolean = (bytes[0].toInt() and 0x40) != 0
    fun isDdaSupported(): Boolean = (bytes[0].toInt() and 0x20) != 0
    fun isCdaSupported(): Boolean = (bytes[0].toInt() and 0x01) != 0
    fun isElectronicCashSupported(): Boolean = (bytes[1].toInt() and 0x80) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnionPayAip) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

data class UnionPayTransaction(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val type: Byte = 0x00
)

sealed class UnionPayGpoResult {
    data class Success(val aip: UnionPayAip, val afl: ByteArray) : UnionPayGpoResult()
    data class Error(val message: String) : UnionPayGpoResult()
}

sealed class ProcessingResult {
    object Continue : ProcessingResult()
    data class Declined(val reason: String) : ProcessingResult()
}

sealed class UnionPayKernelResult {
    data class OnlineRequired(val authRequest: UnionPayAuthorizationRequest) : UnionPayKernelResult()
    data class Approved(val cryptogram: ByteArray) : UnionPayKernelResult()
    data class Declined(val reason: String) : UnionPayKernelResult()
    data class Error(val message: String) : UnionPayKernelResult()
}

data class UnionPayAuthorizationRequest(
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
    val transactionMode: String,  // "QPBOC" or "MSD"
    val rawCryptogramData: String
)
