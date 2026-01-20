package com.atlas.softpos.kernel.jcb

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
 * JCB J/Speedy Kernel
 *
 * Implements EMV Contactless Book C-5 - JCB Kernel Specification
 *
 * J/Speedy is JCB's contactless payment specification, similar to
 * Visa qVSDC but with JCB-specific extensions and parameters.
 */
class JcbKernel(
    private val transceiver: CardTransceiver,
    private val config: JcbKernelConfig = JcbKernelConfig()
) {
    private val transactionData = mutableMapOf<String, ByteArray>()
    private val cardData = mutableMapOf<String, ByteArray>()

    /**
     * Process a JCB contactless transaction
     */
    suspend fun processTransaction(
        application: SelectedApplication,
        transaction: JcbTransaction
    ): JcbKernelResult {
        try {
            initializeTransactionData(transaction)

            // GET PROCESSING OPTIONS
            val gpoResult = performGpo(application.pdol, transaction)
            if (gpoResult is JcbGpoResult.Error) {
                return JcbKernelResult.Error(gpoResult.message)
            }
            val gpoData = (gpoResult as JcbGpoResult.Success)

            // Read application data
            readApplicationData(gpoData.afl)

            // Processing restrictions check
            val restrictionsResult = checkProcessingRestrictions()
            if (restrictionsResult is ProcessingResult.Declined) {
                return JcbKernelResult.Declined(restrictionsResult.reason)
            }

            // CVM processing
            performCvm(transaction, gpoData.aip)

            // Generate AC
            val cryptogram = generateAc(EmvCommands.CryptogramType.ARQC)
                ?: return JcbKernelResult.Error("Failed to generate ARQC")

            val authRequest = buildAuthorizationRequest(cryptogram)
            return JcbKernelResult.OnlineRequired(authRequest)

        } catch (e: Exception) {
            return JcbKernelResult.Error("Kernel error: ${e.message}")
        }
    }

    private fun initializeTransactionData(transaction: JcbTransaction) {
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

        // JCB TTQ
        transactionData["9F66"] = config.defaultTtq
    }

    private suspend fun performGpo(pdol: ByteArray?, transaction: JcbTransaction): JcbGpoResult {
        val pdolData = buildPdolData(pdol)
        val command = EmvCommands.getProcessingOptions(pdolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return JcbGpoResult.Error("GPO failed: ${response.statusDescription}")
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

    private fun parseGpoResponse(data: ByteArray): JcbGpoResult {
        val tlvList = TlvParser.parse(data)
        if (tlvList.isEmpty()) return JcbGpoResult.Error("Empty GPO response")

        val firstTlv = tlvList[0]

        return when (firstTlv.tag.hex) {
            "80" -> {
                if (firstTlv.value.size < 2) {
                    return JcbGpoResult.Error("Invalid Format 1 response")
                }
                val aip = JcbAip(firstTlv.value.copyOfRange(0, 2))
                val afl = if (firstTlv.value.size > 2) {
                    firstTlv.value.copyOfRange(2, firstTlv.value.size)
                } else ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl
                JcbGpoResult.Success(aip, afl)
            }
            "77" -> {
                val aipTlv = TlvParser.findTag(firstTlv.value, EmvTags.AIP)
                    ?: return JcbGpoResult.Error("Missing AIP")
                val aflTlv = TlvParser.findTag(firstTlv.value, EmvTags.AFL)

                val aip = JcbAip(aipTlv.value)
                val afl = aflTlv?.value ?: ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl

                for (tlv in TlvParser.parse(firstTlv.value)) {
                    cardData[tlv.tag.hex] = tlv.value
                }

                JcbGpoResult.Success(aip, afl)
            }
            else -> JcbGpoResult.Error("Unknown GPO response format")
        }
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

        return ProcessingResult.Continue
    }

    private fun performCvm(transaction: JcbTransaction, aip: JcbAip) {
        if (transaction.amount <= config.cvmRequiredLimit) {
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0000".hexToByteArray()
        } else {
            val ctq = cardData["9F6C"]
            if (ctq != null && (ctq[0].toInt() and 0x80) != 0) {
                transactionData[EmvTags.CVM_RESULTS.hex] = "1F0002".hexToByteArray()
            } else {
                transactionData[EmvTags.CVM_RESULTS.hex] = "020000".hexToByteArray()
            }
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

    private fun buildAuthorizationRequest(cryptogramData: ByteArray): JcbAuthorizationRequest {
        val cryptogramTlvs = TlvParser.parseToMap(cryptogramData)

        return JcbAuthorizationRequest(
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
                ?: cardData[EmvTags.DF_NAME.hex]?.toHexString() ?: "A0000000651010",
            cardholderName = cardData[EmvTags.CARDHOLDER_NAME.hex]?.let { String(it) } ?: "",
            rawCryptogramData = cryptogramData.toHexString()
        )
    }

    private fun setTvrBit(byteIndex: Int, bitMask: Int) {
        val tvr = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)
        tvr[byteIndex] = (tvr[byteIndex].toInt() or bitMask).toByte()
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = tvr
    }
}

// Configuration and Data Classes

data class JcbKernelConfig(
    val terminalType: Byte = 0x22,
    val terminalCapabilities: ByteArray = "E0F0C8".hexToByteArray(),
    val terminalCountryCode: ByteArray = "0840".hexToByteArray(),
    val transactionCurrencyCode: ByteArray = "0840".hexToByteArray(),
    val merchantIdentifier: String = "ATLASMERCHANT01",
    val terminalIdentification: String = "ATLAS001",
    val cvmRequiredLimit: Long = 2500,
    val contactlessTransactionLimit: Long = 100000,
    val defaultTtq: ByteArray = "36000000".hexToByteArray(),
    val tacDenial: ByteArray = "0000000000".hexToByteArray(),
    val tacOnline: ByteArray = "F850ACF800".hexToByteArray(),
    val tacDefault: ByteArray = "F850ACF800".hexToByteArray()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JcbKernelConfig) return false
        return merchantIdentifier == other.merchantIdentifier
    }

    override fun hashCode(): Int = merchantIdentifier.hashCode()
}

data class JcbAip(val bytes: ByteArray) {
    fun isEmvModeSupported(): Boolean = (bytes[0].toInt() and 0x10) != 0
    fun isSdaSupported(): Boolean = (bytes[0].toInt() and 0x40) != 0
    fun isDdaSupported(): Boolean = (bytes[0].toInt() and 0x20) != 0
    fun isCdaSupported(): Boolean = (bytes[0].toInt() and 0x01) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JcbAip) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

data class JcbTransaction(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val type: Byte = 0x00
)

sealed class JcbGpoResult {
    data class Success(val aip: JcbAip, val afl: ByteArray) : JcbGpoResult()
    data class Error(val message: String) : JcbGpoResult()
}

sealed class ProcessingResult {
    object Continue : ProcessingResult()
    data class Declined(val reason: String) : ProcessingResult()
}

sealed class JcbKernelResult {
    data class OnlineRequired(val authRequest: JcbAuthorizationRequest) : JcbKernelResult()
    data class Approved(val cryptogram: ByteArray) : JcbKernelResult()
    data class Declined(val reason: String) : JcbKernelResult()
    data class Error(val message: String) : JcbKernelResult()
}

data class JcbAuthorizationRequest(
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
    val rawCryptogramData: String
)
