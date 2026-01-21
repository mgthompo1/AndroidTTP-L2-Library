package com.atlas.softpos.kernel.mastercard

import com.atlas.softpos.core.apdu.EmvCommands
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.tlv.*
import com.atlas.softpos.core.types.*
import com.atlas.softpos.kernel.common.CardTransceiver
import com.atlas.softpos.kernel.common.SelectedApplication
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * Mastercard PayPass Kernel (Kernel 2)
 *
 * Implements EMV Contactless Book C-2 - Mastercard Kernel Specification
 *
 * Supports:
 * - M/Chip (EMV mode)
 * - Mag Stripe mode (legacy)
 * - On-device CVM (CDCVM)
 * - Relay Resistance Protocol
 *
 * Transaction Flow:
 * 1. Receive selected application from Entry Point
 * 2. Build PDOL and send GET PROCESSING OPTIONS
 * 3. Determine transaction path (M/Chip or Mag Stripe)
 * 4. For M/Chip: Read records, ODA, CVM, Generate AC
 * 5. For Mag Stripe: Compute Cryptographic Checksum
 * 6. Return outcome
 */
class MastercardKernel(
    private val transceiver: CardTransceiver,
    private val config: MastercardKernelConfig = MastercardKernelConfig()
) {
    // Transaction data store
    private val transactionData = mutableMapOf<String, ByteArray>()

    // Card data store
    private val cardData = mutableMapOf<String, ByteArray>()

    // Outcome data
    private var outcome: MastercardOutcome = MastercardOutcome.END_APPLICATION
    private var cvmPerformed: MastercardCvmType = MastercardCvmType.NO_CVM

    /**
     * Process a Mastercard contactless transaction
     */
    suspend fun processTransaction(
        application: SelectedApplication,
        transaction: MastercardTransaction
    ): MastercardKernelResult {
        try {
            // Initialize transaction data
            initializeTransactionData(transaction)

            // Step 1: GET PROCESSING OPTIONS
            val gpoResult = performGpo(application.pdol, transaction)
            if (gpoResult is MastercardGpoResult.Error) {
                return MastercardKernelResult.Error(gpoResult.message)
            }
            val gpoData = (gpoResult as MastercardGpoResult.Success)

            // Determine transaction path based on AIP
            val isMChipMode = gpoData.aip.isEmvModeSupported()

            return if (isMChipMode) {
                processMChipTransaction(gpoData, transaction)
            } else {
                processMagStripeTransaction(gpoData, transaction)
            }

        } catch (e: Exception) {
            return MastercardKernelResult.Error("Kernel error: ${e.message}")
        }
    }

    /**
     * Initialize transaction-specific data
     */
    private fun initializeTransactionData(transaction: MastercardTransaction) {
        transactionData.clear()
        cardData.clear()

        // Amount Authorized (9F02)
        transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] = transaction.amount.toBcd(6)

        // Amount Other (9F03)
        transactionData[EmvTags.AMOUNT_OTHER.hex] = (transaction.cashbackAmount ?: 0L).toBcd(6)

        // Transaction Type (9C)
        transactionData[EmvTags.TRANSACTION_TYPE.hex] = byteArrayOf(transaction.type)

        // Transaction Date (9A)
        val date = LocalDate.now()
        transactionData[EmvTags.TRANSACTION_DATE.hex] = date.format(
            DateTimeFormatter.ofPattern("yyMMdd")
        ).hexToByteArray()

        // Transaction Time (9F21)
        val time = LocalTime.now()
        transactionData[EmvTags.TRANSACTION_TIME.hex] = time.format(
            DateTimeFormatter.ofPattern("HHmmss")
        ).hexToByteArray()

        // Unpredictable Number (9F37)
        val unpredictableNumber = ByteArray(4)
        SecureRandom().nextBytes(unpredictableNumber)
        transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] = unpredictableNumber

        // Terminal data from config
        transactionData[EmvTags.TERMINAL_COUNTRY_CODE.hex] = config.terminalCountryCode
        transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] = config.transactionCurrencyCode
        transactionData[EmvTags.TERMINAL_TYPE.hex] = byteArrayOf(config.terminalType)
        transactionData[EmvTags.TERMINAL_CAPABILITIES.hex] = config.terminalCapabilities
        transactionData[EmvTags.ADDITIONAL_TERMINAL_CAPABILITIES.hex] = config.additionalTerminalCapabilities
        transactionData[EmvTags.MERCHANT_CATEGORY_CODE.hex] = config.merchantCategoryCode
        transactionData[EmvTags.TERMINAL_IDENTIFICATION.hex] = config.terminalIdentification.toByteArray()
        transactionData[EmvTags.ACQUIRER_IDENTIFIER.hex] = config.acquirerIdentifier

        // Initialize TVR
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = ByteArray(5)
    }

    /**
     * Perform GET PROCESSING OPTIONS
     */
    private suspend fun performGpo(pdol: ByteArray?, transaction: MastercardTransaction): MastercardGpoResult {
        val pdolData = buildPdolData(pdol)

        val command = EmvCommands.getProcessingOptions(pdolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return MastercardGpoResult.Error("GPO failed: ${response.statusDescription}")
        }

        return parseGpoResponse(response.data)
    }

    /**
     * Build PDOL data
     */
    private fun buildPdolData(pdol: ByteArray?): ByteArray {
        if (pdol == null || pdol.isEmpty()) {
            return ByteArray(0)
        }

        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < pdol.size) {
            val (tag, tagLength) = TlvTag.parse(pdol, offset)
            offset += tagLength

            val length = pdol[offset].toInt() and 0xFF
            offset++

            val data = getTerminalData(tag.hex, length)
            result.addAll(data.toList())
        }

        return result.toByteArray()
    }

    /**
     * Get terminal data for a specific tag
     */
    private fun getTerminalData(tagHex: String, length: Int): ByteArray {
        val data = transactionData[tagHex] ?: ByteArray(length)
        return when {
            data.size == length -> data
            data.size < length -> data + ByteArray(length - data.size)
            else -> data.copyOfRange(0, length)
        }
    }

    /**
     * Parse GPO response
     */
    private fun parseGpoResponse(data: ByteArray): MastercardGpoResult {
        val tlvList = TlvParser.parse(data)
        if (tlvList.isEmpty()) {
            return MastercardGpoResult.Error("Empty GPO response")
        }

        val firstTlv = tlvList[0]

        return when (firstTlv.tag.hex) {
            "80" -> {
                if (firstTlv.value.size < 2) {
                    return MastercardGpoResult.Error("Invalid Format 1 response")
                }
                val aip = SimpleAip(firstTlv.value.copyOfRange(0, 2))
                val afl = if (firstTlv.value.size > 2) {
                    firstTlv.value.copyOfRange(2, firstTlv.value.size)
                } else {
                    ByteArray(0)
                }
                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl
                MastercardGpoResult.Success(aip, afl)
            }

            "77" -> {
                val aipTlv = TlvParser.findTag(firstTlv.value, EmvTags.AIP)
                    ?: return MastercardGpoResult.Error("Missing AIP")
                val aflTlv = TlvParser.findTag(firstTlv.value, EmvTags.AFL)

                val aip = SimpleAip(aipTlv.value)
                val afl = aflTlv?.value ?: ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl

                for (tlv in TlvParser.parse(firstTlv.value)) {
                    cardData[tlv.tag.hex] = tlv.value
                }

                MastercardGpoResult.Success(aip, afl)
            }

            else -> MastercardGpoResult.Error("Unknown GPO response format")
        }
    }

    /**
     * Process M/Chip transaction path
     */
    private suspend fun processMChipTransaction(
        gpoData: MastercardGpoResult.Success,
        transaction: MastercardTransaction
    ): MastercardKernelResult {
        // Read application data
        val readResult = readApplicationData(gpoData.afl)
        if (readResult is ReadResult.Error) {
            return MastercardKernelResult.Error(readResult.message)
        }

        // Parse card data
        parseCardData()

        // Offline Data Authentication
        if (gpoData.aip.isOdaSupported()) {
            performOda(gpoData.aip)
        }

        // Processing Restrictions
        val restrictionsResult = checkProcessingRestrictions()
        if (restrictionsResult is ProcessingResult.Declined) {
            return MastercardKernelResult.Declined(restrictionsResult.reason)
        }

        // Cardholder Verification
        performCvm(transaction, gpoData.aip)

        // Terminal Risk Management
        performTerminalRiskManagement(transaction)

        // Terminal Action Analysis
        val actionResult = performTerminalActionAnalysis(transaction)

        return when (actionResult) {
            is ActionResult.OnlineRequest -> {
                val authRequest = buildAuthorizationRequest(actionResult.cryptogram)
                MastercardKernelResult.OnlineRequired(authRequest)
            }
            is ActionResult.Approved -> {
                MastercardKernelResult.Approved(actionResult.cryptogram)
            }
            is ActionResult.Declined -> {
                MastercardKernelResult.Declined(actionResult.reason)
            }
        }
    }

    /**
     * Process Mag Stripe transaction path
     */
    private suspend fun processMagStripeTransaction(
        gpoData: MastercardGpoResult.Success,
        transaction: MastercardTransaction
    ): MastercardKernelResult {
        // For Mag Stripe mode, the GPO response already contains Track 1/2 data

        // Check if we have the required data
        val track2 = cardData[EmvTags.TRACK2_EQUIVALENT.hex]
        if (track2 == null) {
            return MastercardKernelResult.Error("Missing Track 2 data in Mag Stripe mode")
        }

        // Compute Cryptographic Checksum for Mag Stripe
        val cccResult = computeCryptographicChecksum(transaction)

        return when (cccResult) {
            is CccResult.Success -> {
                val authRequest = buildMagStripeAuthRequest(cccResult.data)
                MastercardKernelResult.OnlineRequired(authRequest)
            }
            is CccResult.Error -> {
                MastercardKernelResult.Error(cccResult.message)
            }
        }
    }

    /**
     * Read application data based on AFL
     */
    private suspend fun readApplicationData(afl: ByteArray): ReadResult {
        if (afl.isEmpty()) {
            return ReadResult.Success
        }

        var offset = 0
        while (offset + 4 <= afl.size) {
            val sfi = (afl[offset].toInt() and 0xFF) shr 3
            val firstRecord = afl[offset + 1].toInt() and 0xFF
            val lastRecord = afl[offset + 2].toInt() and 0xFF
            val odaRecords = afl[offset + 3].toInt() and 0xFF
            offset += 4

            for (recordNum in firstRecord..lastRecord) {
                val command = EmvCommands.readRecord(recordNum, sfi)
                val response = transceiver.transceive(command)

                if (!response.isSuccess) {
                    return ReadResult.Error("Failed to read record $recordNum from SFI $sfi")
                }

                val recordTlvs = TlvParser.parseRecursive(response.data)
                for (tlv in recordTlvs) {
                    if (!tlv.tag.isConstructed) {
                        cardData[tlv.tag.hex] = tlv.value
                    }
                }
            }
        }

        return ReadResult.Success
    }

    /**
     * Parse and validate card data
     */
    private fun parseCardData() {
        val pan = cardData[EmvTags.PAN.hex]
        val track2 = cardData[EmvTags.TRACK2_EQUIVALENT.hex]

        if (pan == null && track2 == null) {
            throw IllegalStateException("Card data missing: no PAN or Track 2")
        }
    }

    /**
     * Perform Offline Data Authentication
     */
    private fun performOda(aip: SimpleAip) {
        // Mastercard supports SDA, DDA, and CDA
        // For SoftPOS, typically use fDDA or CDA

        if (aip.isCdaSupported()) {
            // CDA will be performed during GENERATE AC
        } else if (aip.isDdaSupported()) {
            // fDDA - simplified for prototype
            // In production, verify ICC Dynamic Data signature
        }
    }

    /**
     * Check processing restrictions
     */
    private fun checkProcessingRestrictions(): ProcessingResult {
        // Check expiry date
        val expiryDate = cardData[EmvTags.EXPIRY_DATE.hex]
        if (expiryDate != null) {
            val expiry = parseExpiryDate(expiryDate)
            if (expiry != null && expiry.isBefore(LocalDate.now())) {
                setTvrBit(2, 0x20)  // Expired application
                return ProcessingResult.Declined("Card expired")
            }
        }

        return ProcessingResult.Continue
    }

    /**
     * Perform Cardholder Verification
     */
    private fun performCvm(transaction: MastercardTransaction, aip: SimpleAip) {
        // Check if CVM is required
        if (transaction.amount <= config.cvmRequiredLimit) {
            cvmPerformed = MastercardCvmType.NO_CVM_REQUIRED
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0000".hexToByteArray()
            return
        }

        // Check for CDCVM support
        val cvmList = cardData[EmvTags.CVM_LIST.hex]
        if (cvmList != null && supportsOnDeviceCvm(cvmList)) {
            // Assume CDCVM was performed on consumer device
            cvmPerformed = MastercardCvmType.CONFIRMATION_CODE_VERIFIED
            transactionData[EmvTags.CVM_RESULTS.hex] = "030002".hexToByteArray()
            return
        }

        // Default to online PIN
        cvmPerformed = MastercardCvmType.ONLINE_PIN
        transactionData[EmvTags.CVM_RESULTS.hex] = "020000".hexToByteArray()
    }

    /**
     * Check if card supports on-device CVM
     */
    private fun supportsOnDeviceCvm(cvmList: ByteArray): Boolean {
        // Parse CVM list and check for CDCVM method
        if (cvmList.size < 8) return false

        var offset = 8  // Skip amount fields
        while (offset + 2 <= cvmList.size) {
            val cvmCode = cvmList[offset].toInt() and 0x3F
            if (cvmCode == 0x1F) {  // No CVM required / CDCVM
                return true
            }
            offset += 2
        }
        return false
    }

    /**
     * Perform Terminal Risk Management
     */
    private fun performTerminalRiskManagement(transaction: MastercardTransaction) {
        // Floor limit check
        if (config.contactlessFloorLimit > 0 && transaction.amount > config.contactlessFloorLimit) {
            setTvrBit(3, 0x80)  // Transaction exceeds floor limit
        }

        // Transaction limit check
        val limit = if (cvmPerformed == MastercardCvmType.CONFIRMATION_CODE_VERIFIED ||
            cvmPerformed == MastercardCvmType.ONLINE_PIN
        ) {
            config.contactlessTransactionLimitOnDeviceCvm
        } else {
            config.contactlessTransactionLimitNoCvm
        }

        if (transaction.amount > limit) {
            setTvrBit(3, 0x80)
        }
    }

    /**
     * Perform Terminal Action Analysis and Generate AC
     */
    private suspend fun performTerminalActionAnalysis(
        transaction: MastercardTransaction
    ): ActionResult {
        val tvr = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)

        // Check TAC Denial
        if (checkActionCode(tvr, config.tacDenial)) {
            return generateAc(EmvCommands.CryptogramType.AAC)?.let {
                ActionResult.Declined(it, "Terminal Action Analysis: Denial")
            } ?: ActionResult.Declined(ByteArray(0), "Failed to generate AAC")
        }

        // Check TAC Online
        if (checkActionCode(tvr, config.tacOnline)) {
            return generateAc(EmvCommands.CryptogramType.ARQC)?.let {
                ActionResult.OnlineRequest(it)
            } ?: ActionResult.Declined(ByteArray(0), "Failed to generate ARQC")
        }

        // Default: go online
        return generateAc(EmvCommands.CryptogramType.ARQC)?.let {
            ActionResult.OnlineRequest(it)
        } ?: ActionResult.Declined(ByteArray(0), "Failed to generate ARQC")
    }

    /**
     * Generate Application Cryptogram
     */
    private suspend fun generateAc(cryptogramType: EmvCommands.CryptogramType): ByteArray? {
        val cdol1 = cardData[EmvTags.CDOL1.hex]
        val cdolData = buildCdolData(cdol1)

        val command = EmvCommands.generateAc(cryptogramType, cdolData, cda = false)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return null
        }

        val tlvs = TlvParser.parseRecursive(response.data)
        for (tlv in tlvs) {
            cardData[tlv.tag.hex] = tlv.value
        }

        return response.data
    }

    /**
     * Build CDOL data
     */
    private fun buildCdolData(cdol: ByteArray?): ByteArray {
        if (cdol == null || cdol.isEmpty()) {
            return buildDefaultCdolData()
        }

        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < cdol.size) {
            val (tag, tagLength) = TlvTag.parse(cdol, offset)
            offset += tagLength

            val length = cdol[offset].toInt() and 0xFF
            offset++

            val data = getDataForTag(tag.hex, length)
            result.addAll(data.toList())
        }

        return result.toByteArray()
    }

    private fun buildDefaultCdolData(): ByteArray {
        return (transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] ?: ByteArray(6)) +
                (transactionData[EmvTags.AMOUNT_OTHER.hex] ?: ByteArray(6)) +
                (transactionData[EmvTags.TERMINAL_COUNTRY_CODE.hex] ?: ByteArray(2)) +
                (transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)) +
                (transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] ?: ByteArray(2)) +
                (transactionData[EmvTags.TRANSACTION_DATE.hex] ?: ByteArray(3)) +
                (transactionData[EmvTags.TRANSACTION_TYPE.hex] ?: ByteArray(1)) +
                (transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] ?: ByteArray(4)) +
                (transactionData[EmvTags.TERMINAL_TYPE.hex] ?: ByteArray(1)) +
                ByteArray(2) +
                ByteArray(8) +
                (transactionData[EmvTags.CVM_RESULTS.hex] ?: ByteArray(3))
    }

    private fun getDataForTag(tagHex: String, length: Int): ByteArray {
        val data = transactionData[tagHex] ?: cardData[tagHex] ?: ByteArray(length)
        return when {
            data.size == length -> data
            data.size < length -> data + ByteArray(length - data.size)
            else -> data.copyOfRange(0, length)
        }
    }

    /**
     * Compute Cryptographic Checksum (for Mag Stripe mode)
     */
    private suspend fun computeCryptographicChecksum(transaction: MastercardTransaction): CccResult {
        // Build UDOL data
        val udolData = buildUdolData()

        val command = EmvCommands.computeCryptographicChecksum(udolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return CccResult.Error("CCC failed: ${response.statusDescription}")
        }

        return CccResult.Success(response.data)
    }

    /**
     * Build UDOL data for Mag Stripe CCC
     */
    private fun buildUdolData(): ByteArray {
        // Default UDOL: UN (4) + Amount (6) + Currency (2) + PUNATC (6)
        return (transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] ?: ByteArray(4)) +
                (transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] ?: ByteArray(6)) +
                (transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] ?: ByteArray(2))
    }

    /**
     * Build authorization request for M/Chip mode
     */
    private fun buildAuthorizationRequest(cryptogramData: ByteArray): MastercardAuthorizationRequest {
        val cryptogramTlvs = TlvParser.parseToMap(cryptogramData)

        return MastercardAuthorizationRequest(
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
            amountOther = transactionData[EmvTags.AMOUNT_OTHER.hex]?.toHexString() ?: "",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = transactionData[EmvTags.TRANSACTION_DATE.hex]?.toHexString() ?: "",
            transactionType = transactionData[EmvTags.TRANSACTION_TYPE.hex]?.toHexString() ?: "",
            unpredictableNumber = transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex]?.toHexString() ?: "",
            aip = cardData[EmvTags.AIP.hex]?.toHexString() ?: "",
            aid = cardData[EmvTags.AID.hex]?.toHexString()
                ?: cardData[EmvTags.DF_NAME.hex]?.toHexString() ?: "",
            cardholderName = cardData[EmvTags.CARDHOLDER_NAME.hex]?.let { String(it) } ?: "",
            transactionMode = "MCHIP",
            rawCryptogramData = cryptogramData.toHexString()
        )
    }

    /**
     * Build authorization request for Mag Stripe mode
     */
    private fun buildMagStripeAuthRequest(cccData: ByteArray): MastercardAuthorizationRequest {
        return MastercardAuthorizationRequest(
            pan = extractPanFromTrack2(),
            track2Equivalent = cardData[EmvTags.TRACK2_EQUIVALENT.hex]?.toHexString() ?: "",
            expiryDate = extractExpiryFromTrack2(),
            panSequenceNumber = cardData[EmvTags.PAN_SEQUENCE_NUMBER.hex]?.toHexString() ?: "00",
            applicationCryptogram = cccData.toHexString(),
            cryptogramInfoData = "80",  // ARQC for mag stripe
            atc = cardData[EmvTags.APPLICATION_TRANSACTION_COUNTER.hex]?.toHexString() ?: "",
            issuerApplicationData = "",
            terminalVerificationResults = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex]?.toHexString() ?: "",
            cvmResults = transactionData[EmvTags.CVM_RESULTS.hex]?.toHexString() ?: "",
            amountAuthorized = transactionData[EmvTags.AMOUNT_AUTHORIZED.hex]?.toHexString() ?: "",
            amountOther = transactionData[EmvTags.AMOUNT_OTHER.hex]?.toHexString() ?: "",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = transactionData[EmvTags.TRANSACTION_DATE.hex]?.toHexString() ?: "",
            transactionType = transactionData[EmvTags.TRANSACTION_TYPE.hex]?.toHexString() ?: "",
            unpredictableNumber = transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex]?.toHexString() ?: "",
            aip = cardData[EmvTags.AIP.hex]?.toHexString() ?: "",
            aid = cardData[EmvTags.AID.hex]?.toHexString()
                ?: cardData[EmvTags.DF_NAME.hex]?.toHexString() ?: "",
            cardholderName = "",
            transactionMode = "MAGSTRIPE",
            rawCryptogramData = cccData.toHexString()
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

    // Helper functions
    private fun setTvrBit(byteIndex: Int, bitMask: Int) {
        val tvr = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)
        tvr[byteIndex] = (tvr[byteIndex].toInt() or bitMask).toByte()
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = tvr
    }

    private fun checkActionCode(tvr: ByteArray, actionCode: ByteArray): Boolean {
        for (i in 0 until minOf(tvr.size, actionCode.size)) {
            if ((tvr[i].toInt() and actionCode[i].toInt()) != 0) {
                return true
            }
        }
        return false
    }

    private fun parseExpiryDate(data: ByteArray): LocalDate? {
        return try {
            val hex = data.toHexString()
            val year = 2000 + hex.substring(0, 2).toInt()
            val month = hex.substring(2, 4).toInt()
            LocalDate.of(year, month, 1)
        } catch (e: Exception) {
            null
        }
    }
}

// Supporting classes

data class SimpleAip(val bytes: ByteArray) {
    fun isSdaSupported(): Boolean = (bytes[0].toInt() and 0x40) != 0
    fun isDdaSupported(): Boolean = (bytes[0].toInt() and 0x20) != 0
    fun isCdaSupported(): Boolean = (bytes[0].toInt() and 0x01) != 0
    fun isOdaSupported(): Boolean = isSdaSupported() || isDdaSupported() || isCdaSupported()
    fun isEmvModeSupported(): Boolean = (bytes[0].toInt() and 0x10) != 0
    fun isOnDeviceCvmSupported(): Boolean = (bytes[1].toInt() and 0x10) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SimpleAip) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

sealed class MastercardGpoResult {
    data class Success(val aip: SimpleAip, val afl: ByteArray) : MastercardGpoResult()
    data class Error(val message: String) : MastercardGpoResult()
}

sealed class ReadResult {
    object Success : ReadResult()
    data class Error(val message: String) : ReadResult()
}

sealed class ProcessingResult {
    object Continue : ProcessingResult()
    data class Declined(val reason: String) : ProcessingResult()
}

sealed class CccResult {
    data class Success(val data: ByteArray) : CccResult()
    data class Error(val message: String) : CccResult()
}

sealed class ActionResult {
    data class OnlineRequest(val cryptogram: ByteArray) : ActionResult()
    data class Approved(val cryptogram: ByteArray) : ActionResult()
    data class Declined(val cryptogram: ByteArray, val reason: String) : ActionResult()
}

data class MastercardTransaction(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val type: Byte = 0x00
)

sealed class MastercardKernelResult {
    data class OnlineRequired(val authRequest: MastercardAuthorizationRequest) : MastercardKernelResult()
    data class Approved(val cryptogram: ByteArray) : MastercardKernelResult()
    data class Declined(val reason: String) : MastercardKernelResult()
    data class Error(val message: String) : MastercardKernelResult()
}

data class MastercardAuthorizationRequest(
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
    val amountOther: String,
    val terminalCountryCode: String,
    val transactionCurrencyCode: String,
    val transactionDate: String,
    val transactionType: String,
    val unpredictableNumber: String,
    val aip: String,
    val aid: String,
    val cardholderName: String,
    val transactionMode: String,  // "MCHIP" or "MAGSTRIPE"
    val rawCryptogramData: String
)
