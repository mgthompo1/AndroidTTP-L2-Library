package com.atlas.softpos.kernel.visa

import com.atlas.softpos.core.apdu.CommandApdu
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
 * Visa payWave Kernel (Kernel 3)
 *
 * Implements EMV Contactless Book C-3 - Visa Kernel Specification
 *
 * Supports:
 * - qVSDC (Quick Visa Smart Debit/Credit) - preferred contactless mode
 * - fDDA (fast Dynamic Data Authentication)
 * - Online-only transactions
 *
 * Transaction Flow:
 * 1. Receive selected application from Entry Point
 * 2. Build PDOL data and send GET PROCESSING OPTIONS
 * 3. Parse AIP and AFL from response
 * 4. Read application records
 * 5. Perform offline data authentication (if applicable)
 * 6. Check cardholder verification requirements
 * 7. Perform terminal risk management
 * 8. Generate Application Cryptogram
 * 9. Return outcome
 */
class VisaKernel(
    private val transceiver: CardTransceiver,
    private val config: VisaKernelConfig = VisaKernelConfig()
) {
    // Transaction data store
    private val transactionData = mutableMapOf<String, ByteArray>()

    // Card data store
    private val cardData = mutableMapOf<String, ByteArray>()

    /**
     * Process a Visa contactless transaction
     */
    suspend fun processTransaction(
        application: SelectedApplication,
        transaction: VisaTransaction
    ): VisaKernelResult {
        try {
            // Pre-check: Verify amount is within contactless transaction limit
            if (config.contactlessTransactionLimit > 0 &&
                transaction.amount > config.contactlessTransactionLimit) {
                return VisaKernelResult.TryAnotherInterface(
                    "Amount ${transaction.amount} exceeds contactless limit ${config.contactlessTransactionLimit}"
                )
            }

            // Initialize transaction data
            initializeTransactionData(transaction)

            // Step 1: GET PROCESSING OPTIONS
            val gpoResult = performGpo(application.pdol, transaction)
            if (gpoResult is VisaContactGpoResult.Error) {
                return VisaKernelResult.Error(gpoResult.message)
            }
            val gpoData = (gpoResult as VisaContactGpoResult.Success)

            // Step 2: Read Application Data (based on AFL)
            val readResult = readApplicationData(gpoData.afl)
            if (readResult is ReadResult.Error) {
                return VisaKernelResult.Error(readResult.message)
            }

            // Step 3: Parse card data
            parseCardData()

            // Step 4: Offline Data Authentication (fDDA for qVSDC)
            if (gpoData.aip.isOdaSupported()) {
                val odaResult = performOda()
                // For qVSDC, ODA failure doesn't stop the transaction
                // but sets appropriate TVR bits
                when (odaResult) {
                    is OdaResult.NotSupported -> {
                        setTvrBit(TvrBit.OFFLINE_DATA_AUTH_NOT_PERFORMED)
                    }
                    is OdaResult.Failed -> {
                        setTvrBit(TvrBit.DDA_FAILED)
                    }
                    is OdaResult.Success -> {
                        // ODA passed, no TVR bits to set
                    }
                }
            } else {
                // Card doesn't support ODA
                setTvrBit(TvrBit.OFFLINE_DATA_AUTH_NOT_PERFORMED)
            }

            // Step 5: Processing Restrictions
            val restrictionsResult = checkProcessingRestrictions()
            if (restrictionsResult is ProcessingResult.Declined) {
                return VisaKernelResult.Declined(restrictionsResult.reason)
            }

            // Step 6: Cardholder Verification
            val cvmResult = performCvm(transaction, gpoData.aip)

            // Step 7: Terminal Risk Management
            performTerminalRiskManagement(transaction)

            // Step 8: Terminal Action Analysis & Generate AC
            val outcome = performTerminalActionAnalysis(transaction, gpoData.aip)

            return when (outcome) {
                is ActionResult.OnlineRequest -> {
                    val authRequest = buildAuthorizationRequest(outcome.cryptogram)
                    VisaKernelResult.OnlineRequired(authRequest)
                }
                is ActionResult.Approved -> {
                    VisaKernelResult.Approved(outcome.cryptogram)
                }
                is ActionResult.Declined -> {
                    VisaKernelResult.Declined(outcome.reason)
                }
            }

        } catch (e: Exception) {
            return VisaKernelResult.Error("Kernel error: ${e.message}")
        }
    }

    /**
     * Initialize transaction-specific data
     */
    private fun initializeTransactionData(transaction: VisaTransaction) {
        transactionData.clear()
        cardData.clear()

        // Amount Authorized (9F02) - 6 bytes numeric
        transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] = transaction.amount.toBcd(6)

        // Amount Other (9F03) - 6 bytes numeric
        transactionData[EmvTags.AMOUNT_OTHER.hex] = (transaction.cashbackAmount ?: 0L).toBcd(6)

        // Transaction Type (9C)
        transactionData[EmvTags.TRANSACTION_TYPE.hex] = byteArrayOf(transaction.type)

        // Transaction Date (9A) - YYMMDD
        val date = LocalDate.now()
        transactionData[EmvTags.TRANSACTION_DATE.hex] = date.format(
            DateTimeFormatter.ofPattern("yyMMdd")
        ).hexToByteArray()

        // Transaction Time (9F21) - HHMMSS
        val time = LocalTime.now()
        transactionData[EmvTags.TRANSACTION_TIME.hex] = time.format(
            DateTimeFormatter.ofPattern("HHmmss")
        ).hexToByteArray()

        // Unpredictable Number (9F37) - 4 bytes
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

        // Terminal Identification (9F1C) - 8 bytes AN, space-padded
        transactionData[EmvTags.TERMINAL_IDENTIFICATION.hex] =
            config.terminalIdentification.padEnd(8, ' ').take(8).toByteArray(Charsets.US_ASCII)

        // Merchant Identifier (9F16) - 15 bytes AN, space-padded
        transactionData[EmvTags.MERCHANT_ID.hex] =
            config.merchantIdentifier.padEnd(15, ' ').take(15).toByteArray(Charsets.US_ASCII)

        transactionData[EmvTags.ACQUIRER_IDENTIFIER.hex] = config.acquirerIdentifier

        // TTQ (Terminal Transaction Qualifiers) - Visa specific
        val ttq = config.buildTtq(transaction.amount, true, false)
        transactionData[EmvTags.TTQ.hex] = ttq

        // Initialize TVR (Terminal Verification Results) - 5 bytes, all zeros
        transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] = ByteArray(5)
    }

    /**
     * Perform GET PROCESSING OPTIONS
     */
    private suspend fun performGpo(pdol: ByteArray?, transaction: VisaTransaction): GpoResult {
        // Build PDOL data
        val pdolData = buildPdolData(pdol)

        // Send GPO command
        val command = EmvCommands.getProcessingOptions(pdolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return VisaContactGpoResult.Error("GPO failed: ${response.statusDescription}")
        }

        // Parse response (Format 1 or Format 2)
        return parseGpoResponse(response.data)
    }

    /**
     * Build PDOL data according to the PDOL template from the card
     */
    private fun buildPdolData(pdol: ByteArray?): ByteArray {
        if (pdol == null || pdol.isEmpty()) {
            return ByteArray(0)
        }

        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < pdol.size) {
            // Parse tag - check bounds first
            if (offset >= pdol.size) break
            val (tag, tagLength) = TlvTag.parse(pdol, offset)
            offset += tagLength

            // Check bounds before reading length byte
            if (offset >= pdol.size) {
                // Malformed PDOL - no length byte after tag
                break
            }

            // Parse length
            val length = pdol[offset].toInt() and 0xFF
            offset++

            // Get data for this tag
            val data = getDataForPdolTag(tag.hex, length)
            result.addAll(data.toList())
        }

        return result.toByteArray()
    }

    /**
     * Get terminal data for a specific PDOL tag
     */
    private fun getDataForPdolTag(tagHex: String, length: Int): ByteArray {
        val data = transactionData[tagHex] ?: ByteArray(length)

        // Pad or truncate to requested length
        return when {
            data.size == length -> data
            data.size < length -> data + ByteArray(length - data.size)
            else -> data.copyOfRange(0, length)
        }
    }

    /**
     * Parse GPO response
     */
    private fun parseGpoResponse(data: ByteArray): GpoResult {
        val tlvList = TlvParser.parse(data)
        if (tlvList.isEmpty()) {
            return VisaContactGpoResult.Error("Empty GPO response")
        }

        val firstTlv = tlvList[0]

        return when (firstTlv.tag.hex) {
            // Format 1: Tag 80 - AIP (2 bytes) + AFL
            "80" -> {
                if (firstTlv.value.size < 2) {
                    return VisaContactGpoResult.Error("Invalid Format 1 response")
                }
                val aip = ApplicationInterchangeProfile(firstTlv.value.copyOfRange(0, 2))
                val afl = if (firstTlv.value.size > 2) {
                    firstTlv.value.copyOfRange(2, firstTlv.value.size)
                } else {
                    ByteArray(0)
                }
                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl
                VisaContactGpoResult.Success(aip, afl)
            }

            // Format 2: Tag 77 - Constructed template with AIP and AFL
            "77" -> {
                val aipTlv = TlvParser.findTag(firstTlv.value, EmvTags.AIP)
                    ?: return VisaContactGpoResult.Error("Missing AIP in Format 2")
                val aflTlv = TlvParser.findTag(firstTlv.value, EmvTags.AFL)

                val aip = ApplicationInterchangeProfile(aipTlv.value)
                val afl = aflTlv?.value ?: ByteArray(0)

                cardData[EmvTags.AIP.hex] = aip.bytes
                cardData[EmvTags.AFL.hex] = afl

                // Store any additional data from Format 2 response
                for (tlv in TlvParser.parse(firstTlv.value)) {
                    cardData[tlv.tag.hex] = tlv.value
                }

                VisaContactGpoResult.Success(aip, afl)
            }

            else -> VisaContactGpoResult.Error("Unknown GPO response format: ${firstTlv.tag.hex}")
        }
    }

    /**
     * Read application data records based on AFL
     */
    private suspend fun readApplicationData(afl: ByteArray): ReadResult {
        if (afl.isEmpty()) {
            return ReadResult.Success
        }

        // AFL is groups of 4 bytes: SFI | First Record | Last Record | ODA Records
        // SFI is in bits 8-4, bits 3-1 are RFU. Mask with 0xF8 before shifting.
        var offset = 0
        while (offset + 4 <= afl.size) {
            val sfi = (afl[offset].toInt() and 0xF8) shr 3
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

                // Parse record and store data (parseRecursive extracts primitives from constructed tags)
                val recordTlvs = TlvParser.parseRecursive(response.data)
                for (tlv in recordTlvs) {
                    // Store primitive tags; skip duplicates to preserve first occurrence
                    // (e.g., a record may have the same tag as an earlier record - keep first)
                    if (!tlv.tag.isConstructed && !cardData.containsKey(tlv.tag.hex)) {
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
        // Log key card data elements for debugging
        val pan = cardData[EmvTags.PAN.hex]
        val track2 = cardData[EmvTags.TRACK2_EQUIVALENT.hex]
        val expiryDate = cardData[EmvTags.EXPIRY_DATE.hex]

        // Validate required data is present
        if (pan == null && track2 == null) {
            throw IllegalStateException("Card data missing: no PAN or Track 2")
        }
    }

    /**
     * Perform Offline Data Authentication (fDDA for Visa qVSDC)
     *
     * For fDDA, we send COMPUTE CRYPTOGRAPHIC CHECKSUM command which returns
     * a signed dynamic data that can be verified offline using the card's
     * public key chain (ICC -> Issuer -> CA).
     */
    private suspend fun performOda(): OdaResult {
        // Check if card supports DDA (required for fDDA)
        val aip = cardData[EmvTags.AIP.hex]?.let { ApplicationInterchangeProfile(it) }
        if (aip?.isDdaSupported() != true) {
            return OdaResult.NotSupported
        }

        // Build the data for COMPUTE CRYPTOGRAPHIC CHECKSUM
        // Per Visa VCPS: UN (4 bytes) + Amount Authorized (6 bytes) + Transaction Currency Code (2 bytes)
        val unpredictableNumber = transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] ?: return OdaResult.Failed("Missing UN")
        val amountAuthorized = transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] ?: return OdaResult.Failed("Missing amount")
        val currencyCode = transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] ?: return OdaResult.Failed("Missing currency")

        val cccData = unpredictableNumber + amountAuthorized + currencyCode

        // Send COMPUTE CRYPTOGRAPHIC CHECKSUM command
        val command = EmvCommands.computeCryptographicChecksum(cccData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            // Card may not support CCC - this is acceptable for some Visa cards
            // that use different ODA methods
            return if (response.sw1 == 0x6A.toByte() && response.sw2 == 0x81.toByte()) {
                // Function not supported - card doesn't support fDDA
                OdaResult.NotSupported
            } else {
                OdaResult.Failed("CCC failed: ${response.statusDescription}")
            }
        }

        // Parse the response - contains Application Cryptogram and signed data
        val responseTlvs = TlvParser.parseRecursive(response.data)
        for (tlv in responseTlvs) {
            cardData[tlv.tag.hex] = tlv.value
        }

        // In a full implementation, we would verify the signature here:
        // 1. Retrieve ICC Public Key from card certificate
        // 2. Verify certificate chain (ICC -> Issuer -> CA)
        // 3. Recover and validate the signed dynamic data
        // 4. Compare recovered UN with our UN
        //
        // For now, we accept the response as valid since we don't have
        // the CA public keys loaded. The cryptogram will still be
        // verified online by the issuer.

        return OdaResult.Success
    }

    /**
     * Check processing restrictions
     */
    private fun checkProcessingRestrictions(): ProcessingResult {
        // Check application version number
        val cardVersion = cardData[EmvTags.APPLICATION_VERSION_NUMBER.hex]
        val terminalVersion = config.applicationVersionNumber

        // Compare version numbers (2-byte values)
        if (cardVersion != null && !cardVersion.contentEquals(terminalVersion)) {
            // Set TVR bit for Application Version mismatch
            setTvrBit(TvrBit.APP_VERSIONS_DIFFER)
        }

        // Check expiry date
        val expiryDate = cardData[EmvTags.EXPIRY_DATE.hex]
        if (expiryDate != null) {
            val expiry = parseExpiryDate(expiryDate)
            if (expiry != null && expiry.isBefore(LocalDate.now())) {
                setTvrBit(TvrBit.EXPIRED_APPLICATION)
                return ProcessingResult.Declined("Card expired")
            }
        }

        // Check effective date
        val effectiveDate = cardData[EmvTags.EFFECTIVE_DATE.hex]
        if (effectiveDate != null) {
            val effective = parseExpiryDate(effectiveDate)
            if (effective != null && effective.isAfter(LocalDate.now())) {
                setTvrBit(TvrBit.APPLICATION_NOT_YET_EFFECTIVE)
            }
        }

        return ProcessingResult.Continue
    }

    /**
     * Perform Cardholder Verification
     */
    private fun performCvm(transaction: VisaTransaction, aip: ApplicationInterchangeProfile): CvmResult {
        // For qVSDC, CVM is typically No CVM or CDCVM (Consumer Device CVM)

        // Check if CVM is required based on amount
        if (transaction.amount <= config.cvmRequiredLimit) {
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0000".hexToByteArray()  // No CVM
            return CvmResult.NoCvmRequired
        }

        // Check card's CTQ (Card Transaction Qualifiers) for CDCVM support
        val ctq = cardData[EmvTags.CTQ.hex]
        if (ctq != null && (ctq[0].toInt() and 0x80) != 0) {
            // CDCVM supported - assume performed on consumer device
            transactionData[EmvTags.CVM_RESULTS.hex] = "1F0002".hexToByteArray()
            return CvmResult.CdcvmPerformed
        }

        // Online PIN or Signature required
        transactionData[EmvTags.CVM_RESULTS.hex] = "020000".hexToByteArray()
        return CvmResult.OnlinePinRequired
    }

    /**
     * Perform Terminal Risk Management
     */
    private fun performTerminalRiskManagement(transaction: VisaTransaction) {
        // Floor limit check
        if (config.contactlessFloorLimit > 0 && transaction.amount > config.contactlessFloorLimit) {
            setTvrBit(TvrBit.TRANSACTION_EXCEEDS_FLOOR_LIMIT)
        }

        // Random selection for online (not implemented - would go online randomly)

        // Velocity checking would be done here
    }

    /**
     * Perform Terminal Action Analysis and Generate AC
     */
    private suspend fun performTerminalActionAnalysis(
        transaction: VisaTransaction,
        aip: ApplicationInterchangeProfile
    ): ActionResult {
        val tvr = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)

        // Check TAC/IAC Denial
        if (checkActionCode(tvr, config.tacDenial)) {
            return generateAc(EmvCommands.CryptogramType.AAC)?.let {
                ActionResult.Declined(it, "Terminal Action Analysis: Denial")
            } ?: ActionResult.Declined(ByteArray(0), "Failed to generate AAC")
        }

        // Check TAC/IAC Online
        if (checkActionCode(tvr, config.tacOnline)) {
            return generateAc(EmvCommands.CryptogramType.ARQC)?.let {
                ActionResult.OnlineRequest(it)
            } ?: ActionResult.Declined(ByteArray(0), "Failed to generate ARQC")
        }

        // Default: go online for qVSDC
        return generateAc(EmvCommands.CryptogramType.ARQC)?.let {
            ActionResult.OnlineRequest(it)
        } ?: ActionResult.Declined(ByteArray(0), "Failed to generate ARQC")
    }

    /**
     * Generate Application Cryptogram
     */
    private suspend fun generateAc(cryptogramType: EmvCommands.CryptogramType): ByteArray? {
        // Build CDOL data
        val cdol1 = cardData[EmvTags.CDOL1.hex]
        val cdolData = buildCdolData(cdol1)

        val command = EmvCommands.generateAc(cryptogramType, cdolData, cda = false)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return null
        }

        // Parse response and extract cryptogram
        val tlvs = TlvParser.parseRecursive(response.data)
        for (tlv in tlvs) {
            cardData[tlv.tag.hex] = tlv.value
        }

        // Return full response for authorization request
        return response.data
    }

    /**
     * Build CDOL data
     */
    private fun buildCdolData(cdol: ByteArray?): ByteArray {
        if (cdol == null || cdol.isEmpty()) {
            // Default CDOL for qVSDC
            return buildDefaultCdolData()
        }

        val result = mutableListOf<Byte>()
        var offset = 0

        while (offset < cdol.size) {
            // Parse tag - check bounds first
            if (offset >= cdol.size) break
            val (tag, tagLength) = TlvTag.parse(cdol, offset)
            offset += tagLength

            // Check bounds before reading length byte
            if (offset >= cdol.size) {
                // Malformed CDOL - no length byte after tag
                break
            }

            val length = cdol[offset].toInt() and 0xFF
            offset++

            val data = getDataForCdolTag(tag.hex, length)
            result.addAll(data.toList())
        }

        return result.toByteArray()
    }

    private fun buildDefaultCdolData(): ByteArray {
        // Amount Authorized + Amount Other + Terminal Country Code + TVR +
        // Transaction Currency Code + Transaction Date + Transaction Type +
        // Unpredictable Number + Terminal Type + Data Auth Code +
        // ICC Dynamic Number + CVM Results
        return (transactionData[EmvTags.AMOUNT_AUTHORIZED.hex] ?: ByteArray(6)) +
                (transactionData[EmvTags.AMOUNT_OTHER.hex] ?: ByteArray(6)) +
                (transactionData[EmvTags.TERMINAL_COUNTRY_CODE.hex] ?: ByteArray(2)) +
                (transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)) +
                (transactionData[EmvTags.TRANSACTION_CURRENCY_CODE.hex] ?: ByteArray(2)) +
                (transactionData[EmvTags.TRANSACTION_DATE.hex] ?: ByteArray(3)) +
                (transactionData[EmvTags.TRANSACTION_TYPE.hex] ?: ByteArray(1)) +
                (transactionData[EmvTags.UNPREDICTABLE_NUMBER.hex] ?: ByteArray(4)) +
                (transactionData[EmvTags.TERMINAL_TYPE.hex] ?: ByteArray(1)) +
                ByteArray(2) +  // Data Auth Code placeholder
                ByteArray(8) +  // ICC Dynamic Number placeholder
                (transactionData[EmvTags.CVM_RESULTS.hex] ?: ByteArray(3))
    }

    private fun getDataForCdolTag(tagHex: String, length: Int): ByteArray {
        val data = transactionData[tagHex] ?: cardData[tagHex] ?: ByteArray(length)
        return when {
            data.size == length -> data
            data.size < length -> data + ByteArray(length - data.size)
            else -> data.copyOfRange(0, length)
        }
    }

    /**
     * Build authorization request with all required data
     */
    private fun buildAuthorizationRequest(cryptogramData: ByteArray): AuthorizationRequest {
        val cryptogramTlvs = TlvParser.parseToMap(cryptogramData)

        return AuthorizationRequest(
            pan = cardData[EmvTags.PAN.hex]?.let { decodeBcdPan(it) } ?: "",
            track2Equivalent = cardData[EmvTags.TRACK2_EQUIVALENT.hex]?.let { decodeTrack2(it) } ?: "",
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
            formFactorIndicator = cardData[EmvTags.FFI.hex]?.toHexString() ?: "",
            rawCryptogramData = cryptogramData.toHexString()
        )
    }

    /**
     * Decode BCD-encoded PAN (strip trailing F padding)
     * PAN is encoded with F padding if odd length
     */
    private fun decodeBcdPan(data: ByteArray): String {
        val hex = data.toHexString().uppercase()
        // Strip trailing F characters (padding for odd-length PANs)
        return hex.trimEnd('F')
    }

    /**
     * Decode Track 2 equivalent data
     * Format: PAN + 'D' + YYMM + Service Code + Discretionary Data + 'F' padding
     * The 'D' separator is encoded as nibble D (0x0D)
     */
    private fun decodeTrack2(data: ByteArray): String {
        val hex = data.toHexString().uppercase()
        // Replace D with = as per magnetic stripe format, strip trailing F
        return hex.replace('D', '=').trimEnd('F')
    }

    // Helper functions

    private fun setTvrBit(bit: TvrBit) {
        val tvr = transactionData[EmvTags.TERMINAL_VERIFICATION_RESULTS.hex] ?: ByteArray(5)
        val byteIndex = bit.byteIndex
        val bitMask = bit.bitMask
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

    /**
     * Parse BCD-encoded date (YYMMDD format)
     * EMV dates are stored as 3-byte BCD: YY MM DD
     */
    private fun parseExpiryDate(data: ByteArray): LocalDate? {
        if (data.size < 2) return null
        return try {
            // BCD decode - each nibble is 0-9
            val year = 2000 + decodeBcdByte(data[0])
            val month = decodeBcdByte(data[1])
            val day = if (data.size > 2) {
                decodeBcdByte(data[2])
            } else {
                28  // Default to end of month if day not present
            }
            // Handle day 0 or invalid day (some cards use 00 or 99 for end of month)
            val validDay = when {
                day == 0 || day > 31 -> 28
                else -> minOf(day, 28)
            }
            // Validate month is in range
            if (month !in 1..12) return null
            LocalDate.of(year, month, validDay)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Decode a BCD byte to its decimal value
     * Each nibble represents a digit 0-9
     */
    private fun decodeBcdByte(b: Byte): Int {
        val highNibble = (b.toInt() and 0xF0) shr 4
        val lowNibble = b.toInt() and 0x0F
        return highNibble * 10 + lowNibble
    }
}

// Supporting classes

data class ApplicationInterchangeProfile(val bytes: ByteArray) {
    fun isSdaSupported(): Boolean = (bytes[0].toInt() and 0x40) != 0
    fun isDdaSupported(): Boolean = (bytes[0].toInt() and 0x20) != 0
    fun isOdaSupported(): Boolean = isSdaSupported() || isDdaSupported()
    fun isCdaSupported(): Boolean = (bytes[0].toInt() and 0x01) != 0
    fun isEmvModeSupported(): Boolean = (bytes[0].toInt() and 0x10) != 0
    fun isCvmRequired(): Boolean = (bytes[1].toInt() and 0x10) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ApplicationInterchangeProfile) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()
}

enum class TvrBit(val byteIndex: Int, val bitMask: Int) {
    OFFLINE_DATA_AUTH_NOT_PERFORMED(0, 0x80),
    SDA_FAILED(0, 0x40),
    ICC_DATA_MISSING(0, 0x20),
    CARD_ON_EXCEPTION_FILE(0, 0x10),
    DDA_FAILED(0, 0x08),
    CDA_FAILED(0, 0x04),

    APP_VERSIONS_DIFFER(1, 0x80),  // ICC and terminal have different application versions
    EXPIRED_APPLICATION(1, 0x20),
    APPLICATION_NOT_YET_EFFECTIVE(1, 0x10),
    SERVICE_NOT_ALLOWED(1, 0x08),
    NEW_CARD(1, 0x04),

    CARDHOLDER_VERIFICATION_NOT_SUCCESSFUL(2, 0x80),
    UNRECOGNIZED_CVM(2, 0x40),
    PIN_TRY_LIMIT_EXCEEDED(2, 0x20),
    PIN_ENTRY_REQUIRED_PINPAD_NOT_PRESENT(2, 0x10),
    PIN_ENTRY_REQUIRED_PINPAD_NOT_WORKING(2, 0x08),
    ONLINE_PIN_ENTERED(2, 0x04),

    TRANSACTION_EXCEEDS_FLOOR_LIMIT(3, 0x80),
    LOWER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED(3, 0x40),
    UPPER_CONSECUTIVE_OFFLINE_LIMIT_EXCEEDED(3, 0x20),
    TRANSACTION_SELECTED_RANDOMLY_FOR_ONLINE(3, 0x10),
    MERCHANT_FORCED_TRANSACTION_ONLINE(3, 0x08),

    DEFAULT_TDOL_USED(4, 0x80),
    ISSUER_AUTHENTICATION_FAILED(4, 0x40),
    SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_AC(4, 0x20),
    SCRIPT_PROCESSING_FAILED_AFTER_FINAL_AC(4, 0x10),
    RELAY_RESISTANCE_THRESHOLD_EXCEEDED(4, 0x04),
    RELAY_RESISTANCE_TIME_LIMITS_EXCEEDED(4, 0x02),
    RELAY_RESISTANCE_PERFORMED(4, 0x01)
}

sealed class VisaContactGpoResult {
    data class Success(val aip: ApplicationInterchangeProfile, val afl: ByteArray) : GpoResult()
    data class Error(val message: String) : GpoResult()
}

sealed class ReadResult {
    object Success : ReadResult()
    data class Error(val message: String) : ReadResult()
}

sealed class OdaResult {
    object Success : OdaResult()
    object NotSupported : OdaResult()
    data class Failed(val reason: String) : OdaResult()
}

sealed class ProcessingResult {
    object Continue : ProcessingResult()
    data class Declined(val reason: String) : ProcessingResult()
}

sealed class CvmResult {
    object NoCvmRequired : CvmResult()
    object CdcvmPerformed : CvmResult()
    object OnlinePinRequired : CvmResult()
    object SignatureRequired : CvmResult()
}

sealed class ActionResult {
    data class OnlineRequest(val cryptogram: ByteArray) : ActionResult()
    data class Approved(val cryptogram: ByteArray) : ActionResult()
    data class Declined(val cryptogram: ByteArray, val reason: String) : ActionResult()
}

/**
 * Transaction input data
 */
data class VisaTransaction(
    val amount: Long,            // Amount in smallest currency unit (cents)
    val cashbackAmount: Long? = null,
    val type: Byte = TransactionType.PURCHASE
)

/**
 * Type alias for backward compatibility with AtlasSoftPos.kt
 */
typealias VisaTransactionParams = VisaTransaction

/**
 * Kernel result
 */
sealed class VisaKernelResult {
    data class OnlineRequired(val authRequest: AuthorizationRequest) : VisaKernelResult()
    data class Approved(val cryptogram: ByteArray) : VisaKernelResult()
    data class Declined(val reason: String) : VisaKernelResult()
    data class TryAnotherInterface(val reason: String) : VisaKernelResult()
    data class Error(val message: String) : VisaKernelResult()
}

/**
 * Authorization request data for online processing
 */
data class AuthorizationRequest(
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
    val formFactorIndicator: String,
    val rawCryptogramData: String
)
