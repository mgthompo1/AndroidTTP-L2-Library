package com.atlas.softpos.kernel.visa

import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.dol.DataStore
import com.atlas.softpos.core.dol.DolParser
import com.atlas.softpos.core.dol.TerminalConfiguration
import com.atlas.softpos.core.dol.TransactionData
import com.atlas.softpos.core.tlv.EmvTags
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.tlv.Tlv
import com.atlas.softpos.crypto.CaPublicKeyStore
import com.atlas.softpos.crypto.OfflineDataAuthentication
import com.atlas.softpos.crypto.OdaResult
import com.atlas.softpos.crypto.OdaFailureReason
import com.atlas.softpos.crypto.StandaloneOdaProcessor
import com.atlas.softpos.kernel.common.*
import com.atlas.softpos.security.SecureMemory
import timber.log.Timber
import java.security.SecureRandom
import java.util.*

// Tag value for internal ODA data storage (not a standard EMV tag)
private const val TAG_ODA_DATA = 0xDF8101

/**
 * Visa Contactless Kernel (qVSDC/VCPS)
 *
 * Production implementation following:
 * - Visa Contactless Payment Specification (VCPS) v2.2
 * - EMV Contactless Book C-3 (Visa)
 * - EMV Book 3 & 4
 *
 * Supports:
 * - qVSDC (Quick VSDC) - Full EMV with online cryptogram
 * - fDDA (Fast DDA) - Optimized offline data authentication
 * - MSD (Magnetic Stripe Data) - Fallback mode
 *
 * Transaction Flow:
 * 1. SELECT → Parse FCI/PDOL
 * 2. GPO → Get AIP/AFL, validate CTQ
 * 3. READ RECORD → Gather card data
 * 4. ODA → fDDA or full DDA based on AIP
 * 5. Processing Restrictions
 * 6. CVM Processing (CDCVM for SoftPOS)
 * 7. Terminal Risk Management
 * 8. Terminal Action Analysis
 * 9. GENERATE AC → Get cryptogram
 */
class VisaContactlessKernel(
    private val transceiver: CardTransceiver,
    private val config: VisaKernelConfiguration
) {
    // Card data storage
    private val cardData = mutableMapOf<String, Tlv>()
    private val dataStore = DataStore()

    // Terminal status
    private val tvr = TerminalVerificationResults()
    private val tsi = TransactionStatusInformation()

    // State
    private var selectedAid: ByteArray? = null
    private var aip: ByteArray? = null
    private var afl: ByteArray? = null
    private var ctq: ByteArray? = null

    /**
     * Process a contactless transaction
     */
    suspend fun processTransaction(
        aid: ByteArray,
        pdol: ByteArray?,
        transaction: VisaTransactionData
    ): VisaKernelOutcome {
        try {
            Timber.d("=== VISA KERNEL START ===")
            selectedAid = aid

            // Initialize terminal data
            initializeTerminalData(transaction)

            // Step 1: GPO
            val gpoResult = performGpo(pdol)
            if (gpoResult !is GpoResult.Success) {
                return handleGpoError(gpoResult)
            }

            // Validate AIP
            if (!validateAip(gpoResult.aip)) {
                return VisaKernelOutcome.EndApplication("AIP validation failed")
            }

            aip = gpoResult.aip
            afl = gpoResult.afl
            ctq = gpoResult.ctq

            // Check CTQ for online required
            if (isOnlineOnlyCtq(ctq)) {
                Timber.d("CTQ indicates online-only")
            }

            // Step 2: Read Application Data
            val readResult = readApplicationData(gpoResult.afl)
            if (!readResult) {
                tvr.iccDataMissing = true
                return VisaKernelOutcome.EndApplication("Failed to read application data")
            }

            // Extract critical data
            val pan = cardData["5A"]?.value
            val track2 = cardData["57"]?.value
            val expiryDate = cardData["5F24"]?.value

            if (pan == null || track2 == null) {
                tvr.iccDataMissing = true
                return VisaKernelOutcome.EndApplication("Missing critical card data")
            }

            // Step 3: Offline Data Authentication
            val odaOutcome = performOda(gpoResult.aip, transaction)
            tsi.odaPerformed = true
            if (odaOutcome is OdaOutcome.Failed) {
                // ODA failure - set TVR bits, may still proceed online
                Timber.w("ODA failed: ${odaOutcome.reason}")
            }

            // Step 4: Processing Restrictions
            checkProcessingRestrictions(expiryDate)

            // Step 5: Cardholder Verification
            val cvmOutcome = performCvm(transaction.amount)
            tsi.cvmPerformed = true

            // Step 6: Terminal Risk Management
            performTerminalRiskManagement(transaction)
            tsi.terminalRiskManagementPerformed = true

            // Step 7: Terminal Action Analysis
            val decision = performTerminalActionAnalysis()

            // Step 8: Generate AC
            return generateApplicationCryptogram(decision, transaction, pan, track2)

        } catch (e: Exception) {
            Timber.e(e, "Visa kernel exception")
            return VisaKernelOutcome.EndApplication("Kernel error: ${e.message}")
        }
    }

    /**
     * Initialize terminal data store
     */
    private fun initializeTerminalData(transaction: VisaTransactionData) {
        tvr.reset()
        tsi.reset()
        cardData.clear()
        dataStore.clear()

        // Generate unpredictable number
        val un = ByteArray(4)
        SecureRandom().nextBytes(un)

        // Build TTQ
        val ttq = buildTtq(transaction)

        // Current date/time
        val calendar = Calendar.getInstance()
        val date = byteArrayOf(
            ((calendar.get(Calendar.YEAR) % 100) / 10 * 16 + (calendar.get(Calendar.YEAR) % 10)).toByte(),
            ((calendar.get(Calendar.MONTH) + 1) / 10 * 16 + (calendar.get(Calendar.MONTH) + 1) % 10).toByte(),
            (calendar.get(Calendar.DAY_OF_MONTH) / 10 * 16 + calendar.get(Calendar.DAY_OF_MONTH) % 10).toByte()
        )
        val time = byteArrayOf(
            (calendar.get(Calendar.HOUR_OF_DAY) / 10 * 16 + calendar.get(Calendar.HOUR_OF_DAY) % 10).toByte(),
            (calendar.get(Calendar.MINUTE) / 10 * 16 + calendar.get(Calendar.MINUTE) % 10).toByte(),
            (calendar.get(Calendar.SECOND) / 10 * 16 + calendar.get(Calendar.SECOND) % 10).toByte()
        )

        val terminalConfig = TerminalConfiguration(
            countryCode = config.terminalCountryCode,
            currencyCode = config.transactionCurrencyCode,
            terminalCapabilities = config.terminalCapabilities,
            terminalType = config.terminalType,
            additionalTerminalCapabilities = config.additionalTerminalCapabilities,
            ifdSerialNumber = config.ifdSerialNumber,
            mcc = config.merchantCategoryCode,
            ttq = ttq,
            applicationVersion = byteArrayOf(0x00, 0x8C.toByte()), // Visa version
            acquirerId = config.acquirerId,
            terminalId = config.terminalId,
            merchantId = config.merchantId
        )

        val transactionData = TransactionData(
            amountAuthorized = transaction.amount,
            amountOther = transaction.cashbackAmount ?: 0,
            date = date,
            time = time,
            type = transaction.transactionType,
            unpredictableNumber = un,
            sequenceNumber = config.transactionSequenceNumber
        )

        dataStore.populateTerminalData(terminalConfig, transactionData)
    }

    /**
     * Build Terminal Transaction Qualifiers (TTQ)
     *
     * Byte 1:
     *   b8: MSD supported
     *   b7: Reserved
     *   b6: qVSDC supported
     *   b5: EMV contact chip supported
     *   b4: Offline-only reader
     *   b3: Online PIN supported
     *   b2: Signature supported
     *   b1: Offline Data Authentication for Online Auth supported
     *
     * Byte 2:
     *   b8: Online cryptogram required
     *   b7: CVM required
     *   b6: Offline PIN supported (contact)
     *   b5-b1: Reserved
     *
     * Byte 3:
     *   b8: Issuer Update Processing supported
     *   b7: Consumer Device CVM supported
     *   b6-b1: Reserved
     *
     * Byte 4: Reserved
     */
    private fun buildTtq(transaction: VisaTransactionData): ByteArray {
        var byte1 = 0x00
        var byte2 = 0x00
        var byte3 = 0x00
        var byte4 = 0x00

        // Byte 1
        if (config.supportMsd) byte1 = byte1 or 0x80
        byte1 = byte1 or 0x20  // qVSDC supported (always for SoftPOS)
        if (config.supportOnlinePin) byte1 = byte1 or 0x08
        if (config.supportSignature) byte1 = byte1 or 0x04
        byte1 = byte1 or 0x02  // ODA for online supported

        // Byte 2
        byte2 = byte2 or 0x80  // Online cryptogram required (SoftPOS is online-only)
        if (transaction.amount > config.cvmRequiredLimit) {
            byte2 = byte2 or 0x40  // CVM required
        }

        // Byte 3
        byte3 = byte3 or 0x80  // Issuer Update Processing supported
        byte3 = byte3 or 0x40  // Consumer Device CVM supported (critical for SoftPOS)

        return byteArrayOf(byte1.toByte(), byte2.toByte(), byte3.toByte(), byte4.toByte())
    }

    /**
     * Perform GET PROCESSING OPTIONS
     */
    private suspend fun performGpo(pdol: ByteArray?): GpoResult {
        Timber.d("Performing GPO")

        // Build PDOL data
        val pdolData = if (pdol != null && pdol.isNotEmpty()) {
            DolParser.buildDolData(pdol, dataStore)
        } else {
            // No PDOL - send empty
            byteArrayOf()
        }

        // Construct command data: Tag 83 | Length | PDOL data
        val commandData = if (pdolData.isNotEmpty()) {
            byteArrayOf(0x83.toByte(), pdolData.size.toByte()) + pdolData
        } else {
            byteArrayOf(0x83.toByte(), 0x00)
        }

        val command = CommandApdu(
            cla = 0x80.toByte(),
            ins = 0xA8.toByte(),
            p1 = 0x00,
            p2 = 0x00,
            data = commandData,
            le = 0x00
        )

        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            Timber.e("GPO failed: SW=%04X", response.sw)
            return when (response.sw) {
                0x6984 -> GpoResult.ReferenceDataNotFound
                0x6985 -> GpoResult.ConditionsNotSatisfied
                0x6A81 -> GpoResult.FunctionNotSupported
                else -> GpoResult.Error("GPO failed: %04X".format(response.sw))
            }
        }

        // Parse response
        return parseGpoResponse(response.data)
    }

    /**
     * Parse GPO response (Format 1 or Format 2)
     */
    private fun parseGpoResponse(data: ByteArray): GpoResult {
        if (data.isEmpty()) {
            return GpoResult.Error("Empty GPO response")
        }

        return when (data[0]) {
            0x80.toByte() -> {
                // Format 1: 80 | Length | AIP (2) | AFL (var)
                parseGpoFormat1(data)
            }
            0x77.toByte() -> {
                // Format 2: 77 | Length | TLV data
                parseGpoFormat2(data)
            }
            else -> {
                GpoResult.Error("Unknown GPO response format: ${data[0]}")
            }
        }
    }

    /**
     * Parse GPO Format 1 (primitive)
     */
    private fun parseGpoFormat1(data: ByteArray): GpoResult {
        val tlv = TlvParser.parse(data).firstOrNull()
            ?: return GpoResult.Error("Failed to parse Format 1")

        val value = tlv.value
        if (value.size < 2) {
            return GpoResult.Error("Format 1 too short")
        }

        val aip = value.copyOfRange(0, 2)
        val afl = if (value.size > 2) value.copyOfRange(2, value.size) else byteArrayOf()

        return GpoResult.Success(
            aip = aip,
            afl = afl,
            ctq = null,
            sdad = null
        )
    }

    /**
     * Parse GPO Format 2 (constructed)
     */
    private fun parseGpoFormat2(data: ByteArray): GpoResult {
        val tlvs = TlvParser.parseRecursive(data)
        val tlvMap = tlvs.associateBy { it.tag.hex }

        val aip = tlvMap["82"]?.value
            ?: return GpoResult.Error("Missing AIP in Format 2")

        val afl = tlvMap["94"]?.value ?: byteArrayOf()
        val ctq = tlvMap["9F6C"]?.value
        val sdad = tlvMap["9F4B"]?.value  // For fDDA
        val iccDynamicNumber = tlvMap["9F4C"]?.value

        // Store for later use
        ctq?.let { cardData["9F6C"] = Tlv.fromHex("9F6C", it.toHexString()) }
        sdad?.let { cardData["9F4B"] = Tlv.fromHex("9F4B", it.toHexString()) }
        iccDynamicNumber?.let { cardData["9F4C"] = Tlv.fromHex("9F4C", it.toHexString()) }

        return GpoResult.Success(
            aip = aip,
            afl = afl,
            ctq = ctq,
            sdad = sdad
        )
    }

    /**
     * Validate Application Interchange Profile
     *
     * AIP Byte 1 bits (per EMV Book 3):
     *   b8 (0x80): Reserved for use by the payment systems
     *   b7 (0x40): SDA supported
     *   b6 (0x20): DDA supported
     *   b5 (0x10): Cardholder verification is supported
     *   b4 (0x08): Terminal risk management to be performed
     *   b3 (0x04): Issuer authentication is supported
     *   b2 (0x02): Reserved for use by the payment systems
     *   b1 (0x01): CDA supported
     *
     * For Visa qVSDC, we check if any EMV processing is indicated.
     * Card returning AIP in GPO means it supports EMV mode.
     */
    private fun validateAip(aip: ByteArray): Boolean {
        if (aip.size < 2) return false

        val aipByte1 = aip[0].toInt() and 0xFF

        // Check ODA support (SDA, DDA, or CDA)
        val supportsSda = (aipByte1 and 0x40) != 0
        val supportsDda = (aipByte1 and 0x20) != 0
        val supportsCda = (aipByte1 and 0x01) != 0
        val supportsOda = supportsSda || supportsDda || supportsCda

        // Check if terminal risk management required
        val trmRequired = (aipByte1 and 0x08) != 0

        Timber.d("AIP: ${aip.toHexString()}, SDA=$supportsSda, DDA=$supportsDda, CDA=$supportsCda, TRM=$trmRequired")

        // For qVSDC, the card has already indicated EMV support by returning AIP.
        // If MSD fallback is supported and no ODA methods available, allow MSD path.
        // Otherwise, require at least some EMV capability indication.
        return supportsOda || trmRequired || config.supportMsd
    }

    /**
     * Check if CTQ indicates online-only
     */
    private fun isOnlineOnlyCtq(ctq: ByteArray?): Boolean {
        if (ctq == null || ctq.size < 2) return false
        // CTQ Byte 1, Bit 8: Online cryptogram required
        return (ctq[0].toInt() and 0x80) != 0
    }

    /**
     * Read Application Data from AFL
     */
    private suspend fun readApplicationData(afl: ByteArray): Boolean {
        if (afl.isEmpty()) {
            Timber.d("Empty AFL - no records to read")
            return true
        }

        // AFL format: SFI (5 bits) | First Record | Last Record | ODA Records
        // Each AFL entry is 4 bytes
        if (afl.size % 4 != 0) {
            Timber.e("Invalid AFL length: ${afl.size}")
            return false
        }

        var odaData = byteArrayOf()  // Data for offline authentication

        for (i in afl.indices step 4) {
            val sfi = (afl[i].toInt() and 0xF8) shr 3
            val firstRecord = afl[i + 1].toInt() and 0xFF
            val lastRecord = afl[i + 2].toInt() and 0xFF
            val odaRecords = afl[i + 3].toInt() and 0xFF

            Timber.d("AFL entry: SFI=$sfi, First=$firstRecord, Last=$lastRecord, ODA=$odaRecords")

            for (record in firstRecord..lastRecord) {
                val recordData = readRecord(sfi, record)
                    ?: return false

                // Parse TLVs from record
                val recordTlvs = TlvParser.parseRecursive(recordData)
                for (tlv in recordTlvs) {
                    cardData[tlv.tag.hex] = tlv
                    // Log tag only, not value (may contain sensitive data like PAN/Track2)
                    Timber.v("Card data: ${tlv.tag.hex} (${tlv.value.size} bytes)")
                }

                // Accumulate ODA data
                if (record - firstRecord < odaRecords) {
                    // Exclude tag 70 wrapper for ODA
                    val innerData = if (recordData.isNotEmpty() && recordData[0] == 0x70.toByte()) {
                        TlvParser.parse(recordData).firstOrNull()?.value ?: recordData
                    } else {
                        recordData
                    }
                    odaData += innerData
                }
            }
        }

        // Store ODA data for authentication (using proprietary tag)
        dataStore.set(TAG_ODA_DATA, odaData)

        return true
    }

    /**
     * Read a single record
     */
    private suspend fun readRecord(sfi: Int, record: Int): ByteArray? {
        val p2 = ((sfi shl 3) or 0x04).toByte()

        val command = CommandApdu(
            cla = 0x00,
            ins = 0xB2.toByte(),
            p1 = record.toByte(),
            p2 = p2,
            le = 0x00
        )

        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            Timber.e("Read record failed: SFI=$sfi, Record=$record, SW=%04X", response.sw)
            return null
        }

        return response.data
    }

    /**
     * Perform Offline Data Authentication
     */
    private suspend fun performOda(aip: ByteArray, transaction: VisaTransactionData): OdaOutcome {
        // Check AIP for ODA support
        val supportsSda = (aip[0].toInt() and 0x40) != 0
        val supportsDda = (aip[0].toInt() and 0x20) != 0
        val supportsCda = (aip[0].toInt() and 0x01) != 0

        Timber.d("ODA support - SDA: $supportsSda, DDA: $supportsDda, CDA: $supportsCda")

        // Check for fDDA data from GPO
        val sdad = cardData["9F4B"]?.value
        val iccDynamicNumber = cardData["9F4C"]?.value

        if (sdad != null && iccDynamicNumber != null) {
            // Perform fDDA (fast DDA)
            return performFdda(sdad, iccDynamicNumber)
        }

        if (!supportsSda && !supportsDda && !supportsCda) {
            tvr.odaNotPerformed = true
            return OdaOutcome.NotSupported
        }

        // For full ODA, we need CA public key and certificates
        val caIndexValue = cardData["8F"]?.value
        if (caIndexValue == null || caIndexValue.isEmpty()) {
            tvr.odaNotPerformed = true
            return OdaOutcome.Failed("Missing CA Public Key Index")
        }
        val caIndex = caIndexValue[0]

        // Validate AID length before truncating
        val aid = selectedAid
        if (aid == null || aid.size < 5) {
            tvr.odaNotPerformed = true
            return OdaOutcome.Failed("Invalid AID length")
        }

        val caKey = CaPublicKeyStore.getKey(aid.copyOfRange(0, 5), caIndex)
        if (caKey == null) {
            tvr.odaNotPerformed = true
            return OdaOutcome.Failed("CA Public Key not found")
        }

        // Create ODA processor
        val oda = OfflineDataAuthentication(transceiver, cardData)
        val odaData = dataStore.get(TAG_ODA_DATA) ?: byteArrayOf()

        val result = oda.performOda(aip, odaData)

        return when (result) {
            is OdaResult.SdaSuccess -> {
                tvr.sdaSelected = true
                OdaOutcome.Success("SDA")
            }
            is OdaResult.DdaSuccess -> OdaOutcome.Success("DDA")
            is OdaResult.FddaSuccess -> OdaOutcome.Success("fDDA")
            is OdaResult.CdaPrepared -> OdaOutcome.Success("CDA prepared")
            is OdaResult.NotSupported -> {
                tvr.odaNotPerformed = true
                OdaOutcome.NotSupported
            }
            is OdaResult.Success -> OdaOutcome.Success(result.type)
            is OdaResult.Failure -> OdaOutcome.Failed(result.reason)
            is OdaResult.Failed -> {
                val reason = result.failureReason
                when {
                    reason.name.contains("SDA") || reason == OdaFailureReason.INVALID_SSAD_FORMAT -> tvr.sdaFailed = true
                    reason.name.contains("DDA") || reason == OdaFailureReason.DDA_SIGNATURE_INVALID -> tvr.ddaFailed = true
                    reason.name.contains("CDA") -> tvr.cdaFailed = true
                    reason.name.contains("FDDA") -> tvr.ddaFailed = true  // fDDA is a DDA variant
                }
                OdaOutcome.Failed(reason.name)
            }
        }
    }

    /**
     * Perform fDDA (Fast DDA) using data from GPO
     *
     * fDDA verifies the SDAD (Signed Dynamic Application Data) returned in GPO response.
     * This requires recovering the ICC public key and verifying the signature.
     */
    private fun performFdda(sdad: ByteArray, iccDynamicNumber: ByteArray): OdaOutcome {
        Timber.d("Performing fDDA")

        // Get terminal unpredictable number
        val un = dataStore.get(0x9F37) ?: return OdaOutcome.Failed("Missing UN")

        // Get CA public key index
        val caIndexValue = cardData["8F"]?.value
        if (caIndexValue == null || caIndexValue.isEmpty()) {
            tvr.ddaFailed = true
            return OdaOutcome.Failed("Missing CA Public Key Index for fDDA")
        }
        val caIndex = caIndexValue[0]

        // Validate AID
        val aid = selectedAid
        if (aid == null || aid.size < 5) {
            tvr.ddaFailed = true
            return OdaOutcome.Failed("Invalid AID for fDDA")
        }

        // Get CA public key
        val caKey = CaPublicKeyStore.getKey(aid.copyOfRange(0, 5), caIndex)
        if (caKey == null) {
            tvr.ddaFailed = true
            return OdaOutcome.Failed("CA Public Key not found for fDDA")
        }

        // Get issuer public key certificate (tag 90)
        val issuerCert = cardData["90"]?.value
        if (issuerCert == null) {
            tvr.ddaFailed = true
            return OdaOutcome.Failed("Missing Issuer Public Key Certificate")
        }

        // Get ICC public key certificate (tag 9F46)
        val iccCert = cardData["9F46"]?.value
        if (iccCert == null) {
            tvr.ddaFailed = true
            return OdaOutcome.Failed("Missing ICC Public Key Certificate")
        }

        // Build static data to authenticate from AIP
        val aip = cardData["82"]?.value ?: ByteArray(2)
        val staticDataToAuthenticate = aip  // For fDDA, static data is typically the AIP

        // Perform fDDA using StandaloneOdaProcessor
        val issuerPkCert = cardData["90"]?.value ?: run {
            tvr.ddaFailed = true
            return OdaOutcome.Failed("Missing Issuer Public Key Certificate")
        }
        val issuerPkExp = cardData["9F32"]?.value ?: byteArrayOf(0x03)
        val iccPkExp = cardData["9F47"]?.value ?: byteArrayOf(0x03)

        val fddaResult = StandaloneOdaProcessor.performFdda(
            aid = selectedAid ?: ByteArray(0),
            issuerPkCertificate = issuerPkCert,
            issuerPkExponent = issuerPkExp,
            iccPkCertificate = iccCert,
            iccPkExponent = iccPkExp,
            signedDynamicData = sdad,
            staticDataToAuthenticate = staticDataToAuthenticate,
            unpredictableNumber = un
        )

        return when (fddaResult) {
            is OdaResult.FddaSuccess -> OdaOutcome.Success("fDDA")
            is OdaResult.Failed -> {
                this.tvr.ddaFailed = true
                OdaOutcome.Failed(fddaResult.failureReason.name)
            }
            is OdaResult.Failure -> {
                this.tvr.ddaFailed = true
                OdaOutcome.Failed(fddaResult.reason)
            }
            else -> {
                this.tvr.ddaFailed = true
                OdaOutcome.Failed("Unexpected fDDA result")
            }
        }
    }

    /**
     * Check processing restrictions
     */
    private fun checkProcessingRestrictions(expiryDate: ByteArray?) {
        if (expiryDate == null || expiryDate.size < 3) {
            tvr.expiredApplication = true
            return
        }

        // Expiry format: YYMMDD (BCD encoded)
        val expYearYY = ((expiryDate[0].toInt() and 0xF0) shr 4) * 10 + (expiryDate[0].toInt() and 0x0F)
        val expMonth = ((expiryDate[1].toInt() and 0xF0) shr 4) * 10 + (expiryDate[1].toInt() and 0x0F)

        val calendar = Calendar.getInstance()
        val currentYear = calendar.get(Calendar.YEAR)
        val currentMonth = calendar.get(Calendar.MONTH) + 1

        // Convert 2-digit year to 4-digit year using sliding window
        // Cards typically valid for ~10 years, so use current century with adjustment
        val expYear = bcdYearToFullYear(expYearYY, currentYear)

        if (expYear < currentYear || (expYear == currentYear && expMonth < currentMonth)) {
            tvr.expiredApplication = true
            Timber.w("Card expired: $expMonth/$expYear")
        }

        // Check effective date if present
        val effectiveDate = cardData["5F25"]?.value
        if (effectiveDate != null && effectiveDate.size >= 3) {
            val effYearYY = ((effectiveDate[0].toInt() and 0xF0) shr 4) * 10 + (effectiveDate[0].toInt() and 0x0F)
            val effMonth = ((effectiveDate[1].toInt() and 0xF0) shr 4) * 10 + (effectiveDate[1].toInt() and 0x0F)
            val effYear = bcdYearToFullYear(effYearYY, currentYear)

            if (effYear > currentYear || (effYear == currentYear && effMonth > currentMonth)) {
                tvr.applicationNotYetEffective = true
                Timber.w("Card not yet effective: $effMonth/$effYear")
            }
        }

        // Check Application Usage Control
        val auc = cardData["9F07"]?.value
        if (auc != null && auc.size >= 2) {
            checkAuc(auc)
        }
    }

    /**
     * Check Application Usage Control
     */
    private fun checkAuc(auc: ByteArray) {
        val byte1 = auc[0].toInt()
        val byte2 = auc[1].toInt()

        // Byte 1 checks
        val domesticCashAllowed = (byte1 and 0x80) != 0
        val internationalCashAllowed = (byte1 and 0x40) != 0
        val domesticGoodsAllowed = (byte1 and 0x20) != 0
        val internationalGoodsAllowed = (byte1 and 0x10) != 0
        val domesticServicesAllowed = (byte1 and 0x08) != 0
        val internationalServicesAllowed = (byte1 and 0x04) != 0
        val atmsAllowed = (byte1 and 0x02) != 0
        val nonAtmsAllowed = (byte1 and 0x01) != 0

        // For SoftPOS (non-ATM, goods/services), check appropriate bits
        if (!nonAtmsAllowed) {
            tvr.serviceNotAllowed = true
        }
    }

    /**
     * Perform CVM (Cardholder Verification Method)
     */
    private fun performCvm(amount: Long): CvmOutcome {
        val cvmList = cardData["8E"]?.value
        val ctq = this.ctq

        // Check CTQ for CVM requirements
        if (ctq != null && ctq.size >= 2) {
            // CTQ Byte 2, Bit 8: Consumer Device CVM performed
            val cdcvmPerformed = (ctq[1].toInt() and 0x80) != 0

            if (cdcvmPerformed) {
                // Card indicates CDCVM was performed on consumer device
                dataStore.set(0x9F34, byteArrayOf(0x2F, 0x00, 0x02))  // CDCVM successful
                return CvmOutcome.CdcvmPerformed
            }
        }

        // Check if CVM is required based on amount
        if (amount <= config.cvmRequiredLimit) {
            // No CVM required
            dataStore.set(0x9F34, byteArrayOf(0x1F, 0x00, 0x02))  // No CVM, successful
            return CvmOutcome.NoCvmRequired
        }

        // For SoftPOS, CDCVM is primary method
        // The actual biometric prompt is handled by the app layer
        // Here we set the appropriate CVM results

        dataStore.set(0x9F34, byteArrayOf(0x2F, 0x00, 0x01))  // CDCVM required but not performed yet
        return CvmOutcome.CdcvmRequired
    }

    /**
     * Perform Terminal Risk Management
     */
    private fun performTerminalRiskManagement(transaction: VisaTransactionData) {
        // Floor limit check
        if (transaction.amount > config.terminalFloorLimit) {
            tvr.floorLimitExceeded = true
        }

        // For SoftPOS, always force online
        tvr.merchantForcedOnline = true

        // Random selection (if configured)
        if (config.randomSelectionThreshold > 0) {
            val random = SecureRandom().nextInt(100)
            if (random < config.randomSelectionThreshold) {
                tvr.randomlySelectedOnline = true
            }
        }
    }

    /**
     * Perform Terminal Action Analysis
     */
    private fun performTerminalActionAnalysis(): CryptogramDecision {
        // Get IAC (Issuer Action Codes) and TAC (Terminal Action Codes)
        val iacDenial = cardData["9F0E"]?.value ?: ByteArray(5)
        val iacOnline = cardData["9F0F"]?.value ?: ByteArray(5)
        val iacDefault = cardData["9F0D"]?.value ?: ByteArray(5)

        val tacDenial = config.tacDenial
        val tacOnline = config.tacOnline
        val tacDefault = config.tacDefault

        // Denial check: (TVR AND (IAC-Denial OR TAC-Denial)) != 0 → AAC
        val denialResult = combineActionCodes(iacDenial, tacDenial)
        if (tvr.matchesActionCode(denialResult)) {
            Timber.d("Terminal Action Analysis: DECLINE")
            return CryptogramDecision.AAC
        }

        // Online check: (TVR AND (IAC-Online OR TAC-Online)) != 0 → ARQC
        val onlineResult = combineActionCodes(iacOnline, tacOnline)
        if (tvr.matchesActionCode(onlineResult)) {
            Timber.d("Terminal Action Analysis: ONLINE")
            return CryptogramDecision.ARQC
        }

        // Default check for offline capable terminals
        // For SoftPOS, we always go online
        Timber.d("Terminal Action Analysis: ONLINE (default for SoftPOS)")
        return CryptogramDecision.ARQC
    }

    /**
     * Combine IAC and TAC (OR operation)
     */
    private fun combineActionCodes(iac: ByteArray, tac: ByteArray): ByteArray {
        val result = ByteArray(5)
        for (i in 0 until 5) {
            val iacByte = if (i < iac.size) iac[i].toInt() else 0
            val tacByte = if (i < tac.size) tac[i].toInt() else 0
            result[i] = (iacByte or tacByte).toByte()
        }
        return result
    }

    /**
     * Generate Application Cryptogram (GENERATE AC)
     */
    private suspend fun generateApplicationCryptogram(
        decision: CryptogramDecision,
        transaction: VisaTransactionData,
        pan: ByteArray,
        track2: ByteArray
    ): VisaKernelOutcome {
        Timber.d("Generating AC: $decision")

        // Get CDOL1
        val cdol1 = cardData["8C"]?.value
        if (cdol1 == null || cdol1.isEmpty()) {
            return VisaKernelOutcome.EndApplication("Missing CDOL1")
        }

        // Update TVR in data store
        dataStore.set(0x95, tvr.toBytes())

        // Build CDOL1 data
        val cdolData = DolParser.buildDolData(cdol1, dataStore)

        // Determine reference control parameter (P1 for GENERATE AC)
        // Bits 8-7: Cryptogram type requested
        //   00 = AAC (Application Authentication Cryptogram - decline)
        //   01 = TC (Transaction Certificate - offline approve)
        //   10 = ARQC (Authorization Request Cryptogram - online)
        val p1: Byte = when (decision) {
            CryptogramDecision.AAC -> 0x00.toByte()     // AAC
            CryptogramDecision.TC -> 0x40.toByte()      // TC
            CryptogramDecision.ARQC -> 0x80.toByte()    // ARQC
        }

        val command = CommandApdu(
            cla = 0x80.toByte(),
            ins = 0xAE.toByte(),
            p1 = p1,
            p2 = 0x00,
            data = cdolData,
            le = 0x00
        )

        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return VisaKernelOutcome.EndApplication("GENERATE AC failed: %04X".format(response.sw))
        }

        // Parse response
        val acResponse = parseGenerateAcResponse(response.data)
            ?: return VisaKernelOutcome.EndApplication("Failed to parse AC response")

        // Build authorization data
        val authData = buildAuthorizationData(
            pan = pan,
            track2 = track2,
            cryptogram = acResponse.cryptogram,
            cid = acResponse.cid,
            atc = acResponse.atc,
            iad = acResponse.iad,
            transaction = transaction
        )

        // Determine outcome based on CID
        return when (acResponse.cryptogramType) {
            CryptogramType.ARQC -> {
                Timber.d("Card returned ARQC - online authorization required")
                VisaKernelOutcome.OnlineRequest(authData)
            }
            CryptogramType.TC -> {
                Timber.d("Card returned TC - offline approved")
                VisaKernelOutcome.Approved(authData)
            }
            CryptogramType.AAC -> {
                Timber.d("Card returned AAC - declined")
                VisaKernelOutcome.Declined(authData, "Card declined transaction")
            }
            CryptogramType.AAR -> {
                Timber.d("Card returned AAR - referral")
                VisaKernelOutcome.OnlineRequest(authData)
            }
        }
    }

    /**
     * Parse GENERATE AC response
     */
    private fun parseGenerateAcResponse(data: ByteArray): AcResponse? {
        if (data.isEmpty()) return null

        return when (data[0]) {
            0x80.toByte() -> parseAcFormat1(data)
            0x77.toByte() -> parseAcFormat2(data)
            else -> null
        }
    }

    /**
     * Parse AC Format 1
     */
    private fun parseAcFormat1(data: ByteArray): AcResponse? {
        val tlv = TlvParser.parse(data).firstOrNull() ?: return null
        val value = tlv.value

        // Format 1: CID (1) | ATC (2) | AC (8) | IAD (var)
        if (value.size < 11) return null

        val cid = value[0]
        val atc = value.copyOfRange(1, 3)
        val ac = value.copyOfRange(3, 11)
        val iad = if (value.size > 11) value.copyOfRange(11, value.size) else byteArrayOf()

        return AcResponse(
            cid = cid,
            atc = atc,
            cryptogram = ac,
            iad = iad,
            cryptogramType = getCryptogramType(cid)
        )
    }

    /**
     * Parse AC Format 2
     */
    private fun parseAcFormat2(data: ByteArray): AcResponse? {
        val tlvs = TlvParser.parseRecursive(data)
        val tlvMap = tlvs.associateBy { it.tag.hex }

        val cid = tlvMap["9F27"]?.value?.get(0) ?: return null
        val atc = tlvMap["9F36"]?.value ?: return null
        val ac = tlvMap["9F26"]?.value ?: return null
        val iad = tlvMap["9F10"]?.value ?: byteArrayOf()

        // Also capture SDAD if present (for CDA)
        val sdad = tlvMap["9F4B"]?.value

        return AcResponse(
            cid = cid,
            atc = atc,
            cryptogram = ac,
            iad = iad,
            cryptogramType = getCryptogramType(cid),
            sdad = sdad
        )
    }

    /**
     * Determine cryptogram type from CID
     */
    private fun getCryptogramType(cid: Byte): CryptogramType {
        return when ((cid.toInt() and 0xC0) shr 6) {
            0 -> CryptogramType.AAC
            1 -> CryptogramType.TC
            2 -> CryptogramType.ARQC
            3 -> CryptogramType.AAR
            else -> CryptogramType.AAC
        }
    }

    /**
     * Build authorization data for acquirer
     */
    private fun buildAuthorizationData(
        pan: ByteArray,
        track2: ByteArray,
        cryptogram: ByteArray,
        cid: Byte,
        atc: ByteArray,
        iad: ByteArray,
        transaction: VisaTransactionData
    ): VisaAuthorizationData {
        return VisaAuthorizationData(
            pan = pan.toHexString().replace("F", ""),
            maskedPan = maskPan(pan),
            panSequenceNumber = cardData["5F34"]?.value?.toHexString() ?: "00",
            track2Equivalent = track2.toHexString(),
            expiryDate = cardData["5F24"]?.value?.toHexString() ?: "",
            applicationCryptogram = cryptogram.toHexString(),
            cryptogramInformationData = cid.toHexString(),
            atc = atc.toHexString(),
            issuerApplicationData = iad.toHexString(),
            terminalVerificationResults = tvr.toBytes().toHexString(),
            transactionDate = dataStore.get(0x9A)?.toHexString() ?: "",
            transactionType = "%02X".format(transaction.transactionType),
            amountAuthorized = "%012d".format(transaction.amount),
            amountOther = "%012d".format(transaction.cashbackAmount ?: 0),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            applicationInterchangeProfile = aip?.toHexString() ?: "",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            cvmResults = dataStore.get(0x9F34)?.toHexString() ?: "000000",
            terminalCapabilities = config.terminalCapabilities.toHexString(),
            terminalType = "%02X".format(config.terminalType),
            unpredictableNumber = dataStore.get(0x9F37)?.toHexString() ?: "",
            aid = selectedAid?.toHexString() ?: "",
            dfName = cardData["84"]?.value?.toHexString() ?: "",
            cardholderName = cardData["5F20"]?.value?.let { String(it).trim() } ?: ""
        )
    }

    private fun maskPan(pan: ByteArray): String {
        val panStr = pan.toHexString().replace("F", "")
        if (panStr.length < 10) return panStr
        return panStr.take(6) + "*".repeat(panStr.length - 10) + panStr.takeLast(4)
    }

    private fun handleGpoError(result: GpoResult): VisaKernelOutcome {
        return when (result) {
            is GpoResult.ConditionsNotSatisfied -> VisaKernelOutcome.TryAnotherInterface
            is GpoResult.ReferenceDataNotFound -> VisaKernelOutcome.EndApplication("Reference data not found")
            is GpoResult.FunctionNotSupported -> VisaKernelOutcome.TryAnotherInterface
            is GpoResult.Error -> VisaKernelOutcome.EndApplication(result.message)
            else -> VisaKernelOutcome.EndApplication("Unexpected GPO error")
        }
    }

    /**
     * Convert 2-digit BCD year to 4-digit year using sliding window algorithm.
     *
     * Uses a 80-year window: years 00-79 map to 2000-2079, years 80-99 map to 1980-1999.
     * This handles the Y2K issue and extends validity to 2079.
     *
     * @param yy 2-digit year (0-99)
     * @param currentYear Current 4-digit year for context
     * @return Full 4-digit year
     */
    private fun bcdYearToFullYear(yy: Int, currentYear: Int): Int {
        val currentCentury = (currentYear / 100) * 100
        val currentYY = currentYear % 100

        // Use sliding window: if yy is more than 20 years in the past from current YY,
        // assume it's in the next century. If more than 80 years in the future, assume previous century.
        return when {
            yy >= 80 && currentYY < 80 -> currentCentury - 100 + yy  // e.g., 99 in 2025 = 1999
            yy < 20 && currentYY >= 80 -> currentCentury + 100 + yy  // e.g., 05 in 2099 = 2105
            else -> currentCentury + yy
        }
    }

    // Extension functions
    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
    private fun Byte.toHexString() = "%02X".format(this)
}

// ==================== DATA CLASSES ====================

sealed class GpoResult {
    data class Success(
        val aip: ByteArray,
        val afl: ByteArray,
        val ctq: ByteArray?,
        val sdad: ByteArray?
    ) : GpoResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Success) return false
            return aip.contentEquals(other.aip) &&
                    afl.contentEquals(other.afl) &&
                    ctq.contentEquals(other.ctq) &&
                    sdad.contentEquals(other.sdad)
        }

        override fun hashCode(): Int {
            var result = aip.contentHashCode()
            result = 31 * result + afl.contentHashCode()
            result = 31 * result + (ctq?.contentHashCode() ?: 0)
            result = 31 * result + (sdad?.contentHashCode() ?: 0)
            return result
        }
    }
    object ConditionsNotSatisfied : GpoResult()
    object ReferenceDataNotFound : GpoResult()
    object FunctionNotSupported : GpoResult()
    data class Error(val message: String) : GpoResult()
}

sealed class OdaOutcome {
    data class Success(val method: String) : OdaOutcome()
    object NotSupported : OdaOutcome()
    data class Failed(val reason: String) : OdaOutcome()
}

sealed class CvmOutcome {
    object CdcvmPerformed : CvmOutcome()
    object CdcvmRequired : CvmOutcome()
    object NoCvmRequired : CvmOutcome()
    object OnlinePinRequired : CvmOutcome()
}

enum class CryptogramDecision {
    AAC,    // Application Authentication Cryptogram (decline)
    TC,     // Transaction Certificate (offline approve)
    ARQC    // Authorization Request Cryptogram (online)
}

data class AcResponse(
    val cid: Byte,
    val atc: ByteArray,
    val cryptogram: ByteArray,
    val iad: ByteArray,
    val cryptogramType: CryptogramType,
    val sdad: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AcResponse) return false
        return cid == other.cid &&
                atc.contentEquals(other.atc) &&
                cryptogram.contentEquals(other.cryptogram) &&
                iad.contentEquals(other.iad) &&
                cryptogramType == other.cryptogramType &&
                sdad.contentEquals(other.sdad)
    }

    override fun hashCode(): Int {
        var result = cid.toInt()
        result = 31 * result + atc.contentHashCode()
        result = 31 * result + cryptogram.contentHashCode()
        result = 31 * result + iad.contentHashCode()
        result = 31 * result + cryptogramType.hashCode()
        result = 31 * result + (sdad?.contentHashCode() ?: 0)
        return result
    }
}

sealed class VisaKernelOutcome {
    data class Approved(val authData: VisaAuthorizationData) : VisaKernelOutcome()
    data class Declined(val authData: VisaAuthorizationData, val reason: String) : VisaKernelOutcome()
    data class OnlineRequest(val authData: VisaAuthorizationData) : VisaKernelOutcome()
    data class EndApplication(val reason: String) : VisaKernelOutcome()
    object TryAnotherInterface : VisaKernelOutcome()
    data class TryAgain(val reason: String) : VisaKernelOutcome()
}

data class VisaAuthorizationData(
    val pan: String,
    val maskedPan: String,
    val panSequenceNumber: String,
    val track2Equivalent: String,
    val expiryDate: String,
    val applicationCryptogram: String,
    val cryptogramInformationData: String,
    val atc: String,
    val issuerApplicationData: String,
    val terminalVerificationResults: String,
    val transactionDate: String,
    val transactionType: String,
    val amountAuthorized: String,
    val amountOther: String,
    val transactionCurrencyCode: String,
    val applicationInterchangeProfile: String,
    val terminalCountryCode: String,
    val cvmResults: String,
    val terminalCapabilities: String,
    val terminalType: String,
    val unpredictableNumber: String,
    val aid: String,
    val dfName: String,
    val cardholderName: String
)

data class VisaKernelConfiguration(
    val terminalCountryCode: ByteArray,
    val transactionCurrencyCode: ByteArray,
    val terminalCapabilities: ByteArray,
    val terminalType: Byte,
    val additionalTerminalCapabilities: ByteArray,
    val ifdSerialNumber: ByteArray,
    val merchantCategoryCode: ByteArray,
    val terminalFloorLimit: Long,
    val cvmRequiredLimit: Long,
    val contactlessTransactionLimit: Long,
    val acquirerId: ByteArray? = null,
    val terminalId: ByteArray? = null,
    val merchantId: ByteArray? = null,
    val transactionSequenceNumber: ByteArray? = null,
    val supportMsd: Boolean = false,
    val supportOnlinePin: Boolean = false,
    val supportSignature: Boolean = false,
    val randomSelectionThreshold: Int = 0,
    val tacDenial: ByteArray = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00),
    val tacOnline: ByteArray = byteArrayOf(0xFC.toByte(), 0x50.toByte(), 0xBC.toByte(), 0x80.toByte(), 0x00),
    val tacDefault: ByteArray = byteArrayOf(0xFC.toByte(), 0x50.toByte(), 0xBC.toByte(), 0xF8.toByte(), 0x00)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VisaKernelConfiguration) return false
        return terminalCountryCode.contentEquals(other.terminalCountryCode) &&
                transactionCurrencyCode.contentEquals(other.transactionCurrencyCode) &&
                terminalCapabilities.contentEquals(other.terminalCapabilities) &&
                terminalType == other.terminalType &&
                additionalTerminalCapabilities.contentEquals(other.additionalTerminalCapabilities) &&
                ifdSerialNumber.contentEquals(other.ifdSerialNumber) &&
                merchantCategoryCode.contentEquals(other.merchantCategoryCode) &&
                terminalFloorLimit == other.terminalFloorLimit &&
                cvmRequiredLimit == other.cvmRequiredLimit &&
                contactlessTransactionLimit == other.contactlessTransactionLimit &&
                acquirerId.contentEquals(other.acquirerId) &&
                terminalId.contentEquals(other.terminalId) &&
                merchantId.contentEquals(other.merchantId) &&
                transactionSequenceNumber.contentEquals(other.transactionSequenceNumber) &&
                supportMsd == other.supportMsd &&
                supportOnlinePin == other.supportOnlinePin &&
                supportSignature == other.supportSignature &&
                randomSelectionThreshold == other.randomSelectionThreshold &&
                tacDenial.contentEquals(other.tacDenial) &&
                tacOnline.contentEquals(other.tacOnline) &&
                tacDefault.contentEquals(other.tacDefault)
    }

    override fun hashCode(): Int {
        var result = terminalCountryCode.contentHashCode()
        result = 31 * result + transactionCurrencyCode.contentHashCode()
        result = 31 * result + terminalCapabilities.contentHashCode()
        result = 31 * result + terminalType.toInt()
        result = 31 * result + additionalTerminalCapabilities.contentHashCode()
        result = 31 * result + ifdSerialNumber.contentHashCode()
        result = 31 * result + merchantCategoryCode.contentHashCode()
        result = 31 * result + terminalFloorLimit.hashCode()
        result = 31 * result + cvmRequiredLimit.hashCode()
        result = 31 * result + contactlessTransactionLimit.hashCode()
        result = 31 * result + (acquirerId?.contentHashCode() ?: 0)
        result = 31 * result + (terminalId?.contentHashCode() ?: 0)
        result = 31 * result + (merchantId?.contentHashCode() ?: 0)
        result = 31 * result + (transactionSequenceNumber?.contentHashCode() ?: 0)
        result = 31 * result + supportMsd.hashCode()
        result = 31 * result + supportOnlinePin.hashCode()
        result = 31 * result + supportSignature.hashCode()
        result = 31 * result + randomSelectionThreshold
        result = 31 * result + tacDenial.contentHashCode()
        result = 31 * result + tacOnline.contentHashCode()
        result = 31 * result + tacDefault.contentHashCode()
        return result
    }
}

data class VisaTransactionData(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val transactionType: Byte = 0x00  // Purchase
)
