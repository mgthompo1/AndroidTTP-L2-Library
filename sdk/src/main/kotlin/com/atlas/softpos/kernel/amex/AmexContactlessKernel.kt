package com.atlas.softpos.kernel.amex

import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.dol.DataStore
import com.atlas.softpos.core.dol.DolParser
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.tlv.Tlv
import com.atlas.softpos.crypto.CaPublicKeyStore
import com.atlas.softpos.crypto.OfflineDataAuthentication
import com.atlas.softpos.crypto.OdaResult
import com.atlas.softpos.kernel.common.*
import timber.log.Timber
import java.security.SecureRandom
import java.util.*

/**
 * American Express ExpressPay Contactless Kernel
 *
 * Production implementation following:
 * - EMV Contactless Book C-4 (American Express Specification)
 * - American Express ExpressPay 4.0 Terminal Implementation Guide
 * - EMV Book 3 & 4
 *
 * Supports:
 * - EMV mode transactions
 * - Mag Stripe mode (legacy)
 * - Enhanced Contactless Reader (ECR) capabilities
 * - Offline Data Authentication (SDA, DDA)
 * - Consumer Device CVM (CDCVM)
 *
 * Transaction Flow:
 * 1. SELECT → Parse FCI/PDOL
 * 2. GPO → Get AIP/AFL, determine EMV or MSD mode
 * 3. READ RECORD → Gather card data
 * 4. ODA → SDA/DDA based on AIP
 * 5. Processing Restrictions
 * 6. CVM Processing
 * 7. Terminal Risk Management
 * 8. Terminal Action Analysis
 * 9. GENERATE AC → Get cryptogram
 */
class AmexContactlessKernel(
    private val transceiver: CardTransceiver,
    private val config: AmexKernelConfiguration
) {
    // Card data storage
    private val cardData = mutableMapOf<String, Tlv>()
    private val dataStore = DataStore()

    // Terminal status
    private val tvr = TerminalVerificationResults()
    private val tsi = TransactionStatusInformation()

    // State
    private var selectedAid: ByteArray? = null
    private var aip: AmexApplicationInterchangeProfile? = null
    private var afl: ByteArray? = null
    private var ctq: AmexCardTransactionQualifiers? = null

    /**
     * Process a contactless transaction
     */
    suspend fun processTransaction(
        aid: ByteArray,
        pdol: ByteArray?,
        transaction: AmexTransactionData
    ): AmexKernelOutcome {
        try {
            Timber.d("=== AMEX KERNEL START ===")
            selectedAid = aid

            // Initialize terminal data
            initializeTerminalData(transaction)

            // Step 1: GPO
            val gpoResult = performGpo(pdol)
            if (gpoResult !is AmexGpoResult.Success) {
                return handleGpoError(gpoResult)
            }

            // Validate AIP
            aip = AmexApplicationInterchangeProfile(gpoResult.aip)
            afl = gpoResult.afl
            ctq = gpoResult.ctq?.let { AmexCardTransactionQualifiers(it) }

            Timber.d("AIP: ${aip!!.toHexString()}, EMV mode: ${aip!!.emvModeSupported}")

            // Determine processing path
            return if (aip!!.emvModeSupported) {
                processEmvMode(gpoResult, transaction)
            } else if (aip!!.magStripeModeSupported) {
                processMagStripeMode(gpoResult, transaction)
            } else {
                AmexKernelOutcome.EndApplication("Card does not support EMV or MSD mode")
            }

        } catch (e: Exception) {
            Timber.e(e, "AmEx kernel exception")
            return AmexKernelOutcome.EndApplication("Kernel error: ${e.message}")
        }
    }

    /**
     * Process EMV mode transaction
     */
    private suspend fun processEmvMode(
        gpoData: AmexGpoResult.Success,
        transaction: AmexTransactionData
    ): AmexKernelOutcome {
        Timber.d("Processing EMV mode transaction")

        // Step 2: Read Application Data
        val readResult = readApplicationData(gpoData.afl)
        if (!readResult) {
            tvr.iccDataMissing = true
            return AmexKernelOutcome.EndApplication("Failed to read application data")
        }

        // Extract critical data
        val pan = cardData[AmexTags.PAN]?.value
        val track2 = cardData[AmexTags.TRACK2_EQUIVALENT]?.value
        val expiryDate = cardData[AmexTags.EXPIRY_DATE]?.value

        if (pan == null || track2 == null) {
            tvr.iccDataMissing = true
            return AmexKernelOutcome.EndApplication("Missing critical card data")
        }

        // Step 3: Offline Data Authentication
        val odaOutcome = performOda(transaction)
        tsi.odaPerformed = true
        if (odaOutcome is OdaOutcome.Failed) {
            Timber.w("ODA failed: ${odaOutcome.reason}")
            // Continue to online - ODA failure doesn't necessarily decline
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
    }

    /**
     * Process Mag Stripe mode transaction
     */
    private suspend fun processMagStripeMode(
        gpoData: AmexGpoResult.Success,
        transaction: AmexTransactionData
    ): AmexKernelOutcome {
        Timber.d("Processing Mag Stripe mode transaction")

        // In MSD mode, cryptogram is returned in GPO response
        val track2 = cardData[AmexTags.TRACK2_EQUIVALENT]?.value
            ?: gpoData.track2

        if (track2 == null) {
            return AmexKernelOutcome.EndApplication("Missing Track 2 data")
        }

        // Parse Track 2
        val track2Parsed = AmexTrack2Parser.parse(track2)
            ?: return AmexKernelOutcome.EndApplication("Invalid Track 2 format")

        // Check CVM for MSD
        performCvm(transaction.amount)

        // Build MSD auth data
        val authData = buildMsdAuthorizationData(
            track2 = track2,
            track2Parsed = track2Parsed,
            cryptogram = gpoData.cryptogram,
            atc = gpoData.atc,
            transaction = transaction
        )

        return AmexKernelOutcome.OnlineRequest(authData)
    }

    /**
     * Initialize terminal data store
     */
    private fun initializeTerminalData(transaction: AmexTransactionData) {
        tvr.reset()
        tsi.reset()
        cardData.clear()
        dataStore.clear()

        // Generate unpredictable number
        val un = ByteArray(4)
        SecureRandom().nextBytes(un)

        // Build ECR Capabilities
        val ecr = config.enhancedContactlessReaderCapabilities

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

        // Store terminal data
        dataStore.set(0x9F02, amountToBytes(transaction.amount))
        dataStore.set(0x9F03, amountToBytes(transaction.cashbackAmount ?: 0))
        dataStore.set(0x9C, byteArrayOf(transaction.transactionType))
        dataStore.set(0x9A, date)
        dataStore.set(0x9F21, time)
        dataStore.set(0x9F37, un)
        dataStore.set(0x9F1A, config.terminalCountryCode)
        dataStore.set(0x5F2A, config.transactionCurrencyCode)
        dataStore.set(0x9F35, byteArrayOf(config.terminalType))
        dataStore.set(0x9F33, config.terminalCapabilities)
        dataStore.set(0x9F40, config.additionalTerminalCapabilities)
        dataStore.set(0x9F6E, ecr.bytes)  // Enhanced Contactless Reader Capabilities
        dataStore.set(0x95, tvr.toBytes())
    }

    /**
     * Perform GET PROCESSING OPTIONS
     */
    private suspend fun performGpo(pdol: ByteArray?): AmexGpoResult {
        Timber.d("Performing GPO")

        // Build PDOL data
        val pdolData = if (pdol != null && pdol.isNotEmpty()) {
            DolParser.buildDolData(pdol, dataStore)
        } else {
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
            Timber.e("GPO failed: SW=${response.sw.toString(16)}")
            return when {
                response.sw1 == 0x69.toByte() && response.sw2 == 0x84.toByte() ->
                    AmexGpoResult.ReferenceDataNotFound
                response.sw1 == 0x69.toByte() && response.sw2 == 0x85.toByte() ->
                    AmexGpoResult.ConditionsNotSatisfied
                else -> AmexGpoResult.Error("GPO failed: ${response.sw.toString(16)}")
            }
        }

        return parseGpoResponse(response.data)
    }

    /**
     * Parse GPO response
     */
    private fun parseGpoResponse(data: ByteArray): AmexGpoResult {
        if (data.isEmpty()) {
            return AmexGpoResult.Error("Empty GPO response")
        }

        return when (data[0]) {
            0x80.toByte() -> parseGpoFormat1(data)
            0x77.toByte() -> parseGpoFormat2(data)
            else -> AmexGpoResult.Error("Unknown GPO response format: ${data[0]}")
        }
    }

    /**
     * Parse GPO Format 1 (primitive)
     */
    private fun parseGpoFormat1(data: ByteArray): AmexGpoResult {
        val tlv = TlvParser.parse(data).firstOrNull()
            ?: return AmexGpoResult.Error("Failed to parse Format 1")

        val value = tlv.value
        if (value.size < 2) {
            return AmexGpoResult.Error("Format 1 too short")
        }

        val aip = value.copyOfRange(0, 2)
        val afl = if (value.size > 2) value.copyOfRange(2, value.size) else byteArrayOf()

        return AmexGpoResult.Success(
            aip = aip,
            afl = afl,
            ctq = null,
            track2 = null,
            cryptogram = null,
            atc = null
        )
    }

    /**
     * Parse GPO Format 2 (constructed)
     */
    private fun parseGpoFormat2(data: ByteArray): AmexGpoResult {
        val tlvs = TlvParser.parseRecursive(data)
        val tlvMap = tlvs.associateBy { it.tag.hex }

        val aip = tlvMap["82"]?.value
            ?: return AmexGpoResult.Error("Missing AIP in Format 2")

        val afl = tlvMap["94"]?.value ?: byteArrayOf()
        val ctq = tlvMap["9F6C"]?.value
        val track2 = tlvMap["57"]?.value
        val cryptogram = tlvMap["9F26"]?.value
        val atc = tlvMap["9F36"]?.value

        // Store GPO response data
        ctq?.let { cardData["9F6C"] = Tlv.fromHex("9F6C", it.toHexString()) }
        track2?.let { cardData["57"] = Tlv.fromHex("57", it.toHexString()) }
        cryptogram?.let { cardData["9F26"] = Tlv.fromHex("9F26", it.toHexString()) }
        atc?.let { cardData["9F36"] = Tlv.fromHex("9F36", it.toHexString()) }

        return AmexGpoResult.Success(
            aip = aip,
            afl = afl,
            ctq = ctq,
            track2 = track2,
            cryptogram = cryptogram,
            atc = atc
        )
    }

    /**
     * Read Application Data from AFL
     */
    private suspend fun readApplicationData(afl: ByteArray): Boolean {
        if (afl.isEmpty()) {
            Timber.d("Empty AFL - no records to read")
            return true
        }

        if (afl.size % 4 != 0) {
            Timber.e("Invalid AFL length: ${afl.size}")
            return false
        }

        var odaData = byteArrayOf()

        for (i in afl.indices step 4) {
            val sfi = (afl[i].toInt() and 0xF8) shr 3
            val firstRecord = afl[i + 1].toInt() and 0xFF
            val lastRecord = afl[i + 2].toInt() and 0xFF
            val odaRecords = afl[i + 3].toInt() and 0xFF

            Timber.d("AFL entry: SFI=$sfi, First=$firstRecord, Last=$lastRecord, ODA=$odaRecords")

            for (record in firstRecord..lastRecord) {
                val recordData = readRecord(sfi, record) ?: return false

                // Parse TLVs from record
                val recordTlvs = TlvParser.parseRecursive(recordData)
                for (tlv in recordTlvs) {
                    cardData[tlv.tag.hex] = tlv
                }

                // Accumulate ODA data
                if (record - firstRecord < odaRecords) {
                    val innerData = if (recordData.isNotEmpty() && recordData[0] == 0x70.toByte()) {
                        TlvParser.parse(recordData).firstOrNull()?.value ?: recordData
                    } else {
                        recordData
                    }
                    odaData += innerData
                }
            }
        }

        dataStore.set("ODA_DATA", odaData)
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
            Timber.e("Read record failed: SFI=$sfi, Record=$record")
            return null
        }

        return response.data
    }

    /**
     * Perform Offline Data Authentication
     */
    private suspend fun performOda(transaction: AmexTransactionData): OdaOutcome {
        val aipLocal = aip ?: return OdaOutcome.NotSupported

        if (!aipLocal.supportsOda()) {
            tvr.odaNotPerformed = true
            return OdaOutcome.NotSupported
        }

        Timber.d("ODA support - SDA: ${aipLocal.sdaSupported}, DDA: ${aipLocal.ddaSupported}, CDA: ${aipLocal.cdaSupported}")

        // Get CA public key index
        val caIndex = cardData[AmexTags.CA_PUBLIC_KEY_INDEX]?.value?.get(0)
        if (caIndex == null) {
            tvr.odaNotPerformed = true
            return OdaOutcome.Failed("Missing CA Public Key Index")
        }

        // Get CA public key for AmEx
        val caKey = CaPublicKeyStore.getKey(AmexAids.EXPRESSPAY.copyOfRange(0, 5), caIndex)
        if (caKey == null) {
            tvr.odaNotPerformed = true
            return OdaOutcome.Failed("CA Public Key not found")
        }

        // Create ODA processor
        val oda = OfflineDataAuthentication(transceiver, cardData.mapValues { it.value })
        val odaData = dataStore.get("ODA_DATA") ?: byteArrayOf()

        val result = oda.performOda(aipLocal.bytes, odaData)

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
            is OdaResult.Failed -> {
                when {
                    result.failureReason.name.contains("SDA") -> tvr.sdaFailed = true
                    result.failureReason.name.contains("DDA") -> tvr.ddaFailed = true
                    result.failureReason.name.contains("CDA") -> tvr.cdaFailed = true
                }
                OdaOutcome.Failed(result.failureReason.name)
            }
            is OdaResult.Success -> OdaOutcome.Success(result.type)
            is OdaResult.Failure -> OdaOutcome.Failed(result.reason)
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

        // Expiry format: YYMMDD
        val expYear = 2000 + ((expiryDate[0].toInt() and 0xF0) shr 4) * 10 + (expiryDate[0].toInt() and 0x0F)
        val expMonth = ((expiryDate[1].toInt() and 0xF0) shr 4) * 10 + (expiryDate[1].toInt() and 0x0F)

        val calendar = Calendar.getInstance()
        val currentYear = calendar.get(Calendar.YEAR)
        val currentMonth = calendar.get(Calendar.MONTH) + 1

        if (expYear < currentYear || (expYear == currentYear && expMonth < currentMonth)) {
            tvr.expiredApplication = true
            Timber.w("Card expired: $expMonth/$expYear")
        }

        // Check effective date
        val effectiveDate = cardData["5F25"]?.value
        if (effectiveDate != null && effectiveDate.size >= 3) {
            val effYear = 2000 + ((effectiveDate[0].toInt() and 0xF0) shr 4) * 10 + (effectiveDate[0].toInt() and 0x0F)
            val effMonth = ((effectiveDate[1].toInt() and 0xF0) shr 4) * 10 + (effectiveDate[1].toInt() and 0x0F)

            if (effYear > currentYear || (effYear == currentYear && effMonth > currentMonth)) {
                tvr.applicationNotYetEffective = true
            }
        }
    }

    /**
     * Perform CVM (Cardholder Verification Method)
     */
    private fun performCvm(amount: Long): CvmOutcome {
        val ctqLocal = ctq

        // Check CTQ for CDCVM
        if (ctqLocal != null && ctqLocal.cdcvmPerformed) {
            Timber.d("CDCVM performed on consumer device")
            dataStore.set(0x9F34, byteArrayOf(0x2F, 0x00, 0x02))  // CDCVM successful
            return CvmOutcome.CdcvmPerformed
        }

        // Check amount thresholds
        if (amount <= config.cvmRequiredLimit) {
            dataStore.set(0x9F34, byteArrayOf(0x1F, 0x00, 0x02))  // No CVM, successful
            return CvmOutcome.NoCvmRequired
        }

        // CVM required but not performed - set for online PIN
        if (config.supportOnlinePin) {
            dataStore.set(0x9F34, byteArrayOf(0x02, 0x00, 0x01))  // Online PIN required
            return CvmOutcome.OnlinePinRequired
        }

        // CDCVM required
        dataStore.set(0x9F34, byteArrayOf(0x2F, 0x00, 0x01))
        return CvmOutcome.CdcvmRequired
    }

    /**
     * Perform Terminal Risk Management
     */
    private fun performTerminalRiskManagement(transaction: AmexTransactionData) {
        // Floor limit check
        if (transaction.amount > config.terminalFloorLimit) {
            tvr.floorLimitExceeded = true
        }

        // Contactless limit check (using Upper Contactless Offline Limit)
        if (transaction.amount > config.contactlessTransactionLimit) {
            tvr.ucolExceeded = true
        }

        // For SoftPOS, always force online
        tvr.merchantForcedOnline = true

        // Random selection
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
        val iacDenial = cardData["9F0E"]?.value ?: ByteArray(5)
        val iacOnline = cardData["9F0F"]?.value ?: ByteArray(5)
        val iacDefault = cardData["9F0D"]?.value ?: ByteArray(5)

        val tacDenial = config.tacDenial
        val tacOnline = config.tacOnline
        val tacDefault = config.tacDefault

        // Denial check
        val denialResult = combineActionCodes(iacDenial, tacDenial)
        if (tvr.matchesActionCode(denialResult)) {
            Timber.d("Terminal Action Analysis: DECLINE")
            return CryptogramDecision.AAC
        }

        // Online check
        val onlineResult = combineActionCodes(iacOnline, tacOnline)
        if (tvr.matchesActionCode(onlineResult)) {
            Timber.d("Terminal Action Analysis: ONLINE")
            return CryptogramDecision.ARQC
        }

        // SoftPOS always goes online
        Timber.d("Terminal Action Analysis: ONLINE (default for SoftPOS)")
        return CryptogramDecision.ARQC
    }

    /**
     * Combine IAC and TAC
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
     * Generate Application Cryptogram
     */
    private suspend fun generateApplicationCryptogram(
        decision: CryptogramDecision,
        transaction: AmexTransactionData,
        pan: ByteArray,
        track2: ByteArray
    ): AmexKernelOutcome {
        Timber.d("Generating AC: $decision")

        // Get CDOL1
        val cdol1 = cardData[AmexTags.CDOL1]?.value
        if (cdol1 == null || cdol1.isEmpty()) {
            return AmexKernelOutcome.EndApplication("Missing CDOL1")
        }

        // Update TVR in data store
        dataStore.set(0x95, tvr.toBytes())

        // Build CDOL1 data
        val cdolData = DolParser.buildDolData(cdol1, dataStore)

        // Reference control parameter
        val p1 = when (decision) {
            CryptogramDecision.AAC -> 0x00
            CryptogramDecision.TC -> 0x40
            CryptogramDecision.ARQC -> 0x80.toByte()
        }

        val command = CommandApdu(
            cla = 0x80.toByte(),
            ins = 0xAE.toByte(),
            p1 = p1.toByte(),
            p2 = 0x00,
            data = cdolData,
            le = 0x00
        )

        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return AmexKernelOutcome.EndApplication("GENERATE AC failed: ${response.sw.toString(16)}")
        }

        // Parse response
        val acResponse = parseGenerateAcResponse(response.data)
            ?: return AmexKernelOutcome.EndApplication("Failed to parse AC response")

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

        // Determine outcome
        return when (acResponse.cryptogramType) {
            CryptogramType.ARQC -> {
                Timber.d("Card returned ARQC - online authorization required")
                AmexKernelOutcome.OnlineRequest(authData)
            }
            CryptogramType.TC -> {
                Timber.d("Card returned TC - offline approved")
                AmexKernelOutcome.Approved(authData)
            }
            CryptogramType.AAC -> {
                Timber.d("Card returned AAC - declined")
                AmexKernelOutcome.Declined(authData, "Card declined transaction")
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

    private fun parseAcFormat1(data: ByteArray): AcResponse? {
        val tlv = TlvParser.parse(data).firstOrNull() ?: return null
        val value = tlv.value

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

    private fun parseAcFormat2(data: ByteArray): AcResponse? {
        val tlvs = TlvParser.parseRecursive(data)
        val tlvMap = tlvs.associateBy { it.tag.hex }

        val cid = tlvMap["9F27"]?.value?.get(0) ?: return null
        val atc = tlvMap["9F36"]?.value ?: return null
        val ac = tlvMap["9F26"]?.value ?: return null
        val iad = tlvMap["9F10"]?.value ?: byteArrayOf()

        return AcResponse(
            cid = cid,
            atc = atc,
            cryptogram = ac,
            iad = iad,
            cryptogramType = getCryptogramType(cid)
        )
    }

    private fun getCryptogramType(cid: Byte): CryptogramType {
        return when ((cid.toInt() and 0xC0) shr 6) {
            0 -> CryptogramType.AAC
            1 -> CryptogramType.TC
            2 -> CryptogramType.ARQC
            else -> CryptogramType.AAC
        }
    }

    /**
     * Build authorization data
     */
    private fun buildAuthorizationData(
        pan: ByteArray,
        track2: ByteArray,
        cryptogram: ByteArray,
        cid: Byte,
        atc: ByteArray,
        iad: ByteArray,
        transaction: AmexTransactionData
    ): AmexAuthorizationData {
        return AmexAuthorizationData(
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
            cardholderName = cardData["5F20"]?.value?.let { String(it).trim() } ?: "",
            enhancedContactlessReaderCapabilities = config.enhancedContactlessReaderCapabilities.bytes.toHexString()
        )
    }

    /**
     * Build MSD authorization data
     */
    private fun buildMsdAuthorizationData(
        track2: ByteArray,
        track2Parsed: AmexTrack2,
        cryptogram: ByteArray?,
        atc: ByteArray?,
        transaction: AmexTransactionData
    ): AmexAuthorizationData {
        return AmexAuthorizationData(
            pan = track2Parsed.pan,
            maskedPan = track2Parsed.maskedPan,
            panSequenceNumber = "00",
            track2Equivalent = track2.toHexString(),
            expiryDate = track2Parsed.expiryDate,
            applicationCryptogram = cryptogram?.toHexString() ?: "",
            cryptogramInformationData = "80",  // MSD mode
            atc = atc?.toHexString() ?: "",
            issuerApplicationData = "",
            terminalVerificationResults = tvr.toBytes().toHexString(),
            transactionDate = dataStore.get(0x9A)?.toHexString() ?: "",
            transactionType = "%02X".format(transaction.transactionType),
            amountAuthorized = "%012d".format(transaction.amount),
            amountOther = "%012d".format(transaction.cashbackAmount ?: 0),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            applicationInterchangeProfile = aip?.toHexString() ?: "",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            cvmResults = dataStore.get(0x9F34)?.toHexString() ?: "1F0000",
            terminalCapabilities = config.terminalCapabilities.toHexString(),
            terminalType = "%02X".format(config.terminalType),
            unpredictableNumber = dataStore.get(0x9F37)?.toHexString() ?: "",
            aid = selectedAid?.toHexString() ?: "A00000002501",
            dfName = "",
            cardholderName = "",
            enhancedContactlessReaderCapabilities = config.enhancedContactlessReaderCapabilities.bytes.toHexString()
        )
    }

    private fun maskPan(pan: ByteArray): String {
        val panStr = pan.toHexString().replace("F", "")
        if (panStr.length < 10) return panStr
        return panStr.take(6) + "*".repeat(panStr.length - 10) + panStr.takeLast(4)
    }

    private fun handleGpoError(result: AmexGpoResult): AmexKernelOutcome {
        return when (result) {
            is AmexGpoResult.ConditionsNotSatisfied -> AmexKernelOutcome.TryAnotherInterface
            is AmexGpoResult.ReferenceDataNotFound -> AmexKernelOutcome.EndApplication("Reference data not found")
            is AmexGpoResult.Error -> AmexKernelOutcome.EndApplication(result.message)
            else -> AmexKernelOutcome.EndApplication("Unexpected GPO error")
        }
    }

    // ==================== ONLINE RESPONSE PROCESSING ====================

    /**
     * Process online authorization response from issuer
     *
     * @param onlineResponse Response from issuer/acquirer
     * @param previousAuthData Authorization data from initial GENERATE AC
     * @return Result of online processing
     */
    suspend fun processOnlineResponse(
        onlineResponse: AmexOnlineAuthResponse,
        previousAuthData: AmexAuthorizationData
    ): AmexOnlineResponseResult {
        Timber.d("=== AMEX ONLINE RESPONSE PROCESSING ===")
        Timber.d("Online approved: ${onlineResponse.approved}")

        try {
            // Step 1: Verify ARPC if provided
            if (onlineResponse.arpc != null && onlineResponse.arc != null) {
                val arpcValid = verifyArpc(
                    arqc = previousAuthData.applicationCryptogram.hexToByteArray(),
                    arpc = onlineResponse.arpc,
                    arc = onlineResponse.arc
                )

                if (!arpcValid) {
                    tvr.issuerAuthFailed = true
                    Timber.w("ARPC verification failed")
                }
            }

            // Step 2: Execute issuer scripts before 2nd GENERATE AC (tag 71)
            val script71Results = mutableListOf<AmexIssuerScriptResult>()
            onlineResponse.issuerScripts71?.let { scripts ->
                Timber.d("Processing ${scripts.size} tag 71 issuer scripts")
                for (script in scripts) {
                    val result = executeIssuerScript(script, true)
                    script71Results.add(result)
                    if (!result.success && result.abortTransaction) {
                        return AmexOnlineResponseResult.ScriptFailed(
                            scriptResults = script71Results,
                            failedScriptTag = "71",
                            tvr = tvr.toBytes().toHexString()
                        )
                    }
                }
            }

            // Step 3: Perform second GENERATE AC
            val secondAcResult = performSecondGenerateAc(onlineResponse.approved)

            // Step 4: Execute issuer scripts after 2nd GENERATE AC (tag 72)
            val script72Results = mutableListOf<AmexIssuerScriptResult>()
            onlineResponse.issuerScripts72?.let { scripts ->
                Timber.d("Processing ${scripts.size} tag 72 issuer scripts")
                for (script in scripts) {
                    val result = executeIssuerScript(script, false)
                    script72Results.add(result)
                }
            }

            val allScriptResults = script71Results + script72Results

            return when (secondAcResult) {
                is AmexSecondAcResult.Approved -> AmexOnlineResponseResult.Approved(
                    cryptogram = secondAcResult.cryptogram,
                    cryptogramType = "TC",
                    scriptResults = allScriptResults,
                    tvr = tvr.toBytes().toHexString()
                )
                is AmexSecondAcResult.Declined -> AmexOnlineResponseResult.Declined(
                    cryptogram = secondAcResult.cryptogram,
                    reason = secondAcResult.reason,
                    scriptResults = allScriptResults,
                    tvr = tvr.toBytes().toHexString()
                )
                is AmexSecondAcResult.Error -> AmexOnlineResponseResult.Error(
                    reason = secondAcResult.message,
                    scriptResults = allScriptResults,
                    tvr = tvr.toBytes().toHexString()
                )
            }

        } catch (e: Exception) {
            Timber.e(e, "Online response processing failed")
            return AmexOnlineResponseResult.Error(
                reason = "Processing error: ${e.message}",
                scriptResults = emptyList(),
                tvr = tvr.toBytes().toHexString()
            )
        }
    }

    /**
     * Verify ARPC (Authorization Response Cryptogram)
     */
    private fun verifyArpc(arqc: ByteArray, arpc: ByteArray, arc: ByteArray): Boolean {
        Timber.d("Verifying ARPC")

        val sessionKey = deriveSessionKeyFromCardData() ?: run {
            Timber.w("Could not derive session key for ARPC verification")
            return false
        }

        // ARPC Method 1: ARPC = 3DES_ENC(SK, ARQC XOR (ARC || 0x00000000))
        val arcPadded = ByteArray(8)
        System.arraycopy(arc, 0, arcPadded, 0, minOf(arc.size, 2))

        val xorResult = ByteArray(8)
        for (i in 0 until 8) {
            xorResult[i] = (arqc.getOrElse(i) { 0 }.toInt() xor arcPadded[i].toInt()).toByte()
        }

        return try {
            val cipher = javax.crypto.Cipher.getInstance("DESede/ECB/NoPadding")
            val expandedKey = if (sessionKey.size == 16) {
                sessionKey + sessionKey.copyOfRange(0, 8)
            } else {
                sessionKey
            }
            val keySpec = javax.crypto.spec.SecretKeySpec(expandedKey, "DESede")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec)
            val computedArpc = cipher.doFinal(xorResult)

            val matches = computedArpc.copyOfRange(0, arpc.size).contentEquals(arpc)
            Timber.d("ARPC verification: ${if (matches) "PASSED" else "FAILED"}")
            matches
        } catch (e: Exception) {
            Timber.e(e, "ARPC calculation error")
            false
        }
    }

    /**
     * Execute an issuer script command
     */
    private suspend fun executeIssuerScript(script: ByteArray, isPreAc: Boolean): AmexIssuerScriptResult {
        Timber.d("Executing issuer script (${script.size} bytes)")

        try {
            val commands = parseIssuerScriptCommands(script)
            if (commands.isEmpty()) {
                return AmexIssuerScriptResult(success = true, sw = 0x9000, abortTransaction = false)
            }

            var lastSw = 0x9000
            for (commandData in commands) {
                if (commandData.size < 4) continue

                val command = CommandApdu(
                    cla = commandData[0],
                    ins = commandData[1],
                    p1 = commandData[2],
                    p2 = commandData[3],
                    data = if (commandData.size > 5) {
                        val lc = commandData[4].toInt() and 0xFF
                        commandData.copyOfRange(5, minOf(5 + lc, commandData.size))
                    } else null,
                    le = null
                )

                val response = transceiver.transceive(command)
                lastSw = response.sw

                if (!response.isSuccess) {
                    Timber.w("Script command failed: SW=%04X", lastSw)

                    if (isPreAc) {
                        tvr.scriptFailedBeforeAc = true
                    } else {
                        tvr.scriptFailedAfterAc = true
                    }

                    return AmexIssuerScriptResult(
                        success = false,
                        sw = lastSw,
                        abortTransaction = isPreAc && lastSw == 0x6985
                    )
                }
            }

            return AmexIssuerScriptResult(success = true, sw = lastSw, abortTransaction = false)

        } catch (e: Exception) {
            Timber.e(e, "Error executing issuer script")
            if (isPreAc) {
                tvr.scriptFailedBeforeAc = true
            } else {
                tvr.scriptFailedAfterAc = true
            }
            return AmexIssuerScriptResult(success = false, sw = 0x6F00, abortTransaction = false)
        }
    }

    /**
     * Parse issuer script commands from tag 71/72 data
     */
    private fun parseIssuerScriptCommands(script: ByteArray): List<ByteArray> {
        val commands = mutableListOf<ByteArray>()
        var offset = 0

        while (offset < script.size) {
            if (script[offset] != 0x86.toByte()) {
                offset++
                continue
            }
            offset++

            if (offset >= script.size) break

            var length = script[offset].toInt() and 0xFF
            offset++

            if (length == 0x81) {
                if (offset >= script.size) break
                length = script[offset].toInt() and 0xFF
                offset++
            }

            if (offset + length > script.size) break

            commands.add(script.copyOfRange(offset, offset + length))
            offset += length
        }

        return commands
    }

    /**
     * Perform second GENERATE AC
     */
    private suspend fun performSecondGenerateAc(approved: Boolean): AmexSecondAcResult {
        Timber.d("Performing second GENERATE AC, approved=$approved")

        val cdol2 = cardData[AmexTags.CDOL2]?.value ?: cardData[AmexTags.CDOL1]?.value
        if (cdol2 == null) {
            return AmexSecondAcResult.Error("Missing CDOL2/CDOL1 for second AC")
        }

        dataStore.set(0x95, tvr.toBytes())
        val cdolData = DolParser.buildDolData(cdol2, dataStore)

        val p1 = if (approved) 0x40.toByte() else 0x00.toByte()

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
            return AmexSecondAcResult.Error("Second GENERATE AC failed: ${response.sw.toString(16)}")
        }

        val acResponse = parseGenerateAcResponse(response.data)
        if (acResponse == null) {
            return AmexSecondAcResult.Error("Failed to parse second AC response")
        }

        val cryptogramHex = acResponse.cryptogram.toHexString()

        return when (acResponse.cryptogramType) {
            CryptogramType.TC -> AmexSecondAcResult.Approved(cryptogramHex)
            CryptogramType.AAC -> AmexSecondAcResult.Declined(cryptogramHex, "Card declined after online auth")
            else -> AmexSecondAcResult.Declined(cryptogramHex, "Unexpected response")
        }
    }

    /**
     * Derive session key from card data
     */
    private fun deriveSessionKeyFromCardData(): ByteArray? {
        val atc = cardData[AmexTags.ATC]?.value
        val pan = cardData[AmexTags.PAN]?.value
        val psn = cardData["5F34"]?.value

        if (atc == null || pan == null) return null

        Timber.w("Using simplified session key derivation - production should use proper key management")

        val keyMaterial = ByteArray(16)
        val panBytes = pan.copyOfRange(0, minOf(8, pan.size))
        System.arraycopy(panBytes, 0, keyMaterial, 0, panBytes.size)
        System.arraycopy(atc, 0, keyMaterial, 8, minOf(2, atc.size))
        psn?.let { System.arraycopy(it, 0, keyMaterial, 10, minOf(1, it.size)) }

        return keyMaterial
    }

    private fun String.hexToByteArray(): ByteArray {
        require(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun amountToBytes(amount: Long): ByteArray {
        val hex = "%012d".format(amount)
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }
    private fun Byte.toHexString() = "%02X".format(this)
}

// ==================== DATA CLASSES ====================

sealed class AmexGpoResult {
    data class Success(
        val aip: ByteArray,
        val afl: ByteArray,
        val ctq: ByteArray?,
        val track2: ByteArray?,
        val cryptogram: ByteArray?,
        val atc: ByteArray?
    ) : AmexGpoResult()
    object ConditionsNotSatisfied : AmexGpoResult()
    object ReferenceDataNotFound : AmexGpoResult()
    data class Error(val message: String) : AmexGpoResult()
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
    AAC, TC, ARQC
}

data class AcResponse(
    val cid: Byte,
    val atc: ByteArray,
    val cryptogram: ByteArray,
    val iad: ByteArray,
    val cryptogramType: CryptogramType
)

enum class CryptogramType {
    AAC, TC, ARQC
}

sealed class AmexKernelOutcome {
    data class Approved(val authData: AmexAuthorizationData) : AmexKernelOutcome()
    data class Declined(val authData: AmexAuthorizationData, val reason: String) : AmexKernelOutcome()
    data class OnlineRequest(val authData: AmexAuthorizationData) : AmexKernelOutcome()
    data class EndApplication(val reason: String) : AmexKernelOutcome()
    object TryAnotherInterface : AmexKernelOutcome()
}

data class AmexAuthorizationData(
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
    val cardholderName: String,
    val enhancedContactlessReaderCapabilities: String
)

data class AmexKernelConfiguration(
    val terminalCountryCode: ByteArray = byteArrayOf(0x08, 0x40),
    val transactionCurrencyCode: ByteArray = byteArrayOf(0x08, 0x40),
    val terminalCapabilities: ByteArray = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
    val terminalType: Byte = 0x22,
    val additionalTerminalCapabilities: ByteArray = byteArrayOf(0x8F.toByte(), 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01),
    val enhancedContactlessReaderCapabilities: EnhancedContactlessReaderCapabilities = EnhancedContactlessReaderCapabilities.forSoftPos(),
    val terminalFloorLimit: Long = 0,
    val cvmRequiredLimit: Long = 0,
    val contactlessTransactionLimit: Long = 100000,
    val supportOnlinePin: Boolean = true,
    val randomSelectionThreshold: Int = 0,
    val tacDenial: ByteArray = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00),
    val tacOnline: ByteArray = byteArrayOf(0xF8.toByte(), 0x50.toByte(), 0xAC.toByte(), 0xF8.toByte(), 0x00),
    val tacDefault: ByteArray = byteArrayOf(0xF8.toByte(), 0x50.toByte(), 0xAC.toByte(), 0xF8.toByte(), 0x00)
)

data class AmexTransactionData(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val transactionType: Byte = 0x00
)

// ==================== ONLINE RESPONSE DATA CLASSES ====================

/**
 * Online authorization response from issuer
 */
data class AmexOnlineAuthResponse(
    val approved: Boolean,
    val arc: ByteArray? = null,
    val arpc: ByteArray? = null,
    val issuerScripts71: List<ByteArray>? = null,
    val issuerScripts72: List<ByteArray>? = null,
    val issuerAuthData: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AmexOnlineAuthResponse) return false
        return approved == other.approved &&
                arc.contentEquals(other.arc) &&
                arpc.contentEquals(other.arpc)
    }

    override fun hashCode(): Int {
        var result = approved.hashCode()
        result = 31 * result + (arc?.contentHashCode() ?: 0)
        result = 31 * result + (arpc?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * Result of processing online authorization response
 */
sealed class AmexOnlineResponseResult {
    data class Approved(
        val cryptogram: String,
        val cryptogramType: String,
        val scriptResults: List<AmexIssuerScriptResult>,
        val tvr: String
    ) : AmexOnlineResponseResult()

    data class Declined(
        val cryptogram: String,
        val reason: String,
        val scriptResults: List<AmexIssuerScriptResult>,
        val tvr: String
    ) : AmexOnlineResponseResult()

    data class ScriptFailed(
        val scriptResults: List<AmexIssuerScriptResult>,
        val failedScriptTag: String,
        val tvr: String
    ) : AmexOnlineResponseResult()

    data class Error(
        val reason: String,
        val scriptResults: List<AmexIssuerScriptResult>,
        val tvr: String
    ) : AmexOnlineResponseResult()
}

/**
 * Result of issuer script execution
 */
data class AmexIssuerScriptResult(
    val success: Boolean,
    val sw: Int,
    val abortTransaction: Boolean
)

/**
 * Result of second GENERATE AC
 */
sealed class AmexSecondAcResult {
    data class Approved(val cryptogram: String) : AmexSecondAcResult()
    data class Declined(val cryptogram: String, val reason: String) : AmexSecondAcResult()
    data class Error(val message: String) : AmexSecondAcResult()
}
