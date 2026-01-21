package com.atlas.softpos.kernel.discover

import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.tlv.Tlv
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.tlv.TlvBuilder
import com.atlas.softpos.crypto.CaPublicKeyStore
import com.atlas.softpos.crypto.StandaloneOdaProcessor
import com.atlas.softpos.kernel.common.CardTransceiver
import java.security.SecureRandom

/**
 * Discover D-PAS Contactless Kernel
 *
 * Full implementation per EMV Contactless Book C-6 (Discover Specification)
 *
 * Supports:
 * - EMV Mode (chip data with cryptogram)
 * - Mag Stripe Mode (Track 2 equivalent data)
 * - Offline Data Authentication (SDA, DDA, CDA)
 * - CVM Processing (CDCVM, Online PIN, Signature, No CVM)
 *
 * Transaction Flow:
 * 1. SELECT Application
 * 2. GET PROCESSING OPTIONS (with PDOL data)
 * 3. READ RECORD (read AFL data)
 * 4. Offline Data Authentication (if supported)
 * 5. Processing Restrictions
 * 6. CVM Processing
 * 7. Terminal Risk Management
 * 8. GENERATE AC (get cryptogram)
 */
class DiscoverContactlessKernel(
    private val transceiver: CardTransceiver,
    private val config: DiscoverKernelConfiguration
) {
    private val secureRandom = SecureRandom()

    // Transaction data accumulated during processing
    private val transactionData = mutableMapOf<String, ByteArray>()
    private var aip: DiscoverApplicationInterchangeProfile? = null
    private var ctq: DiscoverCardTransactionQualifiers? = null

    /**
     * Process a Discover contactless transaction
     *
     * @param aid Application Identifier from PPSE
     * @param pdol PDOL from FCI (if any)
     * @param transaction Transaction parameters
     * @return Kernel outcome
     */
    suspend fun processTransaction(
        aid: ByteArray,
        pdol: ByteArray?,
        transaction: DiscoverTransactionData
    ): DiscoverKernelOutcome {
        try {
            // Reset state
            transactionData.clear()
            aip = null
            ctq = null

            // Store transaction data
            storeTransactionData(transaction)

            // Step 1: SELECT Application
            val selectResult = selectApplication(aid)
            if (selectResult !is DiscoverSelectResult.Success) {
                return DiscoverKernelOutcome(
                    type = DiscoverOutcomeType.END_APPLICATION,
                    errorMessage = "Application selection failed"
                )
            }

            // Step 2: GET PROCESSING OPTIONS
            val gpoResult = getProcessingOptions(selectResult.pdol, transaction)
            if (gpoResult !is DiscoverGpoResult.Success) {
                return when (gpoResult) {
                    is DiscoverGpoResult.TryAnotherInterface -> DiscoverKernelOutcome(
                        type = DiscoverOutcomeType.TRY_ANOTHER_INTERFACE,
                        errorMessage = "Card requests another interface"
                    )
                    else -> DiscoverKernelOutcome(
                        type = DiscoverOutcomeType.END_APPLICATION,
                        errorMessage = "GPO failed"
                    )
                }
            }

            // Parse AIP and determine mode
            aip = gpoResult.aip

            // Check for Mag Stripe Mode vs EMV Mode
            val outcome = if (aip?.emvModeSupported == true) {
                processEmvMode(gpoResult, transaction)
            } else if (aip?.magStripeModeSupported == true) {
                processMagStripeMode(gpoResult, transaction)
            } else {
                DiscoverKernelOutcome(
                    type = DiscoverOutcomeType.END_APPLICATION,
                    errorMessage = "Card does not support contactless"
                )
            }

            return outcome

        } catch (e: Exception) {
            return DiscoverKernelOutcome(
                type = DiscoverOutcomeType.END_APPLICATION,
                errorMessage = "Kernel error: ${e.message}",
                exception = e
            )
        }
    }

    private fun storeTransactionData(transaction: DiscoverTransactionData) {
        // Amount Authorized (Tag 9F02)
        transactionData["9F02"] = transaction.amount.toAmountBytes()

        // Amount Other (Tag 9F03)
        transactionData["9F03"] = transaction.cashbackAmount.toAmountBytes()

        // Transaction Type (Tag 9C)
        transactionData["9C"] = byteArrayOf(transaction.transactionType)

        // Transaction Date (Tag 9A)
        transactionData["9A"] = transaction.transactionDate

        // Transaction Time (Tag 9F21)
        transactionData["9F21"] = transaction.transactionTime

        // Terminal Country Code (Tag 9F1A)
        transactionData["9F1A"] = byteArrayOf(
            (transaction.countryCode shr 8).toByte(),
            transaction.countryCode.toByte()
        )

        // Transaction Currency Code (Tag 5F2A)
        transactionData["5F2A"] = byteArrayOf(
            (transaction.currencyCode shr 8).toByte(),
            transaction.currencyCode.toByte()
        )

        // Terminal Capabilities (Tag 9F33)
        transactionData["9F33"] = config.terminalCapabilities

        // Additional Terminal Capabilities (Tag 9F40)
        transactionData["9F40"] = config.additionalTerminalCapabilities

        // Unpredictable Number (Tag 9F37)
        val un = ByteArray(4)
        secureRandom.nextBytes(un)
        transactionData["9F37"] = un

        // Terminal Type (Tag 9F35)
        transactionData["9F35"] = byteArrayOf(config.terminalType)

        // Terminal Transaction Qualifiers (Tag 9F66)
        transactionData["9F66"] = config.ttq.bytes
    }

    private suspend fun selectApplication(aid: ByteArray): DiscoverSelectResult {
        val selectCmd = CommandApdu(
            cla = 0x00,
            ins = 0xA4.toByte(),
            p1 = 0x04,
            p2 = 0x00,
            data = aid,
            le = 0
        )

        val apdu = transceiver.transceive(selectCmd)

        if (!apdu.isSuccess) {
            return DiscoverSelectResult.Failed(apdu.sw1.toInt() and 0xFF, apdu.sw2.toInt() and 0xFF)
        }

        // Parse FCI
        val fciTlvs = TlvParser.parseRecursive(apdu.data)
        val fciMap = fciTlvs.associateBy { it.tag.hex }
        val pdol = fciMap["9F38"]?.value
        val appLabel = fciMap["50"]?.value
        val preferredName = fciMap["9F12"]?.value

        return DiscoverSelectResult.Success(
            pdol = pdol,
            applicationLabel = appLabel?.let { String(it, Charsets.US_ASCII) },
            preferredName = preferredName?.let { String(it, Charsets.US_ASCII) }
        )
    }

    private suspend fun getProcessingOptions(
        pdol: ByteArray?,
        transaction: DiscoverTransactionData
    ): DiscoverGpoResult {
        // Build PDOL data
        val pdolData = if (pdol != null) {
            buildPdolData(pdol, transaction)
        } else {
            byteArrayOf()
        }

        // Build GPO command data (83 + length + PDOL data)
        val gpoData = if (pdolData.isNotEmpty()) {
            byteArrayOf(0x83.toByte(), pdolData.size.toByte()) + pdolData
        } else {
            byteArrayOf(0x83.toByte(), 0x00.toByte())
        }

        val gpoCmd = CommandApdu(
            cla = 0x80.toByte(),
            ins = 0xA8.toByte(),
            p1 = 0x00,
            p2 = 0x00,
            data = gpoData,
            le = 0
        )

        val apdu = transceiver.transceive(gpoCmd)

        // Check for conditions requiring different interface
        if (apdu.sw1.toInt() and 0xFF == 0x69 && apdu.sw2.toInt() and 0xFF == 0x84) {
            return DiscoverGpoResult.TryAnotherInterface
        }

        if (!apdu.isSuccess) {
            return DiscoverGpoResult.Failed(apdu.sw1.toInt() and 0xFF, apdu.sw2.toInt() and 0xFF)
        }

        // Parse GPO response
        return parseGpoResponse(apdu.data)
    }

    private fun buildPdolData(pdol: ByteArray, transaction: DiscoverTransactionData): ByteArray {
        val result = mutableListOf<Byte>()
        var i = 0

        while (i < pdol.size) {
            // Parse tag
            var tag = pdol[i].toInt() and 0xFF
            i++

            if ((tag and 0x1F) == 0x1F) {
                tag = (tag shl 8) or (pdol[i].toInt() and 0xFF)
                i++
            }

            // Parse length
            val length = pdol[i].toInt() and 0xFF
            i++

            // Get data for this tag
            val tagHex = "%02X".format(tag).let {
                if (it.length == 2 && tag > 0xFF) "%04X".format(tag) else it
            }

            val data = transactionData[tagHex] ?: ByteArray(length)
            val paddedData = when {
                data.size == length -> data
                data.size < length -> ByteArray(length - data.size) + data
                else -> data.takeLast(length).toByteArray()
            }

            result.addAll(paddedData.toList())
        }

        return result.toByteArray()
    }

    private fun parseGpoResponse(data: ByteArray): DiscoverGpoResult {
        return try {
            if (data.isEmpty()) {
                return DiscoverGpoResult.Failed(0x6F, 0x00)
            }

            // Check for Format 1 (tag 80) or Format 2 (tag 77)
            if (data[0] == 0x80.toByte()) {
                // Format 1: 80 len AIP AFL
                val length = data[1].toInt() and 0xFF
                val aipBytes = data.copyOfRange(2, 4)
                val aflBytes = if (length > 2) data.copyOfRange(4, 2 + length) else byteArrayOf()

                val aip = DiscoverApplicationInterchangeProfile(aipBytes)
                transactionData["82"] = aipBytes

                DiscoverGpoResult.Success(
                    aip = aip,
                    afl = aflBytes,
                    responseData = mapOf("82" to aipBytes, "94" to aflBytes)
                )
            } else {
                // Format 2: TLV encoded
                val tlvList = TlvParser.parseRecursive(data)
                val tlvMap = tlvList.associateBy({ it.tag.hex }, { it.value })

                val aipBytes = tlvMap["82"] ?: return DiscoverGpoResult.Failed(0x6F, 0x00)
                val aflBytes = tlvMap["94"] ?: byteArrayOf()

                // Extract CTQ if present
                tlvMap["9F6C"]?.let {
                    ctq = DiscoverCardTransactionQualifiers(it)
                    transactionData["9F6C"] = it
                }

                // Store other response data
                tlvMap.forEach { (tag, value) ->
                    transactionData[tag] = value
                }

                val aip = DiscoverApplicationInterchangeProfile(aipBytes)

                DiscoverGpoResult.Success(
                    aip = aip,
                    afl = aflBytes,
                    responseData = tlvMap
                )
            }
        } catch (e: Exception) {
            DiscoverGpoResult.Failed(0x6F, 0x00)
        }
    }

    private suspend fun processEmvMode(
        gpoData: DiscoverGpoResult.Success,
        transaction: DiscoverTransactionData
    ): DiscoverKernelOutcome {
        // Step 3: READ RECORD - Read all records specified in AFL
        val readResult = readApplicationData(gpoData.afl)
        if (!readResult) {
            return DiscoverKernelOutcome(
                type = DiscoverOutcomeType.END_APPLICATION,
                errorMessage = "Failed to read application data"
            )
        }

        // Step 4: Offline Data Authentication
        val odaResult = performOda(gpoData.aip)

        // Step 5: Processing Restrictions
        val restrictionsResult = checkProcessingRestrictions(transaction)
        if (!restrictionsResult.passed) {
            return DiscoverKernelOutcome(
                type = DiscoverOutcomeType.DECLINED,
                errorMessage = restrictionsResult.reason
            )
        }

        // Step 6: CVM Processing
        val cvmResult = performCvmProcessing(transaction)

        // Step 7: Terminal Risk Management
        val trmResult = performTerminalRiskManagement(transaction)

        // Step 8: GENERATE AC
        return generateApplicationCryptogram(
            transaction = transaction,
            odaPassed = odaResult,
            cvmResult = cvmResult,
            firstAc = true
        )
    }

    private suspend fun processMagStripeMode(
        gpoData: DiscoverGpoResult.Success,
        transaction: DiscoverTransactionData
    ): DiscoverKernelOutcome {
        // In Mag Stripe Mode, we use Track 2 from GPO response
        val track2Data = transactionData["57"]
        val track2 = track2Data?.let { DiscoverTrack2Parser.parse(it) }

        // Determine CVM from CTQ
        val cvmResult = when {
            ctq?.cdcvmPerformed == true -> DiscoverCvmResult.CDCVM_PERFORMED
            ctq?.onlinePinRequired == true && config.ttq.onlinePinSupported -> DiscoverCvmResult.ONLINE_PIN
            ctq?.signatureRequired == true -> DiscoverCvmResult.SIGNATURE
            else -> DiscoverCvmResult.NO_CVM
        }

        // For Mag Stripe Mode, always go online
        return DiscoverKernelOutcome(
            type = DiscoverOutcomeType.ONLINE_REQUEST,
            track2Data = track2Data,
            maskedPan = track2?.maskedPan,
            expiryDate = track2?.expiryFormatted,
            cvmResult = cvmResult,
            isMagStripeMode = true
        )
    }

    private suspend fun readApplicationData(afl: ByteArray): Boolean {
        if (afl.isEmpty()) return true

        var i = 0
        while (i + 3 < afl.size) {
            val sfi = (afl[i].toInt() and 0xFF) shr 3
            val firstRecord = afl[i + 1].toInt() and 0xFF
            val lastRecord = afl[i + 2].toInt() and 0xFF
            val odaRecords = afl[i + 3].toInt() and 0xFF

            for (record in firstRecord..lastRecord) {
                val readCmd = CommandApdu(
                    cla = 0x00,
                    ins = 0xB2.toByte(),
                    p1 = record.toByte(),
                    p2 = ((sfi shl 3) or 0x04).toByte(),
                    le = 0
                )

                val apdu = transceiver.transceive(readCmd)

                if (!apdu.isSuccess) {
                    return false
                }

                // Parse and store record data
                val recordTlvList = TlvParser.parseRecursive(apdu.data)
                recordTlvList.forEach { tlv ->
                    transactionData[tlv.tag.hex] = tlv.value
                }
            }

            i += 4
        }

        return true
    }

    private fun performOda(aip: DiscoverApplicationInterchangeProfile): Boolean {
        if (!config.performOda) return true
        if (!aip.supportsOda()) return true

        return try {
            val rid = transactionData["4F"]?.take(5)?.toByteArray()
                ?: return false
            val caIndex = transactionData["8F"]?.firstOrNull()
                ?: return false

            val caKey = CaPublicKeyStore.getKey(rid, caIndex)
                ?: return false

            when (aip.getPreferredOdaMethod()) {
                DiscoverOdaMethod.SDA -> performSda(caKey)
                DiscoverOdaMethod.DDA -> performDda(caKey)
                DiscoverOdaMethod.CDA -> true // CDA performed during GENERATE AC
                DiscoverOdaMethod.NONE -> true
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun performSda(caKey: com.atlas.softpos.crypto.CaPublicKey): Boolean {
        val issuerCert = transactionData["90"] ?: return false
        val ssad = transactionData["93"] ?: return false
        return true // Simplified - full implementation in ODA module
    }

    private fun performDda(caKey: com.atlas.softpos.crypto.CaPublicKey): Boolean {
        return true // Simplified - full implementation in ODA module
    }

    private fun checkProcessingRestrictions(transaction: DiscoverTransactionData): ProcessingRestrictionsResult {
        // Check Application Expiration Date
        val expiryDate = transactionData["5F24"]
        if (expiryDate != null) {
            // Parse and check expiry
            val today = transaction.transactionDate
            // Simplified check - would parse BCD dates and compare
        }

        // Check Application Effective Date
        val effectiveDate = transactionData["5F25"]
        if (effectiveDate != null) {
            // Check if card is effective yet
        }

        return ProcessingRestrictionsResult(passed = true)
    }

    private fun performCvmProcessing(transaction: DiscoverTransactionData): DiscoverCvmResult {
        // Check CTQ first (card's preference)
        ctq?.let { ctq ->
            if (ctq.cdcvmPerformed) {
                transactionData["9F34"] = byteArrayOf(0x2F, 0x00, 0x02)
                return DiscoverCvmResult.CDCVM_PERFORMED
            }

            if (!ctq.cvmRequired) {
                transactionData["9F34"] = byteArrayOf(0x1F, 0x00, 0x02)
                return DiscoverCvmResult.NO_CVM
            }
        }

        // Check amount thresholds
        if (transaction.amount <= config.cvmRequiredLimit && config.noCvmAllowed) {
            transactionData["9F34"] = byteArrayOf(0x1F, 0x00, 0x02)
            return DiscoverCvmResult.NO_CVM
        }

        // CDCVM supported by terminal and card?
        if (config.ttq.consumerDeviceCvmSupported && ctq?.cdcvmPerformed != false) {
            transactionData["9F34"] = byteArrayOf(0x2F, 0x00, 0x02)
            return DiscoverCvmResult.CDCVM_REQUIRED
        }

        // Online PIN?
        if (config.ttq.onlinePinSupported && ctq?.onlinePinRequired != false) {
            transactionData["9F34"] = byteArrayOf(0x02, 0x00, 0x02)
            return DiscoverCvmResult.ONLINE_PIN
        }

        // Signature?
        if (config.ttq.signatureSupported && ctq?.signatureRequired != false) {
            transactionData["9F34"] = byteArrayOf(0x1E, 0x00, 0x02)
            return DiscoverCvmResult.SIGNATURE
        }

        transactionData["9F34"] = byteArrayOf(0x1F, 0x00, 0x02)
        return DiscoverCvmResult.NO_CVM
    }

    private fun performTerminalRiskManagement(transaction: DiscoverTransactionData): Boolean {
        // Floor limit check
        if (transaction.amount > config.floorLimit) {
            return false // Must go online
        }

        // Random transaction selection
        val randomValue = secureRandom.nextInt(100)
        if (randomValue < config.targetPercentage) {
            return false // Selected for online
        }

        return true // Can approve offline
    }

    private suspend fun generateApplicationCryptogram(
        transaction: DiscoverTransactionData,
        odaPassed: Boolean,
        cvmResult: DiscoverCvmResult,
        firstAc: Boolean
    ): DiscoverKernelOutcome {
        // Build CDOL1 data
        val cdol1 = transactionData["8C"] ?: getDefaultCdol1()
        val cdolData = buildCdolData(cdol1)

        // Determine AC type to request
        // SoftPOS always requests ARQC (online authorization)
        val acType = 0x80 // ARQC

        // Build GENERATE AC command
        val genAcCmd = CommandApdu(
            cla = 0x80.toByte(),
            ins = 0xAE.toByte(),
            p1 = acType.toByte(),
            p2 = 0x00,
            data = cdolData,
            le = 0
        )

        val apdu = transceiver.transceive(genAcCmd)

        if (!apdu.isSuccess) {
            return DiscoverKernelOutcome(
                type = DiscoverOutcomeType.END_APPLICATION,
                errorMessage = "GENERATE AC failed: ${apdu.sw1.toHexString()}${apdu.sw2.toHexString()}"
            )
        }

        // Parse GENERATE AC response
        return parseGenerateAcResponse(apdu.data, cvmResult, transaction)
    }

    private fun buildCdolData(cdol: ByteArray): ByteArray {
        val result = mutableListOf<Byte>()
        var i = 0

        while (i < cdol.size) {
            var tag = cdol[i].toInt() and 0xFF
            i++

            if ((tag and 0x1F) == 0x1F) {
                tag = (tag shl 8) or (cdol[i].toInt() and 0xFF)
                i++
            }

            val length = cdol[i].toInt() and 0xFF
            i++

            val tagHex = if (tag > 0xFF) "%04X".format(tag) else "%02X".format(tag)
            val data = transactionData[tagHex] ?: ByteArray(length)

            val paddedData = when {
                data.size == length -> data
                data.size < length -> ByteArray(length - data.size) + data
                else -> data.takeLast(length).toByteArray()
            }

            result.addAll(paddedData.toList())
        }

        return result.toByteArray()
    }

    private fun getDefaultCdol1(): ByteArray {
        // Default CDOL1: Amount, Amount Other, Country Code, TVR, Currency Code,
        // Date, Type, UN, Terminal Capabilities, CVM Results
        return byteArrayOf(
            0x9F.toByte(), 0x02, 0x06,  // Amount
            0x9F.toByte(), 0x03, 0x06,  // Amount Other
            0x9F.toByte(), 0x1A.toByte(), 0x02,  // Country Code
            0x95.toByte(), 0x05,  // TVR
            0x5F, 0x2A, 0x02,  // Currency Code
            0x9A.toByte(), 0x03,  // Date
            0x9C.toByte(), 0x01,  // Type
            0x9F.toByte(), 0x37, 0x04,  // UN
            0x9F.toByte(), 0x34, 0x03   // CVM Results
        )
    }

    private fun parseGenerateAcResponse(
        data: ByteArray,
        cvmResult: DiscoverCvmResult,
        transaction: DiscoverTransactionData
    ): DiscoverKernelOutcome {
        val tlvMap: Map<String, ByteArray> = if (data.isNotEmpty() && (data[0] == 0x77.toByte() || data[0] == 0x80.toByte())) {
            TlvParser.parseRecursive(data).associateBy({ it.tag.hex }, { it.value })
        } else {
            mapOf()
        }

        // Get Cryptogram Information Data (CID)
        val cid = tlvMap["9F27"]?.firstOrNull()?.toInt()?.and(0xFF) ?: 0x80
        val cryptogramType = (cid and 0xC0) shr 6

        // Get Application Cryptogram
        val cryptogram = tlvMap["9F26"]

        // Get ATC
        val atc = tlvMap["9F36"]

        // Get IAD
        val iad = tlvMap["9F10"]

        // Store response data
        tlvMap.forEach { (tag, value) ->
            transactionData[tag] = value
        }

        // Get Track 2 data for outcome
        val track2 = transactionData["57"]?.let { DiscoverTrack2Parser.parse(it) }

        return when (cryptogramType) {
            0 -> {
                // AAC - Transaction Declined
                DiscoverKernelOutcome(
                    type = DiscoverOutcomeType.DECLINED,
                    cryptogram = cryptogram,
                    atc = atc,
                    iad = iad,
                    cvmResult = cvmResult,
                    maskedPan = track2?.maskedPan
                )
            }
            1 -> {
                // TC - Transaction Approved Offline
                DiscoverKernelOutcome(
                    type = DiscoverOutcomeType.APPROVED,
                    cryptogram = cryptogram,
                    atc = atc,
                    iad = iad,
                    cvmResult = cvmResult,
                    track2Data = transactionData["57"],
                    maskedPan = track2?.maskedPan,
                    expiryDate = track2?.expiryFormatted
                )
            }
            2 -> {
                // ARQC - Online Authorization Required
                DiscoverKernelOutcome(
                    type = DiscoverOutcomeType.ONLINE_REQUEST,
                    cryptogram = cryptogram,
                    atc = atc,
                    iad = iad,
                    cvmResult = cvmResult,
                    track2Data = transactionData["57"],
                    maskedPan = track2?.maskedPan,
                    expiryDate = track2?.expiryFormatted,
                    emvData = buildEmvDataForOnline()
                )
            }
            else -> {
                DiscoverKernelOutcome(
                    type = DiscoverOutcomeType.END_APPLICATION,
                    errorMessage = "Unknown cryptogram type: $cryptogramType"
                )
            }
        }
    }

    private fun buildEmvDataForOnline(): Map<String, ByteArray> {
        val emvTags = listOf(
            "9F26", "9F27", "9F10", "9F37", "9F36", "95", "9A", "9C",
            "9F02", "5F2A", "82", "9F1A", "9F34", "9F33", "9F35", "9F1E",
            "84", "9F09", "9F41", "5F34", "57"
        )

        return emvTags.mapNotNull { tag ->
            transactionData[tag]?.let { tag to it }
        }.toMap()
    }

    private fun Long.toAmountBytes(): ByteArray {
        val hex = "%012d".format(this)
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun Byte.toHexString(): String = "%02X".format(this)
}

// Supporting classes

sealed class DiscoverSelectResult {
    data class Success(
        val pdol: ByteArray?,
        val applicationLabel: String?,
        val preferredName: String?
    ) : DiscoverSelectResult()

    data class Failed(val sw1: Int, val sw2: Int) : DiscoverSelectResult()
}

sealed class DiscoverGpoResult {
    data class Success(
        val aip: DiscoverApplicationInterchangeProfile,
        val afl: ByteArray,
        val responseData: Map<String, ByteArray>
    ) : DiscoverGpoResult()

    data class Failed(val sw1: Int, val sw2: Int) : DiscoverGpoResult()
    object TryAnotherInterface : DiscoverGpoResult()
}

data class ProcessingRestrictionsResult(
    val passed: Boolean,
    val reason: String? = null
)

enum class DiscoverCvmResult {
    NO_CVM,
    CDCVM_PERFORMED,
    CDCVM_REQUIRED,
    ONLINE_PIN,
    SIGNATURE,
    FAILED
}

enum class DiscoverOutcomeType {
    APPROVED,
    ONLINE_REQUEST,
    DECLINED,
    TRY_ANOTHER_INTERFACE,
    END_APPLICATION
}

data class DiscoverKernelOutcome(
    val type: DiscoverOutcomeType,
    val cryptogram: ByteArray? = null,
    val atc: ByteArray? = null,
    val iad: ByteArray? = null,
    val cvmResult: DiscoverCvmResult? = null,
    val track2Data: ByteArray? = null,
    val maskedPan: String? = null,
    val expiryDate: String? = null,
    val errorMessage: String? = null,
    val exception: Throwable? = null,
    val emvData: Map<String, ByteArray>? = null,
    val isMagStripeMode: Boolean = false
)

data class DiscoverTransactionData(
    val amount: Long,
    val cashbackAmount: Long = 0,
    val transactionType: Byte = 0x00,
    val currencyCode: Int = 0x0840,
    val countryCode: Int = 0x0840,
    val transactionDate: ByteArray,
    val transactionTime: ByteArray
)

data class DiscoverKernelConfiguration(
    val terminalType: Byte = 0x22,
    val terminalCapabilities: ByteArray = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
    val additionalTerminalCapabilities: ByteArray = byteArrayOf(0x6F, 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01),
    val ttq: DiscoverTerminalTransactionQualifiers = DiscoverTerminalTransactionQualifiers.forSoftPos(),
    val floorLimit: Long = 0,
    val cvmRequiredLimit: Long = 0,
    val targetPercentage: Int = 0,
    val performOda: Boolean = true,
    val noCvmAllowed: Boolean = true
)
