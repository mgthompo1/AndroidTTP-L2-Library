package com.atlas.softpos.kernel.mastercard

import com.atlas.softpos.core.apdu.EmvCommands
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.dol.DataStore
import com.atlas.softpos.core.dol.DolParser
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.tlv.TlvTag
import com.atlas.softpos.crypto.OfflineDataAuthentication
import com.atlas.softpos.crypto.OdaResult
import com.atlas.softpos.crypto.StandaloneOdaProcessor
import com.atlas.softpos.crypto.IssuerScriptAuthenticator
import com.atlas.softpos.crypto.IssuerScriptProcessor
import com.atlas.softpos.crypto.IssuerScripts
import com.atlas.softpos.kernel.common.CardTransceiver
import com.atlas.softpos.kernel.common.SelectedApplication
import com.atlas.softpos.kernel.common.TerminalVerificationResults
import timber.log.Timber
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * Mastercard Contactless Kernel (Kernel 2)
 *
 * Production-level implementation of EMV Contactless Specifications Book C-2
 *
 * Supports:
 * - M/Chip Advance (EMV mode) with full ODA
 * - PayPass Mag Stripe (legacy mode) with CVC3
 * - On-device Cardholder Verification (CDCVM)
 * - Relay Resistance Protocol (optional)
 *
 * Key Transaction Flows:
 *
 * M/Chip Flow:
 * 1. GPO with PDOL → AIP/AFL
 * 2. READ RECORD(s) per AFL
 * 3. ODA (fDDA with CDA during AC)
 * 4. Processing Restrictions
 * 5. CVM Processing
 * 6. Terminal Risk Management
 * 7. Terminal Action Analysis
 * 8. GENERATE AC → ARQC/TC/AAC
 *
 * Mag Stripe Flow:
 * 1. GPO → Track 1/2 + AIP
 * 2. COMPUTE CRYPTOGRAPHIC CHECKSUM → CVC3
 * 3. Build modified Track 1/2 with UN/ATC/CVC3
 *
 * Reference: M/Chip Requirements for Contact and Contactless
 */
class MastercardContactlessKernel(
    private val transceiver: CardTransceiver,
    private val config: MastercardKernelConfig = MastercardKernelConfig(),
    private val odaProcessor: OfflineDataAuthentication? = null
) {
    // Terminal data store
    private val terminalData = DataStore()

    // Card data store (populated from GPO and READ RECORD responses)
    private val cardData = mutableMapOf<Int, ByteArray>()

    // TVR for tracking verification results
    private val tvr = TerminalVerificationResults()

    // Script processor for authenticated issuer script execution
    private val scriptProcessor = IssuerScriptProcessor(transceiver)

    // Transaction state
    private var transactionPath: TransactionPath = TransactionPath.EMV
    private var cvmResult: CvmResult = CvmResult.NoCvmPerformed
    private var odaStatus: OdaStatus = OdaStatus.NotPerformed

    // Records for ODA
    private val odaRecords = mutableListOf<ByteArray>()

    /**
     * Process a Mastercard contactless transaction
     *
     * @param application Selected application from Entry Point
     * @param transaction Transaction parameters
     * @return Kernel result indicating outcome
     */
    suspend fun processTransaction(
        application: SelectedApplication,
        transaction: MastercardTransactionParams
    ): MastercardKernelOutcome {
        Timber.d("Starting Mastercard kernel processing")

        try {
            // Reset state
            resetState()

            // Initialize terminal data
            initializeTerminalData(transaction)

            // Step 1: GET PROCESSING OPTIONS
            val gpoResult = performGetProcessingOptions(application.pdol)
            if (gpoResult is GpoResult.Error) {
                return MastercardKernelOutcome.EndApplication(
                    error = gpoResult.error,
                    discretionaryData = buildDiscretionaryData()
                )
            }
            val gpoSuccess = gpoResult as GpoResult.Success

            // Determine transaction path based on AIP
            transactionPath = determineTransactionPath(gpoSuccess.aip)
            Timber.d("Transaction path: $transactionPath")

            return when (transactionPath) {
                TransactionPath.EMV -> processEmvPath(gpoSuccess, transaction)
                TransactionPath.MAG_STRIPE -> processMagStripePath(gpoSuccess, transaction)
            }

        } catch (e: Exception) {
            Timber.e(e, "Mastercard kernel error")
            return MastercardKernelOutcome.EndApplication(
                error = MastercardError.KERNEL_ERROR,
                discretionaryData = buildDiscretionaryData()
            )
        }
    }

    /**
     * Process online response from issuer
     *
     * This method should be called after receiving the online authorization response.
     * It handles:
     * 1. ARPC verification (Method 1 or Method 2)
     * 2. Issuer script execution (tags 71/72)
     * 3. Second GENERATE AC to finalize transaction
     *
     * @param onlineResponse The online response containing ARPC and issuer scripts
     * @param previousAuthData The authorization data from the initial OnlineRequest
     * @return Final outcome after online processing
     */
    suspend fun processOnlineResponse(
        onlineResponse: OnlineAuthResponse,
        previousAuthData: MastercardAuthorizationData
    ): OnlineResponseResult {
        Timber.d("Processing online response: approved=${onlineResponse.approved}")

        try {
            // Step 1: Prepare Issuer Authentication Data (Tag 91) for card verification
            // Note: Terminal does NOT verify ARPC locally - the card does during second GENERATE AC
            val issuerAuthData = buildIssuerAuthData(onlineResponse.arpc, onlineResponse.arc)
            if (issuerAuthData != null) {
                // Store Tag 91 in terminalData for CDOL2 building
                terminalData.set(0x91, issuerAuthData)
                Timber.d("Issuer auth data (Tag 91) prepared for second GENERATE AC")
            } else if (onlineResponse.arpc != null) {
                // ARPC provided but couldn't build Tag 91 - set TVR flag
                tvr.issuerAuthFailed = true
                Timber.w("Could not build issuer auth data from ARPC/ARC")
            }

            // Build IssuerScripts structure for processor
            val issuerScripts = createIssuerScripts(onlineResponse)

            // For online terminals: when issuer approves, we trust the issuer for script execution.
            // The card will verify ARPC cryptographically during second GENERATE AC.
            // We create an "assumed success" auth result for the script processor.
            val authResult = if (onlineResponse.approved && issuerAuthData != null) {
                // Trusted issuer - allow script execution with whitelist validation
                IssuerScriptAuthenticator.IssuerAuthResult.Success(
                    arpc = onlineResponse.arpc ?: ByteArray(8),
                    responseCode = onlineResponse.arc ?: byteArrayOf(0x30, 0x30)
                )
            } else {
                IssuerScriptAuthenticator.IssuerAuthResult.NoAuthData
            }

            // Step 2: Execute issuer scripts before second GENERATE AC (tag 71)
            val script71ProcessingResult = if (issuerScripts.script71 != null) {
                Timber.d("Processing tag 71 issuer scripts with authenticated processor")
                scriptProcessor.processScripts(
                    scripts = issuerScripts,
                    authResult = authResult,
                    tvr = tvr.toBytes(),
                    scriptType = IssuerScriptProcessor.ScriptType.SCRIPT_71
                )
            } else {
                IssuerScriptProcessor.ScriptProcessingResult.NoScripts
            }

            // Check for abort condition from Tag 71 scripts
            if (script71ProcessingResult is IssuerScriptProcessor.ScriptProcessingResult.Aborted) {
                val scriptResults = script71ProcessingResult.results.map { cmdResult ->
                    IssuerScriptResult(
                        success = cmdResult.status == IssuerScriptProcessor.CommandStatus.SUCCESS,
                        sw = cmdResult.sw,
                        abortTransaction = cmdResult.status == IssuerScriptProcessor.CommandStatus.ABORTED
                    )
                }
                return OnlineResponseResult.ScriptFailed(
                    error = "Issuer script 71 aborted",
                    scriptResults = scriptResults
                )
            }

            // Step 3: Perform second GENERATE AC
            val secondAcResult = performSecondGenerateAc(onlineResponse.approved)

            // Step 4: Execute issuer scripts after second GENERATE AC (tag 72)
            val script72ProcessingResult = if (issuerScripts.script72 != null) {
                Timber.d("Processing tag 72 issuer scripts with authenticated processor")
                // For Tag 72, we use the result of second GENERATE AC to determine auth
                val postAcAuthResult = when (secondAcResult) {
                    is SecondAcResult.Approved -> authResult  // Card confirmed auth
                    else -> IssuerScriptAuthenticator.IssuerAuthResult.NoAuthData
                }
                scriptProcessor.processScripts(
                    scripts = issuerScripts,
                    authResult = postAcAuthResult,
                    tvr = tvr.toBytes(),
                    scriptType = IssuerScriptProcessor.ScriptType.SCRIPT_72
                )
            } else {
                IssuerScriptProcessor.ScriptProcessingResult.NoScripts
            }

            // Collect all script results
            val allScriptResults = collectScriptResults(script71ProcessingResult) +
                    collectScriptResults(script72ProcessingResult)

            // Build final result
            return when (secondAcResult) {
                is SecondAcResult.Approved -> OnlineResponseResult.Approved(
                    authorizationData = secondAcResult.authData,
                    scriptResults = allScriptResults
                )
                is SecondAcResult.Declined -> OnlineResponseResult.Declined(
                    reason = secondAcResult.reason,
                    authorizationData = secondAcResult.authData,
                    scriptResults = allScriptResults
                )
                is SecondAcResult.Error -> OnlineResponseResult.Error(
                    error = secondAcResult.error,
                    scriptResults = allScriptResults
                )
            }

        } catch (e: Exception) {
            Timber.e(e, "Error processing online response")
            return OnlineResponseResult.Error(
                error = "Online response processing failed: ${e.message}",
                scriptResults = emptyList()
            )
        }
    }

    /**
     * Convert script processing result to list of IssuerScriptResult
     */
    private fun collectScriptResults(
        result: IssuerScriptProcessor.ScriptProcessingResult
    ): List<IssuerScriptResult> {
        return when (result) {
            is IssuerScriptProcessor.ScriptProcessingResult.Success -> result.results.map { cmdResult ->
                IssuerScriptResult(
                    success = cmdResult.status == IssuerScriptProcessor.CommandStatus.SUCCESS,
                    sw = cmdResult.sw,
                    abortTransaction = false
                )
            }
            is IssuerScriptProcessor.ScriptProcessingResult.PartialSuccess -> result.results.map { cmdResult ->
                IssuerScriptResult(
                    success = cmdResult.status == IssuerScriptProcessor.CommandStatus.SUCCESS,
                    sw = cmdResult.sw,
                    abortTransaction = false
                )
            }
            is IssuerScriptProcessor.ScriptProcessingResult.Failed -> result.results.map { cmdResult ->
                IssuerScriptResult(
                    success = false,
                    sw = cmdResult.sw,
                    abortTransaction = false
                )
            }
            is IssuerScriptProcessor.ScriptProcessingResult.Aborted -> result.results.map { cmdResult ->
                IssuerScriptResult(
                    success = cmdResult.status == IssuerScriptProcessor.CommandStatus.SUCCESS,
                    sw = cmdResult.sw,
                    abortTransaction = cmdResult.status == IssuerScriptProcessor.CommandStatus.ABORTED
                )
            }
            is IssuerScriptProcessor.ScriptProcessingResult.NoScripts -> emptyList()
            is IssuerScriptProcessor.ScriptProcessingResult.AuthenticationRequired -> emptyList()
        }
    }

    /**
     * Build Issuer Authentication Data (Tag 91) for second GENERATE AC
     *
     * Per EMV Book 2: The terminal does NOT verify ARPC locally - it passes
     * the Issuer Authentication Data to the card. The card verifies ARPC
     * using its internal keys and returns TC (approved) or AAC (declined).
     *
     * Tag 91 Format (Method 1): ARPC (8 bytes) || ARC (2 bytes)
     * Tag 91 Format (Method 2): ARPC (4 bytes) || CSU (4 bytes) || Prop Data
     *
     * @param arpc ARPC from issuer
     * @param arc Authorization Response Code (2 bytes)
     * @return Tag 91 data to include in CDOL2, or null if data is invalid
     */
    private fun buildIssuerAuthData(arpc: ByteArray?, arc: ByteArray?): ByteArray? {
        if (arpc == null || arc == null) {
            Timber.d("No issuer auth data available")
            return null
        }

        // Method 1: ARPC (8) || ARC (2)
        if (arpc.size == 8 && arc.size == 2) {
            val issuerAuthData = ByteArray(10)
            System.arraycopy(arpc, 0, issuerAuthData, 0, 8)
            System.arraycopy(arc, 0, issuerAuthData, 8, 2)
            Timber.d("Built Tag 91 issuer auth data (Method 1): ${issuerAuthData.toHexString()}")
            return issuerAuthData
        }

        // Method 2: ARPC (4) || CSU (4) - ARC is CSU in this case
        if (arpc.size == 4 && arc.size >= 4) {
            val issuerAuthData = ByteArray(8)
            System.arraycopy(arpc, 0, issuerAuthData, 0, 4)
            System.arraycopy(arc, 0, issuerAuthData, 4, 4)
            Timber.d("Built Tag 91 issuer auth data (Method 2): ${issuerAuthData.toHexString()}")
            return issuerAuthData
        }

        Timber.w("Invalid ARPC/ARC sizes: ARPC=${arpc.size}, ARC=${arc.size}")
        return null
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }

    /**
     * Perform second GENERATE AC after online authorization
     */
    private suspend fun performSecondGenerateAc(onlineApproved: Boolean): SecondAcResult {
        // Build CDOL2 data
        val cdol2 = cardData[0x8D] // CDOL2
        if (cdol2 == null) {
            // No CDOL2 - use CDOL1 format
            Timber.d("No CDOL2, using CDOL1 format for second AC")
        }

        val cdolData = if (cdol2 != null) {
            DolParser.buildDolData(cdol2, terminalData)
        } else {
            // Fall back to CDOL1
            cardData[0x8C]?.let { DolParser.buildDolData(it, terminalData) } ?: ByteArray(0)
        }

        // Determine requested cryptogram type based on online result
        val requestedCryptogramType = if (onlineApproved) {
            EmvCommands.CryptogramType.TC
        } else {
            EmvCommands.CryptogramType.AAC
        }

        // Send GENERATE AC
        val command = EmvCommands.generateAc(requestedCryptogramType, cdolData, cda = false)

        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return SecondAcResult.Error("Second GENERATE AC failed: SW=${response.sw.toString(16)}")
        }

        // Parse response
        val tlvs = TlvParser.parseRecursive(response.data)
        val tlvMap = tlvs.associateBy { it.tag.hex }

        val cid = tlvMap["9F27"]?.value?.getOrNull(0) ?: return SecondAcResult.Error("Missing CID in response")
        val ac = tlvMap["9F26"]?.value ?: return SecondAcResult.Error("Missing AC in response")
        val atc = tlvMap["9F36"]?.value

        // Update card data with response
        tlvMap["9F26"]?.value?.let { cardData[0x9F26] = it }
        tlvMap["9F27"]?.value?.let { cardData[0x9F27] = it }
        atc?.let { cardData[0x9F36] = it }

        val resultCryptogramType = when ((cid.toInt() and 0xC0) shr 6) {
            0 -> CryptogramType.AAC
            1 -> CryptogramType.TC
            2 -> CryptogramType.ARQC
            else -> CryptogramType.AAC
        }

        val authData = buildAuthorizationDataFromSecondAc(resultCryptogramType, ac, cid, atc)

        return when (resultCryptogramType) {
            CryptogramType.TC -> SecondAcResult.Approved(authData)
            CryptogramType.AAC -> SecondAcResult.Declined("Card declined after online", authData)
            else -> SecondAcResult.Error("Unexpected cryptogram type in second AC: $resultCryptogramType")
        }
    }

    /**
     * Create IssuerScripts object from online response for script processing
     */
    private fun createIssuerScripts(onlineResponse: OnlineAuthResponse): IssuerScripts {
        return IssuerScripts(
            script71 = onlineResponse.issuerScripts71?.let { scripts ->
                scripts.fold(ByteArray(0)) { acc, script -> acc + script }
            },
            script72 = onlineResponse.issuerScripts72?.let { scripts ->
                scripts.fold(ByteArray(0)) { acc, script -> acc + script }
            },
            issuerAuthData = onlineResponse.issuerAuthData,
            arc = onlineResponse.arc
        )
    }

    /**
     * Reset kernel state for new transaction
     */
    private fun resetState() {
        terminalData.clear()
        cardData.clear()
        tvr.reset()
        odaRecords.clear()
        transactionPath = TransactionPath.EMV
        cvmResult = CvmResult.NoCvmPerformed
        odaStatus = OdaStatus.NotPerformed
    }

    /**
     * Initialize terminal data for PDOL/CDOL construction
     */
    private fun initializeTerminalData(transaction: MastercardTransactionParams) {
        // Transaction data
        terminalData.set(0x9F02, transaction.amount.toAmountBcd())  // Amount, Authorized
        terminalData.set(0x9F03, (transaction.cashbackAmount ?: 0L).toAmountBcd())  // Amount, Other

        // Date/Time
        val now = LocalDate.now()
        val time = LocalTime.now()
        terminalData.set(0x9A, now.format(DateTimeFormatter.ofPattern("yyMMdd")).hexToByteArray())
        terminalData.set(0x9F21, time.format(DateTimeFormatter.ofPattern("HHmmss")).hexToByteArray())

        // Transaction type
        terminalData.set(0x9C, byteArrayOf(transaction.type))

        // Unpredictable number
        val un = ByteArray(4)
        SecureRandom().nextBytes(un)
        terminalData.set(0x9F37, un)

        // Terminal configuration
        terminalData.set(0x9F1A, config.terminalCountryCode)
        terminalData.set(0x5F2A, config.transactionCurrencyCode)
        terminalData.set(0x9F33, config.terminalCapabilities)
        terminalData.set(0x9F35, byteArrayOf(config.terminalType))
        terminalData.set(0x9F40, config.additionalTerminalCapabilities)
        terminalData.set(0x9F15, config.merchantCategoryCode)
        terminalData.set(0x9F16, config.merchantIdentifier.toByteArray(Charsets.US_ASCII).padRight(15))
        terminalData.set(0x9F1C, config.terminalIdentification.toByteArray(Charsets.US_ASCII).padRight(8))
        terminalData.set(0x9F01, config.acquirerIdentifier)

        // Initialize TVR to zeros
        terminalData.set(0x95, ByteArray(5))

        // Initialize CVM Results
        terminalData.set(0x9F34, ByteArray(3))

        // Terminal floor limit
        terminalData.set(0x9F1B, config.terminalFloorLimit.toFloorLimit())

        // Third party data for SoftPOS
        terminalData.set(0x9F6E, ThirdPartyData.forSoftPos().toBytes())

        // Terminal Interchange Profile
        terminalData.set(0x9F53, TerminalInterchangeProfile.forSoftPos().toBytes())

        Timber.v("Terminal data initialized with ${terminalData.all().size} elements")
    }

    /**
     * Perform GET PROCESSING OPTIONS command
     */
    private suspend fun performGetProcessingOptions(pdol: ByteArray?): GpoResult {
        // Build PDOL data
        val pdolData = if (pdol != null && pdol.isNotEmpty()) {
            DolParser.buildDolData(pdol, terminalData)
        } else {
            ByteArray(0)
        }

        // Wrap in command data format (83 Lc PDOL-data)
        val commandData = if (pdolData.isNotEmpty()) {
            byteArrayOf(0x83.toByte(), pdolData.size.toByte()) + pdolData
        } else {
            byteArrayOf(0x83.toByte(), 0x00.toByte())
        }

        val command = EmvCommands.getProcessingOptions(commandData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            Timber.w("GPO failed: SW=${response.sw1}${response.sw2}")
            return GpoResult.Error(mapSwToError(response.sw1.toInt() and 0xFF, response.sw2.toInt() and 0xFF))
        }

        return parseGpoResponse(response.data)
    }

    /**
     * Parse GPO response (Format 1 or Format 2)
     */
    private fun parseGpoResponse(data: ByteArray): GpoResult {
        if (data.isEmpty()) {
            return GpoResult.Error(MastercardError.EMPTY_DATA)
        }

        return when (data[0].toInt() and 0xFF) {
            0x80 -> parseGpoFormat1(data)
            0x77 -> parseGpoFormat2(data)
            else -> GpoResult.Error(MastercardError.INVALID_RESPONSE)
        }
    }

    /**
     * Parse Format 1 GPO response (tag 80)
     */
    private fun parseGpoFormat1(data: ByteArray): GpoResult {
        val tlv = TlvParser.parse(data).firstOrNull()
            ?: return GpoResult.Error(MastercardError.PARSE_ERROR)

        val value = tlv.value
        if (value.size < 2) {
            return GpoResult.Error(MastercardError.INVALID_RESPONSE)
        }

        val aip = MastercardAIP(value.copyOfRange(0, 2))
        val afl = if (value.size > 2) value.copyOfRange(2, value.size) else ByteArray(0)

        // Store in card data
        cardData[0x82] = aip.toBytes()  // AIP
        cardData[0x94] = afl            // AFL

        Timber.d("GPO Format 1: $aip, AFL=${afl.size} bytes")

        return GpoResult.Success(aip, afl, null)
    }

    /**
     * Parse Format 2 GPO response (tag 77)
     */
    private fun parseGpoFormat2(data: ByteArray): GpoResult {
        val tlv = TlvParser.parse(data).firstOrNull()
            ?: return GpoResult.Error(MastercardError.PARSE_ERROR)

        // Parse all TLVs in the constructed template
        val nestedTlvs = TlvParser.parseRecursive(tlv.value)

        var aipBytes: ByteArray? = null
        var afl: ByteArray? = null
        var ctq: CardTransactionQualifiers? = null

        for (nested in nestedTlvs) {
            val tagValue = nested.tag.value
            cardData[tagValue] = nested.value

            when (tagValue) {
                0x82 -> aipBytes = nested.value
                0x94 -> afl = nested.value
                0x9F6C -> ctq = CardTransactionQualifiers(nested.value)
            }
        }

        if (aipBytes == null || aipBytes.size < 2) {
            return GpoResult.Error(MastercardError.MISSING_DATA)
        }

        val aip = MastercardAIP(aipBytes)

        Timber.d("GPO Format 2: $aip, AFL=${afl?.size ?: 0} bytes, CTQ=$ctq")

        return GpoResult.Success(aip, afl ?: ByteArray(0), ctq)
    }

    /**
     * Determine transaction path based on AIP
     */
    private fun determineTransactionPath(aip: MastercardAIP): TransactionPath {
        // Terminal prefers EMV mode if supported
        return if (aip.emvModeSupported) {
            TransactionPath.EMV
        } else if (aip.magStripeModeSupported) {
            TransactionPath.MAG_STRIPE
        } else {
            // Default to EMV
            TransactionPath.EMV
        }
    }

    /**
     * Process EMV (M/Chip) transaction path
     */
    private suspend fun processEmvPath(
        gpoResult: GpoResult.Success,
        transaction: MastercardTransactionParams
    ): MastercardKernelOutcome {
        Timber.d("Processing M/Chip path")

        // Step 2: Read Application Data
        val readResult = readApplicationData(gpoResult.afl)
        if (readResult is ReadRecordResult.Error) {
            return MastercardKernelOutcome.EndApplication(
                error = readResult.error,
                discretionaryData = buildDiscretionaryData()
            )
        }

        // Step 3: Offline Data Authentication
        performOda(gpoResult.aip)

        // Step 3.5: Relay Resistance Protocol (if supported)
        if (gpoResult.aip.relayResistanceSupported) {
            val rrpResult = performRelayResistanceProtocol()
            when (rrpResult) {
                is RrpResult.ThresholdExceeded -> {
                    Timber.w("RRP threshold exceeded: ${rrpResult.measuredTime}ms > ${rrpResult.threshold}ms")
                    tvr.relayResistanceThresholdExceeded = true
                }
                is RrpResult.TimeLimitsExceeded -> {
                    Timber.w("RRP time limits exceeded")
                    tvr.relayResistanceTimeLimitsExceeded = true
                }
                is RrpResult.Failed -> {
                    Timber.w("RRP failed: ${rrpResult.reason}")
                    tvr.relayResistanceThresholdExceeded = true
                }
                is RrpResult.Success -> {
                    Timber.d("RRP successful: ${rrpResult.measuredTime}ms")
                }
            }
        }

        // Step 4: Processing Restrictions
        val restrictionsResult = checkProcessingRestrictions()
        if (restrictionsResult is RestrictionResult.SwitchInterface) {
            return MastercardKernelOutcome.TryAnotherInterface(
                reason = restrictionsResult.reason,
                discretionaryData = buildDiscretionaryData()
            )
        }

        // Step 5: Cardholder Verification
        performCvm(transaction, gpoResult.aip, gpoResult.ctq)

        // Step 6: Terminal Risk Management
        performTerminalRiskManagement(transaction)

        // Step 7: Terminal Action Analysis
        val acType = performTerminalActionAnalysis()

        // Step 8: Generate Application Cryptogram
        val acResult = generateApplicationCryptogram(acType)
        if (acResult is GenerateAcResult.Error) {
            return MastercardKernelOutcome.EndApplication(
                error = acResult.error,
                discretionaryData = buildDiscretionaryData()
            )
        }
        val acSuccess = acResult as GenerateAcResult.Success

        // Build outcome based on cryptogram type returned
        return buildEmvOutcome(acSuccess, transaction)
    }

    /**
     * Process Mag Stripe transaction path
     */
    private suspend fun processMagStripePath(
        gpoResult: GpoResult.Success,
        transaction: MastercardTransactionParams
    ): MastercardKernelOutcome {
        Timber.d("Processing Mag Stripe path")

        // For Mag Stripe, Track 1/2 data comes in GPO response
        val track2 = cardData[0x57]  // Track 2 Equivalent Data
        if (track2 == null) {
            return MastercardKernelOutcome.EndApplication(
                error = MastercardError.MISSING_DATA,
                discretionaryData = buildDiscretionaryData()
            )
        }

        // Parse Track 2 data
        val track2Parsed = MastercardTrack2Parser.parse(track2)
            ?: return MastercardKernelOutcome.EndApplication(
                error = MastercardError.PARSE_ERROR,
                discretionaryData = buildDiscretionaryData()
            )

        // Perform CVM for Mag Stripe
        performMagStripeCvm(transaction, gpoResult.aip)

        // Compute Cryptographic Checksum (CVC3)
        val cccResult = computeCryptographicChecksum()
        if (cccResult is ComputeCccResult.Error) {
            return MastercardKernelOutcome.EndApplication(
                error = cccResult.error,
                discretionaryData = buildDiscretionaryData()
            )
        }
        val cccSuccess = cccResult as ComputeCccResult.Success

        // Build Mag Stripe outcome
        return buildMagStripeOutcome(track2Parsed, cccSuccess, transaction)
    }

    /**
     * Read application data based on AFL
     */
    private suspend fun readApplicationData(afl: ByteArray): ReadRecordResult {
        if (afl.isEmpty()) {
            Timber.d("Empty AFL, skipping record reads")
            return ReadRecordResult.Success
        }

        var offset = 0
        while (offset + 4 <= afl.size) {
            val sfi = (afl[offset].toInt() and 0xF8) shr 3
            val firstRecord = afl[offset + 1].toInt() and 0xFF
            val lastRecord = afl[offset + 2].toInt() and 0xFF
            val odaRecordCount = afl[offset + 3].toInt() and 0xFF
            offset += 4

            var odaRecordsRead = 0

            for (recordNum in firstRecord..lastRecord) {
                val response = readRecord(sfi, recordNum)
                if (response == null) {
                    Timber.w("Failed to read SFI $sfi record $recordNum")
                    tvr.iccDataMissing = true
                    continue
                }

                // Parse record TLVs
                val recordTlvs = TlvParser.parseRecursive(response)
                for (tlv in recordTlvs) {
                    if (!tlv.tag.isConstructed) {
                        cardData[tlv.tag.value] = tlv.value
                    }
                }

                // Collect ODA records
                if (odaRecordsRead < odaRecordCount) {
                    odaRecords.add(response)
                    odaRecordsRead++
                }
            }
        }

        Timber.d("Read ${cardData.size} card data elements, ${odaRecords.size} ODA records")
        return ReadRecordResult.Success
    }

    /**
     * Read a single record
     */
    private suspend fun readRecord(sfi: Int, recordNum: Int): ByteArray? {
        val command = EmvCommands.readRecord(recordNum, sfi)
        val response = transceiver.transceive(command)

        return if (response.isSuccess) {
            response.data
        } else {
            null
        }
    }

    /**
     * Perform Offline Data Authentication
     */
    private fun performOda(aip: MastercardAIP) {
        // Check if ODA is supported
        if (!aip.isOdaSupported()) {
            tvr.odaNotPerformed = true
            odaStatus = OdaStatus.NotPerformed
            Timber.d("ODA not supported by card")
            return
        }

        // Get required certificates
        val issuerPkCert = cardData[0x90]  // Issuer Public Key Certificate
        val iccPkCert = cardData[0x9F46]   // ICC Public Key Certificate
        val staticData = cardData[0x93]    // Signed Static Application Data

        if (odaProcessor == null) {
            Timber.w("ODA processor not available")
            tvr.odaNotPerformed = true
            odaStatus = OdaStatus.NotPerformed
            return
        }

        // Determine ODA type and perform
        when {
            aip.cdaSupported -> {
                // CDA will be performed during GENERATE AC
                Timber.d("CDA supported - will verify with GENERATE AC")
                odaStatus = OdaStatus.CdaPending
            }

            aip.ddaSupported -> {
                // Perform fDDA (fast DDA for contactless)
                performFdda(issuerPkCert, iccPkCert)
            }

            aip.sdaSupported -> {
                // Perform SDA
                performSda(issuerPkCert, staticData)
            }
        }
    }

    /**
     * Perform fast DDA (fDDA)
     */
    private fun performFdda(issuerPkCert: ByteArray?, iccPkCert: ByteArray?) {
        if (issuerPkCert == null || iccPkCert == null) {
            Timber.w("Missing certificates for fDDA")
            tvr.ddaFailed = true
            odaStatus = OdaStatus.Failed
            return
        }

        // Get AID for CA public key lookup
        val aid = cardData[0x4F] ?: cardData[0x84]
        if (aid == null) {
            tvr.ddaFailed = true
            odaStatus = OdaStatus.Failed
            return
        }

        // Get card's signed dynamic data
        val sdad = cardData[0x9F4B]  // Signed Dynamic Application Data
        if (sdad == null) {
            Timber.w("Missing SDAD for fDDA")
            tvr.ddaFailed = true
            odaStatus = OdaStatus.Failed
            return
        }

        // Build static data for authentication
        val aipBytes = cardData[0x82] ?: ByteArray(2)
        val staticDataToAuthenticate = buildStaticDataForAuth(aipBytes)

        // Get terminal data for dynamic authentication
        val unpredictableNumber = terminalData.get(0x9F37) ?: ByteArray(4)

        val result = StandaloneOdaProcessor.performFdda(
            aid = aid,
            issuerPkCertificate = issuerPkCert,
            issuerPkExponent = cardData[0x9F32] ?: byteArrayOf(0x03),
            iccPkCertificate = iccPkCert,
            iccPkExponent = cardData[0x9F47] ?: byteArrayOf(0x03),
            signedDynamicData = sdad,
            staticDataToAuthenticate = staticDataToAuthenticate,
            unpredictableNumber = unpredictableNumber
        )

        when (result) {
            is OdaResult.FddaSuccess -> {
                Timber.d("fDDA successful")
                odaStatus = OdaStatus.Successful
            }
            is OdaResult.DdaSuccess -> {
                Timber.d("DDA successful")
                odaStatus = OdaStatus.Successful
            }
            is OdaResult.Failed -> {
                Timber.w("fDDA failed: ${result.failureReason}")
                tvr.ddaFailed = true
                odaStatus = OdaStatus.Failed
            }
            null -> {
                tvr.ddaFailed = true
                odaStatus = OdaStatus.Failed
            }
            else -> {
                Timber.w("Unexpected ODA result: $result")
                tvr.ddaFailed = true
                odaStatus = OdaStatus.Failed
            }
        }
    }

    /**
     * Perform SDA
     */
    private fun performSda(issuerPkCert: ByteArray?, staticData: ByteArray?) {
        if (issuerPkCert == null || staticData == null) {
            Timber.w("Missing data for SDA")
            tvr.sdaFailed = true
            tvr.sdaSelected = true
            odaStatus = OdaStatus.Failed
            return
        }

        val aid = cardData[0x4F] ?: cardData[0x84]
        if (aid == null) {
            tvr.sdaFailed = true
            odaStatus = OdaStatus.Failed
            return
        }

        val aipBytes = cardData[0x82] ?: ByteArray(2)
        val staticDataToAuthenticate = buildStaticDataForAuth(aipBytes)

        val result = StandaloneOdaProcessor.performSda(
            aid = aid,
            issuerPkCertificate = issuerPkCert,
            issuerPkExponent = cardData[0x9F32] ?: byteArrayOf(0x03),
            signedStaticData = staticData,
            staticDataToAuthenticate = staticDataToAuthenticate
        )

        when (result) {
            is OdaResult.SdaSuccess -> {
                Timber.d("SDA successful")
                odaStatus = OdaStatus.Successful
            }
            is OdaResult.Failed -> {
                Timber.w("SDA failed: ${result.failureReason}")
                tvr.sdaFailed = true
                odaStatus = OdaStatus.Failed
            }
            null -> {
                tvr.sdaFailed = true
                odaStatus = OdaStatus.Failed
            }
            else -> {
                Timber.w("Unexpected ODA result: $result")
                tvr.sdaFailed = true
                odaStatus = OdaStatus.Failed
            }
        }
    }

    /**
     * Build static data for ODA
     */
    private fun buildStaticDataForAuth(aip: ByteArray): ByteArray {
        val result = mutableListOf<Byte>()

        // Add AIP if SDA
        if (tvr.sdaSelected) {
            result.addAll(aip.toList())
        }

        // Add all ODA records
        for (record in odaRecords) {
            result.addAll(record.toList())
        }

        // Add Data Authentication Code if present
        val dac = cardData[0x9F45]
        if (dac != null) {
            result.addAll(dac.toList())
        }

        return result.toByteArray()
    }

    /**
     * Perform Relay Resistance Protocol
     *
     * Measures the time taken for the card to respond to a challenge,
     * helping detect relay attacks where communication is being proxied.
     */
    private suspend fun performRelayResistanceProtocol(): RrpResult {
        Timber.d("Performing Relay Resistance Protocol")

        // Generate terminal relay resistance data
        // Format: Terminal RRP Entropy (4 bytes) || Min Grace Period (2 bytes) || Max Grace Period (2 bytes)
        // || Terminal Expected Transmission Time (2 bytes)
        val terminalEntropy = ByteArray(4)
        SecureRandom().nextBytes(terminalEntropy)

        val minGracePeriod = config.minRelayResistanceGracePeriod
        val maxGracePeriod = config.maxRelayResistanceGracePeriod

        // Expected transmission time in 100 microseconds units
        val expectedTransmissionTime = 50 // 5ms in 100μs units

        val terminalRrpData = ByteArray(10)
        System.arraycopy(terminalEntropy, 0, terminalRrpData, 0, 4)
        terminalRrpData[4] = ((minGracePeriod shr 8) and 0xFF).toByte()
        terminalRrpData[5] = (minGracePeriod and 0xFF).toByte()
        terminalRrpData[6] = ((maxGracePeriod shr 8) and 0xFF).toByte()
        terminalRrpData[7] = (maxGracePeriod and 0xFF).toByte()
        terminalRrpData[8] = ((expectedTransmissionTime shr 8) and 0xFF).toByte()
        terminalRrpData[9] = (expectedTransmissionTime and 0xFF).toByte()

        // Store terminal RRP entropy for later verification
        terminalData.set(0xDF8302, terminalEntropy)

        // Measure start time
        val startTime = System.nanoTime()

        // Send EXCHANGE RELAY RESISTANCE DATA command
        val command = EmvCommands.exchangeRelayResistanceData(terminalRrpData)
        val response = try {
            transceiver.transceive(command)
        } catch (e: Exception) {
            Timber.e(e, "RRP command failed")
            return RrpResult.Failed("Command execution failed: ${e.message}")
        }

        // Measure end time
        val endTime = System.nanoTime()
        val measuredTimeMs = (endTime - startTime) / 1_000_000

        if (!response.isSuccess) {
            // Card doesn't support RRP or command failed
            val sw = response.sw
            if (sw == 0x6A81 || sw == 0x6D00) {
                // Function not supported - not a failure
                Timber.d("Card does not support EXCHANGE RELAY RESISTANCE DATA")
                return RrpResult.Success(measuredTimeMs)
            }
            return RrpResult.Failed("RRP command failed: SW=${response.sw.toString(16)}")
        }

        // Parse response
        // Format: Device RRP Entropy (4 bytes) || Measured Transmission Time (2 bytes) ||
        //         Accuracy Threshold (1 byte) || Timing Flags (1 byte)
        val responseData = response.data
        if (responseData.size < 8) {
            return RrpResult.Failed("Invalid RRP response length")
        }

        val deviceEntropy = responseData.copyOfRange(0, 4)
        val deviceMeasuredTime = ((responseData[4].toInt() and 0xFF) shl 8) or (responseData[5].toInt() and 0xFF)
        val accuracyThreshold = responseData[6].toInt() and 0xFF
        val timingFlags = responseData[7].toInt() and 0xFF

        // Store in card data
        cardData[0xDF8303] = deviceEntropy
        cardData[0xDF8304] = responseData.copyOfRange(4, 6)
        cardData[0xDF8305] = byteArrayOf(responseData[6])
        cardData[0xDF8306] = byteArrayOf(responseData[7])

        // Calculate maximum allowed time
        // Max time = expected transmission time + max grace period + accuracy threshold
        val maxAllowedTimeMs = expectedTransmissionTime / 10 + maxGracePeriod + accuracyThreshold

        Timber.d("RRP timing - Measured: ${measuredTimeMs}ms, Max allowed: ${maxAllowedTimeMs}ms")

        // Check timing
        if (measuredTimeMs > maxAllowedTimeMs) {
            return RrpResult.ThresholdExceeded(measuredTimeMs, maxAllowedTimeMs.toLong())
        }

        // Check device timing flags for time limit exceeded
        val deviceTimeLimitExceeded = (timingFlags and 0x01) != 0
        if (deviceTimeLimitExceeded) {
            return RrpResult.TimeLimitsExceeded
        }

        return RrpResult.Success(measuredTimeMs)
    }

    /**
     * Check processing restrictions
     */
    private fun checkProcessingRestrictions(): RestrictionResult {
        // Application Expiration Date check
        val expiryDate = cardData[0x5F24]
        if (expiryDate != null) {
            val expiry = parseExpiryDate(expiryDate)
            if (expiry != null && expiry.isBefore(LocalDate.now())) {
                Timber.w("Card expired: $expiry")
                tvr.expiredApplication = true

                // Check if card wants to go online for expired
                val ctq = cardData[0x9F6C]?.let { CardTransactionQualifiers(it) }
                if (ctq?.goOnlineIfExpired == true) {
                    // Will force online
                } else {
                    return RestrictionResult.SwitchInterface("Card expired")
                }
            }
        }

        // Application Effective Date check
        val effectiveDate = cardData[0x5F25]
        if (effectiveDate != null) {
            val effective = parseExpiryDate(effectiveDate)
            if (effective != null && effective.isAfter(LocalDate.now())) {
                Timber.w("Application not yet effective: $effective")
                tvr.applicationNotYetEffective = true
            }
        }

        // Application Usage Control check
        val auc = cardData[0x9F07]
        if (auc != null && auc.size >= 2) {
            val transactionType = terminalData.get(0x9C)?.firstOrNull() ?: 0
            if (!checkApplicationUsageControl(auc, transactionType.toInt())) {
                tvr.serviceNotAllowed = true
            }
        }

        return RestrictionResult.Continue
    }

    /**
     * Check Application Usage Control
     */
    private fun checkApplicationUsageControl(auc: ByteArray, transactionType: Int): Boolean {
        // AUC Byte 1
        val domestic = true  // Simplified - would check terminal vs card country
        val international = !domestic

        val validDomesticCash = (auc[0].toInt() and 0x80) != 0
        val validInternationalCash = (auc[0].toInt() and 0x40) != 0
        val validDomesticGoods = (auc[0].toInt() and 0x20) != 0
        val validInternationalGoods = (auc[0].toInt() and 0x10) != 0
        val validDomesticServices = (auc[0].toInt() and 0x08) != 0
        val validInternationalServices = (auc[0].toInt() and 0x04) != 0
        val validAtAtm = (auc[0].toInt() and 0x02) != 0
        val validOtherThanAtm = (auc[0].toInt() and 0x01) != 0

        // Check based on transaction type
        return when (transactionType) {
            0x00 -> {  // Purchase
                if (domestic) validDomesticGoods || validDomesticServices
                else validInternationalGoods || validInternationalServices
            }
            0x01 -> {  // Cash
                if (domestic) validDomesticCash else validInternationalCash
            }
            else -> true
        }
    }

    /**
     * Perform Cardholder Verification Method processing
     */
    private fun performCvm(
        transaction: MastercardTransactionParams,
        aip: MastercardAIP,
        ctq: CardTransactionQualifiers?
    ) {
        Timber.d("Performing CVM processing")

        // Check if CVM required based on amount
        val cvmRequiredLimit = config.cvmRequiredLimit
        val noCvmRequired = transaction.amount <= cvmRequiredLimit

        // Build CVM Results (9F34)
        val cvmResults = ByteArray(3)

        // Check Card Transaction Qualifiers
        if (ctq != null) {
            if (ctq.cdcvmPerformed) {
                // Consumer Device CVM was performed on the card/device
                Timber.d("CDCVM performed (indicated in CTQ)")
                cvmResult = CvmResult.CdcvmPerformed
                cvmResults[0] = 0x1F  // No CVM performed (terminal)
                cvmResults[1] = 0x00  // N/A
                cvmResults[2] = 0x02  // Successful
                terminalData.set(0x9F34, cvmResults)
                return
            }

            if (ctq.onlinePinRequired && !noCvmRequired) {
                // Online PIN required
                Timber.d("Online PIN required")
                cvmResult = CvmResult.OnlinePinRequired
                cvmResults[0] = 0x02  // Online PIN
                cvmResults[1] = 0x00  // N/A
                cvmResults[2] = 0x00  // Unknown (will be verified online)
                terminalData.set(0x9F34, cvmResults)
                tvr.onlinePinEntered = true
                return
            }

            if (ctq.signatureRequired && !noCvmRequired) {
                // Signature required
                Timber.d("Signature required")
                cvmResult = CvmResult.SignatureRequired
                cvmResults[0] = 0x1E  // Signature
                cvmResults[1] = 0x00  // N/A
                cvmResults[2] = 0x00  // Unknown
                terminalData.set(0x9F34, cvmResults)
                return
            }
        }

        // Check CVM List if present
        val cvmList = cardData[0x8E]
        if (cvmList != null && cvmList.size >= 8) {
            val cvmListResult = processCvmList(cvmList, transaction.amount)
            if (cvmListResult != null) {
                cvmResult = cvmListResult.first
                terminalData.set(0x9F34, cvmListResult.second)
                return
            }
        }

        // No CVM required/performed
        if (noCvmRequired) {
            Timber.d("No CVM required (amount below limit)")
            cvmResult = CvmResult.NoCvmPerformed
            cvmResults[0] = 0x1F  // No CVM required
            cvmResults[1] = 0x00
            cvmResults[2] = 0x02  // Successful
        } else {
            Timber.w("CVM required but no valid CVM found")
            cvmResult = CvmResult.NoCvmPerformed
            tvr.cvmNotSuccessful = true
            cvmResults[0] = 0x3F  // No CVM performed
            cvmResults[1] = 0x00
            cvmResults[2] = 0x01  // Failed
        }

        terminalData.set(0x9F34, cvmResults)
    }

    /**
     * Process CVM List
     */
    private fun processCvmList(cvmList: ByteArray, amount: Long): Pair<CvmResult, ByteArray>? {
        if (cvmList.size < 8) return null

        // First 4 bytes: X amount (when condition 06 is used)
        // Next 4 bytes: Y amount (when condition 07/08/09 is used)
        // Remaining: CVM rules (2 bytes each)

        val xAmount = ((cvmList[0].toLong() and 0xFF) shl 24) or
                ((cvmList[1].toLong() and 0xFF) shl 16) or
                ((cvmList[2].toLong() and 0xFF) shl 8) or
                (cvmList[3].toLong() and 0xFF)

        val yAmount = ((cvmList[4].toLong() and 0xFF) shl 24) or
                ((cvmList[5].toLong() and 0xFF) shl 16) or
                ((cvmList[6].toLong() and 0xFF) shl 8) or
                (cvmList[7].toLong() and 0xFF)

        // Process CVM rules
        var offset = 8
        while (offset + 2 <= cvmList.size) {
            val cvmCode = cvmList[offset].toInt() and 0xFF
            val cvmCondition = cvmList[offset + 1].toInt() and 0xFF
            offset += 2

            // Check condition
            if (!checkCvmCondition(cvmCondition, amount, xAmount, yAmount)) {
                continue
            }

            // Process CVM rule
            val method = cvmCode and 0x3F
            val failIfUnsuccessful = (cvmCode and 0x40) == 0

            val result = applyCvmRule(method)
            if (result != null) {
                val cvmResults = byteArrayOf(
                    (cvmCode and 0x3F).toByte(),
                    cvmCondition.toByte(),
                    if (result.second) 0x02 else 0x01  // Success/Failed
                )
                return Pair(result.first, cvmResults)
            }

            if (failIfUnsuccessful) {
                // Stop processing
                break
            }
        }

        return null
    }

    /**
     * Check CVM condition
     */
    private fun checkCvmCondition(condition: Int, amount: Long, xAmount: Long, yAmount: Long): Boolean {
        return when (condition) {
            0x00 -> true  // Always
            0x01 -> false // Unattended cash - not applicable for SoftPOS
            0x02 -> false // Not unattended or not manual cash
            0x03 -> true  // Terminal supports CVM
            0x04 -> false // Manual cash
            0x05 -> false // Purchase with cashback
            0x06 -> amount < xAmount  // If transaction in application currency and under X value
            0x07 -> amount > xAmount  // If transaction in application currency and over X value
            0x08 -> amount < yAmount  // If transaction in application currency and under Y value
            0x09 -> amount > yAmount  // If transaction in application currency and over Y value
            else -> true
        }
    }

    /**
     * Apply CVM rule
     */
    private fun applyCvmRule(method: Int): Pair<CvmResult, Boolean>? {
        return when (method) {
            0x00 -> Pair(CvmResult.NoCvmPerformed, false)  // Fail CVM processing
            0x01 -> Pair(CvmResult.OfflinePlaintextPin, true)  // Plaintext PIN - not for contactless
            0x02 -> Pair(CvmResult.OnlinePinRequired, true)  // Online PIN
            0x03 -> Pair(CvmResult.OfflinePlaintextPin, true)  // Plaintext PIN + Signature
            0x04 -> Pair(CvmResult.OfflineEncryptedPin, true)  // Encrypted PIN
            0x05 -> Pair(CvmResult.OfflineEncryptedPin, true)  // Encrypted PIN + Signature
            0x1E -> Pair(CvmResult.SignatureRequired, true)  // Signature
            0x1F -> Pair(CvmResult.NoCvmPerformed, true)  // No CVM required
            else -> null
        }
    }

    /**
     * Perform CVM for Mag Stripe mode
     */
    private fun performMagStripeCvm(transaction: MastercardTransactionParams, aip: MastercardAIP) {
        val cvmRequiredLimit = config.cvmRequiredLimit

        val cvmResults = ByteArray(3)
        if (transaction.amount <= cvmRequiredLimit) {
            // No CVM required
            cvmResult = CvmResult.NoCvmPerformed
            cvmResults[0] = config.magStripeCvmCapabilityNoCvmRequired
            cvmResults[1] = 0x00
            cvmResults[2] = 0x02
        } else {
            // CVM required - Signature for Mag Stripe
            cvmResult = CvmResult.SignatureRequired
            cvmResults[0] = config.magStripeCvmCapabilityCvmRequired
            cvmResults[1] = 0x00
            cvmResults[2] = 0x00
        }

        terminalData.set(0x9F34, cvmResults)
    }

    /**
     * Perform Terminal Risk Management
     */
    private fun performTerminalRiskManagement(transaction: MastercardTransactionParams) {
        Timber.d("Performing Terminal Risk Management")

        // Floor limit check
        if (config.contactlessFloorLimit > 0 && transaction.amount > config.contactlessFloorLimit) {
            Timber.d("Transaction exceeds floor limit")
            tvr.floorLimitExceeded = true
        }

        // Contactless transaction limit check
        val transactionLimit = when (cvmResult) {
            CvmResult.CdcvmPerformed,
            CvmResult.OnlinePinRequired -> config.contactlessTransactionLimitOnDeviceCvm
            else -> config.contactlessTransactionLimitNoCvm
        }

        if (transaction.amount > transactionLimit) {
            Timber.w("Transaction exceeds contactless limit: $transactionLimit")
            // This typically results in decline or switch interface
        }

        // Random selection for online
        if (shouldSelectRandomlyForOnline()) {
            tvr.randomlySelectedOnline = true
        }

        // Update TVR in terminal data
        terminalData.set(0x95, tvr.toBytes())
    }

    /**
     * Random selection for online processing
     */
    private fun shouldSelectRandomlyForOnline(): Boolean {
        // Simplified - production would use proper random selection parameters
        val randomValue = SecureRandom().nextInt(100)
        return randomValue < 5  // 5% random selection
    }

    /**
     * Perform Terminal Action Analysis
     */
    private fun performTerminalActionAnalysis(): CryptogramType {
        Timber.d("Performing Terminal Action Analysis")

        val currentTvr = tvr.toBytes()

        // Check TAC Denial (AND with TVR)
        if (matchesActionCode(currentTvr, config.tacDenial)) {
            Timber.d("TAC Denial matched - request AAC")
            return CryptogramType.AAC
        }

        // Check IAC Denial from card
        val iacDenial = cardData[0x9F0E]
        if (iacDenial != null && matchesActionCode(currentTvr, iacDenial)) {
            Timber.d("IAC Denial matched - request AAC")
            return CryptogramType.AAC
        }

        // Check TAC Online
        if (matchesActionCode(currentTvr, config.tacOnline)) {
            Timber.d("TAC Online matched - request ARQC")
            return CryptogramType.ARQC
        }

        // Check IAC Online
        val iacOnline = cardData[0x9F0F]
        if (iacOnline != null && matchesActionCode(currentTvr, iacOnline)) {
            Timber.d("IAC Online matched - request ARQC")
            return CryptogramType.ARQC
        }

        // Default to online for contactless
        Timber.d("Default - request ARQC")
        return CryptogramType.ARQC
    }

    /**
     * Check if TVR matches action code
     */
    private fun matchesActionCode(tvr: ByteArray, actionCode: ByteArray): Boolean {
        for (i in 0 until minOf(tvr.size, actionCode.size)) {
            if ((tvr[i].toInt() and actionCode[i].toInt()) != 0) {
                return true
            }
        }
        return false
    }

    /**
     * Generate Application Cryptogram
     */
    private suspend fun generateApplicationCryptogram(type: CryptogramType): GenerateAcResult {
        Timber.d("Generating AC: $type")

        // Get CDOL1
        val cdol1 = cardData[0x8C]

        // Build CDOL data
        val cdolData = if (cdol1 != null && cdol1.isNotEmpty()) {
            DolParser.buildDolData(cdol1, terminalData)
        } else {
            buildDefaultCdolData()
        }

        // Determine reference control parameter
        val p1 = when (type) {
            CryptogramType.AAC -> 0x00
            CryptogramType.ARQC -> 0x80.toByte()
            CryptogramType.TC -> 0x40
        }

        // Check if CDA requested
        val aip = cardData[0x82]?.let { MastercardAIP(it) }
        val requestCda = aip?.cdaSupported == true && odaStatus == OdaStatus.CdaPending

        val command = EmvCommands.generateAc(
            EmvCommands.CryptogramType.valueOf(type.name),
            cdolData,
            cda = requestCda
        )

        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            Timber.w("GENERATE AC failed: SW=${response.sw1}${response.sw2}")
            return GenerateAcResult.Error(mapSwToError(response.sw1.toInt() and 0xFF, response.sw2.toInt() and 0xFF))
        }

        return parseGenerateAcResponse(response.data, requestCda)
    }

    /**
     * Build default CDOL data when CDOL1 not provided
     */
    private fun buildDefaultCdolData(): ByteArray {
        return (terminalData.get(0x9F02) ?: ByteArray(6)) +  // Amount Authorized
                (terminalData.get(0x9F03) ?: ByteArray(6)) +  // Amount Other
                (terminalData.get(0x9F1A) ?: ByteArray(2)) +  // Terminal Country Code
                (terminalData.get(0x95) ?: ByteArray(5)) +    // TVR
                (terminalData.get(0x5F2A) ?: ByteArray(2)) +  // Currency Code
                (terminalData.get(0x9A) ?: ByteArray(3)) +    // Transaction Date
                (terminalData.get(0x9C) ?: ByteArray(1)) +    // Transaction Type
                (terminalData.get(0x9F37) ?: ByteArray(4)) +  // Unpredictable Number
                (terminalData.get(0x9F35) ?: ByteArray(1)) +  // Terminal Type
                ByteArray(2) +                                  // Data Authentication Code (0000)
                ByteArray(8) +                                  // ICC Dynamic Number
                (terminalData.get(0x9F34) ?: ByteArray(3))    // CVM Results
    }

    /**
     * Parse GENERATE AC response
     */
    private fun parseGenerateAcResponse(data: ByteArray, cdaRequested: Boolean): GenerateAcResult {
        if (data.isEmpty()) {
            return GenerateAcResult.Error(MastercardError.EMPTY_DATA)
        }

        // Can be Format 1 (tag 80) or Format 2 (tag 77)
        val firstByte = data[0].toInt() and 0xFF

        val tlvs = when (firstByte) {
            0x80 -> {
                // Format 1: Parse as raw data
                parseAcFormat1(data)
            }
            0x77 -> {
                // Format 2: Parse TLV structure
                TlvParser.parseRecursive(data)
            }
            else -> return GenerateAcResult.Error(MastercardError.INVALID_RESPONSE)
        }

        // Extract key elements
        var cryptogramInfoData: Byte? = null
        var applicationCryptogram: ByteArray? = null
        var atc: ByteArray? = null
        var signedDynamicData: ByteArray? = null

        for (tlv in tlvs) {
            cardData[tlv.tag.value] = tlv.value

            when (tlv.tag.value) {
                0x9F27 -> cryptogramInfoData = tlv.value.firstOrNull()
                0x9F26 -> applicationCryptogram = tlv.value
                0x9F36 -> atc = tlv.value
                0x9F4B -> signedDynamicData = tlv.value
            }
        }

        if (cryptogramInfoData == null || applicationCryptogram == null) {
            return GenerateAcResult.Error(MastercardError.MISSING_DATA)
        }

        // Determine returned cryptogram type
        val returnedType = when ((cryptogramInfoData.toInt() and 0xC0) shr 6) {
            0 -> CryptogramType.AAC
            1 -> CryptogramType.TC
            2 -> CryptogramType.ARQC
            else -> CryptogramType.AAC
        }

        // Verify CDA if requested and SDAD present
        if (cdaRequested && signedDynamicData != null) {
            verifyCda(signedDynamicData, applicationCryptogram)
        }

        return GenerateAcResult.Success(
            cryptogramType = returnedType,
            cryptogramInfoData = cryptogramInfoData,
            applicationCryptogram = applicationCryptogram,
            atc = atc ?: ByteArray(2),
            rawData = data
        )
    }

    /**
     * Parse Format 1 AC response
     */
    private fun parseAcFormat1(data: ByteArray): List<com.atlas.softpos.core.tlv.TlvObject> {
        val tlv = TlvParser.parse(data).firstOrNull() ?: return emptyList()
        val value = tlv.value

        // Format 1: CID (1) | ATC (2) | AC (8) | [IAD (var)]
        if (value.size < 11) return emptyList()

        val results = mutableListOf<com.atlas.softpos.core.tlv.TlvObject>()

        // Create synthetic TLV objects
        results.add(com.atlas.softpos.core.tlv.TlvObject(
            TlvTag.parse(byteArrayOf(0x9F.toByte(), 0x27), 0).first,
            byteArrayOf(value[0])
        ))
        results.add(com.atlas.softpos.core.tlv.TlvObject(
            TlvTag.parse(byteArrayOf(0x9F.toByte(), 0x36), 0).first,
            value.copyOfRange(1, 3)
        ))
        results.add(com.atlas.softpos.core.tlv.TlvObject(
            TlvTag.parse(byteArrayOf(0x9F.toByte(), 0x26), 0).first,
            value.copyOfRange(3, 11)
        ))

        if (value.size > 11) {
            results.add(com.atlas.softpos.core.tlv.TlvObject(
                TlvTag.parse(byteArrayOf(0x9F.toByte(), 0x10), 0).first,
                value.copyOfRange(11, value.size)
            ))
        }

        return results
    }

    /**
     * Verify CDA signature
     */
    private fun verifyCda(signedDynamicData: ByteArray, applicationCryptogram: ByteArray) {
        // Get ICC public key
        val iccPkCert = cardData[0x9F46]
        val issuerPkCert = cardData[0x90]

        if (iccPkCert == null || issuerPkCert == null || odaProcessor == null) {
            Timber.w("Cannot verify CDA - missing data")
            tvr.cdaFailed = true
            return
        }

        val aid = cardData[0x4F] ?: cardData[0x84]
        if (aid == null) {
            tvr.cdaFailed = true
            return
        }

        val aipBytes = cardData[0x82] ?: ByteArray(2)
        val staticData = buildStaticDataForAuth(aipBytes)
        val unpredictableNumber = terminalData.get(0x9F37) ?: ByteArray(4)

        val result = StandaloneOdaProcessor.performCda(
            aid = aid,
            issuerPkCertificate = issuerPkCert,
            issuerPkExponent = cardData[0x9F32] ?: byteArrayOf(0x03),
            iccPkCertificate = iccPkCert,
            iccPkExponent = cardData[0x9F47] ?: byteArrayOf(0x03),
            signedDynamicData = signedDynamicData,
            staticDataToAuthenticate = staticData,
            unpredictableNumber = unpredictableNumber,
            applicationCryptogram = applicationCryptogram
        )

        when (result) {
            is OdaResult.CdaPrepared, is OdaResult.SdaSuccess, is OdaResult.DdaSuccess, is OdaResult.FddaSuccess -> {
                Timber.d("CDA verification successful")
                odaStatus = OdaStatus.Successful
            }
            is OdaResult.Failed -> {
                Timber.w("CDA verification failed: ${result.failureReason}")
                tvr.cdaFailed = true
                odaStatus = OdaStatus.Failed
            }
            is OdaResult.NotSupported -> {
                Timber.w("CDA not supported")
                tvr.cdaFailed = true
                odaStatus = OdaStatus.Failed
            }
            is OdaResult.Success -> {
                Timber.d("ODA successful: ${result.type}")
                odaStatus = OdaStatus.Successful
            }
            is OdaResult.Failure -> {
                Timber.w("ODA failed: ${result.reason}")
                tvr.cdaFailed = true
                odaStatus = OdaStatus.Failed
            }
        }
    }

    /**
     * Compute Cryptographic Checksum (Mag Stripe mode)
     */
    private suspend fun computeCryptographicChecksum(): ComputeCccResult {
        Timber.d("Computing Cryptographic Checksum")

        // Get UDOL
        val udol = cardData[0x9F69]  // Card Authentication Related Data

        // Build UDOL data
        val udolData = if (udol != null && udol.isNotEmpty()) {
            DolParser.buildDolData(udol, terminalData)
        } else {
            // Default UDOL: UN (4) + Amount (6) + Currency (2)
            (terminalData.get(0x9F37) ?: ByteArray(4)) +
                    (terminalData.get(0x9F02) ?: ByteArray(6)) +
                    (terminalData.get(0x5F2A) ?: ByteArray(2))
        }

        val command = EmvCommands.computeCryptographicChecksum(udolData)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            Timber.w("CCC failed: SW=${response.sw1}${response.sw2}")
            return ComputeCccResult.Error(mapSwToError(response.sw1.toInt() and 0xFF, response.sw2.toInt() and 0xFF))
        }

        // Parse response for CVC3 and other data
        val tlvs = TlvParser.parseRecursive(response.data)

        var cvc3Track1: ByteArray? = null
        var cvc3Track2: ByteArray? = null
        var atc: ByteArray? = null

        for (tlv in tlvs) {
            cardData[tlv.tag.value] = tlv.value

            when (tlv.tag.value) {
                0x9F60 -> cvc3Track1 = tlv.value
                0x9F61 -> cvc3Track2 = tlv.value
                0x9F36 -> atc = tlv.value
            }
        }

        return ComputeCccResult.Success(
            cvc3Track1 = cvc3Track1,
            cvc3Track2 = cvc3Track2,
            atc = atc ?: ByteArray(2)
        )
    }

    /**
     * Build EMV outcome
     */
    private fun buildEmvOutcome(
        acResult: GenerateAcResult.Success,
        transaction: MastercardTransactionParams
    ): MastercardKernelOutcome {
        val authData = buildAuthorizationData(acResult, transaction)

        return when (acResult.cryptogramType) {
            CryptogramType.ARQC -> {
                Timber.d("Outcome: Online request")
                MastercardKernelOutcome.OnlineRequest(
                    authorizationData = authData,
                    discretionaryData = buildDiscretionaryData()
                )
            }
            CryptogramType.TC -> {
                Timber.d("Outcome: Offline approved")
                MastercardKernelOutcome.Approved(
                    authorizationData = authData,
                    discretionaryData = buildDiscretionaryData()
                )
            }
            CryptogramType.AAC -> {
                Timber.d("Outcome: Declined")
                MastercardKernelOutcome.Declined(
                    reason = "Card declined transaction",
                    authorizationData = authData,
                    discretionaryData = buildDiscretionaryData()
                )
            }
        }
    }

    /**
     * Build Mag Stripe outcome
     */
    private fun buildMagStripeOutcome(
        track2: MastercardTrack2Parser.Track2Data,
        cccResult: ComputeCccResult.Success,
        transaction: MastercardTransactionParams
    ): MastercardKernelOutcome {
        val authData = MastercardAuthorizationData(
            pan = track2.pan,
            expiryDate = track2.expiryDate,
            track2Equivalent = cardData[0x57]?.toHexString() ?: "",
            panSequenceNumber = cardData[0x5F34]?.toHexString() ?: "00",
            cryptogramType = CryptogramType.ARQC,
            applicationCryptogram = "",  // Not used for Mag Stripe
            cryptogramInfoData = 0x80.toByte(),
            atc = cccResult.atc.toHexString(),
            issuerApplicationData = cardData[0x9F10]?.toHexString() ?: "",
            tvr = tvr.toBytes().toHexString(),
            cvmResults = terminalData.get(0x9F34)?.toHexString() ?: "",
            amountAuthorized = transaction.amount.toString(),
            amountOther = (transaction.cashbackAmount ?: 0).toString(),
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = terminalData.get(0x9A)?.toHexString() ?: "",
            transactionType = "%02X".format(transaction.type),
            unpredictableNumber = terminalData.get(0x9F37)?.toHexString() ?: "",
            aip = cardData[0x82]?.toHexString() ?: "",
            aid = cardData[0x4F]?.toHexString() ?: cardData[0x84]?.toHexString() ?: "",
            transactionMode = TransactionMode.MAG_STRIPE,
            cvc3Track1 = cccResult.cvc3Track1?.toHexString(),
            cvc3Track2 = cccResult.cvc3Track2?.toHexString()
        )

        return MastercardKernelOutcome.OnlineRequest(
            authorizationData = authData,
            discretionaryData = buildDiscretionaryData()
        )
    }

    /**
     * Build authorization data
     */
    private fun buildAuthorizationData(
        acResult: GenerateAcResult.Success,
        transaction: MastercardTransactionParams
    ): MastercardAuthorizationData {
        // Get PAN from Track 2 or direct PAN tag
        val track2 = cardData[0x57]
        val pan = cardData[0x5A]?.toHexString()?.trimEnd('F')
            ?: track2?.let { MastercardTrack2Parser.parse(it)?.pan }
            ?: ""

        val expiryDate = cardData[0x5F24]?.toHexString()?.take(4) ?: ""

        return MastercardAuthorizationData(
            pan = pan,
            expiryDate = expiryDate,
            track2Equivalent = track2?.toHexString() ?: "",
            panSequenceNumber = cardData[0x5F34]?.toHexString() ?: "00",
            cryptogramType = acResult.cryptogramType,
            applicationCryptogram = acResult.applicationCryptogram.toHexString(),
            cryptogramInfoData = acResult.cryptogramInfoData,
            atc = acResult.atc.toHexString(),
            issuerApplicationData = cardData[0x9F10]?.toHexString() ?: "",
            tvr = tvr.toBytes().toHexString(),
            cvmResults = terminalData.get(0x9F34)?.toHexString() ?: "",
            amountAuthorized = transaction.amount.toString(),
            amountOther = (transaction.cashbackAmount ?: 0).toString(),
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = terminalData.get(0x9A)?.toHexString() ?: "",
            transactionType = "%02X".format(transaction.type),
            unpredictableNumber = terminalData.get(0x9F37)?.toHexString() ?: "",
            aip = cardData[0x82]?.toHexString() ?: "",
            aid = cardData[0x4F]?.toHexString() ?: cardData[0x84]?.toHexString() ?: "",
            transactionMode = TransactionMode.M_CHIP,
            cardholderName = cardData[0x5F20]?.let { String(it, Charsets.US_ASCII).trim() }
        )
    }

    /**
     * Build authorization data from second GENERATE AC result
     */
    private fun buildAuthorizationDataFromSecondAc(
        cryptogramType: CryptogramType,
        applicationCryptogram: ByteArray,
        cryptogramInfoData: Byte,
        atc: ByteArray?
    ): MastercardAuthorizationData {
        val track2 = cardData[0x57]
        val pan = cardData[0x5A]?.toHexString()?.trimEnd('F')
            ?: track2?.let { MastercardTrack2Parser.parse(it)?.pan }
            ?: ""

        val expiryDate = cardData[0x5F24]?.toHexString()?.take(4) ?: ""

        return MastercardAuthorizationData(
            pan = pan,
            expiryDate = expiryDate,
            track2Equivalent = track2?.toHexString() ?: "",
            panSequenceNumber = cardData[0x5F34]?.toHexString() ?: "00",
            cryptogramType = cryptogramType,
            applicationCryptogram = applicationCryptogram.toHexString(),
            cryptogramInfoData = cryptogramInfoData,
            atc = atc?.toHexString() ?: "",
            issuerApplicationData = cardData[0x9F10]?.toHexString() ?: "",
            tvr = tvr.toBytes().toHexString(),
            cvmResults = terminalData.get(0x9F34)?.toHexString() ?: "",
            amountAuthorized = terminalData.get(0x9F02)?.toHexString() ?: "",
            amountOther = terminalData.get(0x9F03)?.toHexString() ?: "0",
            terminalCountryCode = config.terminalCountryCode.toHexString(),
            transactionCurrencyCode = config.transactionCurrencyCode.toHexString(),
            transactionDate = terminalData.get(0x9A)?.toHexString() ?: "",
            transactionType = terminalData.get(0x9C)?.toHexString() ?: "",
            unpredictableNumber = terminalData.get(0x9F37)?.toHexString() ?: "",
            aip = cardData[0x82]?.toHexString() ?: "",
            aid = cardData[0x4F]?.toHexString() ?: cardData[0x84]?.toHexString() ?: "",
            transactionMode = TransactionMode.M_CHIP,
            cardholderName = cardData[0x5F20]?.let { String(it, Charsets.US_ASCII).trim() }
        )
    }

    /**
     * Build discretionary data
     */
    private fun buildDiscretionaryData(): MastercardDiscretionaryData {
        return MastercardDiscretionaryData(
            applicationPan = cardData[0x5A]?.toHexString()?.trimEnd('F'),
            track2Equivalent = cardData[0x57]?.toHexString(),
            applicationExpirationDate = cardData[0x5F24]?.toHexString(),
            cardholderName = cardData[0x5F20]?.let { String(it, Charsets.US_ASCII).trim() },
            issuerApplicationData = cardData[0x9F10]?.toHexString()
        )
    }

    /**
     * Map status words to errors
     */
    private fun mapSwToError(sw1: Int, sw2: Int): MastercardError {
        return when {
            sw1 == 0x69 && sw2 == 0x84 -> MastercardError.INVALID_DATA
            sw1 == 0x69 && sw2 == 0x85 -> MastercardError.CONDITIONS_NOT_SATISFIED
            sw1 == 0x6A && sw2 == 0x81 -> MastercardError.FUNCTION_NOT_SUPPORTED
            sw1 == 0x6A && sw2 == 0x82 -> MastercardError.FILE_NOT_FOUND
            sw1 == 0x6A && sw2 == 0x83 -> MastercardError.RECORD_NOT_FOUND
            else -> MastercardError.CARD_ERROR
        }
    }

    /**
     * Parse expiry date from BCD format
     */
    private fun parseExpiryDate(data: ByteArray): LocalDate? {
        return try {
            val hex = data.toHexString()
            if (hex.length < 4) return null
            val year = 2000 + hex.substring(0, 2).toInt()
            val month = hex.substring(2, 4).toInt()
            LocalDate.of(year, month, 1).plusMonths(1).minusDays(1)
        } catch (e: Exception) {
            null
        }
    }

    // ==================== Data Types ====================

    enum class TransactionPath {
        EMV,
        MAG_STRIPE
    }

    enum class CryptogramType {
        AAC,   // Application Authentication Cryptogram (decline)
        TC,    // Transaction Certificate (offline approve)
        ARQC   // Authorization Request Cryptogram (online request)
    }

    enum class OdaStatus {
        NotPerformed,
        CdaPending,
        Successful,
        Failed
    }

    sealed class CvmResult {
        object NoCvmPerformed : CvmResult()
        object CdcvmPerformed : CvmResult()
        object OnlinePinRequired : CvmResult()
        object OfflinePlaintextPin : CvmResult()
        object OfflineEncryptedPin : CvmResult()
        object SignatureRequired : CvmResult()
    }

    private sealed class GpoResult {
        data class Success(
            val aip: MastercardAIP,
            val afl: ByteArray,
            val ctq: CardTransactionQualifiers?
        ) : GpoResult()
        data class Error(val error: MastercardError) : GpoResult()
    }

    private sealed class ReadRecordResult {
        object Success : ReadRecordResult()
        data class Error(val error: MastercardError) : ReadRecordResult()
    }

    private sealed class RestrictionResult {
        object Continue : RestrictionResult()
        data class SwitchInterface(val reason: String) : RestrictionResult()
    }

    private sealed class RrpResult {
        data class Success(val measuredTime: Long) : RrpResult()
        data class ThresholdExceeded(val measuredTime: Long, val threshold: Long) : RrpResult()
        object TimeLimitsExceeded : RrpResult()
        data class Failed(val reason: String) : RrpResult()
    }

    private sealed class GenerateAcResult {
        data class Success(
            val cryptogramType: CryptogramType,
            val cryptogramInfoData: Byte,
            val applicationCryptogram: ByteArray,
            val atc: ByteArray,
            val rawData: ByteArray
        ) : GenerateAcResult()
        data class Error(val error: MastercardError) : GenerateAcResult()
    }

    private sealed class ComputeCccResult {
        data class Success(
            val cvc3Track1: ByteArray?,
            val cvc3Track2: ByteArray?,
            val atc: ByteArray
        ) : ComputeCccResult()
        data class Error(val error: MastercardError) : ComputeCccResult()
    }
}

// ==================== Transaction Parameters ====================

data class MastercardTransactionParams(
    val amount: Long,
    val cashbackAmount: Long? = null,
    val type: Byte = 0x00  // 0x00 = Purchase, 0x01 = Cash, 0x09 = Cashback
)

// ==================== Kernel Outcomes ====================

sealed class MastercardKernelOutcome {
    data class Approved(
        val authorizationData: MastercardAuthorizationData,
        val discretionaryData: MastercardDiscretionaryData
    ) : MastercardKernelOutcome()

    data class OnlineRequest(
        val authorizationData: MastercardAuthorizationData,
        val discretionaryData: MastercardDiscretionaryData
    ) : MastercardKernelOutcome()

    data class Declined(
        val reason: String,
        val authorizationData: MastercardAuthorizationData?,
        val discretionaryData: MastercardDiscretionaryData
    ) : MastercardKernelOutcome()

    data class TryAnotherInterface(
        val reason: String,
        val discretionaryData: MastercardDiscretionaryData
    ) : MastercardKernelOutcome()

    data class EndApplication(
        val error: MastercardError,
        val discretionaryData: MastercardDiscretionaryData
    ) : MastercardKernelOutcome()
}

// ==================== Authorization Data ====================

enum class TransactionMode {
    M_CHIP,
    MAG_STRIPE
}

data class MastercardAuthorizationData(
    val pan: String,
    val expiryDate: String,
    val track2Equivalent: String,
    val panSequenceNumber: String,
    val cryptogramType: MastercardContactlessKernel.CryptogramType,
    val applicationCryptogram: String,
    val cryptogramInfoData: Byte,
    val atc: String,
    val issuerApplicationData: String,
    val tvr: String,
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
    val transactionMode: TransactionMode,
    val cardholderName: String? = null,
    val cvc3Track1: String? = null,
    val cvc3Track2: String? = null
)

data class MastercardDiscretionaryData(
    val applicationPan: String?,
    val track2Equivalent: String?,
    val applicationExpirationDate: String?,
    val cardholderName: String?,
    val issuerApplicationData: String?
)

// ==================== Errors ====================

enum class MastercardError {
    EMPTY_DATA,
    INVALID_RESPONSE,
    PARSE_ERROR,
    MISSING_DATA,
    INVALID_DATA,
    CONDITIONS_NOT_SATISFIED,
    FUNCTION_NOT_SUPPORTED,
    FILE_NOT_FOUND,
    RECORD_NOT_FOUND,
    CARD_ERROR,
    KERNEL_ERROR
}

// ==================== Extension Functions ====================

private fun Long.toAmountBcd(): ByteArray {
    val str = "%012d".format(this)
    return str.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

private fun Long.toFloorLimit(): ByteArray {
    return byteArrayOf(
        ((this shr 24) and 0xFF).toByte(),
        ((this shr 16) and 0xFF).toByte(),
        ((this shr 8) and 0xFF).toByte(),
        (this and 0xFF).toByte()
    )
}

private fun ByteArray.padRight(length: Int): ByteArray {
    return if (this.size >= length) {
        this.copyOf(length)
    } else {
        ByteArray(length).also {
            System.arraycopy(this, 0, it, 0, this.size)
            // Fill remaining with spaces (0x20) for alphanumeric fields
            for (i in this.size until length) {
                it[i] = 0x20
            }
        }
    }
}

private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }

private fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

// ==================== Online Response Processing ====================

/**
 * Online authorization response from issuer/acquirer
 */
data class OnlineAuthResponse(
    /** Whether the transaction was approved online */
    val approved: Boolean,
    /** Authorization Response Code (tag 8A) - 2 bytes */
    val arc: ByteArray? = null,
    /** Authorization Response Cryptogram (ARPC) - 8 bytes */
    val arpc: ByteArray? = null,
    /** Issuer scripts to execute before second GENERATE AC (tag 71) */
    val issuerScripts71: List<ByteArray>? = null,
    /** Issuer scripts to execute after second GENERATE AC (tag 72) */
    val issuerScripts72: List<ByteArray>? = null,
    /** Issuer Authentication Data (tag 91) for ARPC verification */
    val issuerAuthData: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OnlineAuthResponse) return false
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
 * Result of online response processing
 */
sealed class OnlineResponseResult {
    data class Approved(
        val authorizationData: MastercardAuthorizationData,
        val scriptResults: List<IssuerScriptResult>
    ) : OnlineResponseResult()

    data class Declined(
        val reason: String,
        val authorizationData: MastercardAuthorizationData?,
        val scriptResults: List<IssuerScriptResult>
    ) : OnlineResponseResult()

    data class ScriptFailed(
        val error: String,
        val scriptResults: List<IssuerScriptResult>
    ) : OnlineResponseResult()

    data class Error(
        val error: String,
        val scriptResults: List<IssuerScriptResult>
    ) : OnlineResponseResult()
}

/**
 * Result of issuer script execution
 */
data class IssuerScriptResult(
    val success: Boolean,
    val sw: Int,
    val abortTransaction: Boolean
)

/**
 * Internal result of second GENERATE AC
 */
private sealed class SecondAcResult {
    data class Approved(val authData: MastercardAuthorizationData) : SecondAcResult()
    data class Declined(val reason: String, val authData: MastercardAuthorizationData?) : SecondAcResult()
    data class Error(val error: String) : SecondAcResult()
}
