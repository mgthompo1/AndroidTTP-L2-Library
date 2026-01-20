package com.atlas.softpos.kernel.common

import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.EmvCommands
import com.atlas.softpos.core.apdu.KnownAids
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.core.tlv.EmvTags
import com.atlas.softpos.core.tlv.Tlv
import com.atlas.softpos.core.tlv.TlvParser
import com.atlas.softpos.core.types.hexToByteArray
import com.atlas.softpos.core.types.toHexString

/**
 * EMV Entry Point - Application Selection
 *
 * Implements EMV Contactless Book B - Entry Point Specification
 *
 * The Entry Point is responsible for:
 * 1. Selecting the PPSE (Proximity Payment System Environment)
 * 2. Parsing the directory of available applications
 * 3. Building candidate list based on terminal's supported AIDs
 * 4. Selecting the final application
 * 5. Activating the appropriate kernel
 */
class EntryPoint(
    private val transceiver: CardTransceiver,
    private val configuration: EntryPointConfiguration
) {
    /**
     * Start the application selection process
     */
    suspend fun start(): EntryPointResult {
        // Step 1: Select PPSE
        val ppseResult = selectPpse()
        if (ppseResult is PpseResult.Error) {
            return EntryPointResult.Error(ppseResult.message)
        }

        val ppseData = (ppseResult as PpseResult.Success).data

        // Step 2: Parse directory and build candidate list
        val candidates = buildCandidateList(ppseData)
        if (candidates.isEmpty()) {
            return EntryPointResult.NoSupportedApplications
        }

        // Step 3: Select application (highest priority matching terminal config)
        for (candidate in candidates.sortedBy { it.priority }) {
            val selectResult = selectApplication(candidate)
            if (selectResult is ApplicationSelectResult.Success) {
                return EntryPointResult.Success(
                    selectedApplication = selectResult.application,
                    kernelId = determineKernel(candidate.aid)
                )
            }
        }

        return EntryPointResult.ApplicationSelectionFailed
    }

    /**
     * Select PPSE and return the FCI template
     */
    private suspend fun selectPpse(): PpseResult {
        val command = EmvCommands.selectPpse()
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            // Try direct AID selection if PPSE not supported
            return PpseResult.NotSupported
        }

        return try {
            PpseResult.Success(response.data)
        } catch (e: Exception) {
            PpseResult.Error("Failed to parse PPSE: ${e.message}")
        }
    }

    /**
     * Build the candidate list from PPSE response
     */
    private fun buildCandidateList(ppseData: ByteArray): List<ApplicationCandidate> {
        val candidates = mutableListOf<ApplicationCandidate>()

        // Parse the FCI template (tag 6F)
        val fciTemplate = TlvParser.findTag(ppseData, EmvTags.FCI_TEMPLATE)
            ?: return emptyList()

        // Get FCI Proprietary Template (tag A5)
        val fciProprietary = TlvParser.findTag(fciTemplate.value, EmvTags.FCI_PROPRIETARY)
            ?: return emptyList()

        // Get FCI Issuer Discretionary Data (tag BF0C)
        val fciIssuer = TlvParser.findTag(fciProprietary.value, EmvTags.FCI_ISSUER_DISCRETIONARY)
            ?: return emptyList()

        // Parse Application Directory Entries (tag 61)
        val tlvList = TlvParser.parse(fciIssuer.value)
        for (tlv in tlvList) {
            if (tlv.tag.hex == EmvTags.APPLICATION_DIRECTORY_ENTRY.hex) {
                val candidate = parseDirectoryEntry(tlv.value)
                if (candidate != null && isAidSupported(candidate.aid)) {
                    candidates.add(candidate)
                }
            }
        }

        return candidates
    }

    /**
     * Parse a single Application Directory Entry
     */
    private fun parseDirectoryEntry(data: ByteArray): ApplicationCandidate? {
        val tlvMap = TlvParser.parseToMap(data)

        val aidTlv = tlvMap[EmvTags.AID.hex] ?: return null
        val aid = aidTlv.value

        val labelTlv = tlvMap[EmvTags.APPLICATION_LABEL.hex]
        val label = labelTlv?.valueAscii() ?: KnownAids.getBrandName(aid)

        val priorityTlv = tlvMap[EmvTags.APPLICATION_PRIORITY.hex]
        val priority = priorityTlv?.value?.firstOrNull()?.toInt()?.and(0x0F) ?: 0

        val kernelIdTlv = tlvMap["9F2A"]  // Kernel Identifier
        val kernelId = kernelIdTlv?.value

        return ApplicationCandidate(
            aid = aid,
            label = label,
            priority = priority,
            kernelId = kernelId
        )
    }

    /**
     * Check if the AID is supported by terminal configuration
     */
    private fun isAidSupported(aid: ByteArray): Boolean {
        val aidHex = aid.toHexString()
        return configuration.supportedAids.any { supportedAid ->
            aidHex.startsWith(supportedAid.toHexString())
        }
    }

    /**
     * Select an application by its AID
     */
    private suspend fun selectApplication(candidate: ApplicationCandidate): ApplicationSelectResult {
        val command = EmvCommands.selectApplication(candidate.aid)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            return ApplicationSelectResult.Failed(response.statusDescription)
        }

        // Parse FCI template
        val fciTemplate = TlvParser.findTag(response.data, EmvTags.FCI_TEMPLATE)
            ?: return ApplicationSelectResult.Failed("Missing FCI template")

        val fciProprietary = TlvParser.findTag(fciTemplate.value, EmvTags.FCI_PROPRIETARY)

        // Extract PDOL if present
        val pdol = fciProprietary?.let {
            TlvParser.findTag(it.value, EmvTags.PDOL)?.value
        }

        // Extract DF Name (AID)
        val dfName = TlvParser.findTag(fciTemplate.value, EmvTags.DF_NAME)?.value
            ?: candidate.aid

        // Extract application label
        val label = fciProprietary?.let {
            TlvParser.findTag(it.value, EmvTags.APPLICATION_LABEL)?.valueAscii()
        } ?: candidate.label

        // Extract preferred name if available
        val preferredName = fciProprietary?.let {
            TlvParser.findTag(it.value, EmvTags.APPLICATION_PREFERRED_NAME)?.valueAscii()
        }

        // Extract language preference
        val languagePreference = fciProprietary?.let {
            TlvParser.findTag(it.value, EmvTags.LANGUAGE_PREFERENCE)?.valueAscii()
        }

        return ApplicationSelectResult.Success(
            SelectedApplication(
                aid = dfName,
                label = preferredName ?: label,
                pdol = pdol,
                languagePreference = languagePreference,
                fciData = response.data
            )
        )
    }

    /**
     * Determine which kernel to use based on AID
     */
    private fun determineKernel(aid: ByteArray): KernelId {
        val aidHex = aid.toHexString().uppercase()
        return when {
            aidHex.startsWith("A000000003") -> KernelId.VISA
            aidHex.startsWith("A000000004") -> KernelId.MASTERCARD
            aidHex.startsWith("A000000025") -> KernelId.AMEX
            aidHex.startsWith("A0000001523") -> KernelId.DISCOVER
            aidHex.startsWith("A0000003241") -> KernelId.DISCOVER
            aidHex.startsWith("A000000065") -> KernelId.JCB
            aidHex.startsWith("A000000333") -> KernelId.UNIONPAY
            aidHex.startsWith("A000000277") -> KernelId.INTERAC
            else -> KernelId.UNKNOWN
        }
    }
}

/**
 * Interface for card communication
 */
interface CardTransceiver {
    suspend fun transceive(command: CommandApdu): ResponseApdu
}

/**
 * Entry Point configuration
 */
data class EntryPointConfiguration(
    val supportedAids: List<ByteArray> = listOf(
        KnownAids.VISA_CREDIT,
        KnownAids.VISA_DEBIT,
        KnownAids.MASTERCARD_CREDIT,
        KnownAids.MASTERCARD_DEBIT,
        KnownAids.AMEX,
        KnownAids.DISCOVER
    ),
    val terminalType: Byte = 0x22,  // Attended, online only
    val terminalCapabilities: ByteArray = "E0F0C8".hexToByteArray(),
    val additionalTerminalCapabilities: ByteArray = "FF00F0A001".hexToByteArray()
)

/**
 * Application candidate from PPSE
 */
data class ApplicationCandidate(
    val aid: ByteArray,
    val label: String,
    val priority: Int,
    val kernelId: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ApplicationCandidate) return false
        return aid.contentEquals(other.aid)
    }

    override fun hashCode(): Int = aid.contentHashCode()
}

/**
 * Selected application with FCI data
 */
data class SelectedApplication(
    val aid: ByteArray,
    val label: String,
    val pdol: ByteArray?,
    val languagePreference: String?,
    val fciData: ByteArray
) {
    fun aidHex(): String = aid.toHexString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SelectedApplication) return false
        return aid.contentEquals(other.aid)
    }

    override fun hashCode(): Int = aid.contentHashCode()
}

/**
 * Kernel identifiers
 */
enum class KernelId {
    VISA,       // Kernel 3 - Visa payWave
    MASTERCARD, // Kernel 2 - Mastercard PayPass
    AMEX,       // Kernel 4 - American Express ExpressPay
    DISCOVER,   // Kernel 5 - Discover D-PAS
    JCB,        // Kernel 5 - JCB J/Speedy
    UNIONPAY,   // Kernel 7 - UnionPay QuickPass
    INTERAC,    // Interac Flash
    UNKNOWN
}

/**
 * PPSE selection results
 */
sealed class PpseResult {
    data class Success(val data: ByteArray) : PpseResult()
    data class Error(val message: String) : PpseResult()
    object NotSupported : PpseResult()
}

/**
 * Application selection results
 */
sealed class ApplicationSelectResult {
    data class Success(val application: SelectedApplication) : ApplicationSelectResult()
    data class Failed(val reason: String) : ApplicationSelectResult()
}

/**
 * Entry Point results
 */
sealed class EntryPointResult {
    data class Success(
        val selectedApplication: SelectedApplication,
        val kernelId: KernelId
    ) : EntryPointResult()

    object NoSupportedApplications : EntryPointResult()
    object ApplicationSelectionFailed : EntryPointResult()
    data class Error(val message: String) : EntryPointResult()
}
