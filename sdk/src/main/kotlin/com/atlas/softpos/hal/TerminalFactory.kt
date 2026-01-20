package com.atlas.softpos.hal

import com.atlas.softpos.hal.impl.*

/**
 * Terminal Hardware Factory
 *
 * Factory for creating terminal-specific hardware abstraction implementations.
 * Automatically detects terminal type when possible, or allows explicit selection.
 *
 * Usage:
 * ```kotlin
 * // Auto-detect terminal type
 * val terminal = TerminalFactory.create()
 *
 * // Or specify terminal type
 * val terminal = TerminalFactory.create(TerminalType.PAX_A920)
 *
 * // Use terminal components
 * val kernel = VisaContactlessKernel(
 *     transceiver = CardTransceiverAdapter(terminal.cardReader),
 *     configuration = ...
 * )
 *
 * // Start transaction
 * terminal.cardReader.startPolling().collect { event ->
 *     when (event) {
 *         is CardDetectionEvent.CardDetected -> {
 *             // Process card
 *         }
 *     }
 * }
 * ```
 */
object TerminalFactory {

    /**
     * Create terminal components for the detected or specified terminal type
     *
     * @param type Terminal type (auto-detect if null)
     * @param nativeModules Optional native module instances for terminal SDKs
     * @return Terminal components
     */
    fun create(
        type: TerminalType? = null,
        nativeModules: NativeModules? = null
    ): TerminalComponents {
        val terminalType = type ?: detectTerminalType()

        return when (terminalType) {
            TerminalType.ANDROID_SOFTPOS -> createSoftPosComponents()
            TerminalType.PAX_A920,
            TerminalType.PAX_A80,
            TerminalType.PAX_E_SERIES,
            TerminalType.PAX_IM30 -> createPaxComponents(nativeModules)
            TerminalType.CASTLES_SATURN,
            TerminalType.CASTLES_VEGA,
            TerminalType.CASTLES_MP200 -> createCastlesComponents(nativeModules)
            TerminalType.INGENICO_MOVE,
            TerminalType.INGENICO_LANE -> createIngenicoComponents(nativeModules)
            TerminalType.VERIFONE_V400,
            TerminalType.VERIFONE_E285 -> createVerifoneComponents(nativeModules)
            TerminalType.GENERIC_ANDROID -> createGenericAndroidComponents()
            TerminalType.UNKNOWN -> createSoftPosComponents() // Fallback
        }
    }

    /**
     * Detect terminal type based on system properties
     */
    fun detectTerminalType(): TerminalType {
        val manufacturer = android.os.Build.MANUFACTURER.lowercase()
        val model = android.os.Build.MODEL.lowercase()
        val brand = android.os.Build.BRAND.lowercase()

        return when {
            // PAX Detection
            manufacturer.contains("pax") || brand.contains("pax") -> {
                when {
                    model.contains("a920") -> TerminalType.PAX_A920
                    model.contains("a80") -> TerminalType.PAX_A80
                    model.contains("e600") || model.contains("e700") ||
                            model.contains("e800") -> TerminalType.PAX_E_SERIES
                    model.contains("im30") -> TerminalType.PAX_IM30
                    else -> TerminalType.PAX_A920 // Default PAX
                }
            }

            // Castles Detection
            manufacturer.contains("castles") || brand.contains("castles") -> {
                when {
                    model.contains("s1") || model.contains("saturn") -> TerminalType.CASTLES_SATURN
                    model.contains("vega") -> TerminalType.CASTLES_VEGA
                    model.contains("mp200") -> TerminalType.CASTLES_MP200
                    else -> TerminalType.CASTLES_SATURN // Default Castles
                }
            }

            // Ingenico Detection
            manufacturer.contains("ingenico") || brand.contains("ingenico") -> {
                when {
                    model.contains("move") -> TerminalType.INGENICO_MOVE
                    model.contains("lane") -> TerminalType.INGENICO_LANE
                    else -> TerminalType.INGENICO_MOVE // Default Ingenico
                }
            }

            // Verifone Detection
            manufacturer.contains("verifone") || brand.contains("verifone") -> {
                when {
                    model.contains("v400") -> TerminalType.VERIFONE_V400
                    model.contains("e285") -> TerminalType.VERIFONE_E285
                    else -> TerminalType.VERIFONE_V400 // Default Verifone
                }
            }

            // Check for SoftPOS capability (phone with NFC)
            hasNfcCapability() -> TerminalType.ANDROID_SOFTPOS

            // Generic Android terminal
            else -> TerminalType.GENERIC_ANDROID
        }
    }

    /**
     * Check if device has NFC capability for SoftPOS
     */
    private fun hasNfcCapability(): Boolean {
        return try {
            val nfcAdapter = android.nfc.NfcAdapter.getDefaultAdapter(null)
            nfcAdapter != null
        } catch (e: Exception) {
            false
        }
    }

    private fun createSoftPosComponents(): TerminalComponents {
        return TerminalComponents(
            type = TerminalType.ANDROID_SOFTPOS,
            cardReader = AndroidNfcCardReader(),
            pinPad = null, // SoftPOS uses on-screen PIN entry
            securityModule = null, // SoftPOS uses software crypto
            capabilities = TerminalCapabilities(
                hasHardwarePinPad = false,
                hasHardwareSecurityModule = false,
                supportsContactless = true,
                supportsContact = false,
                supportsMagStripe = false,
                pciPtsCertified = false,
                supportsOfflinePin = false,
                supportsOnlinePin = true, // Via on-screen entry
                supportsCdcvm = true
            )
        )
    }

    private fun createPaxComponents(nativeModules: NativeModules?): TerminalComponents {
        return TerminalComponents(
            type = TerminalType.PAX_A920,
            cardReader = PaxCardReader(nativeModules?.paxPicc),
            pinPad = PaxPinPad(nativeModules?.paxPed),
            securityModule = PaxSecurityModule(nativeModules?.paxPed),
            capabilities = TerminalCapabilities(
                hasHardwarePinPad = true,
                hasHardwareSecurityModule = true,
                supportsContactless = true,
                supportsContact = true,
                supportsMagStripe = true,
                pciPtsCertified = true,
                supportsOfflinePin = true,
                supportsOnlinePin = true,
                supportsCdcvm = true
            )
        )
    }

    private fun createCastlesComponents(nativeModules: NativeModules?): TerminalComponents {
        return TerminalComponents(
            type = TerminalType.CASTLES_SATURN,
            cardReader = CastlesCardReader(nativeModules?.castlesClss),
            pinPad = CastlesPinPad(nativeModules?.castlesPin),
            securityModule = CastlesSecurityModule(nativeModules?.castlesCrypto),
            capabilities = TerminalCapabilities(
                hasHardwarePinPad = true,
                hasHardwareSecurityModule = true,
                supportsContactless = true,
                supportsContact = true,
                supportsMagStripe = true,
                pciPtsCertified = true,
                supportsOfflinePin = true,
                supportsOnlinePin = true,
                supportsCdcvm = true
            )
        )
    }

    private fun createIngenicoComponents(nativeModules: NativeModules?): TerminalComponents {
        // Ingenico uses a similar architecture - stub for now
        return TerminalComponents(
            type = TerminalType.INGENICO_MOVE,
            cardReader = AndroidNfcCardReader(), // Placeholder
            pinPad = null,
            securityModule = null,
            capabilities = TerminalCapabilities(
                hasHardwarePinPad = true,
                hasHardwareSecurityModule = true,
                supportsContactless = true,
                supportsContact = true,
                supportsMagStripe = true,
                pciPtsCertified = true,
                supportsOfflinePin = true,
                supportsOnlinePin = true,
                supportsCdcvm = true
            )
        )
    }

    private fun createVerifoneComponents(nativeModules: NativeModules?): TerminalComponents {
        // Verifone uses their own SDK - stub for now
        return TerminalComponents(
            type = TerminalType.VERIFONE_V400,
            cardReader = AndroidNfcCardReader(), // Placeholder
            pinPad = null,
            securityModule = null,
            capabilities = TerminalCapabilities(
                hasHardwarePinPad = true,
                hasHardwareSecurityModule = true,
                supportsContactless = true,
                supportsContact = true,
                supportsMagStripe = true,
                pciPtsCertified = true,
                supportsOfflinePin = true,
                supportsOnlinePin = true,
                supportsCdcvm = true
            )
        )
    }

    private fun createGenericAndroidComponents(): TerminalComponents {
        return TerminalComponents(
            type = TerminalType.GENERIC_ANDROID,
            cardReader = AndroidNfcCardReader(),
            pinPad = null,
            securityModule = null,
            capabilities = TerminalCapabilities(
                hasHardwarePinPad = false,
                hasHardwareSecurityModule = false,
                supportsContactless = true,
                supportsContact = false,
                supportsMagStripe = false,
                pciPtsCertified = false,
                supportsOfflinePin = false,
                supportsOnlinePin = true,
                supportsCdcvm = true
            )
        )
    }
}

/**
 * Supported terminal types
 */
enum class TerminalType {
    // SoftPOS (standard Android phone/tablet)
    ANDROID_SOFTPOS,

    // PAX terminals
    PAX_A920,
    PAX_A80,
    PAX_E_SERIES,
    PAX_IM30,

    // Castles terminals
    CASTLES_SATURN,
    CASTLES_VEGA,
    CASTLES_MP200,

    // Ingenico terminals
    INGENICO_MOVE,
    INGENICO_LANE,

    // Verifone terminals
    VERIFONE_V400,
    VERIFONE_E285,

    // Generic Android terminal
    GENERIC_ANDROID,

    // Unknown
    UNKNOWN
}

/**
 * Terminal components bundle
 */
data class TerminalComponents(
    val type: TerminalType,
    val cardReader: CardReaderInterface,
    val pinPad: PinPadInterface?,
    val securityModule: SecurityModuleInterface?,
    val capabilities: TerminalCapabilities
)

/**
 * Terminal capabilities
 */
data class TerminalCapabilities(
    val hasHardwarePinPad: Boolean,
    val hasHardwareSecurityModule: Boolean,
    val supportsContactless: Boolean,
    val supportsContact: Boolean,
    val supportsMagStripe: Boolean,
    val pciPtsCertified: Boolean,
    val supportsOfflinePin: Boolean,
    val supportsOnlinePin: Boolean,
    val supportsCdcvm: Boolean
)

/**
 * Native module instances for terminal SDKs
 *
 * Pass this when creating terminal components to provide
 * pre-initialized native SDK instances.
 */
data class NativeModules(
    // PAX modules
    val paxPicc: Any? = null,
    val paxPed: Any? = null,

    // Castles modules
    val castlesClss: Any? = null,
    val castlesPin: Any? = null,
    val castlesCrypto: Any? = null,

    // Ingenico modules
    val ingenicoClReader: Any? = null,
    val ingenicoPinPad: Any? = null,

    // Verifone modules
    val verifoneEmv: Any? = null
)
