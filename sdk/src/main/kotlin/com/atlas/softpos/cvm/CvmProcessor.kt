package com.atlas.softpos.cvm

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.atlas.softpos.core.tlv.Tlv
import com.atlas.softpos.core.tlv.TlvTag
import com.atlas.softpos.core.types.toHexString
import kotlinx.coroutines.suspendCancellableCoroutine
import timber.log.Timber
import kotlin.coroutines.resume

/**
 * Cardholder Verification Method (CVM) Processor
 *
 * Handles all CVM processing for EMV contactless transactions including:
 * - CDCVM (Consumer Device CVM) via Android Biometrics
 * - Online PIN (delegated to terminal)
 * - Signature (not used in contactless)
 * - No CVM Required
 *
 * For SoftPOS, CDCVM is the primary method using device biometrics
 * (fingerprint, face recognition, device PIN/pattern).
 */
class CvmProcessor(
    private val context: Context,
    private val config: CvmConfiguration
) {
    /**
     * Process CVM based on card's CVM List and transaction amount
     *
     * @param cvmList Card's CVM List (Tag 8E)
     * @param amount Transaction amount in smallest currency unit
     * @param amountOther Other amount (cashback)
     * @param applicationCurrencyCode Currency code from card
     * @return CVM processing result
     */
    suspend fun processCvm(
        cvmList: ByteArray?,
        amount: Long,
        amountOther: Long,
        applicationCurrencyCode: ByteArray?
    ): CvmResult {
        if (cvmList == null || cvmList.size < 8) {
            Timber.d("No CVM List or invalid - No CVM performed")
            return CvmResult.NoCvmPerformed
        }

        // Parse CVM List
        // First 4 bytes: Amount X (upper limit for CVM condition)
        // Next 4 bytes: Amount Y (lower limit for CVM condition)
        // Remaining: CVM rules (2 bytes each)
        val amountX = extractAmount(cvmList, 0)
        val amountY = extractAmount(cvmList, 4)

        Timber.d("CVM List - Amount X: $amountX, Amount Y: $amountY")

        // Parse CVM rules
        val rules = mutableListOf<CvmRule>()
        var offset = 8
        while (offset + 1 < cvmList.size) {
            val cvmCode = cvmList[offset]
            val conditionCode = cvmList[offset + 1]
            rules.add(CvmRule(cvmCode, conditionCode))
            offset += 2
        }

        Timber.d("CVM Rules: ${rules.map { it.toString() }}")

        // Process rules in order
        for (rule in rules) {
            if (!checkCondition(rule.conditionCode, amount, amountOther, amountX, amountY)) {
                continue
            }

            val result = processRule(rule, amount)

            when (result) {
                is CvmRuleResult.Success -> {
                    return CvmResult.Success(
                        method = result.method,
                        cvmResults = buildCvmResults(rule.cvmCode, true)
                    )
                }
                is CvmRuleResult.Failed -> {
                    if (!rule.continueOnFail) {
                        return CvmResult.Failed(
                            reason = result.reason,
                            cvmResults = buildCvmResults(rule.cvmCode, false)
                        )
                    }
                    // Continue to next rule
                }
                is CvmRuleResult.NotSupported -> {
                    if (!rule.continueOnFail) {
                        return CvmResult.Failed(
                            reason = "CVM method not supported",
                            cvmResults = buildCvmResults(rule.cvmCode, false)
                        )
                    }
                }
            }
        }

        // No CVM rule succeeded
        return if (config.allowNoCvm) {
            CvmResult.NoCvmPerformed
        } else {
            CvmResult.Failed("No valid CVM method", buildCvmResults(0x00, false))
        }
    }

    /**
     * Process a single CVM rule
     */
    private suspend fun processRule(rule: CvmRule, amount: Long): CvmRuleResult {
        val method = rule.cvmCode.toInt() and 0x3F  // Lower 6 bits

        return when (method) {
            CVM_FAIL -> CvmRuleResult.Failed("CVM Fail rule")

            CVM_PLAINTEXT_PIN_BY_ICC -> {
                // Not supported for contactless SoftPOS
                CvmRuleResult.NotSupported
            }

            CVM_ENCIPHERED_PIN_ONLINE -> {
                // Online PIN - requires PIN entry UI
                // The actual PIN entry is handled by OnlinePinEntry component
                // Here we indicate that Online PIN is required
                if (config.onlinePinSupported) {
                    CvmRuleResult.Success(CvmMethod.ONLINE_PIN)
                } else {
                    // If terminal doesn't support online PIN, try next method
                    CvmRuleResult.NotSupported
                }
            }

            CVM_PLAINTEXT_PIN_BY_ICC_WITH_SIGNATURE -> {
                CvmRuleResult.NotSupported
            }

            CVM_ENCIPHERED_PIN_BY_ICC -> {
                CvmRuleResult.NotSupported
            }

            CVM_ENCIPHERED_PIN_BY_ICC_WITH_SIGNATURE -> {
                CvmRuleResult.NotSupported
            }

            CVM_SIGNATURE -> {
                // Signature not used for contactless
                if (config.allowSignature) {
                    CvmRuleResult.Success(CvmMethod.SIGNATURE)
                } else {
                    CvmRuleResult.NotSupported
                }
            }

            CVM_NO_CVM_REQUIRED -> {
                if (amount <= config.noCvmLimit || config.allowNoCvm) {
                    CvmRuleResult.Success(CvmMethod.NO_CVM)
                } else {
                    CvmRuleResult.Failed("Amount exceeds No CVM limit")
                }
            }

            CVM_CDCVM -> {
                // Consumer Device CVM - use biometrics
                performCdcvm()
            }

            else -> {
                Timber.w("Unknown CVM method: $method")
                CvmRuleResult.NotSupported
            }
        }
    }

    /**
     * Perform CDCVM using Android Biometrics
     */
    private suspend fun performCdcvm(): CvmRuleResult {
        // Check biometric availability
        val biometricManager = BiometricManager.from(context)
        val canAuthenticate = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )

        return when (canAuthenticate) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                // Biometrics available - prompt user
                promptBiometric()
            }

            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                Timber.w("No biometric hardware")
                // Fall back to device credential if available
                if (config.allowDeviceCredential) {
                    promptDeviceCredential()
                } else {
                    CvmRuleResult.NotSupported
                }
            }

            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                Timber.w("Biometric hardware unavailable")
                CvmRuleResult.Failed("Biometric hardware unavailable")
            }

            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                Timber.w("No biometrics enrolled")
                if (config.allowDeviceCredential) {
                    promptDeviceCredential()
                } else {
                    CvmRuleResult.Failed("No biometrics enrolled")
                }
            }

            else -> {
                CvmRuleResult.NotSupported
            }
        }
    }

    /**
     * Show biometric prompt to user
     */
    private suspend fun promptBiometric(): CvmRuleResult =
        suspendCancellableCoroutine { continuation ->
            val activity = config.activity
                ?: run {
                    continuation.resume(CvmRuleResult.Failed("Activity not available"))
                    return@suspendCancellableCoroutine
                }

            val executor = ContextCompat.getMainExecutor(context)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    Timber.d("CDCVM biometric authentication succeeded")
                    continuation.resume(CvmRuleResult.Success(CvmMethod.CDCVM))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Timber.w("CDCVM biometric error: $errorCode - $errString")
                    val result = when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                            CvmRuleResult.Failed("User cancelled authentication")
                        }
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                            CvmRuleResult.Failed("Biometric locked out")
                        }
                        else -> {
                            CvmRuleResult.Failed(errString.toString())
                        }
                    }
                    continuation.resume(result)
                }

                override fun onAuthenticationFailed() {
                    Timber.w("CDCVM biometric authentication failed")
                    // Don't resume yet - user can retry
                }
            }

            val biometricPrompt = BiometricPrompt(activity, executor, callback)

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(config.biometricPromptTitle)
                .setSubtitle(config.biometricPromptSubtitle)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            if (config.allowDeviceCredential) {
                                BiometricManager.Authenticators.DEVICE_CREDENTIAL
                            } else {
                                0
                            }
                )
                .apply {
                    if (!config.allowDeviceCredential) {
                        setNegativeButtonText("Cancel")
                    }
                }
                .build()

            biometricPrompt.authenticate(promptInfo)

            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }
        }

    /**
     * Prompt for device credential (PIN/pattern/password)
     */
    private suspend fun promptDeviceCredential(): CvmRuleResult =
        suspendCancellableCoroutine { continuation ->
            val activity = config.activity
                ?: run {
                    continuation.resume(CvmRuleResult.Failed("Activity not available"))
                    return@suspendCancellableCoroutine
                }

            val executor = ContextCompat.getMainExecutor(context)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    continuation.resume(CvmRuleResult.Success(CvmMethod.CDCVM))
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    continuation.resume(CvmRuleResult.Failed(errString.toString()))
                }
            }

            val biometricPrompt = BiometricPrompt(activity, executor, callback)

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(config.biometricPromptTitle)
                .setSubtitle("Enter your device PIN, pattern, or password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()

            biometricPrompt.authenticate(promptInfo)

            continuation.invokeOnCancellation {
                biometricPrompt.cancelAuthentication()
            }
        }

    /**
     * Check if CVM condition is satisfied
     */
    private fun checkCondition(
        conditionCode: Byte,
        amount: Long,
        amountOther: Long,
        amountX: Long,
        amountY: Long
    ): Boolean {
        return when (conditionCode.toInt() and 0xFF) {
            0x00 -> true  // Always
            0x01 -> amount > 0  // If unattended cash
            0x02 -> amount > 0 && amountOther == 0L  // If not unattended cash and not manual cash and not purchase with cashback
            0x03 -> true  // If terminal supports CVM
            0x04 -> true  // If manual cash
            0x05 -> amountOther > 0  // If purchase with cashback
            0x06 -> true  // If transaction in application currency and under X
            0x07 -> true  // If transaction in application currency and over X
            0x08 -> amount < amountY  // If transaction in application currency and under Y
            0x09 -> amount >= amountY  // If transaction in application currency and over Y
            else -> true  // Unknown condition - apply rule
        }
    }

    /**
     * Build CVM Results (Tag 9F34)
     */
    private fun buildCvmResults(cvmCode: Byte, successful: Boolean): ByteArray {
        val byte1 = cvmCode
        val byte2: Byte = 0x00  // Condition - always
        val byte3 = if (successful) {
            0x02.toByte()  // Successful
        } else {
            0x01.toByte()  // Failed
        }
        return byteArrayOf(byte1, byte2, byte3)
    }

    private fun extractAmount(data: ByteArray, offset: Int): Long {
        if (offset + 4 > data.size) return 0
        return ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
    }

    companion object {
        // CVM Method codes (lower 6 bits of CVM Code)
        const val CVM_FAIL = 0x00
        const val CVM_PLAINTEXT_PIN_BY_ICC = 0x01
        const val CVM_ENCIPHERED_PIN_ONLINE = 0x02
        const val CVM_PLAINTEXT_PIN_BY_ICC_WITH_SIGNATURE = 0x03
        const val CVM_ENCIPHERED_PIN_BY_ICC = 0x04
        const val CVM_ENCIPHERED_PIN_BY_ICC_WITH_SIGNATURE = 0x05
        const val CVM_SIGNATURE = 0x1E
        const val CVM_NO_CVM_REQUIRED = 0x1F
        const val CVM_CDCVM = 0x2F  // Consumer Device CVM (mobile)
    }
}

/**
 * CVM Rule from CVM List
 */
data class CvmRule(
    val cvmCode: Byte,
    val conditionCode: Byte
) {
    val method: Int get() = cvmCode.toInt() and 0x3F
    val continueOnFail: Boolean get() = (cvmCode.toInt() and 0x40) != 0

    override fun toString(): String {
        val methodName = when (method) {
            0x00 -> "FAIL"
            0x01 -> "PLAINTEXT_PIN_ICC"
            0x02 -> "ENCIPHERED_PIN_ONLINE"
            0x03 -> "PLAINTEXT_PIN_ICC_SIG"
            0x04 -> "ENCIPHERED_PIN_ICC"
            0x05 -> "ENCIPHERED_PIN_ICC_SIG"
            0x1E -> "SIGNATURE"
            0x1F -> "NO_CVM"
            0x2F -> "CDCVM"
            else -> "UNKNOWN($method)"
        }
        return "$methodName (continue=$continueOnFail, condition=${conditionCode.toInt() and 0xFF})"
    }
}

/**
 * Result of processing a single CVM rule
 */
sealed class CvmRuleResult {
    data class Success(val method: CvmMethod) : CvmRuleResult()
    data class Failed(val reason: String) : CvmRuleResult()
    object NotSupported : CvmRuleResult()
}

/**
 * Final CVM result
 */
sealed class CvmResult {
    data class Success(
        val method: CvmMethod,
        val cvmResults: ByteArray  // Tag 9F34
    ) : CvmResult()

    data class Failed(
        val reason: String,
        val cvmResults: ByteArray
    ) : CvmResult()

    object NoCvmPerformed : CvmResult()
}

/**
 * CVM Methods
 */
enum class CvmMethod {
    ONLINE_PIN,
    SIGNATURE,
    CDCVM,
    NO_CVM
}

/**
 * CVM Configuration
 */
data class CvmConfiguration(
    val activity: FragmentActivity? = null,
    val noCvmLimit: Long = 0,  // Amount below which No CVM is allowed
    val allowNoCvm: Boolean = true,
    val allowSignature: Boolean = false,
    val allowDeviceCredential: Boolean = true,  // Allow PIN/pattern as fallback
    val onlinePinSupported: Boolean = true,  // Whether terminal supports Online PIN entry
    val biometricPromptTitle: String = "Verify Payment",
    val biometricPromptSubtitle: String = "Authenticate to complete payment"
)
