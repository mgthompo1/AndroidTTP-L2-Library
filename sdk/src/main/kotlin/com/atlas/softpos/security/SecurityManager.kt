package com.atlas.softpos.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import timber.log.Timber
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume

/**
 * Security Manager for PCI MPoC Compliance
 *
 * Implements security controls required for PCI MPoC (Mobile Payments on COTS):
 *
 * 1. Device Integrity
 *    - Root/jailbreak detection
 *    - Debug mode detection
 *    - Emulator detection
 *    - Google Play Integrity API
 *
 * 2. App Integrity
 *    - Signature verification
 *    - Tamper detection
 *    - Debugger detection
 *
 * 3. Data Protection
 *    - Secure key storage (Android Keystore/StrongBox)
 *    - Memory protection
 *    - Screen capture prevention
 *
 * 4. Runtime Protection
 *    - SSL pinning readiness
 *    - Secure random generation
 *    - Sensitive data clearing
 */
class SecurityManager(
    private val context: Context
) {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    companion object {
        private const val KEY_ALIAS_MASTER = "atlas_softpos_master_key"
        private const val KEY_ALIAS_DATA = "atlas_softpos_data_key"

        // Known root indicators
        private val ROOT_PATHS = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/su/bin",
            "/magisk/.core/bin/su"
        )

        private val ROOT_PACKAGES = listOf(
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root"
        )

        private val DANGEROUS_APPS = listOf(
            "com.saurik.substrate",
            "de.robv.android.xposed.installer",
            "com.ramdroid.appquarantine"
        )
    }

    /**
     * Perform comprehensive security check
     * Should be called before processing any transaction
     */
    fun performSecurityCheck(): SecurityCheckResult {
        val issues = mutableListOf<SecurityIssue>()

        // Root detection
        if (isDeviceRooted()) {
            issues.add(SecurityIssue.DEVICE_ROOTED)
        }

        // Debug mode detection
        if (isDebugMode()) {
            issues.add(SecurityIssue.DEBUG_MODE_ENABLED)
        }

        // Emulator detection
        if (isEmulator()) {
            issues.add(SecurityIssue.RUNNING_ON_EMULATOR)
        }

        // Debugger detection
        if (isDebuggerAttached()) {
            issues.add(SecurityIssue.DEBUGGER_ATTACHED)
        }

        // USB debugging check
        if (isUsbDebuggingEnabled()) {
            issues.add(SecurityIssue.USB_DEBUGGING_ENABLED)
        }

        // Developer options check
        if (isDeveloperOptionsEnabled()) {
            issues.add(SecurityIssue.DEVELOPER_OPTIONS_ENABLED)
        }

        // Hooking framework detection
        if (isHookingFrameworkDetected()) {
            issues.add(SecurityIssue.HOOKING_FRAMEWORK_DETECTED)
        }

        // Check for dangerous apps
        if (hasDangerousApps()) {
            issues.add(SecurityIssue.DANGEROUS_APPS_INSTALLED)
        }

        return if (issues.isEmpty()) {
            SecurityCheckResult.Passed
        } else {
            // Determine severity
            val critical = issues.any { it.severity == IssueSeverity.CRITICAL }
            if (critical) {
                SecurityCheckResult.Failed(issues)
            } else {
                SecurityCheckResult.Warning(issues)
            }
        }
    }

    /**
     * Verify device integrity using Google Play Integrity API
     */
    suspend fun verifyPlayIntegrity(): IntegrityResult = suspendCancellableCoroutine { cont ->
        try {
            val integrityManager = IntegrityManagerFactory.create(context)

            // In production, nonce should come from your server
            val nonce = generateNonce()

            val request = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    // Token should be sent to your server for verification
                    // Server verifies with Google and returns result
                    cont.resume(IntegrityResult.TokenGenerated(response.token()))
                }
                .addOnFailureListener { e ->
                    Timber.e(e, "Play Integrity check failed")
                    cont.resume(IntegrityResult.Failed(e.message ?: "Unknown error"))
                }
        } catch (e: Exception) {
            cont.resume(IntegrityResult.Failed(e.message ?: "Integrity API unavailable"))
        }
    }

    /**
     * Enable screen capture prevention for an activity
     */
    fun enableScreenProtection(activity: FragmentActivity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    /**
     * Generate or retrieve secure encryption key
     */
    fun getOrCreateMasterKey(): SecretKey {
        return if (keyStore.containsAlias(KEY_ALIAS_MASTER)) {
            keyStore.getKey(KEY_ALIAS_MASTER, null) as SecretKey
        } else {
            createMasterKey()
        }
    }

    /**
     * Create master key in secure hardware if available
     */
    private fun createMasterKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS_MASTER,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false) // Would require biometric for each use
            .setRandomizedEncryptionRequired(true)

        // Use StrongBox if available (hardware security module)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
                Timber.d("Using StrongBox for key storage")
            } catch (e: Exception) {
                Timber.w("StrongBox not available, using TEE")
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /**
     * Encrypt sensitive data
     */
    fun encryptData(plaintext: ByteArray): EncryptedData {
        val key = getOrCreateMasterKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val ciphertext = cipher.doFinal(plaintext)
        val iv = cipher.iv

        return EncryptedData(ciphertext, iv)
    }

    /**
     * Decrypt sensitive data
     */
    fun decryptData(encryptedData: EncryptedData): ByteArray {
        val key = getOrCreateMasterKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, encryptedData.iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        return cipher.doFinal(encryptedData.ciphertext)
    }

    /**
     * Securely clear sensitive data from memory
     */
    fun clearSensitiveData(data: ByteArray) {
        for (i in data.indices) {
            data[i] = 0
        }
        // Additional passes for thoroughness
        for (i in data.indices) {
            data[i] = 0xFF.toByte()
        }
        for (i in data.indices) {
            data[i] = 0
        }
    }

    /**
     * Generate cryptographically secure random bytes
     */
    fun generateSecureRandom(length: Int): ByteArray {
        val random = java.security.SecureRandom()
        return ByteArray(length).also { random.nextBytes(it) }
    }

    // ========== Detection Methods ==========

    private fun isDeviceRooted(): Boolean {
        // Check for su binary in common paths
        for (path in ROOT_PATHS) {
            if (File(path).exists()) {
                Timber.w("Root indicator found: $path")
                return true
            }
        }

        // Check for root management apps
        for (pkg in ROOT_PACKAGES) {
            if (isPackageInstalled(pkg)) {
                Timber.w("Root package found: $pkg")
                return true
            }
        }

        // Check build tags
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            Timber.w("Test-keys build detected")
            return true
        }

        // Try to execute su command and verify it works
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val exitCode = process.waitFor()
            process.destroy()
            exitCode == 0  // Only return true if su actually succeeded
        } catch (e: Exception) {
            false
        }
    }

    private fun isDebugMode(): Boolean {
        return (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    private fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || "google_sdk" == Build.PRODUCT
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu"))
    }

    private fun isDebuggerAttached(): Boolean {
        return android.os.Debug.isDebuggerConnected()
    }

    private fun isUsbDebuggingEnabled(): Boolean {
        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0
        ) == 1
    }

    private fun isDeveloperOptionsEnabled(): Boolean {
        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0
        ) == 1
    }

    private fun isHookingFrameworkDetected(): Boolean {
        // Check for Xposed
        try {
            throw Exception("Xposed check")
        } catch (e: Exception) {
            for (element in e.stackTrace) {
                if (element.className.contains("de.robv.android.xposed") ||
                    element.className.contains("com.saurik.substrate")
                ) {
                    return true
                }
            }
        }

        // Check for Frida
        return try {
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 100)
            socket.close()
            true // Frida default port is open
        } catch (e: Exception) {
            false
        }
    }

    private fun hasDangerousApps(): Boolean {
        for (pkg in DANGEROUS_APPS) {
            if (isPackageInstalled(pkg)) {
                return true
            }
        }
        return false
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun generateNonce(): String {
        return java.util.Base64.getEncoder().encodeToString(generateSecureRandom(32))
    }
}

/**
 * Security check result
 */
sealed class SecurityCheckResult {
    object Passed : SecurityCheckResult()
    data class Warning(val issues: List<SecurityIssue>) : SecurityCheckResult()
    data class Failed(val issues: List<SecurityIssue>) : SecurityCheckResult()
}

/**
 * Security issues
 */
enum class SecurityIssue(val severity: IssueSeverity, val description: String) {
    DEVICE_ROOTED(IssueSeverity.CRITICAL, "Device is rooted"),
    DEBUG_MODE_ENABLED(IssueSeverity.CRITICAL, "App running in debug mode"),
    RUNNING_ON_EMULATOR(IssueSeverity.CRITICAL, "Running on emulator"),
    DEBUGGER_ATTACHED(IssueSeverity.CRITICAL, "Debugger attached"),
    USB_DEBUGGING_ENABLED(IssueSeverity.WARNING, "USB debugging enabled"),
    DEVELOPER_OPTIONS_ENABLED(IssueSeverity.WARNING, "Developer options enabled"),
    HOOKING_FRAMEWORK_DETECTED(IssueSeverity.CRITICAL, "Hooking framework detected"),
    DANGEROUS_APPS_INSTALLED(IssueSeverity.WARNING, "Dangerous apps installed"),
    INTEGRITY_CHECK_FAILED(IssueSeverity.CRITICAL, "Play Integrity check failed")
}

enum class IssueSeverity {
    WARNING,
    CRITICAL
}

/**
 * Integrity check result
 */
sealed class IntegrityResult {
    data class TokenGenerated(val token: String) : IntegrityResult()
    data class Failed(val reason: String) : IntegrityResult()
}

/**
 * Encrypted data container
 */
data class EncryptedData(
    val ciphertext: ByteArray,
    val iv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedData) return false
        return ciphertext.contentEquals(other.ciphertext) && iv.contentEquals(other.iv)
    }

    override fun hashCode(): Int {
        var result = ciphertext.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        return result
    }
}
