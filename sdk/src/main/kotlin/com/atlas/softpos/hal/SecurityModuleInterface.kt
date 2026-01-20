package com.atlas.softpos.hal

/**
 * Hardware Abstraction Layer - Security Module Interface
 *
 * Abstracts cryptographic operations for portability across:
 * - SoftPOS (software-based with Android Keystore)
 * - PAX terminals (hardware security module)
 * - Castles terminals (hardware security module)
 * - External HSMs
 */
interface SecurityModuleInterface {

    /**
     * Initialize the security module
     *
     * @param config Security module configuration
     * @return true if initialization successful
     */
    suspend fun initialize(config: SecurityModuleConfig): Boolean

    /**
     * Check if module is ready
     */
    fun isReady(): Boolean

    /**
     * Get security module capabilities
     */
    fun getCapabilities(): SecurityModuleCapabilities

    // ==================== KEY MANAGEMENT ====================

    /**
     * Inject a key into a slot
     *
     * @param keySlot Slot to store the key
     * @param keyBlock TR-31 or raw key block
     * @param keyType Type of key being injected
     * @return true if successful
     */
    suspend fun injectKey(
        keySlot: Int,
        keyBlock: ByteArray,
        keyType: KeyType
    ): Boolean

    /**
     * Derive DUKPT key
     *
     * @param bdkSlot Slot containing BDK/IPEK
     * @param ksn Key Serial Number
     * @return Derived key data
     */
    suspend fun deriveDukptKey(
        bdkSlot: Int,
        ksn: ByteArray
    ): DerivedKeyResult

    /**
     * Generate random bytes
     *
     * @param length Number of bytes to generate
     * @return Random bytes
     */
    suspend fun generateRandom(length: Int): ByteArray

    /**
     * Delete key from slot
     *
     * @param keySlot Slot to clear
     */
    suspend fun deleteKey(keySlot: Int): Boolean

    /**
     * Check if key slot is loaded
     *
     * @param keySlot Slot to check
     */
    fun isKeyLoaded(keySlot: Int): Boolean

    // ==================== ENCRYPTION ====================

    /**
     * Encrypt data using key in slot
     *
     * @param keySlot Key slot to use
     * @param data Data to encrypt
     * @param algorithm Encryption algorithm
     * @return Encrypted data
     */
    suspend fun encrypt(
        keySlot: Int,
        data: ByteArray,
        algorithm: EncryptionAlgorithm
    ): ByteArray

    /**
     * Decrypt data using key in slot
     *
     * @param keySlot Key slot to use
     * @param data Data to decrypt
     * @param algorithm Encryption algorithm
     * @return Decrypted data
     */
    suspend fun decrypt(
        keySlot: Int,
        data: ByteArray,
        algorithm: EncryptionAlgorithm
    ): ByteArray

    /**
     * Encrypt PIN block
     *
     * @param pinBlock Clear PIN block
     * @param keySlot Key slot for encryption
     * @param ksn KSN if using DUKPT
     * @return Encrypted PIN block and optional KSN
     */
    suspend fun encryptPinBlock(
        pinBlock: ByteArray,
        keySlot: Int,
        ksn: ByteArray? = null
    ): EncryptedPinBlock

    // ==================== MAC OPERATIONS ====================

    /**
     * Calculate MAC
     *
     * @param keySlot Key slot to use
     * @param data Data to MAC
     * @param algorithm MAC algorithm
     * @return MAC value
     */
    suspend fun calculateMac(
        keySlot: Int,
        data: ByteArray,
        algorithm: MacAlgorithm
    ): ByteArray

    /**
     * Verify MAC
     *
     * @param keySlot Key slot to use
     * @param data Data that was MACed
     * @param mac MAC to verify
     * @param algorithm MAC algorithm
     * @return true if MAC is valid
     */
    suspend fun verifyMac(
        keySlot: Int,
        data: ByteArray,
        mac: ByteArray,
        algorithm: MacAlgorithm
    ): Boolean

    // ==================== RSA OPERATIONS ====================

    /**
     * Load RSA public key (for ODA)
     *
     * @param keySlot Slot to store key
     * @param modulus RSA modulus
     * @param exponent RSA exponent
     */
    suspend fun loadRsaPublicKey(
        keySlot: Int,
        modulus: ByteArray,
        exponent: ByteArray
    ): Boolean

    /**
     * RSA public key operation (encrypt/verify)
     *
     * @param keySlot Key slot containing public key
     * @param data Data to process
     * @return Result of RSA operation
     */
    suspend fun rsaPublicOperation(
        keySlot: Int,
        data: ByteArray
    ): ByteArray

    /**
     * Verify RSA signature
     *
     * @param keySlot Key slot containing public key
     * @param data Signed data
     * @param signature Signature to verify
     * @param hashAlgorithm Hash algorithm used
     * @return true if signature valid
     */
    suspend fun rsaVerify(
        keySlot: Int,
        data: ByteArray,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm
    ): Boolean

    // ==================== HASH OPERATIONS ====================

    /**
     * Calculate hash
     *
     * @param data Data to hash
     * @param algorithm Hash algorithm
     * @return Hash value
     */
    suspend fun hash(
        data: ByteArray,
        algorithm: HashAlgorithm
    ): ByteArray

    // ==================== SESSION MANAGEMENT ====================

    /**
     * Open secure session
     * Required for some HSMs before cryptographic operations
     */
    suspend fun openSession(): SessionHandle?

    /**
     * Close secure session
     */
    suspend fun closeSession(handle: SessionHandle)

    /**
     * Release security module resources
     */
    suspend fun release()
}

/**
 * Security module configuration
 */
data class SecurityModuleConfig(
    /**
     * Module type
     */
    val type: SecurityModuleType,

    /**
     * Connection parameters (for external HSMs)
     */
    val connectionParams: Map<String, String> = emptyMap(),

    /**
     * Authentication credentials (if required)
     */
    val authCredentials: ByteArray? = null,

    /**
     * Enable FIPS mode
     */
    val fipsMode: Boolean = false,

    /**
     * Key slot configuration
     */
    val keySlots: Map<Int, KeySlotConfig> = emptyMap(),

    /**
     * Terminal-specific configuration
     */
    val terminalConfig: Map<String, Any> = emptyMap()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecurityModuleConfig) return false
        return type == other.type && connectionParams == other.connectionParams
    }

    override fun hashCode(): Int = type.hashCode() * 31 + connectionParams.hashCode()
}

/**
 * Security module types
 */
enum class SecurityModuleType {
    SOFTWARE,           // Software-based (Android Keystore)
    HARDWARE_INTERNAL,  // Built-in HSM (terminal)
    HARDWARE_EXTERNAL,  // External HSM (network/USB)
    TEE,               // Trusted Execution Environment
    SECURE_ELEMENT     // Secure Element (eSE/UICC)
}

/**
 * Key slot configuration
 */
data class KeySlotConfig(
    val keyType: KeyType,
    val algorithm: EncryptionAlgorithm,
    val keyLength: Int,
    val usage: KeyUsage
)

/**
 * Key types
 */
enum class KeyType {
    BDK,                // Base Derivation Key
    IPEK,               // Initial PIN Encryption Key
    PIN_ENCRYPTION,     // PIN Encryption Key (PEK)
    DATA_ENCRYPTION,    // Data Encryption Key (DEK)
    MAC,                // MAC Key
    MASTER_KEY,         // Master Key
    SESSION_KEY,        // Session Key
    RSA_PUBLIC,         // RSA Public Key
    RSA_PRIVATE,        // RSA Private Key
    CA_PUBLIC,          // CA Public Key (for ODA)
    ISSUER_PUBLIC       // Issuer Public Key
}

/**
 * Key usage flags
 */
enum class KeyUsage {
    ENCRYPT,
    DECRYPT,
    ENCRYPT_DECRYPT,
    MAC,
    VERIFY,
    DERIVE,
    WRAP,
    UNWRAP
}

/**
 * Encryption algorithms
 */
enum class EncryptionAlgorithm {
    TDES_ECB,
    TDES_CBC,
    AES_128_ECB,
    AES_128_CBC,
    AES_256_ECB,
    AES_256_CBC
}

/**
 * MAC algorithms
 */
enum class MacAlgorithm {
    TDES_MAC,
    CMAC_TDES,
    CMAC_AES,
    HMAC_SHA256
}

/**
 * Hash algorithms
 */
enum class HashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512
}

/**
 * Security module capabilities
 */
data class SecurityModuleCapabilities(
    /**
     * Module type
     */
    val type: SecurityModuleType,

    /**
     * FIPS 140-2/3 certified
     */
    val fipsCertified: Boolean,

    /**
     * Certification level
     */
    val certificationLevel: String?,

    /**
     * PCI PTS POI certified
     */
    val pciPtsCertified: Boolean,

    /**
     * Number of key slots
     */
    val keySlotCount: Int,

    /**
     * Supports DUKPT
     */
    val dukptSupported: Boolean,

    /**
     * Supports TR-31 key blocks
     */
    val tr31Supported: Boolean,

    /**
     * Supports TR-34 key exchange
     */
    val tr34Supported: Boolean,

    /**
     * Supported encryption algorithms
     */
    val supportedEncryption: Set<EncryptionAlgorithm>,

    /**
     * Supported MAC algorithms
     */
    val supportedMac: Set<MacAlgorithm>,

    /**
     * Supported hash algorithms
     */
    val supportedHash: Set<HashAlgorithm>,

    /**
     * Maximum RSA key size
     */
    val maxRsaKeySize: Int,

    /**
     * Has hardware RNG
     */
    val hardwareRng: Boolean,

    /**
     * Manufacturer
     */
    val manufacturer: String,

    /**
     * Model
     */
    val model: String,

    /**
     * Firmware version
     */
    val firmwareVersion: String
)

/**
 * Derived key result
 */
data class DerivedKeyResult(
    /**
     * Derived key (or key handle for HSMs)
     */
    val key: ByteArray,

    /**
     * Current KSN
     */
    val ksn: ByteArray,

    /**
     * Key slot (if stored in HSM)
     */
    val keySlot: Int? = null,

    /**
     * Remaining key count
     */
    val remainingKeys: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DerivedKeyResult) return false
        return key.contentEquals(other.key) && ksn.contentEquals(other.ksn)
    }

    override fun hashCode(): Int = key.contentHashCode() * 31 + ksn.contentHashCode()

    fun clear() {
        key.fill(0)
    }
}

/**
 * Encrypted PIN block result
 */
data class EncryptedPinBlock(
    /**
     * Encrypted PIN block
     */
    val pinBlock: ByteArray,

    /**
     * KSN (if DUKPT was used)
     */
    val ksn: ByteArray?,

    /**
     * Format used
     */
    val format: PinBlockFormat
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedPinBlock) return false
        return pinBlock.contentEquals(other.pinBlock) && ksn.contentEquals(other.ksn)
    }

    override fun hashCode(): Int = pinBlock.contentHashCode()
}

/**
 * Session handle for HSM operations
 */
data class SessionHandle(
    val id: Long,
    val isValid: Boolean = true
)

/**
 * Security module exceptions
 */
open class SecurityModuleException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

class KeyNotFoundExceptio(keySlot: Int) : SecurityModuleException("Key not found in slot $keySlot")
class CryptographicException(message: String) : SecurityModuleException(message)
class AuthenticationFailedException : SecurityModuleException("HSM authentication failed")
class SessionExpiredException : SecurityModuleException("HSM session expired")
