package com.atlas.softpos.crypto

import timber.log.Timber
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * DUKPT (Derived Unique Key Per Transaction) Key Management
 *
 * Implements ANSI X9.24-1:2009 for secure PIN encryption key derivation.
 *
 * DUKPT provides:
 * - Unique encryption key for every transaction
 * - No sensitive keys stored on terminal
 * - Forward secrecy (compromise of one key doesn't reveal others)
 * - Key injection only needed once (BDK never leaves HSM)
 *
 * Key Hierarchy:
 * ```
 * BDK (Base Derivation Key) - Never leaves HSM
 *   └─> IPEK (Initial PIN Encryption Key) - Injected into terminal
 *         └─> Future Keys (derived using KSN)
 *               └─> PIN Encryption Key (derived per transaction)
 * ```
 *
 * KSN (Key Serial Number) Structure (10 bytes / 80 bits):
 * - Bytes 0-4: Key Set ID (identifies BDK)
 * - Bytes 5-7: Terminal ID (TRSM ID)
 * - Bytes 7-9: Transaction Counter (21 bits, ~2M transactions)
 */
class DukptKeyManager(
    private val config: DukptConfig
) {
    // Current Key Serial Number
    private var ksn: ByteArray = config.initialKsn.copyOf()

    // Future Key Register - holds 21 future keys
    private val futureKeys = Array<ByteArray?>(21) { null }

    // Current working key
    private var currentKey: ByteArray? = null

    // Transaction counter (21 bits = max 2,097,152 transactions)
    private var transactionCounter: Int = 0

    // Flag indicating if initialized
    private var initialized = false

    // Flag indicating if destroyed
    private var destroyed = false

    /**
     * Initialize DUKPT with IPEK (Initial PIN Encryption Key)
     *
     * This should be called once during terminal provisioning.
     * The IPEK is derived from BDK at the HSM and securely injected.
     *
     * @param ipek Initial PIN Encryption Key (16 bytes for TDES, 32 for AES)
     * @param initialKsn Initial Key Serial Number (10 bytes)
     */
    fun initialize(ipek: ByteArray, initialKsn: ByteArray) {
        require(ipek.size == 16 || ipek.size == 32) { "IPEK must be 16 or 32 bytes" }
        require(initialKsn.size == 10) { "KSN must be 10 bytes" }

        this.ksn = initialKsn.copyOf()
        this.transactionCounter = extractCounter(initialKsn)

        // Initialize future key table from IPEK
        initializeFutureKeys(ipek)

        initialized = true
        Timber.d("DUKPT initialized")
    }

    /**
     * Get the next PIN encryption key for a transaction
     *
     * @return Pair of (encryption key, KSN to send with PIN block)
     * @throws IllegalStateException if no more keys available
     */
    fun getNextKey(): DukptKeyResult {
        check(!destroyed) { "DUKPT manager has been destroyed" }
        check(initialized) { "DUKPT not initialized" }
        check(transactionCounter < MAX_TRANSACTION_COUNT) { "DUKPT exhausted - reinject required" }

        // Clear previous current key if exists
        currentKey?.let { secureZero(it) }
        currentKey = null

        // Find next valid counter (skip counters with more than 10 one-bits)
        while (countOneBits(transactionCounter) > 10 && transactionCounter < MAX_TRANSACTION_COUNT) {
            transactionCounter++
        }

        if (transactionCounter >= MAX_TRANSACTION_COUNT) {
            throw IllegalStateException("DUKPT exhausted - reinject required")
        }

        // Derive current key from future keys
        currentKey = deriveCurrentKey(transactionCounter)

        // Build current KSN
        val currentKsn = buildKsn(transactionCounter)

        // Derive key variant based on configuration
        val derivedKey = deriveKeyVariant(currentKey!!, config.keyVariant)

        // Increment counter for next transaction
        transactionCounter++

        // Update future keys (requires currentKey to still be valid)
        updateFutureKeys()

        // NOW clear the session key from memory after future keys are updated
        currentKey?.let { secureZero(it) }
        currentKey = null

        Timber.d("DUKPT key derived (${config.keyVariant}), remaining=${MAX_TRANSACTION_COUNT - transactionCounter}")

        return DukptKeyResult(
            pinEncryptionKey = derivedKey,
            ksn = currentKsn,
            remainingKeys = MAX_TRANSACTION_COUNT - transactionCounter
        )
    }

    /**
     * Securely zero a byte array to clear sensitive key material from memory
     */
    private fun secureZero(array: ByteArray) {
        array.fill(0)
    }

    /**
     * Destroy the DUKPT manager, clearing all key material from memory
     * Call this when the manager is no longer needed
     */
    fun destroy() {
        if (destroyed) return
        destroyed = true

        // Clear current key
        currentKey?.let { secureZero(it) }
        currentKey = null

        // Clear all future keys
        for (i in futureKeys.indices) {
            futureKeys[i]?.let { secureZero(it) }
            futureKeys[i] = null
        }

        // Clear KSN
        secureZero(ksn)

        initialized = false
        Timber.d("DUKPT manager destroyed, all keys cleared")
    }

    /**
     * Get current KSN without consuming a key
     */
    fun getCurrentKsn(): ByteArray {
        return buildKsn(transactionCounter)
    }

    /**
     * Get remaining key count
     */
    fun getRemainingKeyCount(): Int {
        return MAX_TRANSACTION_COUNT - transactionCounter
    }

    /**
     * Check if reinjection is needed soon
     */
    fun needsReinjection(threshold: Int = 1000): Boolean {
        return getRemainingKeyCount() < threshold
    }

    /**
     * Initialize future key register from IPEK
     */
    private fun initializeFutureKeys(ipek: ByteArray) {
        // Start with IPEK as the base
        var baseKey = ipek.copyOf()

        // Generate future keys for each bit position
        for (i in 0 until 21) {
            if ((transactionCounter and (1 shl i)) != 0) {
                // This bit is set in initial counter, derive key for this position
                futureKeys[i] = deriveFutureKey(baseKey, 1 shl i)
            } else {
                futureKeys[i] = null
            }
        }

        // Store IPEK-derived key in highest set bit position
        val highestBit = findHighestSetBit(transactionCounter)
        if (highestBit >= 0) {
            futureKeys[highestBit] = deriveKeyFromIpek(ipek, transactionCounter)
        } else {
            // Counter is 0, use IPEK directly for first derivation
            futureKeys[0] = ipek.copyOf()
        }
    }

    /**
     * Derive current transaction key from future keys
     */
    private fun deriveCurrentKey(counter: Int): ByteArray {
        var key: ByteArray? = null

        // Find the base key (highest set bit in counter)
        for (i in 20 downTo 0) {
            if ((counter and (1 shl i)) != 0 && futureKeys[i] != null) {
                key = futureKeys[i]!!.copyOf()

                // Derive through all lower set bits
                for (j in (i - 1) downTo 0) {
                    if ((counter and (1 shl j)) != 0) {
                        key = deriveFutureKey(key!!, 1 shl j)
                    }
                }
                break
            }
        }

        return key ?: throw IllegalStateException("No valid future key found")
    }

    /**
     * Update future keys after incrementing counter
     */
    private fun updateFutureKeys() {
        // When counter changes, we may need to update future keys
        // This is called after incrementing the counter

        val prevCounter = transactionCounter - 1

        // Find which bit changed from 0 to 1
        val changed = transactionCounter xor prevCounter
        val newBit = findLowestSetBit(changed and transactionCounter)

        if (newBit >= 0 && currentKey != null) {
            // Clear old key at this position before overwriting
            futureKeys[newBit]?.let { secureZero(it) }

            // Store derived key for this new bit position
            futureKeys[newBit] = deriveFutureKey(currentKey!!, 1 shl newBit)

            // Securely clear keys for lower bits (they'll be re-derived)
            for (i in 0 until newBit) {
                futureKeys[i]?.let { secureZero(it) }
                futureKeys[i] = null
            }
        }
    }

    /**
     * Derive a future key using TDES
     *
     * Per ANSI X9.24, this uses the non-reversible key generation process
     */
    private fun deriveFutureKey(baseKey: ByteArray, shiftRegister: Int): ByteArray {
        // Crypto Register = KSN with counter bits masked in
        val cryptoRegister = buildKsn(shiftRegister)

        // Right half key derivation
        val rightKey = baseKey.copyOfRange(8, 16)
        val rightCrypto = cryptoRegister.copyOfRange(2, 10)

        // XOR and encrypt
        val rightXored = xorBytes(rightCrypto, rightKey)
        val rightResult = encryptDes(rightXored, baseKey.copyOfRange(0, 8))

        // Left half key derivation (with key variant)
        val leftKey = xorBytes(baseKey.copyOfRange(0, 8), KEY_VARIANT_CONSTANT)
        val leftKeyRight = xorBytes(baseKey.copyOfRange(8, 16), KEY_VARIANT_CONSTANT)
        val leftCrypto = cryptoRegister.copyOfRange(2, 10)

        val leftXored = xorBytes(leftCrypto, leftKeyRight)
        val leftResult = encryptDes(leftXored, leftKey)

        return leftResult + rightResult
    }

    /**
     * Derive IPEK-based key for initial counter value
     */
    private fun deriveKeyFromIpek(ipek: ByteArray, counter: Int): ByteArray {
        var key = ipek.copyOf()

        // Derive through each set bit
        for (i in 20 downTo 0) {
            if ((counter and (1 shl i)) != 0) {
                key = deriveFutureKey(key, 1 shl i)
            }
        }

        return key
    }

    /**
     * Derive key variant from session key
     *
     * Per ANSI X9.24, XOR with appropriate variant constant
     */
    private fun deriveKeyVariant(sessionKey: ByteArray, variant: KeyVariant): ByteArray {
        val variantConstant = when (variant) {
            KeyVariant.PIN -> PIN_VARIANT_CONSTANT
            KeyVariant.MAC -> MAC_VARIANT_CONSTANT
            KeyVariant.DATA -> DATA_VARIANT_CONSTANT
        }
        return xorBytes(sessionKey, variantConstant)
    }

    /**
     * Get a key for a specific variant (convenience method)
     * Creates a new key derivation for the requested variant
     */
    fun getNextKeyForVariant(variant: KeyVariant): DukptKeyResult {
        check(!destroyed) { "DUKPT manager has been destroyed" }
        check(initialized) { "DUKPT not initialized" }
        check(transactionCounter < MAX_TRANSACTION_COUNT) { "DUKPT exhausted - reinject required" }

        // Clear previous current key if exists
        currentKey?.let { secureZero(it) }
        currentKey = null

        // Find next valid counter
        while (countOneBits(transactionCounter) > 10 && transactionCounter < MAX_TRANSACTION_COUNT) {
            transactionCounter++
        }

        if (transactionCounter >= MAX_TRANSACTION_COUNT) {
            throw IllegalStateException("DUKPT exhausted - reinject required")
        }

        // Derive current key from future keys
        currentKey = deriveCurrentKey(transactionCounter)

        // Build current KSN
        val currentKsn = buildKsn(transactionCounter)

        // Derive requested key variant
        val derivedKey = deriveKeyVariant(currentKey!!, variant)

        // Increment counter for next transaction
        transactionCounter++

        // Update future keys (requires currentKey to still be valid)
        updateFutureKeys()

        // Clear the session key from memory
        currentKey?.let { secureZero(it) }
        currentKey = null

        Timber.d("DUKPT key derived ($variant), remaining=${MAX_TRANSACTION_COUNT - transactionCounter}")

        return DukptKeyResult(
            pinEncryptionKey = derivedKey,
            ksn = currentKsn,
            remainingKeys = MAX_TRANSACTION_COUNT - transactionCounter
        )
    }

    /**
     * Build full KSN from counter
     */
    private fun buildKsn(counter: Int): ByteArray {
        val result = ksn.copyOf()
        // Counter occupies lower 21 bits of last 3 bytes
        result[7] = ((result[7].toInt() and 0xE0) or ((counter shr 16) and 0x1F)).toByte()
        result[8] = ((counter shr 8) and 0xFF).toByte()
        result[9] = (counter and 0xFF).toByte()
        return result
    }

    /**
     * Extract counter from KSN
     */
    private fun extractCounter(ksn: ByteArray): Int {
        return ((ksn[7].toInt() and 0x1F) shl 16) or
                ((ksn[8].toInt() and 0xFF) shl 8) or
                (ksn[9].toInt() and 0xFF)
    }

    /**
     * Count one-bits in an integer (for DUKPT counter validation)
     */
    private fun countOneBits(n: Int): Int {
        var count = 0
        var num = n
        while (num != 0) {
            count += num and 1
            num = num ushr 1
        }
        return count
    }

    private fun findHighestSetBit(n: Int): Int {
        for (i in 20 downTo 0) {
            if ((n and (1 shl i)) != 0) return i
        }
        return -1
    }

    private fun findLowestSetBit(n: Int): Int {
        for (i in 0..20) {
            if ((n and (1 shl i)) != 0) return i
        }
        return -1
    }

    /**
     * Single DES encryption (for key derivation)
     */
    private fun encryptDes(data: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("DES/ECB/NoPadding")
        val keySpec = SecretKeySpec(key.copyOfRange(0, 8), "DES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        return cipher.doFinal(data)
    }

    /**
     * XOR two byte arrays
     */
    private fun xorBytes(a: ByteArray, b: ByteArray): ByteArray {
        val result = ByteArray(minOf(a.size, b.size))
        for (i in result.indices) {
            result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return result
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02X".format(it) }

    companion object {
        // Maximum transaction count (2^21 - 1)
        private const val MAX_TRANSACTION_COUNT = 2097152

        // Key variant constant for future key derivation
        private val KEY_VARIANT_CONSTANT = byteArrayOf(
            0xC0.toByte(), 0xC0.toByte(), 0xC0.toByte(), 0xC0.toByte(),
            0x00, 0x00, 0x00, 0x00
        )

        // PIN encryption key variant (per ANSI X9.24)
        private val PIN_VARIANT_CONSTANT = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF.toByte(),
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF.toByte()
        )

        // MAC key variant
        private val MAC_VARIANT_CONSTANT = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF.toByte(), 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF.toByte(), 0x00
        )

        // Data encryption key variant
        private val DATA_VARIANT_CONSTANT = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF.toByte(), 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF.toByte(), 0x00, 0x00
        )

        /**
         * Calculate IPEK from BDK (typically done at HSM, included for testing)
         *
         * @param bdk Base Derivation Key (16 bytes)
         * @param ksn Initial KSN (10 bytes)
         * @return IPEK (16 bytes)
         */
        fun deriveIpekFromBdk(bdk: ByteArray, ksn: ByteArray): ByteArray {
            require(bdk.size == 16) { "BDK must be 16 bytes" }
            require(ksn.size == 10) { "KSN must be 10 bytes" }

            // Mask counter bits to 0 for IPEK derivation
            val maskedKsn = ksn.copyOf()
            maskedKsn[7] = (maskedKsn[7].toInt() and 0xE0).toByte()
            maskedKsn[8] = 0
            maskedKsn[9] = 0

            // Use right 8 bytes of masked KSN
            val ksnRight = maskedKsn.copyOfRange(2, 10)

            // Left half: TDES encrypt KSN with BDK
            val leftHalf = encryptTripleDes(ksnRight, bdk)

            // Right half: TDES encrypt KSN with modified BDK
            val modifiedBdk = ByteArray(16)
            for (i in 0 until 16) {
                modifiedBdk[i] = (bdk[i].toInt() xor KEY_VARIANT_CONSTANT[i % 8].toInt()).toByte()
            }
            val rightHalf = encryptTripleDes(ksnRight, modifiedBdk)

            return leftHalf + rightHalf
        }

        private fun encryptTripleDes(data: ByteArray, key: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("DESede/ECB/NoPadding")
            // Expand 16-byte key to 24-byte by copying first 8 bytes
            val expandedKey = if (key.size == 16) {
                key + key.copyOfRange(0, 8)
            } else {
                key
            }
            val keySpec = SecretKeySpec(expandedKey, "DESede")
            cipher.init(Cipher.ENCRYPT_MODE, keySpec)
            return cipher.doFinal(data)
        }
    }
}

/**
 * DUKPT Configuration
 */
data class DukptConfig(
    val initialKsn: ByteArray = ByteArray(10),
    val keyVariant: KeyVariant = KeyVariant.PIN
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DukptConfig) return false
        return initialKsn.contentEquals(other.initialKsn) && keyVariant == other.keyVariant
    }

    override fun hashCode(): Int {
        return 31 * initialKsn.contentHashCode() + keyVariant.hashCode()
    }
}

/**
 * Key variant types
 */
enum class KeyVariant {
    PIN,
    MAC,
    DATA
}

/**
 * Result of DUKPT key derivation
 *
 * SECURITY NOTE: The caller MUST call clear() on this result after
 * using the pinEncryptionKey to prevent key material from remaining in memory.
 */
data class DukptKeyResult(
    val pinEncryptionKey: ByteArray,
    val ksn: ByteArray,
    val remainingKeys: Int
) {
    /**
     * Securely clear the PIN encryption key from memory
     * Call this after the key has been used
     */
    fun clear() {
        pinEncryptionKey.fill(0)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DukptKeyResult) return false
        return pinEncryptionKey.contentEquals(other.pinEncryptionKey) &&
                ksn.contentEquals(other.ksn) &&
                remainingKeys == other.remainingKeys
    }

    override fun hashCode(): Int {
        var result = pinEncryptionKey.contentHashCode()
        result = 31 * result + ksn.contentHashCode()
        result = 31 * result + remainingKeys
        return result
    }

    fun toHexStrings(): Pair<String, String> {
        return Pair(
            pinEncryptionKey.joinToString("") { "%02X".format(it) },
            ksn.joinToString("") { "%02X".format(it) }
        )
    }
}
