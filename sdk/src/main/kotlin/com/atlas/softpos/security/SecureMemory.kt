package com.atlas.softpos.security

import java.io.Closeable
import java.security.SecureRandom
import java.util.Arrays
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Secure Memory Management for EMV Sensitive Data
 *
 * Implements PCI MPoC memory protection requirements:
 * - Secure clearing of sensitive data (PAN, PIN, cryptograms)
 * - Constant-time comparison to prevent timing attacks
 * - Automatic cleanup via use-with pattern
 * - Memory overwrite with random data before zeroing
 *
 * Reference: PCI MPoC Security Requirements Section 5.3
 */
object SecureMemory {

    private val secureRandom = SecureRandom()

    /**
     * Securely clear a byte array using multi-pass overwrite
     *
     * Uses DoD 5220.22-M style clearing:
     * 1. Overwrite with 0x00
     * 2. Overwrite with 0xFF
     * 3. Overwrite with random data
     * 4. Final overwrite with 0x00
     */
    fun clear(data: ByteArray?) {
        if (data == null || data.isEmpty()) return

        // Pass 1: Zero fill
        Arrays.fill(data, 0x00.toByte())

        // Pass 2: One fill
        Arrays.fill(data, 0xFF.toByte())

        // Pass 3: Random fill
        secureRandom.nextBytes(data)

        // Pass 4: Final zero
        Arrays.fill(data, 0x00.toByte())
    }

    /**
     * Securely clear a char array (for PIN entry)
     */
    fun clear(data: CharArray?) {
        if (data == null || data.isEmpty()) return

        // Pass 1: Zero fill
        Arrays.fill(data, '\u0000')

        // Pass 2: Random fill
        for (i in data.indices) {
            data[i] = secureRandom.nextInt(65536).toChar()
        }

        // Pass 3: Final zero
        Arrays.fill(data, '\u0000')
    }

    /**
     * Securely clear a string by clearing its underlying char array
     * Note: Strings are immutable in JVM, so this only helps if the
     * string was created from a char array that we can still access
     */
    fun clearString(data: String?) {
        if (data == null) return

        try {
            // Use reflection to clear the internal char array
            // This is a best-effort approach due to JVM string immutability
            val valueField = String::class.java.getDeclaredField("value")
            valueField.isAccessible = true
            val chars = valueField.get(data)
            if (chars is CharArray) {
                clear(chars)
            } else if (chars is ByteArray) {
                // Java 9+ uses byte array internally
                clear(chars)
            }
        } catch (e: Exception) {
            // Reflection failed, can't clear
        }
    }

    /**
     * Constant-time byte array comparison
     *
     * Prevents timing attacks by ensuring comparison takes the same
     * amount of time regardless of where differences occur
     */
    fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean {
        if (a == null && b == null) return true
        if (a == null || b == null) return false
        if (a.size != b.size) return false

        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    /**
     * Create a secure copy of sensitive data
     * Original should be cleared after copying
     */
    fun secureCopy(source: ByteArray): ByteArray {
        val copy = ByteArray(source.size)
        System.arraycopy(source, 0, copy, 0, source.size)
        return copy
    }

    /**
     * XOR two byte arrays securely and clear the inputs
     */
    fun secureXor(a: ByteArray, b: ByteArray, clearInputs: Boolean = false): ByteArray {
        require(a.size == b.size) { "Arrays must be same length" }

        val result = ByteArray(a.size)
        for (i in a.indices) {
            result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }

        if (clearInputs) {
            clear(a)
            clear(b)
        }

        return result
    }
}

/**
 * Interface for objects that hold sensitive data and can be cleared
 */
interface Clearable {
    /**
     * Clear all sensitive data held by this object
     */
    fun clear()

    /**
     * Check if this object has been cleared
     */
    fun isCleared(): Boolean
}

/**
 * Wrapper for sensitive byte array data with automatic clearing
 *
 * Implements Closeable for use-with pattern:
 * ```
 * SensitiveByteArray.wrap(pan).use { sensitiveData ->
 *     // Process data
 * }  // Automatically cleared
 * ```
 */
class SensitiveByteArray private constructor(
    private var data: ByteArray?
) : Clearable, Closeable {

    private val cleared = AtomicBoolean(false)

    /**
     * Get the underlying data
     * @throws IllegalStateException if already cleared
     */
    fun get(): ByteArray {
        check(!cleared.get()) { "SensitiveByteArray has been cleared" }
        return data ?: throw IllegalStateException("Data is null")
    }

    /**
     * Get data size without exposing the data
     */
    val size: Int
        get() = data?.size ?: 0

    /**
     * Check if data is empty
     */
    fun isEmpty(): Boolean = data?.isEmpty() ?: true

    /**
     * Constant-time comparison with another byte array
     */
    fun equalsConstantTime(other: ByteArray?): Boolean {
        return SecureMemory.constantTimeEquals(data, other)
    }

    /**
     * Constant-time comparison with another SensitiveByteArray
     */
    fun equalsConstantTime(other: SensitiveByteArray?): Boolean {
        return SecureMemory.constantTimeEquals(data, other?.data)
    }

    /**
     * Create a copy - caller is responsible for clearing the copy
     */
    fun copy(): SensitiveByteArray {
        check(!cleared.get()) { "Cannot copy cleared data" }
        return wrap(SecureMemory.secureCopy(data!!))
    }

    override fun clear() {
        if (cleared.compareAndSet(false, true)) {
            SecureMemory.clear(data)
            data = null
        }
    }

    override fun isCleared(): Boolean = cleared.get()

    override fun close() {
        clear()
    }

    /**
     * Execute a block with the data and automatically clear afterwards
     */
    inline fun <R> use(block: (ByteArray) -> R): R {
        try {
            return block(get())
        } finally {
            clear()
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SensitiveByteArray) return false
        return equalsConstantTime(other)
    }

    override fun hashCode(): Int {
        // Don't expose data in hashcode
        return System.identityHashCode(this)
    }

    override fun toString(): String {
        // Never expose sensitive data in toString
        return "SensitiveByteArray[size=${size}, cleared=${isCleared()}]"
    }

    protected fun finalize() {
        // Safety net - clear if not already cleared
        clear()
    }

    companion object {
        /**
         * Wrap existing byte array - the original will be cleared
         */
        fun wrap(data: ByteArray): SensitiveByteArray {
            val copy = SecureMemory.secureCopy(data)
            SecureMemory.clear(data)
            return SensitiveByteArray(copy)
        }

        /**
         * Wrap without clearing original (when original ownership is transferred)
         */
        fun wrapNoClear(data: ByteArray): SensitiveByteArray {
            return SensitiveByteArray(data)
        }

        /**
         * Create from hex string
         */
        fun fromHex(hex: String): SensitiveByteArray {
            val data = ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
            return SensitiveByteArray(data)
        }

        /**
         * Create empty instance of specified size
         */
        fun allocate(size: Int): SensitiveByteArray {
            return SensitiveByteArray(ByteArray(size))
        }
    }
}

/**
 * Wrapper for sensitive char array (PIN entry)
 */
class SensitiveCharArray private constructor(
    private var data: CharArray?
) : Clearable, Closeable {

    private val cleared = AtomicBoolean(false)

    fun get(): CharArray {
        check(!cleared.get()) { "SensitiveCharArray has been cleared" }
        return data ?: throw IllegalStateException("Data is null")
    }

    val size: Int
        get() = data?.size ?: 0

    override fun clear() {
        if (cleared.compareAndSet(false, true)) {
            SecureMemory.clear(data)
            data = null
        }
    }

    override fun isCleared(): Boolean = cleared.get()

    override fun close() {
        clear()
    }

    inline fun <R> use(block: (CharArray) -> R): R {
        try {
            return block(get())
        } finally {
            clear()
        }
    }

    override fun toString(): String {
        return "SensitiveCharArray[size=${size}, cleared=${isCleared()}]"
    }

    protected fun finalize() {
        clear()
    }

    companion object {
        fun wrap(data: CharArray): SensitiveCharArray {
            val copy = data.copyOf()
            SecureMemory.clear(data)
            return SensitiveCharArray(copy)
        }

        fun wrapNoClear(data: CharArray): SensitiveCharArray {
            return SensitiveCharArray(data)
        }
    }
}

/**
 * Scope for managing multiple sensitive data items
 *
 * All registered items are cleared when the scope closes:
 * ```
 * SensitiveDataScope().use { scope ->
 *     val pan = scope.register(SensitiveByteArray.wrap(panData))
 *     val track2 = scope.register(SensitiveByteArray.wrap(track2Data))
 *     // Process data
 * }  // All registered items cleared
 * ```
 */
class SensitiveDataScope : Closeable {

    private val items = mutableListOf<Clearable>()
    private val closed = AtomicBoolean(false)

    /**
     * Register a clearable item to be cleared when scope closes
     */
    fun <T : Clearable> register(item: T): T {
        check(!closed.get()) { "Scope is closed" }
        items.add(item)
        return item
    }

    /**
     * Register a byte array for clearing
     */
    fun registerByteArray(data: ByteArray): SensitiveByteArray {
        return register(SensitiveByteArray.wrap(data))
    }

    /**
     * Clear all registered items and close the scope
     */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            items.forEach { it.clear() }
            items.clear()
        }
    }

    /**
     * Execute a block within this scope
     */
    inline fun <R> use(block: (SensitiveDataScope) -> R): R {
        try {
            return block(this)
        } finally {
            close()
        }
    }
}

/**
 * Sensitive PAN (Primary Account Number) holder
 *
 * Provides masking and format operations without exposing full PAN
 */
class SensitivePan private constructor(
    private val data: SensitiveByteArray
) : Clearable {

    /**
     * Get masked PAN for display (first 6 + last 4 visible)
     */
    fun getMasked(): String {
        if (data.isCleared()) return "****"

        val pan = data.get().toString(Charsets.UTF_8)
        return if (pan.length >= 13) {
            "${pan.take(6)}${"*".repeat(pan.length - 10)}${pan.takeLast(4)}"
        } else {
            "*".repeat(pan.length)
        }
    }

    /**
     * Get last 4 digits for receipt
     */
    fun getLast4(): String {
        if (data.isCleared()) return "****"

        val pan = data.get().toString(Charsets.UTF_8)
        return if (pan.length >= 4) pan.takeLast(4) else pan
    }

    /**
     * Get first 6 digits (BIN) for routing
     */
    fun getBin(): String {
        if (data.isCleared()) return "000000"

        val pan = data.get().toString(Charsets.UTF_8)
        return if (pan.length >= 6) pan.take(6) else pan.padStart(6, '0')
    }

    /**
     * Get full PAN bytes for cryptographic operations
     * WARNING: Only use when absolutely necessary
     */
    fun getBytes(): ByteArray = data.get()

    override fun clear() = data.clear()

    override fun isCleared() = data.isCleared()

    override fun toString() = "SensitivePan[${getMasked()}]"

    companion object {
        fun fromBytes(pan: ByteArray): SensitivePan {
            return SensitivePan(SensitiveByteArray.wrap(pan))
        }

        fun fromString(pan: String): SensitivePan {
            val bytes = pan.toByteArray(Charsets.UTF_8)
            return SensitivePan(SensitiveByteArray.wrapNoClear(bytes))
        }
    }
}

/**
 * Sensitive PIN block holder
 */
class SensitivePinBlock private constructor(
    private val data: SensitiveByteArray
) : Clearable {

    fun getBytes(): ByteArray = data.get()

    override fun clear() = data.clear()

    override fun isCleared() = data.isCleared()

    override fun toString() = "SensitivePinBlock[size=${data.size}, cleared=${isCleared()}]"

    companion object {
        fun wrap(pinBlock: ByteArray): SensitivePinBlock {
            return SensitivePinBlock(SensitiveByteArray.wrap(pinBlock))
        }
    }
}

/**
 * Sensitive cryptogram holder
 */
class SensitiveCryptogram private constructor(
    private val data: SensitiveByteArray,
    val type: CryptogramType
) : Clearable {

    enum class CryptogramType {
        ARQC,  // Authorization Request Cryptogram
        TC,    // Transaction Certificate
        AAC    // Application Authentication Cryptogram
    }

    fun getBytes(): ByteArray = data.get()

    fun toHexString(): String {
        return data.get().joinToString("") { "%02X".format(it) }
    }

    override fun clear() = data.clear()

    override fun isCleared() = data.isCleared()

    override fun toString() = "SensitiveCryptogram[$type, size=${data.size}]"

    companion object {
        fun wrap(cryptogram: ByteArray, type: CryptogramType): SensitiveCryptogram {
            return SensitiveCryptogram(SensitiveByteArray.wrap(cryptogram), type)
        }
    }
}

/**
 * Sensitive Track 2 equivalent data holder
 */
class SensitiveTrack2 private constructor(
    private val data: SensitiveByteArray
) : Clearable {

    /**
     * Get masked track 2 for logging
     */
    fun getMasked(): String {
        if (data.isCleared()) return "****"

        val hex = data.get().joinToString("") { "%02X".format(it) }
        val separatorIndex = hex.indexOf('D')

        return if (separatorIndex > 6) {
            // Mask PAN portion
            "${hex.take(6)}${"*".repeat(separatorIndex - 10)}${hex.substring(separatorIndex - 4)}"
        } else {
            "*".repeat(hex.length)
        }
    }

    fun getBytes(): ByteArray = data.get()

    override fun clear() = data.clear()

    override fun isCleared() = data.isCleared()

    override fun toString() = "SensitiveTrack2[${getMasked()}]"

    companion object {
        fun wrap(track2: ByteArray): SensitiveTrack2 {
            return SensitiveTrack2(SensitiveByteArray.wrap(track2))
        }
    }
}
