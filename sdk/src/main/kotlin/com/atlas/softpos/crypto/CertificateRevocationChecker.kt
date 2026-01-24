package com.atlas.softpos.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

/**
 * Certificate Revocation Checker
 *
 * Validates that CA and Issuer certificates have not been revoked.
 * Supports both online CRL checking and local revocation lists.
 *
 * Per EMV Book 2:
 * - Terminals should check for revoked CA public keys
 * - Revoked issuer certificates should be rejected during ODA
 *
 * Reference: EMV Book 2, Section 5.3 - Certificate Revocation
 */
class CertificateRevocationChecker(
    private val config: RevocationConfig = RevocationConfig()
) {
    // Local cache of revocation entries
    private val revokedCaKeys = ConcurrentHashMap<String, RevocationEntry>()
    private val revokedIssuerCerts = ConcurrentHashMap<String, RevocationEntry>()

    // Last CRL update timestamps
    private var lastCrlUpdate: Long = 0

    init {
        // Load known revoked keys
        loadKnownRevocations()
    }

    /**
     * Check if a CA public key is revoked
     *
     * @param rid Registered Application Provider ID
     * @param caKeyIndex CA Public Key Index
     * @param checkOnline Whether to perform online CRL check
     * @return Revocation status
     */
    suspend fun checkCaKeyRevocation(
        rid: ByteArray,
        caKeyIndex: Byte,
        checkOnline: Boolean = config.enableOnlineCrl
    ): RevocationStatus {
        val keyId = buildCaKeyId(rid, caKeyIndex)

        // Check local cache first
        revokedCaKeys[keyId]?.let { entry ->
            Timber.w("CA key $keyId is locally marked as revoked: ${entry.reason}")
            return RevocationStatus.Revoked(entry.reason, entry.revocationDate)
        }

        // Online CRL check if enabled
        if (checkOnline && shouldUpdateCrl()) {
            try {
                updateCrlFromNetwork(rid)
            } catch (e: Exception) {
                Timber.w(e, "CRL update failed, using cached data")
            }

            // Re-check after update
            revokedCaKeys[keyId]?.let { entry ->
                return RevocationStatus.Revoked(entry.reason, entry.revocationDate)
            }
        }

        return RevocationStatus.Valid
    }

    /**
     * Check if an issuer certificate is revoked
     *
     * @param rid RID of the payment network
     * @param issuerIdentifier Issuer Identifier from certificate (typically BIN)
     * @param certificateSerialNumber Certificate serial number
     * @return Revocation status
     */
    suspend fun checkIssuerCertRevocation(
        rid: ByteArray,
        issuerIdentifier: ByteArray,
        certificateSerialNumber: ByteArray
    ): RevocationStatus {
        val certId = buildIssuerCertId(rid, issuerIdentifier, certificateSerialNumber)

        revokedIssuerCerts[certId]?.let { entry ->
            Timber.w("Issuer certificate $certId is revoked: ${entry.reason}")
            return RevocationStatus.Revoked(entry.reason, entry.revocationDate)
        }

        return RevocationStatus.Valid
    }

    /**
     * Add a revoked CA key to local list
     * Used for manual updates between CRL refreshes
     */
    fun addRevokedCaKey(
        rid: ByteArray,
        caKeyIndex: Byte,
        reason: String,
        revocationDate: String? = null
    ) {
        val keyId = buildCaKeyId(rid, caKeyIndex)
        revokedCaKeys[keyId] = RevocationEntry(
            identifier = keyId,
            reason = reason,
            revocationDate = revocationDate,
            addedAt = System.currentTimeMillis()
        )
        Timber.i("Added revoked CA key: $keyId")
    }

    /**
     * Add a revoked issuer certificate to local list
     */
    fun addRevokedIssuerCert(
        rid: ByteArray,
        issuerIdentifier: ByteArray,
        serialNumber: ByteArray,
        reason: String
    ) {
        val certId = buildIssuerCertId(rid, issuerIdentifier, serialNumber)
        revokedIssuerCerts[certId] = RevocationEntry(
            identifier = certId,
            reason = reason,
            revocationDate = null,
            addedAt = System.currentTimeMillis()
        )
        Timber.i("Added revoked issuer certificate: $certId")
    }

    /**
     * Clear all revocation entries (for testing)
     */
    fun clearRevocationList() {
        revokedCaKeys.clear()
        revokedIssuerCerts.clear()
        Timber.d("Revocation list cleared")
    }

    /**
     * Get revocation statistics
     */
    fun getStats(): RevocationStats {
        return RevocationStats(
            revokedCaKeyCount = revokedCaKeys.size,
            revokedIssuerCertCount = revokedIssuerCerts.size,
            lastCrlUpdate = lastCrlUpdate,
            onlineCrlEnabled = config.enableOnlineCrl
        )
    }

    // ==================== Private Methods ====================

    private fun buildCaKeyId(rid: ByteArray, index: Byte): String {
        return "${rid.toHexString()}:${"%02X".format(index)}"
    }

    private fun buildIssuerCertId(
        rid: ByteArray,
        issuerIdentifier: ByteArray,
        serialNumber: ByteArray
    ): String {
        return "${rid.toHexString()}:${issuerIdentifier.toHexString()}:${serialNumber.toHexString()}"
    }

    private fun shouldUpdateCrl(): Boolean {
        if (!config.enableOnlineCrl) return false
        val elapsed = System.currentTimeMillis() - lastCrlUpdate
        return elapsed > config.crlUpdateIntervalMs
    }

    private suspend fun updateCrlFromNetwork(rid: ByteArray) = withContext(Dispatchers.IO) {
        val crlUrl = getCrlUrlForRid(rid) ?: return@withContext

        try {
            Timber.d("Fetching CRL from $crlUrl")
            val connection = URL(crlUrl).openConnection() as HttpURLConnection
            connection.connectTimeout = config.connectionTimeoutMs
            connection.readTimeout = config.readTimeoutMs
            connection.requestMethod = "GET"

            if (connection.responseCode == 200) {
                val response = connection.inputStream.bufferedReader().readText()
                parseCrlResponse(rid, response)
                lastCrlUpdate = System.currentTimeMillis()
                Timber.d("CRL update successful")
            } else {
                Timber.w("CRL fetch failed: HTTP ${connection.responseCode}")
            }
        } catch (e: Exception) {
            Timber.e(e, "CRL network error")
            throw e
        }
    }

    private fun getCrlUrlForRid(rid: ByteArray): String? {
        val ridHex = rid.toHexString()
        return config.crlUrls[ridHex]
    }

    private fun parseCrlResponse(rid: ByteArray, response: String) {
        // Parse CRL format (simplified - real implementation would parse X.509 CRL)
        // Format: one revoked key per line as "INDEX:REASON:DATE"
        response.lines().forEach { line ->
            if (line.isBlank() || line.startsWith("#")) return@forEach

            val parts = line.split(":")
            if (parts.size >= 2) {
                try {
                    val index = parts[0].toInt(16).toByte()
                    val reason = parts[1]
                    val date = parts.getOrNull(2)
                    addRevokedCaKey(rid, index, reason, date)
                } catch (e: Exception) {
                    Timber.w("Invalid CRL entry: $line")
                }
            }
        }
    }

    private fun loadKnownRevocations() {
        // Load revocations from configuration
        // IMPORTANT: Do NOT hardcode revocations here as CA key indices like 0x01 are used
        // by both test AND production keys. Hardcoding could block legitimate production keys.
        //
        // Revocation lists should be:
        // 1. Loaded from configuration passed to RevocationConfig
        // 2. Updated via CRL from payment network bulletins
        // 3. Managed by terminal management system

        for ((keyId, entry) in config.initialRevocations) {
            val parts = keyId.split(":")
            if (parts.size == 2) {
                try {
                    val rid = parts[0].hexToByteArray()
                    val index = parts[1].toInt(16).toByte()
                    addRevokedCaKey(rid, index, entry.reason, entry.revocationDate)
                } catch (e: Exception) {
                    Timber.w("Invalid revocation entry: $keyId - ${e.message}")
                }
            }
        }

        if (revokedCaKeys.isNotEmpty()) {
            Timber.d("Loaded ${revokedCaKeys.size} known revoked CA keys from config")
        }
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02X".format(it) }

    private fun String.hexToByteArray(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}

/**
 * Configuration for revocation checking
 */
data class RevocationConfig(
    /** Enable online CRL fetching */
    val enableOnlineCrl: Boolean = true,

    /** CRL update interval in milliseconds (default: 24 hours) */
    val crlUpdateIntervalMs: Long = 24 * 60 * 60 * 1000,

    /** HTTP connection timeout */
    val connectionTimeoutMs: Int = 10_000,

    /** HTTP read timeout */
    val readTimeoutMs: Int = 30_000,

    /** CRL URLs by RID */
    val crlUrls: Map<String, String> = mapOf(
        // These are placeholder URLs - real URLs come from payment networks
        "A000000003" to "https://crl.visa.com/emv/ca-keys.crl",
        "A000000004" to "https://crl.mastercard.com/emv/ca-keys.crl",
        "A000000025" to "https://crl.americanexpress.com/emv/ca-keys.crl"
    ),

    /**
     * Initial revocations to load at startup.
     * Map key format: "RID:INDEX" (e.g., "A000000003:01")
     * These should come from your terminal management system or payment network bulletins.
     *
     * IMPORTANT: Do NOT hardcode test key revocations as index values like 0x01
     * are used by both test AND production keys.
     */
    val initialRevocations: Map<String, InitialRevocationEntry> = emptyMap()
)

/**
 * Entry for initial revocation configuration
 */
data class InitialRevocationEntry(
    val reason: String,
    val revocationDate: String? = null
)

/**
 * Revocation status result
 */
sealed class RevocationStatus {
    object Valid : RevocationStatus()
    data class Revoked(val reason: String, val revocationDate: String?) : RevocationStatus()
    data class Unknown(val reason: String) : RevocationStatus()
}

/**
 * Revocation list entry
 */
data class RevocationEntry(
    val identifier: String,
    val reason: String,
    val revocationDate: String?,
    val addedAt: Long
)

/**
 * Revocation checker statistics
 */
data class RevocationStats(
    val revokedCaKeyCount: Int,
    val revokedIssuerCertCount: Int,
    val lastCrlUpdate: Long,
    val onlineCrlEnabled: Boolean
)
