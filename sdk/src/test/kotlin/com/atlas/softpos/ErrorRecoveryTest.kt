package com.atlas.softpos

import android.nfc.TagLostException
import com.atlas.softpos.core.apdu.ResponseApdu
import com.atlas.softpos.recovery.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/**
 * Unit tests for Transaction Error Recovery
 */
class ErrorRecoveryTest {

    private lateinit var errorRecovery: TransactionErrorRecovery

    @Before
    fun setup() {
        errorRecovery = TransactionErrorRecovery()
    }

    // ==================== ERROR CLASSIFICATION TESTS ====================

    @Test
    fun `test TagLostException is classified as NFC_TAG_LOST`() {
        val error = errorRecovery.classifyError(TagLostException())

        assertEquals(ErrorCategory.NFC_TAG_LOST, error.category)
        assertTrue(error.isRetryable)
        assertTrue(error.canRetryManually)
        assertEquals(RecoveryAction.TAP_AGAIN, error.recoveryAction)
    }

    @Test
    fun `test IOException with tag lost message is classified as NFC_TAG_LOST`() {
        val error = errorRecovery.classifyError(IOException("Tag was lost"))

        assertEquals(ErrorCategory.NFC_TAG_LOST, error.category)
        assertTrue(error.isRetryable)
    }

    @Test
    fun `test IOException with transceive failed is classified as NFC_TRANSCEIVE_FAILED`() {
        val error = errorRecovery.classifyError(IOException("Transceive failed"))

        assertEquals(ErrorCategory.NFC_TRANSCEIVE_FAILED, error.category)
        assertTrue(error.isRetryable)
        assertEquals(RecoveryAction.TAP_AGAIN, error.recoveryAction)
    }

    @Test
    fun `test SocketTimeoutException is classified as NETWORK_TIMEOUT`() {
        val error = errorRecovery.classifyError(SocketTimeoutException("Connection timed out"))

        assertEquals(ErrorCategory.NETWORK_TIMEOUT, error.category)
        assertTrue(error.isRetryable)
        assertEquals(RecoveryAction.RETRY_NETWORK, error.recoveryAction)
    }

    @Test
    fun `test UnknownHostException is classified as NETWORK_UNREACHABLE`() {
        val error = errorRecovery.classifyError(UnknownHostException("Unable to resolve host"))

        assertEquals(ErrorCategory.NETWORK_UNREACHABLE, error.category)
        assertFalse(error.isRetryable)
        assertEquals(RecoveryAction.CHECK_NETWORK, error.recoveryAction)
    }

    @Test
    fun `test SSLException is classified as NETWORK_SSL_ERROR`() {
        val error = errorRecovery.classifyError(SSLException("Certificate error"))

        assertEquals(ErrorCategory.NETWORK_SSL_ERROR, error.category)
        assertFalse(error.isRetryable)
        assertFalse(error.canRetryManually)
        assertEquals(RecoveryAction.CONTACT_SUPPORT, error.recoveryAction)
    }

    @Test
    fun `test SecurityException is classified as SECURITY_ERROR`() {
        val error = errorRecovery.classifyError(SecurityException("Access denied"))

        assertEquals(ErrorCategory.SECURITY_ERROR, error.category)
        assertFalse(error.isRetryable)
        assertEquals(RecoveryAction.ABORT, error.recoveryAction)
    }

    @Test
    fun `test OutOfMemoryError is classified as SYSTEM_ERROR`() {
        val error = errorRecovery.classifyError(OutOfMemoryError("Heap exhausted"))

        assertEquals(ErrorCategory.SYSTEM_ERROR, error.category)
        assertFalse(error.isRetryable)
        assertEquals(RecoveryAction.RESTART_APP, error.recoveryAction)
    }

    @Test
    fun `test IllegalStateException is classified as PROCESSING_ERROR`() {
        val error = errorRecovery.classifyError(IllegalStateException("Invalid state"))

        assertEquals(ErrorCategory.PROCESSING_ERROR, error.category)
        assertFalse(error.isRetryable)
        assertTrue(error.canRetryManually)
        assertEquals(RecoveryAction.RESTART_TRANSACTION, error.recoveryAction)
    }

    @Test
    fun `test unknown exception is classified as UNKNOWN`() {
        val error = errorRecovery.classifyError(RuntimeException("Something went wrong"))

        assertEquals(ErrorCategory.UNKNOWN, error.category)
        assertFalse(error.isRetryable)
        assertTrue(error.canRetryManually)
    }

    // ==================== CARD RESPONSE HANDLING TESTS ====================

    @Test
    fun `test SW 9000 is Success`() {
        val response = createResponse(0x90, 0x00)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.Success)
    }

    @Test
    fun `test SW 62xx is SuccessWithWarning`() {
        val response = createResponse(0x62, 0x83)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.SuccessWithWarning)
    }

    @Test
    fun `test SW 6985 is Retry`() {
        val response = createResponse(0x69, 0x85)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.Retry)
    }

    @Test
    fun `test SW 6984 is TryAnotherInterface`() {
        val response = createResponse(0x69, 0x84)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.TryAnotherInterface)
    }

    @Test
    fun `test SW 6A81 is Fatal`() {
        val response = createResponse(0x6A, 0x81)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.Fatal)
        assertEquals("Function not supported", (result as CardResponseRecovery.Fatal).reason)
    }

    @Test
    fun `test SW 6A82 is Fatal - file not found`() {
        val response = createResponse(0x6A, 0x82)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.Fatal)
        assertEquals("File or application not found", (result as CardResponseRecovery.Fatal).reason)
    }

    @Test
    fun `test SW 6A83 is Fatal - record not found`() {
        val response = createResponse(0x6A, 0x83)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.Fatal)
    }

    @Test
    fun `test SW 61xx is GetMoreData`() {
        val response = createResponse(0x61, 0x10)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.GetMoreData)
        assertEquals(16, (result as CardResponseRecovery.GetMoreData).remaining)
    }

    @Test
    fun `test SW 6983 is Fatal - auth blocked`() {
        val response = createResponse(0x69, 0x83)
        val result = errorRecovery.handleCardResponse(response, "TEST")

        assertTrue(result is CardResponseRecovery.Fatal)
    }

    // ==================== RETRY WITH RECOVERY TESTS ====================

    @Test
    fun `test executeWithRecovery succeeds on first try`() = runBlocking {
        var callCount = 0

        val result = errorRecovery.executeWithRecovery("TEST") {
            callCount++
            "success"
        }

        assertTrue(result is RecoveryResult.Success)
        assertEquals("success", (result as RecoveryResult.Success).value)
        assertEquals(1, callCount)
    }

    @Test
    fun `test executeWithRecovery retries on retryable error`() = runBlocking {
        var callCount = 0

        val result = errorRecovery.executeWithRecovery(
            operation = "TEST",
            retryPolicy = RetryPolicy(maxRetries = 3, initialDelayMs = 10)
        ) {
            callCount++
            if (callCount < 3) {
                throw IOException("Transceive failed")
            }
            "success after retries"
        }

        assertTrue(result is RecoveryResult.Success)
        assertEquals(3, callCount)
    }

    @Test
    fun `test executeWithRecovery fails after max retries`() = runBlocking {
        var callCount = 0

        val result = errorRecovery.executeWithRecovery(
            operation = "TEST",
            retryPolicy = RetryPolicy(maxRetries = 2, initialDelayMs = 10)
        ) {
            callCount++
            throw IOException("Transceive failed")
        }

        assertTrue(result is RecoveryResult.Failed)
        assertEquals(3, callCount) // Initial + 2 retries
    }

    @Test
    fun `test executeWithRecovery does not retry non-retryable errors`() = runBlocking {
        var callCount = 0

        val result = errorRecovery.executeWithRecovery(
            operation = "TEST",
            retryPolicy = RetryPolicy(maxRetries = 3, initialDelayMs = 10)
        ) {
            callCount++
            throw SecurityException("Access denied")
        }

        assertTrue(result is RecoveryResult.Failed)
        assertEquals(1, callCount) // No retries
    }

    // ==================== RECOVERY SUGGESTION TESTS ====================

    @Test
    fun `test recovery suggestion for TAP_AGAIN`() {
        val error = ErrorInfo(
            category = ErrorCategory.NFC_TAG_LOST,
            message = "Tag lost",
            isRetryable = true,
            canRetryManually = true,
            userMessage = "Please tap again",
            recoveryAction = RecoveryAction.TAP_AGAIN
        )

        val suggestion = errorRecovery.getRecoverySuggestion(error)

        assertEquals("Tap Card Again", suggestion.title)
        assertTrue(suggestion.canAutoRetry)
        assertTrue(suggestion.steps.isNotEmpty())
    }

    @Test
    fun `test recovery suggestion for CHECK_NETWORK`() {
        val error = ErrorInfo(
            category = ErrorCategory.NETWORK_UNREACHABLE,
            message = "No network",
            isRetryable = false,
            canRetryManually = true,
            userMessage = "Check network",
            recoveryAction = RecoveryAction.CHECK_NETWORK
        )

        val suggestion = errorRecovery.getRecoverySuggestion(error)

        assertEquals("Check Network", suggestion.title)
        assertFalse(suggestion.canAutoRetry)
    }

    @Test
    fun `test recovery suggestion for CONTACT_SUPPORT`() {
        val error = ErrorInfo(
            category = ErrorCategory.NETWORK_SSL_ERROR,
            message = "SSL error",
            isRetryable = false,
            canRetryManually = false,
            userMessage = "Contact support",
            recoveryAction = RecoveryAction.CONTACT_SUPPORT
        )

        val suggestion = errorRecovery.getRecoverySuggestion(error)

        assertEquals("Contact Support", suggestion.title)
        assertFalse(suggestion.canAutoRetry)
    }

    // ==================== ERROR STATISTICS TESTS ====================

    @Test
    fun `test error statistics tracking`() = runBlocking {
        // Generate some errors
        repeat(5) {
            errorRecovery.executeWithRecovery(
                operation = "TEST",
                retryPolicy = RetryPolicy(maxRetries = 0, initialDelayMs = 1)
            ) {
                throw IOException("Test error")
            }
        }

        val stats = errorRecovery.getErrorStatistics()

        assertTrue(stats.totalErrors >= 5)
        assertTrue(stats.errorsLast24h >= 5)
    }

    @Test
    fun `test clear history`() = runBlocking {
        // Generate errors
        errorRecovery.executeWithRecovery(
            operation = "TEST",
            retryPolicy = RetryPolicy(maxRetries = 0, initialDelayMs = 1)
        ) {
            throw IOException("Test error")
        }

        errorRecovery.clearHistory()

        val stats = errorRecovery.getErrorStatistics()
        assertEquals(0, stats.totalErrors)
    }

    // ==================== HELPER METHODS ====================

    private fun createResponse(sw1: Int, sw2: Int): ResponseApdu {
        return ResponseApdu(
            data = byteArrayOf(),
            sw1 = sw1.toByte(),
            sw2 = sw2.toByte()
        )
    }
}
