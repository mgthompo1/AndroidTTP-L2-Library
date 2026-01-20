package com.atlas.softpos

import com.atlas.softpos.kernel.common.TerminalVerificationResults
import com.atlas.softpos.kernel.common.TransactionStatusInformation
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for Terminal Verification Results (TVR) and
 * Transaction Status Information (TSI)
 *
 * Tests bit manipulation per EMV Book 3, Annex C3
 */
class TvrTsiTest {

    private lateinit var tvr: TerminalVerificationResults

    @Before
    fun setup() {
        tvr = TerminalVerificationResults()
    }

    // ==================== TVR BYTE 1 TESTS ====================

    @Test
    fun `TVR byte 1 - ODA not performed flag`() {
        assertFalse(tvr.odaNotPerformed)

        tvr.odaNotPerformed = true
        assertTrue(tvr.odaNotPerformed)

        val bytes = tvr.toBytes()
        assertEquals(0x80.toByte(), (bytes[0].toInt() and 0x80).toByte())
    }

    @Test
    fun `TVR byte 1 - SDA failed flag`() {
        assertFalse(tvr.sdaFailed)

        tvr.sdaFailed = true
        assertTrue(tvr.sdaFailed)

        val bytes = tvr.toBytes()
        assertEquals(0x40.toByte(), (bytes[0].toInt() and 0x40).toByte())
    }

    @Test
    fun `TVR byte 1 - ICC data missing flag`() {
        assertFalse(tvr.iccDataMissing)

        tvr.iccDataMissing = true
        assertTrue(tvr.iccDataMissing)

        val bytes = tvr.toBytes()
        assertEquals(0x20.toByte(), (bytes[0].toInt() and 0x20).toByte())
    }

    @Test
    fun `TVR byte 1 - Card on exception file flag`() {
        assertFalse(tvr.cardOnExceptionFile)

        tvr.cardOnExceptionFile = true
        assertTrue(tvr.cardOnExceptionFile)

        val bytes = tvr.toBytes()
        assertEquals(0x10.toByte(), (bytes[0].toInt() and 0x10).toByte())
    }

    @Test
    fun `TVR byte 1 - DDA failed flag`() {
        assertFalse(tvr.ddaFailed)

        tvr.ddaFailed = true
        assertTrue(tvr.ddaFailed)

        val bytes = tvr.toBytes()
        assertEquals(0x08.toByte(), (bytes[0].toInt() and 0x08).toByte())
    }

    @Test
    fun `TVR byte 1 - CDA failed flag`() {
        assertFalse(tvr.cdaFailed)

        tvr.cdaFailed = true
        assertTrue(tvr.cdaFailed)

        val bytes = tvr.toBytes()
        assertEquals(0x04.toByte(), (bytes[0].toInt() and 0x04).toByte())
    }

    // ==================== TVR BYTE 2 TESTS ====================

    @Test
    fun `TVR byte 2 - Application versions differ flag`() {
        assertFalse(tvr.appVersionsDiffer)

        tvr.appVersionsDiffer = true
        assertTrue(tvr.appVersionsDiffer)

        val bytes = tvr.toBytes()
        assertEquals(0x80.toByte(), (bytes[1].toInt() and 0x80).toByte())
    }

    @Test
    fun `TVR byte 2 - Expired application flag`() {
        assertFalse(tvr.expiredApplication)

        tvr.expiredApplication = true
        assertTrue(tvr.expiredApplication)

        val bytes = tvr.toBytes()
        assertEquals(0x40.toByte(), (bytes[1].toInt() and 0x40).toByte())
    }

    @Test
    fun `TVR byte 2 - Application not yet effective flag`() {
        assertFalse(tvr.applicationNotYetEffective)

        tvr.applicationNotYetEffective = true
        assertTrue(tvr.applicationNotYetEffective)

        val bytes = tvr.toBytes()
        assertEquals(0x20.toByte(), (bytes[1].toInt() and 0x20).toByte())
    }

    @Test
    fun `TVR byte 2 - Service not allowed flag`() {
        assertFalse(tvr.serviceNotAllowed)

        tvr.serviceNotAllowed = true
        assertTrue(tvr.serviceNotAllowed)

        val bytes = tvr.toBytes()
        assertEquals(0x10.toByte(), (bytes[1].toInt() and 0x10).toByte())
    }

    // ==================== TVR BYTE 3 TESTS ====================

    @Test
    fun `TVR byte 3 - CVM not successful flag`() {
        assertFalse(tvr.cvmNotSuccessful)

        tvr.cvmNotSuccessful = true
        assertTrue(tvr.cvmNotSuccessful)

        val bytes = tvr.toBytes()
        assertEquals(0x80.toByte(), (bytes[2].toInt() and 0x80).toByte())
    }

    @Test
    fun `TVR byte 3 - Unrecognized CVM flag`() {
        assertFalse(tvr.unrecognisedCvm)

        tvr.unrecognisedCvm = true
        assertTrue(tvr.unrecognisedCvm)

        val bytes = tvr.toBytes()
        assertEquals(0x40.toByte(), (bytes[2].toInt() and 0x40).toByte())
    }

    @Test
    fun `TVR byte 3 - PIN try limit exceeded flag`() {
        assertFalse(tvr.pinTryLimitExceeded)

        tvr.pinTryLimitExceeded = true
        assertTrue(tvr.pinTryLimitExceeded)

        val bytes = tvr.toBytes()
        assertEquals(0x20.toByte(), (bytes[2].toInt() and 0x20).toByte())
    }

    @Test
    fun `TVR byte 3 - Online PIN entered flag`() {
        assertFalse(tvr.onlinePinEntered)

        tvr.onlinePinEntered = true
        assertTrue(tvr.onlinePinEntered)

        val bytes = tvr.toBytes()
        assertEquals(0x04.toByte(), (bytes[2].toInt() and 0x04).toByte())
    }

    // ==================== TVR BYTE 4 TESTS ====================

    @Test
    fun `TVR byte 4 - Floor limit exceeded flag`() {
        assertFalse(tvr.floorLimitExceeded)

        tvr.floorLimitExceeded = true
        assertTrue(tvr.floorLimitExceeded)

        val bytes = tvr.toBytes()
        assertEquals(0x80.toByte(), (bytes[3].toInt() and 0x80).toByte())
    }

    @Test
    fun `TVR byte 4 - LCOL exceeded flag`() {
        assertFalse(tvr.lcolExceeded)

        tvr.lcolExceeded = true
        assertTrue(tvr.lcolExceeded)

        val bytes = tvr.toBytes()
        assertEquals(0x40.toByte(), (bytes[3].toInt() and 0x40).toByte())
    }

    @Test
    fun `TVR byte 4 - UCOL exceeded flag`() {
        assertFalse(tvr.ucolExceeded)

        tvr.ucolExceeded = true
        assertTrue(tvr.ucolExceeded)

        val bytes = tvr.toBytes()
        assertEquals(0x20.toByte(), (bytes[3].toInt() and 0x20).toByte())
    }

    @Test
    fun `TVR byte 4 - Randomly selected online flag`() {
        assertFalse(tvr.randomlySelectedOnline)

        tvr.randomlySelectedOnline = true
        assertTrue(tvr.randomlySelectedOnline)

        val bytes = tvr.toBytes()
        assertEquals(0x10.toByte(), (bytes[3].toInt() and 0x10).toByte())
    }

    @Test
    fun `TVR byte 4 - Merchant forced online flag`() {
        assertFalse(tvr.merchantForcedOnline)

        tvr.merchantForcedOnline = true
        assertTrue(tvr.merchantForcedOnline)

        val bytes = tvr.toBytes()
        assertEquals(0x08.toByte(), (bytes[3].toInt() and 0x08).toByte())
    }

    // ==================== TVR BYTE 5 TESTS ====================

    @Test
    fun `TVR byte 5 - Default TDOL used flag`() {
        assertFalse(tvr.defaultTdolUsed)

        tvr.defaultTdolUsed = true
        assertTrue(tvr.defaultTdolUsed)

        val bytes = tvr.toBytes()
        assertEquals(0x80.toByte(), (bytes[4].toInt() and 0x80).toByte())
    }

    @Test
    fun `TVR byte 5 - Issuer auth failed flag`() {
        assertFalse(tvr.issuerAuthFailed)

        tvr.issuerAuthFailed = true
        assertTrue(tvr.issuerAuthFailed)

        val bytes = tvr.toBytes()
        assertEquals(0x40.toByte(), (bytes[4].toInt() and 0x40).toByte())
    }

    @Test
    fun `TVR byte 5 - Script failed before AC flag`() {
        assertFalse(tvr.scriptFailedBeforeAc)

        tvr.scriptFailedBeforeAc = true
        assertTrue(tvr.scriptFailedBeforeAc)

        val bytes = tvr.toBytes()
        assertEquals(0x20.toByte(), (bytes[4].toInt() and 0x20).toByte())
    }

    @Test
    fun `TVR byte 5 - Script failed after AC flag`() {
        assertFalse(tvr.scriptFailedAfterAc)

        tvr.scriptFailedAfterAc = true
        assertTrue(tvr.scriptFailedAfterAc)

        val bytes = tvr.toBytes()
        assertEquals(0x10.toByte(), (bytes[4].toInt() and 0x10).toByte())
    }

    // ==================== UTILITY METHOD TESTS ====================

    @Test
    fun `TVR toBytes returns 5 byte array`() {
        val bytes = tvr.toBytes()
        assertEquals(5, bytes.size)
    }

    @Test
    fun `TVR reset clears all flags`() {
        tvr.sdaFailed = true
        tvr.expiredApplication = true
        tvr.floorLimitExceeded = true

        tvr.reset()

        assertFalse(tvr.sdaFailed)
        assertFalse(tvr.expiredApplication)
        assertFalse(tvr.floorLimitExceeded)

        val bytes = tvr.toBytes()
        assertTrue(bytes.all { it == 0x00.toByte() })
    }

    @Test
    fun `TVR fromBytes restores state`() {
        val sourceBytes = byteArrayOf(
            0x80.toByte(),  // ODA not performed
            0x40.toByte(),  // Expired
            0x00,
            0x80.toByte(),  // Floor limit exceeded
            0x00
        )

        tvr.fromBytes(sourceBytes)

        assertTrue(tvr.odaNotPerformed)
        assertTrue(tvr.expiredApplication)
        assertTrue(tvr.floorLimitExceeded)
    }

    @Test
    fun `TVR hasOdaFailure detects failures`() {
        assertFalse(tvr.hasOdaFailure())

        tvr.sdaFailed = true
        assertTrue(tvr.hasOdaFailure())

        tvr.sdaFailed = false
        tvr.ddaFailed = true
        assertTrue(tvr.hasOdaFailure())

        tvr.ddaFailed = false
        tvr.cdaFailed = true
        assertTrue(tvr.hasOdaFailure())
    }

    @Test
    fun `TVR hasCvmFailure detects failures`() {
        assertFalse(tvr.hasCvmFailure())

        tvr.cvmNotSuccessful = true
        assertTrue(tvr.hasCvmFailure())

        tvr.cvmNotSuccessful = false
        tvr.pinTryLimitExceeded = true
        assertTrue(tvr.hasCvmFailure())
    }

    @Test
    fun `TVR requiresOnline detects online requirement`() {
        assertFalse(tvr.requiresOnline())

        tvr.floorLimitExceeded = true
        assertTrue(tvr.requiresOnline())

        tvr.floorLimitExceeded = false
        tvr.randomlySelectedOnline = true
        assertTrue(tvr.requiresOnline())
    }

    @Test
    fun `TVR matchesActionCode works correctly`() {
        tvr.expiredApplication = true  // Byte 2, bit 6

        val actionCodeMatch = byteArrayOf(0x00, 0x40, 0x00, 0x00, 0x00)  // Matches expired
        val actionCodeNoMatch = byteArrayOf(0x00, 0x00, 0x80.toByte(), 0x00, 0x00)  // Different bit

        assertTrue(tvr.matchesActionCode(actionCodeMatch))
        assertFalse(tvr.matchesActionCode(actionCodeNoMatch))
    }

    @Test
    fun `TVR toString provides readable output`() {
        tvr.odaNotPerformed = true
        tvr.expiredApplication = true
        tvr.floorLimitExceeded = true

        val string = tvr.toString()

        assertTrue(string.contains("ODA_NOT_PERFORMED"))
        assertTrue(string.contains("EXPIRED"))
        assertTrue(string.contains("FLOOR_LIMIT"))
    }

    // ==================== TSI TESTS ====================

    @Test
    fun `TSI byte 1 - ODA performed flag`() {
        val tsi = TransactionStatusInformation()

        assertFalse(tsi.odaPerformed)

        tsi.odaPerformed = true
        assertTrue(tsi.odaPerformed)

        val bytes = tsi.toBytes()
        assertEquals(0x80.toByte(), (bytes[0].toInt() and 0x80).toByte())
    }

    @Test
    fun `TSI byte 1 - CVM performed flag`() {
        val tsi = TransactionStatusInformation()

        assertFalse(tsi.cvmPerformed)

        tsi.cvmPerformed = true
        assertTrue(tsi.cvmPerformed)

        val bytes = tsi.toBytes()
        assertEquals(0x40.toByte(), (bytes[0].toInt() and 0x40).toByte())
    }

    @Test
    fun `TSI byte 1 - Card risk management performed flag`() {
        val tsi = TransactionStatusInformation()

        assertFalse(tsi.cardRiskManagementPerformed)

        tsi.cardRiskManagementPerformed = true
        assertTrue(tsi.cardRiskManagementPerformed)

        val bytes = tsi.toBytes()
        assertEquals(0x20.toByte(), (bytes[0].toInt() and 0x20).toByte())
    }

    @Test
    fun `TSI byte 1 - Issuer auth performed flag`() {
        val tsi = TransactionStatusInformation()

        assertFalse(tsi.issuerAuthPerformed)

        tsi.issuerAuthPerformed = true
        assertTrue(tsi.issuerAuthPerformed)

        val bytes = tsi.toBytes()
        assertEquals(0x10.toByte(), (bytes[0].toInt() and 0x10).toByte())
    }

    @Test
    fun `TSI byte 1 - Terminal risk management performed flag`() {
        val tsi = TransactionStatusInformation()

        assertFalse(tsi.terminalRiskManagementPerformed)

        tsi.terminalRiskManagementPerformed = true
        assertTrue(tsi.terminalRiskManagementPerformed)

        val bytes = tsi.toBytes()
        assertEquals(0x08.toByte(), (bytes[0].toInt() and 0x08).toByte())
    }

    @Test
    fun `TSI byte 1 - Script processing performed flag`() {
        val tsi = TransactionStatusInformation()

        assertFalse(tsi.scriptProcessingPerformed)

        tsi.scriptProcessingPerformed = true
        assertTrue(tsi.scriptProcessingPerformed)

        val bytes = tsi.toBytes()
        assertEquals(0x04.toByte(), (bytes[0].toInt() and 0x04).toByte())
    }

    @Test
    fun `TSI toBytes returns 2 byte array`() {
        val tsi = TransactionStatusInformation()
        val bytes = tsi.toBytes()
        assertEquals(2, bytes.size)
    }

    @Test
    fun `TSI reset clears all flags`() {
        val tsi = TransactionStatusInformation().apply {
            odaPerformed = true
            cvmPerformed = true
            terminalRiskManagementPerformed = true
        }

        tsi.reset()

        assertFalse(tsi.odaPerformed)
        assertFalse(tsi.cvmPerformed)
        assertFalse(tsi.terminalRiskManagementPerformed)

        val bytes = tsi.toBytes()
        assertTrue(bytes.all { it == 0x00.toByte() })
    }
}
