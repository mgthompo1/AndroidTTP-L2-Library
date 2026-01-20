package com.atlas.softpos

import com.atlas.softpos.kernel.amex.*
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for American Express ExpressPay Kernel
 */
class AmexKernelTest {

    // ==================== ECR CAPABILITIES TESTS ====================

    @Test
    fun `test default ECR capabilities`() {
        val ecr = EnhancedContactlessReaderCapabilities()

        // Default: 0xD8, 0xE0, 0x00, 0x00
        assertTrue(ecr.contactModeSupported)
        assertTrue(ecr.contactlessMsdSupported)
        assertTrue(ecr.contactlessEmvSupported)
        assertTrue(ecr.contactlessMobileDeviceSupported)
        assertTrue(ecr.consumerDeviceCvmSupported)
        assertTrue(ecr.mobileCvmSupported)
    }

    @Test
    fun `test ECR forSoftPos factory`() {
        val ecr = EnhancedContactlessReaderCapabilities.forSoftPos(
            contactlessEmv = true,
            contactlessMsd = true,
            mobileDevice = true,
            onlineRequired = true,
            cdcvm = true,
            mobileCvm = true
        )

        assertTrue(ecr.contactlessEmvSupported)
        assertTrue(ecr.contactlessMsdSupported)
        assertTrue(ecr.contactlessMobileDeviceSupported)
        assertTrue(ecr.onlineCryptogramRequired)
        assertTrue(ecr.consumerDeviceCvmSupported)
        assertTrue(ecr.mobileCvmSupported)

        // Contact mode not set by forSoftPos
        assertFalse(ecr.contactModeSupported)
    }

    @Test
    fun `test ECR with EMV only`() {
        val ecr = EnhancedContactlessReaderCapabilities.forSoftPos(
            contactlessEmv = true,
            contactlessMsd = false,
            mobileDevice = false,
            onlineRequired = true,
            cdcvm = false,
            mobileCvm = false
        )

        assertTrue(ecr.contactlessEmvSupported)
        assertFalse(ecr.contactlessMsdSupported)
        assertFalse(ecr.contactlessMobileDeviceSupported)
        assertFalse(ecr.consumerDeviceCvmSupported)
    }

    @Test
    fun `test ECR equality`() {
        val ecr1 = EnhancedContactlessReaderCapabilities.forSoftPos()
        val ecr2 = EnhancedContactlessReaderCapabilities.forSoftPos()

        assertEquals(ecr1, ecr2)
        assertEquals(ecr1.hashCode(), ecr2.hashCode())
    }

    // ==================== AIP TESTS ====================

    @Test
    fun `test AIP with SDA support`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x40, 0x00))

        assertTrue(aip.sdaSupported)
        assertFalse(aip.ddaSupported)
        assertFalse(aip.cdaSupported)
        assertEquals(OdaMethod.SDA, aip.getPreferredOdaMethod())
    }

    @Test
    fun `test AIP with DDA support`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x20, 0x00))

        assertFalse(aip.sdaSupported)
        assertTrue(aip.ddaSupported)
        assertFalse(aip.cdaSupported)
        assertEquals(OdaMethod.DDA, aip.getPreferredOdaMethod())
    }

    @Test
    fun `test AIP with CDA support`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x01, 0x00))

        assertFalse(aip.sdaSupported)
        assertFalse(aip.ddaSupported)
        assertTrue(aip.cdaSupported)
        assertEquals(OdaMethod.CDA, aip.getPreferredOdaMethod())
    }

    @Test
    fun `test AIP CDA preferred over DDA`() {
        // Both CDA and DDA supported - CDA should be preferred
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x21, 0x00))

        assertTrue(aip.ddaSupported)
        assertTrue(aip.cdaSupported)
        assertEquals(OdaMethod.CDA, aip.getPreferredOdaMethod())
    }

    @Test
    fun `test AIP with mag stripe mode`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x00, 0x80.toByte()))

        assertTrue(aip.magStripeModeSupported)
    }

    @Test
    fun `test AIP with EMV mode`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x10, 0x00))

        assertTrue(aip.emvModeSupported)
    }

    @Test
    fun `test AIP with terminal risk management`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x08, 0x00))

        assertTrue(aip.terminalRiskManagementRequired)
    }

    @Test
    fun `test AIP supportsOda`() {
        // No ODA support
        var aip = AmexApplicationInterchangeProfile(byteArrayOf(0x00, 0x00))
        assertFalse(aip.supportsOda())

        // SDA support
        aip = AmexApplicationInterchangeProfile(byteArrayOf(0x40, 0x00))
        assertTrue(aip.supportsOda())
    }

    @Test
    fun `test AIP toHexString`() {
        val aip = AmexApplicationInterchangeProfile(byteArrayOf(0x19, 0x80.toByte()))

        assertEquals("1980", aip.toHexString())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test AIP requires minimum 2 bytes`() {
        AmexApplicationInterchangeProfile(byteArrayOf(0x00))
    }

    // ==================== CTQ TESTS ====================

    @Test
    fun `test CTQ online cryptogram required`() {
        val ctq = AmexCardTransactionQualifiers(byteArrayOf(0x80.toByte(), 0x00))

        assertTrue(ctq.onlineCryptogramRequired)
        assertFalse(ctq.cvmRequired)
        assertFalse(ctq.signatureRequired)
    }

    @Test
    fun `test CTQ CVM required`() {
        val ctq = AmexCardTransactionQualifiers(byteArrayOf(0x40, 0x00))

        assertFalse(ctq.onlineCryptogramRequired)
        assertTrue(ctq.cvmRequired)
    }

    @Test
    fun `test CTQ signature required`() {
        val ctq = AmexCardTransactionQualifiers(byteArrayOf(0x10, 0x00))

        assertTrue(ctq.signatureRequired)
    }

    @Test
    fun `test CTQ CDCVM performed`() {
        val ctq = AmexCardTransactionQualifiers(byteArrayOf(0x00, 0x80.toByte()))

        assertTrue(ctq.cdcvmPerformed)
    }

    @Test
    fun `test CTQ card supports CDCVM`() {
        val ctq = AmexCardTransactionQualifiers(byteArrayOf(0x00, 0x40))

        assertTrue(ctq.cardSupportsCdcvm)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test CTQ requires minimum 2 bytes`() {
        AmexCardTransactionQualifiers(byteArrayOf(0x00))
    }

    // ==================== IAD TESTS ====================

    @Test
    fun `test IAD parsing`() {
        val iadBytes = byteArrayOf(
            0x01, 0x02,             // DKI
            0x03, 0x04,             // CVN
            0x05, 0x06, 0x07, 0x08, // CVR
            0x09, 0x0A              // Discretionary
        )
        val iad = AmexIssuerApplicationData(iadBytes)

        assertArrayEquals(byteArrayOf(0x01, 0x02), iad.derivationKeyIndex)
        assertArrayEquals(byteArrayOf(0x03, 0x04), iad.cryptogramVersionNumber)
        assertArrayEquals(byteArrayOf(0x05, 0x06, 0x07, 0x08), iad.cardVerificationResults)
        assertArrayEquals(byteArrayOf(0x09, 0x0A), iad.discretionaryData)
    }

    @Test
    fun `test IAD with minimal data`() {
        val iad = AmexIssuerApplicationData(byteArrayOf(0x01))

        assertTrue(iad.derivationKeyIndex.isEmpty())
        assertTrue(iad.cardVerificationResults.isEmpty())
    }

    @Test
    fun `test IAD toHexString`() {
        val iad = AmexIssuerApplicationData(byteArrayOf(0x0A, 0x0B, 0x0C))

        assertEquals("0A0B0C", iad.toHexString())
    }

    // ==================== CVR TESTS ====================

    @Test
    fun `test CVR cryptogram type AAC`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x00, 0x00, 0x00, 0x00))

        assertEquals(AmexCardVerificationResults.CryptogramType.AAC, cvr.cryptogramType)
    }

    @Test
    fun `test CVR cryptogram type TC`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x10, 0x00, 0x00, 0x00))

        assertEquals(AmexCardVerificationResults.CryptogramType.TC, cvr.cryptogramType)
    }

    @Test
    fun `test CVR cryptogram type ARQC`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x20, 0x00, 0x00, 0x00))

        assertEquals(AmexCardVerificationResults.CryptogramType.ARQC, cvr.cryptogramType)
    }

    @Test
    fun `test CVR offline data auth performed`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x02, 0x00, 0x00, 0x00))

        assertTrue(cvr.offlineDataAuthPerformed)
    }

    @Test
    fun `test CVR issuer auth performed`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x01, 0x00, 0x00, 0x00))

        assertTrue(cvr.issuerAuthPerformed)
    }

    @Test
    fun `test CVR offline PIN passed`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x00, 0x08, 0x00, 0x00))

        assertTrue(cvr.offlinePinPassed)
    }

    @Test
    fun `test CVR PIN try limit exceeded`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x00, 0x04, 0x00, 0x00))

        assertTrue(cvr.pinTryLimitExceeded)
    }

    @Test
    fun `test CVR last online not completed`() {
        val cvr = AmexCardVerificationResults(byteArrayOf(0x00, 0x02, 0x00, 0x00))

        assertTrue(cvr.lastOnlineNotCompleted)
    }

    @Test
    fun `test CVR limits exceeded`() {
        var cvr = AmexCardVerificationResults(byteArrayOf(0x00, 0x01, 0x00, 0x00))
        assertTrue(cvr.lowerOfflineLimitExceeded)

        cvr = AmexCardVerificationResults(byteArrayOf(0x00, 0x00, 0x80.toByte(), 0x00))
        assertTrue(cvr.upperOfflineLimitExceeded)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `test CVR requires minimum 4 bytes`() {
        AmexCardVerificationResults(byteArrayOf(0x00, 0x00, 0x00))
    }

    // ==================== TRACK 2 PARSER TESTS ====================

    @Test
    fun `test Track2 parsing standard card`() {
        // Format: PAN D YYMM ServiceCode DiscretionaryData F
        val track2Hex = "374111111111111D25011011234567890F"
        val track2Bytes = hexToBytes(track2Hex)

        val track2 = AmexTrack2Parser.parse(track2Bytes)

        assertNotNull(track2)
        assertEquals("374111111111111", track2!!.pan)
        assertEquals("2501", track2.expiryDate)
        assertEquals("101", track2.serviceCode)
        assertEquals("1234567890", track2.discretionaryData)
    }

    @Test
    fun `test Track2 masked PAN`() {
        val track2Hex = "374111111111111D25011011234567890F"
        val track2 = AmexTrack2Parser.parse(hexToBytes(track2Hex))

        assertNotNull(track2)
        val masked = track2!!.maskedPan
        assertTrue(masked.startsWith("374111"))
        assertTrue(masked.endsWith("1111"))
        assertTrue(masked.contains("*"))
    }

    @Test
    fun `test Track2 expiry formatted`() {
        val track2Hex = "374111111111111D25121011234567890F"
        val track2 = AmexTrack2Parser.parse(hexToBytes(track2Hex))

        assertNotNull(track2)
        assertEquals("12/25", track2!!.expiryFormatted)
    }

    @Test
    fun `test Track2 parsing without separator returns null`() {
        val track2Hex = "374111111111111F"
        val track2 = AmexTrack2Parser.parse(hexToBytes(track2Hex))

        assertNull(track2)
    }

    @Test
    fun `test Track2 parsing short data returns null`() {
        val track2Hex = "374111D250F"
        val track2 = AmexTrack2Parser.parse(hexToBytes(track2Hex))

        assertNull(track2)
    }

    // ==================== AMEX AIDS TESTS ====================

    @Test
    fun `test isAmexAid with valid ExpressPay AID`() {
        val aid = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x00, 0x25, 0x01
        )

        assertTrue(AmexAids.isAmexAid(aid))
    }

    @Test
    fun `test isAmexAid with US Debit AID`() {
        val aid = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x00, 0x25, 0x01, 0x07, 0x01
        )

        assertTrue(AmexAids.isAmexAid(aid))
    }

    @Test
    fun `test isAmexAid with Visa AID returns false`() {
        val aid = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x00, 0x03, 0x10, 0x10
        )

        assertFalse(AmexAids.isAmexAid(aid))
    }

    @Test
    fun `test isAmexAid with Mastercard AID returns false`() {
        val aid = byteArrayOf(
            0xA0.toByte(), 0x00, 0x00, 0x00, 0x04, 0x10, 0x10
        )

        assertFalse(AmexAids.isAmexAid(aid))
    }

    @Test
    fun `test isAmexAid with short AID returns false`() {
        val aid = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00)

        assertFalse(AmexAids.isAmexAid(aid))
    }

    // ==================== AMEX TAGS TESTS ====================

    @Test
    fun `test AmEx tag constants`() {
        assertEquals("9F06", AmexTags.AID)
        assertEquals("9F6E", AmexTags.ENHANCED_CONTACTLESS_READER_CAPABILITIES)
        assertEquals("9F6C", AmexTags.CARD_TRANSACTION_QUALIFIERS)
        assertEquals("9F26", AmexTags.APPLICATION_CRYPTOGRAM)
        assertEquals("9F27", AmexTags.CRYPTOGRAM_INFO_DATA)
        assertEquals("9F10", AmexTags.ISSUER_APPLICATION_DATA)
        assertEquals("9F36", AmexTags.ATC)
        assertEquals("95", AmexTags.TVR)
        assertEquals("9F37", AmexTags.UNPREDICTABLE_NUMBER)
    }

    // ==================== HELPER METHODS ====================

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in result.indices) {
            result[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }
}
