package com.atlas.softpos

import com.atlas.softpos.receipt.*
import org.junit.Assert.*
import org.junit.Test
import java.util.*

/**
 * Unit tests for Receipt Data Builder
 */
class ReceiptDataBuilderTest {

    @Test
    fun `test basic receipt creation`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST MERCHANT")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .build()

        assertNotNull(receipt)
        assertEquals("TEST MERCHANT", receipt[ReceiptField.MERCHANT_NAME])
        assertEquals("APPROVED", receipt[ReceiptField.APPROVAL_STATUS])
    }

    @Test
    fun `test amount formatting`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1234, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .build()

        assertEquals("$12.34", receipt[ReceiptField.AMOUNT])
    }

    @Test
    fun `test amount formatting with cents`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(99, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .build()

        assertEquals("$0.99", receipt[ReceiptField.AMOUNT])
    }

    @Test
    fun `test large amount formatting`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000000, "$")  // $10,000.00
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .build()

        assertEquals("$10000.00", receipt[ReceiptField.AMOUNT])
    }

    @Test
    fun `test PAN masking with full PAN`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")  // 16 digits
            .approvalStatus(true)
            .build()

        val maskedPan = receipt[ReceiptField.MASKED_PAN]
        assertNotNull(maskedPan)
        assertTrue(maskedPan!!.contains("****"))
        assertTrue(maskedPan.contains("4111 11"))  // First 6 visible
        assertTrue(maskedPan.contains("1111"))     // Last 4 visible
    }

    @Test
    fun `test PAN masking with already masked PAN`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("411111******1111")
            .approvalStatus(true)
            .build()

        val maskedPan = receipt[ReceiptField.MASKED_PAN]
        assertNotNull(maskedPan)
        // Should preserve existing masking
    }

    @Test
    fun `test card type detection from Visa AID`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .cardTypeFromAid("A0000000031010")
            .build()

        assertEquals("VISA", receipt[ReceiptField.CARD_TYPE])
    }

    @Test
    fun `test card type detection from Mastercard AID`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("5111111111111111")
            .approvalStatus(true)
            .cardTypeFromAid("A0000000041010")
            .build()

        assertEquals("MASTERCARD", receipt[ReceiptField.CARD_TYPE])
    }

    @Test
    fun `test card type detection from AmEx AID`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("371111111111111")
            .approvalStatus(true)
            .cardTypeFromAid("A00000002501")
            .build()

        assertEquals("AMERICAN EXPRESS", receipt[ReceiptField.CARD_TYPE])
    }

    @Test
    fun `test EMV data fields`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .aid("A0000000031010")
            .atc("001F")
            .tvr("0000000000")
            .cryptogramType(CryptogramType.ARQC)
            .build()

        assertEquals("A0000000031010", receipt[ReceiptField.AID])
        assertEquals("001F", receipt[ReceiptField.ATC])
        assertEquals("0000000000", receipt[ReceiptField.TVR])
        assertEquals("ARQC (ONLINE)", receipt[ReceiptField.CRYPTOGRAM_TYPE])
    }

    @Test
    fun `test CVM method parsing from results`() {
        // Online PIN
        var receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .cvmResults("020002")
            .build()
        assertEquals("ONLINE PIN", receipt[ReceiptField.CVM_METHOD])

        // CDCVM
        receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .cvmResults("2F0002")
            .build()
        assertEquals("CDCVM", receipt[ReceiptField.CVM_METHOD])

        // No CVM
        receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .cvmResults("1F0002")
            .build()
        assertEquals("NO CVM REQUIRED", receipt[ReceiptField.CVM_METHOD])
    }

    @Test
    fun `test plain text receipt format`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("ACME STORE")
            .merchantAddress("123 Main St")
            .merchantCity("New York, NY")
            .transactionDateTime(Date())
            .amount(2599, "$")
            .maskedPan("4111111111111111")
            .cardType(CardType.VISA)
            .approvalStatus(true)
            .authorizationCode("123456")
            .entryMode(EntryMode.CONTACTLESS)
            .build()

        val text = receipt.toPlainText()

        assertTrue(text.contains("ACME STORE"))
        assertTrue(text.contains("123 Main St"))
        assertTrue(text.contains("$25.99"))
        assertTrue(text.contains("APPROVED"))
        assertTrue(text.contains("123456"))
        assertTrue(text.contains("CONTACTLESS"))
    }

    @Test
    fun `test receipt with tip and total`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("RESTAURANT")
            .transactionDateTime(Date())
            .amount(5000, "$")
            .tipAmount(1000, "$")
            .totalAmount(6000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .build()

        assertEquals("$50.00", receipt[ReceiptField.AMOUNT])
        assertEquals("$10.00", receipt[ReceiptField.TIP_AMOUNT])
        assertEquals("$60.00", receipt[ReceiptField.TOTAL_AMOUNT])
    }

    @Test
    fun `test receipt with cashback`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("GROCERY")
            .transactionDateTime(Date())
            .amount(2500, "$")
            .cashbackAmount(2000, "$")
            .totalAmount(4500, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .build()

        assertEquals("$25.00", receipt[ReceiptField.AMOUNT])
        assertEquals("$20.00", receipt[ReceiptField.CASHBACK_AMOUNT])
        assertEquals("$45.00", receipt[ReceiptField.TOTAL_AMOUNT])
    }

    @Test
    fun `test signature required field`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .signatureRequired(true)
            .build()

        assertEquals("YES", receipt[ReceiptField.SIGNATURE_REQUIRED])

        val text = receipt.toPlainText()
        assertTrue(text.contains("CARDHOLDER SIGNATURE"))
    }

    @Test
    fun `test declined receipt`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(false)
            .responseCode("05")
            .build()

        assertEquals("DECLINED", receipt[ReceiptField.APPROVAL_STATUS])
        assertEquals("05", receipt[ReceiptField.RESPONSE_CODE])

        val text = receipt.toPlainText()
        assertTrue(text.contains("DECLINED"))
    }

    @Test(expected = IllegalStateException::class)
    fun `test build fails without required fields`() {
        ReceiptDataBuilder()
            .merchantName("TEST")
            // Missing other required fields
            .build()
    }

    @Test
    fun `test buildPartial allows missing fields`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .buildPartial()

        assertNotNull(receipt)
        assertEquals("TEST", receipt[ReceiptField.MERCHANT_NAME])
    }

    @Test
    fun `test fromAuthData factory`() {
        val authData = mapOf(
            "maskedPan" to "411111******1111",
            "aid" to "A0000000031010",
            "cryptogram" to "1234567890ABCDEF",
            "atc" to "001F",
            "tvr" to "0000000000",
            "cvmResults" to "2F0002"
        )

        val builder = ReceiptDataBuilder.fromAuthData(authData)

        // Complete with required fields
        val receipt = builder
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .approvalStatus(true)
            .build()

        assertEquals("A0000000031010", receipt[ReceiptField.AID])
        assertEquals("VISA", receipt[ReceiptField.CARD_TYPE])
        assertEquals("CDCVM", receipt[ReceiptField.CVM_METHOD])
    }

    @Test
    fun `test toMap for API transmission`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .aid("A0000000031010")
            .build()

        val map = receipt.toMap()

        assertTrue(map.containsKey("fields"))
        assertTrue(map.containsKey("emvData"))
        assertTrue(map.containsKey("timestamp"))

        @Suppress("UNCHECKED_CAST")
        val fields = map["fields"] as Map<String, String>
        assertEquals("TEST", fields["MERCHANT_NAME"])
    }

    @Test
    fun `test transaction types`() {
        TransactionType.values().forEach { type ->
            val receipt = ReceiptDataBuilder()
                .merchantName("TEST")
                .transactionDateTime(Date())
                .amount(1000, "$")
                .maskedPan("4111111111111111")
                .approvalStatus(true)
                .transactionType(type)
                .build()

            assertEquals(type.displayName, receipt[ReceiptField.TRANSACTION_TYPE])
        }
    }

    @Test
    fun `test entry modes`() {
        EntryMode.values().forEach { mode ->
            val receipt = ReceiptDataBuilder()
                .merchantName("TEST")
                .transactionDateTime(Date())
                .amount(1000, "$")
                .maskedPan("4111111111111111")
                .approvalStatus(true)
                .entryMode(mode)
                .build()

            assertEquals(mode.displayName, receipt[ReceiptField.ENTRY_MODE])
        }
    }

    @Test
    fun `test expiration date formatting`() {
        // YYMM format
        var receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .expirationDate("2512")
            .build()
        assertEquals("12/25", receipt[ReceiptField.EXPIRATION_DATE])
    }

    @Test
    fun `test cardholder name with whitespace`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .cardholderName("  JOHN DOE  ")
            .build()

        assertEquals("JOHN DOE", receipt[ReceiptField.CARDHOLDER_NAME])
    }

    @Test
    fun `test blank cardholder name is not included`() {
        val receipt = ReceiptDataBuilder()
            .merchantName("TEST")
            .transactionDateTime(Date())
            .amount(1000, "$")
            .maskedPan("4111111111111111")
            .approvalStatus(true)
            .cardholderName("   ")
            .build()

        assertNull(receipt[ReceiptField.CARDHOLDER_NAME])
    }
}
