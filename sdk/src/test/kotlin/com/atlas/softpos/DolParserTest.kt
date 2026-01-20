package com.atlas.softpos

import com.atlas.softpos.core.dol.DataStore
import com.atlas.softpos.core.dol.DolEntry
import com.atlas.softpos.core.dol.DolParser
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for DOL (Data Object List) parsing and building
 *
 * Tests PDOL, CDOL1, CDOL2 parsing and data construction
 * per EMV Book 3 specifications.
 */
class DolParserTest {

    @Test
    fun `parse empty DOL returns empty list`() {
        val result = DolParser.parse(byteArrayOf())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `parse single byte tag DOL`() {
        // Simple DOL: Tag 9A (Transaction Date) | Length 03
        val dol = byteArrayOf(0x9A.toByte(), 0x03)

        val result = DolParser.parse(dol)

        assertEquals(1, result.size)
        assertEquals(0x9A, result[0].tagValue)
        assertEquals(3, result[0].length)
        assertEquals("9A", result[0].tagHex)
    }

    @Test
    fun `parse two byte tag DOL`() {
        // DOL with two-byte tag: Tag 9F02 (Amount Authorized) | Length 06
        val dol = byteArrayOf(0x9F.toByte(), 0x02, 0x06)

        val result = DolParser.parse(dol)

        assertEquals(1, result.size)
        assertEquals(0x9F02, result[0].tagValue)
        assertEquals(6, result[0].length)
        assertEquals("9F02", result[0].tagHex)
    }

    @Test
    fun `parse complex PDOL`() {
        // Typical Visa PDOL:
        // 9F66 04 (TTQ)
        // 9F02 06 (Amount Authorized)
        // 9F03 06 (Amount Other)
        // 9F1A 02 (Terminal Country Code)
        // 5F2A 02 (Transaction Currency Code)
        // 9A 03 (Transaction Date)
        // 9C 01 (Transaction Type)
        // 9F37 04 (Unpredictable Number)
        val dol = byteArrayOf(
            0x9F.toByte(), 0x66, 0x04,
            0x9F.toByte(), 0x02, 0x06,
            0x9F.toByte(), 0x03, 0x06,
            0x9F.toByte(), 0x1A, 0x02,
            0x5F.toByte(), 0x2A, 0x02,
            0x9A.toByte(), 0x03,
            0x9C.toByte(), 0x01,
            0x9F.toByte(), 0x37, 0x04
        )

        val result = DolParser.parse(dol)

        assertEquals(8, result.size)

        assertEquals(0x9F66, result[0].tagValue)
        assertEquals(4, result[0].length)

        assertEquals(0x9F02, result[1].tagValue)
        assertEquals(6, result[1].length)

        assertEquals(0x9F03, result[2].tagValue)
        assertEquals(6, result[2].length)

        assertEquals(0x9F1A, result[3].tagValue)
        assertEquals(2, result[3].length)

        assertEquals(0x5F2A, result[4].tagValue)
        assertEquals(2, result[4].length)

        assertEquals(0x9A, result[5].tagValue)
        assertEquals(3, result[5].length)

        assertEquals(0x9C, result[6].tagValue)
        assertEquals(1, result[6].length)

        assertEquals(0x9F37, result[7].tagValue)
        assertEquals(4, result[7].length)
    }

    @Test
    fun `build DOL data with exact length values`() {
        // DOL requesting 9A (3 bytes)
        val dol = byteArrayOf(0x9A.toByte(), 0x03)

        val dataStore = DataStore().apply {
            set(0x9A, byteArrayOf(0x25, 0x01, 0x19))  // 2025-01-19
        }

        val result = DolParser.buildDolData(dol, dataStore)

        assertArrayEquals(byteArrayOf(0x25, 0x01, 0x19), result)
    }

    @Test
    fun `build DOL data pads short values`() {
        // DOL requesting 9F02 (6 bytes)
        val dol = byteArrayOf(0x9F.toByte(), 0x02, 0x06)

        val dataStore = DataStore().apply {
            // Only provide 4 bytes
            set(0x9F02, byteArrayOf(0x00, 0x01, 0x00, 0x00))
        }

        val result = DolParser.buildDolData(dol, dataStore)

        // Should be left-padded to 6 bytes
        assertEquals(6, result.size)
    }

    @Test
    fun `build DOL data truncates long values`() {
        // DOL requesting 9C (1 byte)
        val dol = byteArrayOf(0x9C.toByte(), 0x01)

        val dataStore = DataStore().apply {
            // Provide 4 bytes when only 1 is requested
            set(0x9C, byteArrayOf(0x00, 0x01, 0x02, 0x03))
        }

        val result = DolParser.buildDolData(dol, dataStore)

        assertEquals(1, result.size)
        assertEquals(0x00.toByte(), result[0])
    }

    @Test
    fun `build DOL data fills missing values with zeros`() {
        // DOL requesting a tag not in data store
        val dol = byteArrayOf(0x9F.toByte(), 0x37, 0x04)

        val dataStore = DataStore()  // Empty data store

        val result = DolParser.buildDolData(dol, dataStore)

        assertEquals(4, result.size)
        assertTrue(result.all { it == 0x00.toByte() })
    }

    @Test
    fun `build complete PDOL data`() {
        val dol = byteArrayOf(
            0x9F.toByte(), 0x02, 0x06,  // Amount
            0x9F.toByte(), 0x1A, 0x02,  // Country
            0x9C.toByte(), 0x01         // Type
        )

        val dataStore = DataStore().apply {
            set(0x9F02, byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x00, 0x00))  // $100.00
            set(0x9F1A, byteArrayOf(0x08, 0x40))  // USA
            set(0x9C, byteArrayOf(0x00))  // Purchase
        }

        val result = DolParser.buildDolData(dol, dataStore)

        assertEquals(9, result.size)  // 6 + 2 + 1

        // Verify amount
        assertArrayEquals(
            byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x00, 0x00),
            result.copyOfRange(0, 6)
        )

        // Verify country
        assertArrayEquals(
            byteArrayOf(0x08, 0x40),
            result.copyOfRange(6, 8)
        )

        // Verify type
        assertEquals(0x00.toByte(), result[8])
    }

    @Test
    fun `canSatisfy returns true when all critical tags present`() {
        val dol = byteArrayOf(
            0x9F.toByte(), 0x02, 0x06,  // Amount (critical)
            0x9F.toByte(), 0x1A, 0x02,  // Country (critical)
            0x9C.toByte(), 0x01         // Type (critical)
        )

        val dataStore = DataStore().apply {
            set(0x9F02, byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x00, 0x00))
            set(0x9F1A, byteArrayOf(0x08, 0x40))
            set(0x9C, byteArrayOf(0x00))
        }

        val (canSatisfy, missing) = DolParser.canSatisfy(dol, dataStore)

        assertTrue(canSatisfy)
        assertTrue(missing.isEmpty())
    }

    @Test
    fun `canSatisfy returns false when critical tags missing`() {
        val dol = byteArrayOf(
            0x9F.toByte(), 0x02, 0x06,  // Amount (critical)
            0x9F.toByte(), 0x1A, 0x02   // Country (critical)
        )

        val dataStore = DataStore().apply {
            // Only provide Amount, missing Country
            set(0x9F02, byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x00, 0x00))
        }

        val (canSatisfy, missing) = DolParser.canSatisfy(dol, dataStore)

        assertFalse(canSatisfy)
        assertTrue(missing.contains("9F1A"))
    }

    @Test
    fun `DataStore set and get by tag value`() {
        val dataStore = DataStore()

        dataStore.set(0x9F02, byteArrayOf(0x01, 0x02, 0x03))

        val result = dataStore.get(0x9F02)

        assertNotNull(result)
        assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03), result)
    }

    @Test
    fun `DataStore set and get by hex string`() {
        val dataStore = DataStore()

        dataStore.set("9F02", byteArrayOf(0x01, 0x02, 0x03))

        val result = dataStore.get("9F02")

        assertNotNull(result)
        assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03), result)
    }

    @Test
    fun `DataStore contains check`() {
        val dataStore = DataStore()

        assertFalse(dataStore.contains(0x9F02))

        dataStore.set(0x9F02, byteArrayOf(0x01))

        assertTrue(dataStore.contains(0x9F02))
        assertTrue(dataStore.contains("9F02"))
    }

    @Test
    fun `DataStore clear removes all data`() {
        val dataStore = DataStore().apply {
            set(0x9F02, byteArrayOf(0x01))
            set(0x9F1A, byteArrayOf(0x02))
        }

        dataStore.clear()

        assertFalse(dataStore.contains(0x9F02))
        assertFalse(dataStore.contains(0x9F1A))
    }
}
