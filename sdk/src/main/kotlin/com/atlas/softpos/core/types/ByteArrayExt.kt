package com.atlas.softpos.core.types

/**
 * Extension functions for ByteArray operations used throughout EMV processing.
 */

fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }

fun String.hexToByteArray(): ByteArray {
    val cleanHex = this.replace(" ", "").replace(":", "")
    check(cleanHex.length % 2 == 0) { "Hex string must have even length" }
    return ByteArray(cleanHex.length / 2) { i ->
        cleanHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

fun ByteArray.toInt(): Int {
    require(this.size <= 4) { "ByteArray too large to convert to Int" }
    var result = 0
    for (byte in this) {
        result = (result shl 8) or (byte.toInt() and 0xFF)
    }
    return result
}

fun ByteArray.toLong(): Long {
    require(this.size <= 8) { "ByteArray too large to convert to Long" }
    var result = 0L
    for (byte in this) {
        result = (result shl 8) or (byte.toLong() and 0xFF)
    }
    return result
}

fun Int.toByteArray(size: Int = 4): ByteArray {
    return ByteArray(size) { i ->
        (this shr (8 * (size - 1 - i))).toByte()
    }
}

fun Long.toByteArray(size: Int = 8): ByteArray {
    return ByteArray(size) { i ->
        (this shr (8 * (size - 1 - i))).toByte()
    }
}

fun ByteArray.copyOfRangeSafe(fromIndex: Int, toIndex: Int): ByteArray {
    val safeFrom = fromIndex.coerceIn(0, this.size)
    val safeTo = toIndex.coerceIn(safeFrom, this.size)
    return this.copyOfRange(safeFrom, safeTo)
}

fun ByteArray.xor(other: ByteArray): ByteArray {
    require(this.size == other.size) { "Arrays must be same size for XOR" }
    return ByteArray(this.size) { i -> (this[i].toInt() xor other[i].toInt()).toByte() }
}

/**
 * BCD (Binary Coded Decimal) utilities for EMV amount/date encoding
 */
fun Long.toBcd(length: Int): ByteArray {
    val bcd = ByteArray(length)
    var value = this
    for (i in length - 1 downTo 0) {
        bcd[i] = ((value % 10) or ((value / 10 % 10) shl 4)).toByte()
        value /= 100
    }
    return bcd
}

fun ByteArray.fromBcd(): Long {
    var result = 0L
    for (byte in this) {
        val high = (byte.toInt() shr 4) and 0x0F
        val low = byte.toInt() and 0x0F
        result = result * 100 + high * 10 + low
    }
    return result
}
