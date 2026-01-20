package com.atlas.softpos.sample

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.atlas.softpos.kernel.visa.VisaContactlessKernel
import com.atlas.softpos.kernel.visa.VisaTransactionParams
import com.atlas.softpos.kernel.visa.VisaOutcomeType
import com.atlas.softpos.kernel.mastercard.MastercardContactlessKernel
import com.atlas.softpos.kernel.mastercard.MastercardTransactionParams
import com.atlas.softpos.kernel.mastercard.MastercardOutcomeType
import com.atlas.softpos.nfc.NfcCardReader
import com.atlas.softpos.nfc.CardTransceiver
import com.atlas.softpos.emv.EmvTags
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * Sample Activity demonstrating EMV SoftPOS SDK usage.
 *
 * This activity shows how to:
 * 1. Initialize NFC for contactless card reading
 * 2. Configure transaction parameters
 * 3. Process EMV contactless transactions
 * 4. Handle transaction outcomes
 */
class MainActivity : ComponentActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private var intentFilters: Array<IntentFilter>? = null
    private var techLists: Array<Array<String>>? = null

    // UI State
    private val transactionState = mutableStateOf(TransactionState.IDLE)
    private val logMessages = mutableStateOf(listOf<LogEntry>())
    private val amountCents = mutableStateOf("1000") // Default $10.00
    private val detectedAid = mutableStateOf<String?>(null)
    private val outcomeMessage = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize Timber for logging
        if (Timber.treeCount == 0) {
            Timber.plant(Timber.DebugTree())
        }

        setupNfc()

        setContent {
            MaterialTheme {
                TransactionScreen()
            }
        }
    }

    private fun setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        if (nfcAdapter == null) {
            log("NFC not available on this device", LogLevel.ERROR)
            return
        }

        pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )

        val techDiscovered = IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)
        intentFilters = arrayOf(techDiscovered)
        techLists = arrayOf(
            arrayOf(IsoDep::class.java.name)
        )

        log("NFC initialized successfully", LogLevel.INFO)
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.let { adapter ->
            if (!adapter.isEnabled) {
                log("NFC is disabled. Please enable NFC in settings.", LogLevel.WARNING)
            } else {
                adapter.enableForegroundDispatch(this, pendingIntent, intentFilters, techLists)
                if (transactionState.value == TransactionState.IDLE) {
                    transactionState.value = TransactionState.WAITING_FOR_CARD
                    log("Ready - tap card to begin transaction", LogLevel.INFO)
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            tag?.let { handleNfcTag(it) }
        }
    }

    private fun handleNfcTag(tag: Tag) {
        if (transactionState.value != TransactionState.WAITING_FOR_CARD) {
            log("Not ready for card tap", LogLevel.WARNING)
            return
        }

        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            log("Card does not support IsoDep", LogLevel.ERROR)
            return
        }

        transactionState.value = TransactionState.PROCESSING
        log("Card detected, starting transaction...", LogLevel.INFO)

        // Process transaction in background
        val scope = kotlinx.coroutines.MainScope()
        scope.launch {
            processTransaction(isoDep)
        }
    }

    private suspend fun processTransaction(isoDep: IsoDep) {
        try {
            withContext(Dispatchers.IO) {
                isoDep.connect()
                isoDep.timeout = 5000 // 5 second timeout

                log("Connected to card, timeout: ${isoDep.timeout}ms", LogLevel.DEBUG)
                log("Historical bytes: ${isoDep.historicalBytes?.toHexString() ?: "none"}", LogLevel.DEBUG)

                // Create card transceiver
                val transceiver = IsoDepTransceiver(isoDep) { cmd, resp ->
                    log(">> $cmd", LogLevel.APDU)
                    log("<< $resp", LogLevel.APDU)
                }

                // Select PPSE first
                val ppseResponse = selectPpse(transceiver)
                if (ppseResponse == null) {
                    withContext(Dispatchers.Main) {
                        transactionState.value = TransactionState.ERROR
                        outcomeMessage.value = "Failed to select PPSE"
                    }
                    return@withContext
                }

                // Parse available AIDs from PPSE
                val availableAids = parsePpseResponse(ppseResponse)
                if (availableAids.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        transactionState.value = TransactionState.ERROR
                        outcomeMessage.value = "No payment applications found"
                    }
                    return@withContext
                }

                log("Found ${availableAids.size} payment application(s)", LogLevel.INFO)

                // Select first available AID and determine kernel
                val selectedAid = availableAids.first()
                detectedAid.value = selectedAid.toHexString()
                log("Selected AID: ${selectedAid.toHexString()}", LogLevel.INFO)

                // Determine which kernel to use based on AID
                val amount = amountCents.value.toLongOrNull() ?: 1000L

                when {
                    isVisaAid(selectedAid) -> {
                        processVisaTransaction(transceiver, selectedAid, amount)
                    }
                    isMastercardAid(selectedAid) -> {
                        processMastercardTransaction(transceiver, selectedAid, amount)
                    }
                    else -> {
                        withContext(Dispatchers.Main) {
                            transactionState.value = TransactionState.ERROR
                            outcomeMessage.value = "Unsupported card type: ${selectedAid.toHexString()}"
                        }
                    }
                }

                isoDep.close()
            }
        } catch (e: Exception) {
            Timber.e(e, "Transaction error")
            log("Error: ${e.message}", LogLevel.ERROR)
            withContext(Dispatchers.Main) {
                transactionState.value = TransactionState.ERROR
                outcomeMessage.value = "Transaction failed: ${e.message}"
            }
        }
    }

    private suspend fun processVisaTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        amountCents: Long
    ) {
        log("Processing Visa transaction...", LogLevel.INFO)

        val params = VisaTransactionParams(
            amount = amountCents,
            amountOther = 0,
            transactionType = 0x00, // Purchase
            currencyCode = 0x0840, // USD
            countryCode = 0x0840, // USA
            terminalType = 0x22,
            terminalCapabilities = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
            additionalTerminalCapabilities = byteArrayOf(
                0x8F.toByte(), 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01
            ),
            transactionDate = getCurrentDate(),
            transactionTime = getCurrentTime(),
            unpredictableNumber = generateUnpredictableNumber()
        )

        val kernel = VisaContactlessKernel(transceiver, params)
        val outcome = kernel.processTransaction(aid)

        withContext(Dispatchers.Main) {
            when (outcome.type) {
                VisaOutcomeType.APPROVED -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "APPROVED (Offline)"
                    log("Transaction APPROVED offline", LogLevel.SUCCESS)
                }
                VisaOutcomeType.ONLINE_REQUEST -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "ONLINE AUTHORIZATION REQUIRED"
                    log("Online authorization required", LogLevel.INFO)
                    outcome.cryptogram?.let { log("ARQC: ${it.toHexString()}", LogLevel.INFO) }
                }
                VisaOutcomeType.DECLINED -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "DECLINED"
                    log("Transaction DECLINED", LogLevel.ERROR)
                }
                VisaOutcomeType.TRY_ANOTHER_INTERFACE -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "TRY ANOTHER INTERFACE"
                    log("Card requests another interface (insert/swipe)", LogLevel.WARNING)
                }
                VisaOutcomeType.END_APPLICATION -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "APPLICATION ENDED"
                    log("Application ended: ${outcome.errorMessage}", LogLevel.ERROR)
                }
            }

            // Log additional outcome data
            outcome.track2Data?.let { log("Track 2: ${it.toHexString()}", LogLevel.DEBUG) }
            outcome.panHash?.let { log("PAN Hash: ${it.toHexString()}", LogLevel.DEBUG) }
        }
    }

    private suspend fun processMastercardTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        amountCents: Long
    ) {
        log("Processing Mastercard transaction...", LogLevel.INFO)

        val params = MastercardTransactionParams(
            amount = amountCents,
            amountOther = 0,
            transactionType = 0x00, // Purchase
            currencyCode = 0x0840, // USD
            countryCode = 0x0840, // USA
            terminalType = 0x22,
            terminalCapabilities = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
            additionalTerminalCapabilities = byteArrayOf(
                0x8F.toByte(), 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01
            ),
            merchantCategoryCode = 0x5411, // Grocery stores
            terminalCountryCode = 0x0840,
            transactionDate = getCurrentDate(),
            transactionTime = getCurrentTime(),
            unpredictableNumber = generateUnpredictableNumber()
        )

        val kernel = MastercardContactlessKernel(transceiver, params)
        val outcome = kernel.processTransaction(aid)

        withContext(Dispatchers.Main) {
            when (outcome.type) {
                MastercardOutcomeType.APPROVED -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "APPROVED (Offline)"
                    log("Transaction APPROVED offline", LogLevel.SUCCESS)
                }
                MastercardOutcomeType.ONLINE_REQUEST -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "ONLINE AUTHORIZATION REQUIRED"
                    log("Online authorization required", LogLevel.INFO)
                    outcome.cryptogram?.let { log("ARQC: ${it.toHexString()}", LogLevel.INFO) }
                }
                MastercardOutcomeType.DECLINED -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "DECLINED"
                    log("Transaction DECLINED", LogLevel.ERROR)
                }
                MastercardOutcomeType.TRY_ANOTHER_INTERFACE -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "TRY ANOTHER INTERFACE"
                    log("Card requests another interface", LogLevel.WARNING)
                }
                MastercardOutcomeType.END_APPLICATION -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "APPLICATION ENDED"
                    log("Application ended: ${outcome.errorMessage}", LogLevel.ERROR)
                }
            }
        }
    }

    private fun selectPpse(transceiver: CardTransceiver): ByteArray? {
        val ppseAid = "2PAY.SYS.DDF01".toByteArray(Charsets.US_ASCII)
        val selectCommand = buildSelectCommand(ppseAid)

        log("Selecting PPSE...", LogLevel.DEBUG)
        val response = transceiver.transceive(selectCommand)

        return if (response.size >= 2 && response[response.size - 2] == 0x90.toByte() && response[response.size - 1] == 0x00.toByte()) {
            log("PPSE selected successfully", LogLevel.DEBUG)
            response
        } else {
            log("PPSE selection failed: ${response.takeLast(2).toByteArray().toHexString()}", LogLevel.ERROR)
            null
        }
    }

    private fun buildSelectCommand(aid: ByteArray): ByteArray {
        return byteArrayOf(
            0x00, // CLA
            0xA4.toByte(), // INS: SELECT
            0x04, // P1: Select by name
            0x00, // P2: First occurrence
            aid.size.toByte()
        ) + aid + byteArrayOf(0x00) // Le
    }

    private fun parsePpseResponse(response: ByteArray): List<ByteArray> {
        val aids = mutableListOf<ByteArray>()

        // Simple TLV parsing for AID (tag 4F)
        var i = 0
        while (i < response.size - 2) {
            if (response[i] == 0x4F.toByte()) {
                val length = response[i + 1].toInt() and 0xFF
                if (i + 2 + length <= response.size) {
                    val aid = response.copyOfRange(i + 2, i + 2 + length)
                    aids.add(aid)
                    log("Found AID: ${aid.toHexString()}", LogLevel.DEBUG)
                }
                i += 2 + length
            } else {
                i++
            }
        }

        return aids
    }

    private fun isVisaAid(aid: ByteArray): Boolean {
        val visaPrefix = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x03)
        return aid.size >= 5 && aid.take(5).toByteArray().contentEquals(visaPrefix)
    }

    private fun isMastercardAid(aid: ByteArray): Boolean {
        val mcPrefix = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x00, 0x04)
        return aid.size >= 5 && aid.take(5).toByteArray().contentEquals(mcPrefix)
    }

    private fun getCurrentDate(): ByteArray {
        val cal = java.util.Calendar.getInstance()
        val year = cal.get(java.util.Calendar.YEAR) % 100
        val month = cal.get(java.util.Calendar.MONTH) + 1
        val day = cal.get(java.util.Calendar.DAY_OF_MONTH)
        return byteArrayOf(
            ((year / 10) shl 4 or (year % 10)).toByte(),
            ((month / 10) shl 4 or (month % 10)).toByte(),
            ((day / 10) shl 4 or (day % 10)).toByte()
        )
    }

    private fun getCurrentTime(): ByteArray {
        val cal = java.util.Calendar.getInstance()
        val hour = cal.get(java.util.Calendar.HOUR_OF_DAY)
        val minute = cal.get(java.util.Calendar.MINUTE)
        val second = cal.get(java.util.Calendar.SECOND)
        return byteArrayOf(
            ((hour / 10) shl 4 or (hour % 10)).toByte(),
            ((minute / 10) shl 4 or (minute % 10)).toByte(),
            ((second / 10) shl 4 or (second % 10)).toByte()
        )
    }

    private fun generateUnpredictableNumber(): ByteArray {
        return java.security.SecureRandom().let { random ->
            ByteArray(4).also { random.nextBytes(it) }
        }
    }

    private fun log(message: String, level: LogLevel) {
        val entry = LogEntry(
            timestamp = System.currentTimeMillis(),
            message = message,
            level = level
        )
        logMessages.value = logMessages.value + entry

        when (level) {
            LogLevel.ERROR -> Timber.e(message)
            LogLevel.WARNING -> Timber.w(message)
            LogLevel.DEBUG, LogLevel.APDU -> Timber.d(message)
            else -> Timber.i(message)
        }
    }

    private fun resetTransaction() {
        transactionState.value = TransactionState.WAITING_FOR_CARD
        logMessages.value = emptyList()
        detectedAid.value = null
        outcomeMessage.value = null
        log("Ready - tap card to begin transaction", LogLevel.INFO)
    }

    @Composable
    fun TransactionScreen() {
        val scrollState = rememberScrollState()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFFF5F5F5))
                .padding(16.dp)
        ) {
            // Header
            Text(
                text = "EMV SoftPOS Test",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            // Status Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Status: ${transactionState.value.displayName}",
                        fontWeight = FontWeight.Medium,
                        color = transactionState.value.color
                    )

                    detectedAid.value?.let {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(text = "AID: $it", fontSize = 12.sp, color = Color.Gray)
                    }

                    outcomeMessage.value?.let {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = it,
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp,
                            color = if (it.contains("APPROVED")) Color(0xFF4CAF50) else Color(0xFFF44336)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Amount Input
            OutlinedTextField(
                value = amountCents.value,
                onValueChange = { amountCents.value = it.filter { c -> c.isDigit() } },
                label = { Text("Amount (cents)") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
                enabled = transactionState.value == TransactionState.IDLE ||
                         transactionState.value == TransactionState.WAITING_FOR_CARD
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Reset Button
            Button(
                onClick = { resetTransaction() },
                modifier = Modifier.fillMaxWidth(),
                enabled = transactionState.value != TransactionState.PROCESSING
            ) {
                Text("Reset")
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Log Display
            Text(
                text = "Transaction Log",
                fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(bottom = 8.dp)
            )

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                shape = RoundedCornerShape(8.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
            ) {
                Column(
                    modifier = Modifier
                        .padding(8.dp)
                        .verticalScroll(scrollState)
                ) {
                    logMessages.value.forEach { entry ->
                        Text(
                            text = entry.formattedMessage,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = entry.level.color,
                            modifier = Modifier.padding(vertical = 1.dp)
                        )
                    }
                }
            }
        }
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02X".format(it) }

    private fun List<Byte>.toByteArray(): ByteArray =
        this.toByteArray()

    /**
     * IsoDep transceiver implementation
     */
    private class IsoDepTransceiver(
        private val isoDep: IsoDep,
        private val logger: (String, String) -> Unit
    ) : CardTransceiver {

        override fun transceive(command: ByteArray): ByteArray {
            val cmdHex = command.joinToString("") { "%02X".format(it) }
            val response = isoDep.transceive(command)
            val respHex = response.joinToString("") { "%02X".format(it) }
            logger(cmdHex, respHex)
            return response
        }
    }
}

enum class TransactionState(val displayName: String, val color: Color) {
    IDLE("Idle", Color.Gray),
    WAITING_FOR_CARD("Waiting for Card", Color(0xFF2196F3)),
    PROCESSING("Processing", Color(0xFFFF9800)),
    COMPLETE("Complete", Color(0xFF4CAF50)),
    ERROR("Error", Color(0xFFF44336))
}

enum class LogLevel(val color: Color) {
    INFO(Color(0xFFBBBBBB)),
    DEBUG(Color(0xFF888888)),
    WARNING(Color(0xFFFFEB3B)),
    ERROR(Color(0xFFF44336)),
    SUCCESS(Color(0xFF4CAF50)),
    APDU(Color(0xFF64B5F6))
}

data class LogEntry(
    val timestamp: Long,
    val message: String,
    val level: LogLevel
) {
    val formattedMessage: String
        get() {
            val time = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US)
                .format(java.util.Date(timestamp))
            return "[$time] $message"
        }
}
