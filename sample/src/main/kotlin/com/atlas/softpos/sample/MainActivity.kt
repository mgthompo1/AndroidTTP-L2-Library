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
import com.atlas.softpos.kernel.visa.VisaKernelConfiguration
import com.atlas.softpos.kernel.visa.VisaTransactionData
import com.atlas.softpos.kernel.visa.VisaKernelOutcome
import com.atlas.softpos.kernel.mastercard.MastercardContactlessKernel
import com.atlas.softpos.kernel.mastercard.MastercardKernelConfig
import com.atlas.softpos.kernel.mastercard.MastercardTransactionParams
import com.atlas.softpos.kernel.mastercard.MastercardKernelOutcome
import com.atlas.softpos.kernel.common.SelectedApplication
import com.atlas.softpos.nfc.NfcCardReader
import com.atlas.softpos.nfc.CardTransceiver
import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
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

        val config = VisaKernelConfiguration(
            terminalCountryCode = byteArrayOf(0x08, 0x40), // USA
            transactionCurrencyCode = byteArrayOf(0x08, 0x40), // USD
            terminalCapabilities = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
            terminalType = 0x22,
            additionalTerminalCapabilities = byteArrayOf(
                0x8F.toByte(), 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01
            ),
            ifdSerialNumber = "SoftPOS001".toByteArray(),
            merchantCategoryCode = byteArrayOf(0x54, 0x11), // Grocery
            terminalFloorLimit = 0,
            cvmRequiredLimit = 5000, // $50.00
            contactlessTransactionLimit = 25000 // $250.00
        )

        val transactionData = VisaTransactionData(
            amount = amountCents,
            transactionType = 0x00 // Purchase
        )

        val kernel = VisaContactlessKernel(transceiver, config)
        val outcome = kernel.processTransaction(aid, null, transactionData)

        withContext(Dispatchers.Main) {
            when (outcome) {
                is VisaKernelOutcome.Approved -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "APPROVED (Offline)"
                    log("Transaction APPROVED offline", LogLevel.SUCCESS)
                    log("Cryptogram: ${outcome.authData.applicationCryptogram}", LogLevel.INFO)
                }
                is VisaKernelOutcome.OnlineRequest -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "ONLINE AUTHORIZATION REQUIRED"
                    log("Online authorization required", LogLevel.INFO)
                    log("ARQC: ${outcome.authData.applicationCryptogram}", LogLevel.INFO)
                }
                is VisaKernelOutcome.Declined -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "DECLINED"
                    log("Transaction DECLINED: ${outcome.reason}", LogLevel.ERROR)
                }
                is VisaKernelOutcome.TryAnotherInterface -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "TRY ANOTHER INTERFACE"
                    log("Card requests another interface (insert/swipe)", LogLevel.WARNING)
                }
                is VisaKernelOutcome.EndApplication -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "APPLICATION ENDED"
                    log("Application ended: ${outcome.reason}", LogLevel.ERROR)
                }
                is VisaKernelOutcome.TryAgain -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "TRY AGAIN"
                    log("Try again: ${outcome.reason}", LogLevel.WARNING)
                }
            }
        }
    }

    private suspend fun processMastercardTransaction(
        transceiver: CardTransceiver,
        aid: ByteArray,
        amountCents: Long
    ) {
        log("Processing Mastercard transaction...", LogLevel.INFO)

        val config = MastercardKernelConfig()  // Uses sensible defaults

        val transactionParams = MastercardTransactionParams(
            amount = amountCents,
            type = 0x00 // Purchase
        )

        // Create SelectedApplication from the AID
        val application = SelectedApplication(
            aid = aid,
            label = "Mastercard",
            pdol = null,
            languagePreference = null,
            fciData = byteArrayOf()
        )

        val kernel = MastercardContactlessKernel(transceiver, config)
        val outcome = kernel.processTransaction(application, transactionParams)

        withContext(Dispatchers.Main) {
            when (outcome) {
                is MastercardKernelOutcome.Approved -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "APPROVED (Offline)"
                    log("Transaction APPROVED offline", LogLevel.SUCCESS)
                    log("Cryptogram: ${outcome.authorizationData.applicationCryptogram}", LogLevel.INFO)
                }
                is MastercardKernelOutcome.OnlineRequest -> {
                    transactionState.value = TransactionState.COMPLETE
                    outcomeMessage.value = "ONLINE AUTHORIZATION REQUIRED"
                    log("Online authorization required", LogLevel.INFO)
                    log("ARQC: ${outcome.authorizationData.applicationCryptogram}", LogLevel.INFO)
                }
                is MastercardKernelOutcome.Declined -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "DECLINED"
                    log("Transaction DECLINED: ${outcome.reason}", LogLevel.ERROR)
                }
                is MastercardKernelOutcome.TryAnotherInterface -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "TRY ANOTHER INTERFACE"
                    log("Card requests another interface: ${outcome.reason}", LogLevel.WARNING)
                }
                is MastercardKernelOutcome.EndApplication -> {
                    transactionState.value = TransactionState.ERROR
                    outcomeMessage.value = "APPLICATION ENDED"
                    log("Application ended: ${outcome.error.name}", LogLevel.ERROR)
                }
            }
        }
    }

    private suspend fun selectPpse(transceiver: CardTransceiver): ByteArray? {
        val ppseAid = "2PAY.SYS.DDF01".toByteArray(Charsets.US_ASCII)
        val selectCommand = buildSelectCommand(ppseAid)

        log("Selecting PPSE...", LogLevel.DEBUG)
        val response = transceiver.transceive(selectCommand)

        return if (response.sw1 == 0x90.toByte() && response.sw2 == 0x00.toByte()) {
            log("PPSE selected successfully", LogLevel.DEBUG)
            response.data
        } else {
            log("PPSE selection failed: SW=${response.sw.toString(16)}", LogLevel.ERROR)
            null
        }
    }

    private fun buildSelectCommand(aid: ByteArray): CommandApdu {
        return CommandApdu(
            cla = 0x00,
            ins = 0xA4.toByte(),
            p1 = 0x04,
            p2 = 0x00,
            data = aid,
            le = 0
        )
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

        override suspend fun transceive(command: CommandApdu): ResponseApdu {
            val commandBytes = command.encode()
            val cmdHex = commandBytes.joinToString("") { "%02X".format(it) }
            val response = isoDep.transceive(commandBytes)
            val respHex = response.joinToString("") { "%02X".format(it) }
            logger(cmdHex, respHex)
            return ResponseApdu.parse(response)
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
