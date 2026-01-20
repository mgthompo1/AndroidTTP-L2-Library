package com.atlas.softpos.test

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.atlas.softpos.*
import com.atlas.softpos.nfc.NfcStatus
import timber.log.Timber

/**
 * Test Activity for running EMV contactless transactions
 *
 * Use this with EMVCo test cards to validate kernel functionality.
 *
 * Add to your AndroidManifest.xml:
 * ```xml
 * <activity
 *     android:name="com.atlas.softpos.test.TestTransactionActivity"
 *     android:exported="true"
 *     android:launchMode="singleTop">
 *     <intent-filter>
 *         <action android:name="android.nfc.action.TECH_DISCOVERED" />
 *     </intent-filter>
 *     <meta-data
 *         android:name="android.nfc.action.TECH_DISCOVERED"
 *         android:resource="@xml/nfc_tech_filter" />
 * </activity>
 * ```
 *
 * Create res/xml/nfc_tech_filter.xml:
 * ```xml
 * <resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
 *     <tech-list>
 *         <tech>android.nfc.tech.IsoDep</tech>
 *     </tech-list>
 * </resources>
 * ```
 */
class TestTransactionActivity : ComponentActivity() {

    private lateinit var softPos: AtlasSoftPos

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize Timber for logging
        if (Timber.forest().isEmpty()) {
            Timber.plant(Timber.DebugTree())
        }

        // Initialize SoftPOS SDK
        softPos = AtlasSoftPos.Builder(this)
            .setMerchantId("TEST_MERCHANT")
            .setTerminalId("TEST001")
            .setCountryCode(byteArrayOf(0x08, 0x40))  // USA
            .setCurrencyCode(byteArrayOf(0x08, 0x40))  // USD
            .setCvmRequiredLimit(2500)  // $25.00
            .setContactlessTransactionLimit(100000)  // $1000.00
            .build()

        setContent {
            MaterialTheme {
                TestTransactionScreen(softPos)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        softPos.onResume()
    }

    override fun onPause() {
        super.onPause()
        softPos.onPause()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TestTransactionScreen(softPos: AtlasSoftPos) {
    var amount by remember { mutableStateOf("1000") }  // $10.00
    var transactionState by remember { mutableStateOf<TransactionState>(TransactionState.Idle) }
    var logMessages by remember { mutableStateOf(listOf<LogEntry>()) }

    fun addLog(message: String, isError: Boolean = false) {
        logMessages = logMessages + LogEntry(
            timestamp = System.currentTimeMillis(),
            message = message,
            isError = isError
        )
    }

    val callback = remember {
        object : TransactionCallback {
            override fun onWaitingForCard() {
                transactionState = TransactionState.WaitingForCard
                addLog("Waiting for card... Tap now")
            }

            override fun onCardDetected() {
                transactionState = TransactionState.Processing
                addLog("Card detected, processing...")
            }

            override fun onResult(result: TransactionResult) {
                when (result) {
                    is TransactionResult.OnlineRequired -> {
                        transactionState = TransactionState.Complete(
                            success = true,
                            message = "Online Authorization Required"
                        )
                        addLog("=== ONLINE AUTHORIZATION REQUIRED ===")
                        addLog("Card: ${result.cardNetwork.displayName}")
                        addLog("PAN: ${result.authorizationData.maskedPan}")
                        addLog("Cryptogram: ${result.authorizationData.applicationCryptogram}")
                        addLog("Type: ${result.authorizationData.cryptogramType}")
                        addLog("ATC: ${result.authorizationData.atc}")
                        addLog("TVR: ${result.authorizationData.terminalVerificationResults}")
                        addLog("CVM: ${result.authorizationData.cvmResults}")
                        addLog("AID: ${result.authorizationData.aid}")
                        addLog("IAD: ${result.authorizationData.issuerApplicationData}")
                    }
                    is TransactionResult.Approved -> {
                        transactionState = TransactionState.Complete(
                            success = true,
                            message = "Offline Approved"
                        )
                        addLog("=== OFFLINE APPROVED ===")
                        addLog("Card: ${result.cardNetwork.displayName}")
                    }
                    is TransactionResult.Declined -> {
                        transactionState = TransactionState.Complete(
                            success = false,
                            message = "Declined: ${result.reason}"
                        )
                        addLog("=== DECLINED ===", isError = true)
                        addLog("Card: ${result.cardNetwork.displayName}", isError = true)
                        addLog("Reason: ${result.reason}", isError = true)
                    }
                    is TransactionResult.Error -> {
                        transactionState = TransactionState.Complete(
                            success = false,
                            message = "Error: ${result.message}"
                        )
                        addLog("=== ERROR ===", isError = true)
                        addLog(result.message, isError = true)
                    }
                }
            }

            override fun onError(error: TransactionError) {
                transactionState = TransactionState.Complete(
                    success = false,
                    message = "Error: $error"
                )
                addLog("Transaction error: $error", isError = true)
            }

            override fun onCancelled() {
                transactionState = TransactionState.Idle
                addLog("Transaction cancelled")
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("EMV Test Transaction") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            // NFC Status
            val nfcStatus = softPos.checkNfc()
            NfcStatusCard(nfcStatus)

            Spacer(modifier = Modifier.height(16.dp))

            // Amount Input
            OutlinedTextField(
                value = amount,
                onValueChange = { amount = it.filter { c -> c.isDigit() } },
                label = { Text("Amount (cents)") },
                modifier = Modifier.fillMaxWidth(),
                enabled = transactionState is TransactionState.Idle
            )

            Text(
                text = "= \$${(amount.toLongOrNull() ?: 0) / 100.0}",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 16.dp, top = 4.dp)
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Transaction Status
            TransactionStatusCard(transactionState)

            Spacer(modifier = Modifier.height(16.dp))

            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = {
                        val amountCents = amount.toLongOrNull() ?: 0
                        if (amountCents > 0) {
                            logMessages = emptyList()
                            addLog("Starting transaction for \$${amountCents / 100.0}")
                            softPos.startTransaction(
                                amount = amountCents,
                                type = TransactionType.PURCHASE,
                                callback = callback
                            )
                        }
                    },
                    enabled = transactionState is TransactionState.Idle && nfcStatus == NfcStatus.ENABLED,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Start Transaction")
                }

                OutlinedButton(
                    onClick = {
                        softPos.cancelTransaction()
                        transactionState = TransactionState.Idle
                    },
                    enabled = transactionState is TransactionState.WaitingForCard ||
                            transactionState is TransactionState.Processing,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Cancel")
                }
            }

            Button(
                onClick = {
                    transactionState = TransactionState.Idle
                    logMessages = emptyList()
                },
                enabled = transactionState is TransactionState.Complete,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("New Transaction")
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Log Output
            Text(
                text = "Transaction Log:",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF1E1E1E)
                )
            ) {
                LazyColumn(
                    modifier = Modifier.padding(8.dp)
                ) {
                    items(logMessages) { entry ->
                        Text(
                            text = entry.message,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = if (entry.isError) Color.Red else Color.Green
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun NfcStatusCard(status: NfcStatus) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (status) {
                NfcStatus.ENABLED -> Color(0xFF4CAF50)
                NfcStatus.DISABLED -> Color(0xFFFF9800)
                NfcStatus.NOT_AVAILABLE -> Color(0xFFF44336)
            }
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = when (status) {
                    NfcStatus.ENABLED -> "✓ NFC Ready"
                    NfcStatus.DISABLED -> "⚠ NFC Disabled - Enable in Settings"
                    NfcStatus.NOT_AVAILABLE -> "✗ NFC Not Available"
                },
                color = Color.White,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun TransactionStatusCard(state: TransactionState) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            when (state) {
                is TransactionState.Idle -> {
                    Text("Ready", style = MaterialTheme.typography.headlineSmall)
                    Text("Enter amount and tap Start", color = Color.Gray)
                }
                is TransactionState.WaitingForCard -> {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Waiting for Card", style = MaterialTheme.typography.headlineSmall)
                    Text("Tap your EMVCo test card", color = Color.Gray)
                }
                is TransactionState.Processing -> {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Processing", style = MaterialTheme.typography.headlineSmall)
                    Text("Reading card data...", color = Color.Gray)
                }
                is TransactionState.Complete -> {
                    Text(
                        text = if (state.success) "✓" else "✗",
                        fontSize = 48.sp,
                        color = if (state.success) Color(0xFF4CAF50) else Color(0xFFF44336)
                    )
                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.headlineSmall
                    )
                }
            }
        }
    }
}

sealed class TransactionState {
    object Idle : TransactionState()
    object WaitingForCard : TransactionState()
    object Processing : TransactionState()
    data class Complete(val success: Boolean, val message: String) : TransactionState()
}

data class LogEntry(
    val timestamp: Long,
    val message: String,
    val isError: Boolean = false
)
