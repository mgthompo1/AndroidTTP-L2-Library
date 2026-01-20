# EMV SoftPOS SDK

A production-grade EMV Level 2 (L2) contactless kernel SDK for Android, enabling mobile devices to accept tap-to-pay transactions. This SDK transforms NFC-enabled Android phones into payment terminals (SoftPOS/Tap-to-Phone).

## Overview

This SDK provides complete EMV contactless kernel implementations for:

- **Visa** - qVSDC (quick Visa Smart Debit/Credit) kernel
- **Mastercard** - M/Chip Advance contactless kernel
- **American Express** - ExpressPay kernel (in development)
- **Discover** - D-PAS kernel (in development)
- **UnionPay** - QuickPass kernel (in development)

## Features

### Core EMV L2 Processing
- Full EMV contactless transaction flow (SELECT, GPO, READ RECORD, GENERATE AC)
- Application selection via PPSE (Proximity Payment System Environment)
- DOL (Data Object List) parsing and building (PDOL, CDOL1, CDOL2)
- Terminal Verification Results (TVR) and Transaction Status Information (TSI)
- Cardholder Verification Method (CVM) processing
- Terminal Action Analysis with TAC/IAC support
- Application cryptogram generation (TC, ARQC, AAC)

### Security
- Offline Data Authentication (SDA, DDA, fDDA, CDA)
- RSA certificate chain validation
- ICC Dynamic Number verification
- Signed Dynamic Application Data validation
- Secure cryptogram generation

### Card Network Compliance
- EMVCo specification compliance
- Visa qVSDC Entry Point requirements
- Mastercard M/Chip specifications
- Kernel-specific data elements and processing rules

## Requirements

- **Android API Level**: 26+ (Android 8.0 Oreo)
- **NFC Hardware**: Device must have NFC capability
- **Kotlin**: 1.9.22+
- **Java**: 17+

## Project Structure

```
emv-softpos-sdk/
├── sdk/                          # Core SDK library
│   └── src/main/kotlin/
│       └── com/atlas/softpos/
│           ├── kernel/           # EMV kernels
│           │   ├── visa/         # Visa qVSDC kernel
│           │   ├── mastercard/   # Mastercard kernel
│           │   ├── amex/         # AmEx kernel (planned)
│           │   ├── discover/     # Discover kernel (planned)
│           │   └── unionpay/     # UnionPay kernel (planned)
│           ├── emv/              # Core EMV components
│           │   ├── EmvTags.kt    # EMV tag definitions
│           │   ├── DolParser.kt  # DOL parsing/building
│           │   └── Tvr.kt        # TVR/TSI processing
│           ├── crypto/           # Cryptographic operations
│           │   ├── EmvCrypto.kt  # MAC, encryption
│           │   └── Oda.kt        # Offline data auth
│           ├── nfc/              # NFC communication
│           │   ├── NfcCardReader.kt
│           │   └── CardTransceiver.kt
│           └── security/         # Device security
│               └── DeviceAttestation.kt
│
├── sample/                       # Sample application
│   └── src/main/kotlin/
│       └── com/atlas/softpos/sample/
│           └── MainActivity.kt   # Test transaction UI
│
└── docs/                         # Documentation
```

## Installation

### Gradle Setup

Add the SDK module to your project:

```kotlin
// settings.gradle.kts
include(":sdk")
project(":sdk").projectDir = file("path/to/emv-softpos-sdk/sdk")

// app/build.gradle.kts
dependencies {
    implementation(project(":sdk"))
}
```

### Permissions

Add to your AndroidManifest.xml:

```xml
<uses-permission android:name="android.permission.NFC" />
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.USE_BIOMETRIC" />

<uses-feature
    android:name="android.hardware.nfc"
    android:required="true" />
```

## Quick Start

### 1. Initialize NFC Reader

```kotlin
class PaymentActivity : ComponentActivity() {
    private var nfcAdapter: NfcAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, intentFilters, techLists)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
            tag?.let { processCard(IsoDep.get(it)) }
        }
    }
}
```

### 2. Process a Visa Transaction

```kotlin
suspend fun processVisaTransaction(isoDep: IsoDep, amountCents: Long) {
    isoDep.connect()
    isoDep.timeout = 5000

    val transceiver = IsoDepTransceiver(isoDep)

    val params = VisaTransactionParams(
        amount = amountCents,
        amountOther = 0,
        transactionType = 0x00, // Purchase
        currencyCode = 0x0840,  // USD
        countryCode = 0x0840,   // USA
        terminalType = 0x22,
        terminalCapabilities = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
        additionalTerminalCapabilities = byteArrayOf(0x8F.toByte(), 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01),
        transactionDate = getCurrentDate(),
        transactionTime = getCurrentTime(),
        unpredictableNumber = generateUnpredictableNumber()
    )

    val kernel = VisaContactlessKernel(transceiver, params)
    val outcome = kernel.processTransaction(aid)

    when (outcome.type) {
        VisaOutcomeType.APPROVED -> {
            // Offline approval - transaction complete
        }
        VisaOutcomeType.ONLINE_REQUEST -> {
            // Send ARQC to payment processor
            val arqc = outcome.cryptogram
            val authData = outcome.toAuthorizationData()
            // sendToProcessor(authData)
        }
        VisaOutcomeType.DECLINED -> {
            // Transaction declined
        }
        VisaOutcomeType.TRY_ANOTHER_INTERFACE -> {
            // Card requests insert/swipe
        }
    }

    isoDep.close()
}
```

### 3. Process a Mastercard Transaction

```kotlin
suspend fun processMastercardTransaction(isoDep: IsoDep, amountCents: Long) {
    val transceiver = IsoDepTransceiver(isoDep)

    val params = MastercardTransactionParams(
        amount = amountCents,
        amountOther = 0,
        transactionType = 0x00,
        currencyCode = 0x0840,
        countryCode = 0x0840,
        terminalType = 0x22,
        terminalCapabilities = byteArrayOf(0xE0.toByte(), 0xF0.toByte(), 0xC8.toByte()),
        additionalTerminalCapabilities = byteArrayOf(0x8F.toByte(), 0x00, 0xF0.toByte(), 0xF0.toByte(), 0x01),
        merchantCategoryCode = 0x5411,
        terminalCountryCode = 0x0840,
        transactionDate = getCurrentDate(),
        transactionTime = getCurrentTime(),
        unpredictableNumber = generateUnpredictableNumber()
    )

    val kernel = MastercardContactlessKernel(transceiver, params)
    val outcome = kernel.processTransaction(aid)

    // Handle outcome similar to Visa
}
```

## Transaction Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    EMV Contactless Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. SELECT PPSE          ──────────>  Card                      │
│     (2PAY.SYS.DDF01)     <──────────  Available AIDs            │
│                                                                 │
│  2. SELECT AID           ──────────>  Card                      │
│     (A0000000031010)     <──────────  FCI with PDOL             │
│                                                                 │
│  3. GET PROCESSING OPTS  ──────────>  Card                      │
│     (PDOL data)          <──────────  AIP + AFL                 │
│                                                                 │
│  4. READ RECORD(s)       ──────────>  Card                      │
│                          <──────────  Card data (Track2, etc.)  │
│                                                                 │
│  5. [Optional] ODA       Verify certificates and signatures     │
│                                                                 │
│  6. [Optional] CVM       Cardholder verification (PIN/CDCVM)    │
│                                                                 │
│  7. Terminal Action      TAC/IAC analysis                       │
│     Analysis                                                    │
│                                                                 │
│  8. GENERATE AC          ──────────>  Card                      │
│     (CDOL1 data)         <──────────  Cryptogram (TC/ARQC/AAC)  │
│                                                                 │
│  9. Outcome              APPROVED / ONLINE_REQUEST / DECLINED   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## EMV Tags Reference

Key EMV tags used by the SDK:

| Tag | Name | Description |
|-----|------|-------------|
| 9F26 | Application Cryptogram | TC, ARQC, or AAC |
| 9F27 | Cryptogram Information Data | Type of cryptogram |
| 9F10 | Issuer Application Data | Card-specific data |
| 9F37 | Unpredictable Number | Random 4 bytes |
| 9F36 | Application Transaction Counter | ATC |
| 57 | Track 2 Equivalent Data | Card number, expiry |
| 5A | Application PAN | Primary Account Number |
| 9F6C | Card Transaction Qualifiers | Mastercard CTQ |
| 9F66 | Terminal Transaction Qualifiers | Visa TTQ |

## Testing

### Unit Tests

```bash
./gradlew :sdk:test
```

### With EMVCo Test Cards

1. Build and install the sample app
2. Configure transaction amount
3. Tap an EMVCo test card
4. Review transaction log for APDU traces

### Test Card AIDs

| Network | AID |
|---------|-----|
| Visa Credit | A0000000031010 |
| Visa Debit | A0000000032010 |
| Mastercard Credit | A0000000041010 |
| Mastercard Debit | A0000000042010 |

## Certification Path

To achieve production certification:

1. **EMVCo L2 Certification**
   - Contact test labs (UL, Fime, etc.)
   - Pass EMVCo test suite
   - Obtain Letter of Approval (LOA)

2. **Card Network Certification**
   - Visa Tap to Phone certification
   - Mastercard SBMP certification
   - AmEx certification (if supported)

3. **PCI Compliance**
   - PCI PTS POI certification
   - PCI DSS for backend systems

## Security Considerations

- This SDK is designed for SoftPOS/Tap-to-Phone use cases
- Production deployments must include:
  - Device attestation (SafetyNet/Play Integrity)
  - Secure key injection
  - Tamper detection
  - Root/jailbreak detection
  - Secure communication channels

## License

Proprietary - All rights reserved.

## Contact

For questions about certification, licensing, or technical support:
- Email: support@atlas.com
