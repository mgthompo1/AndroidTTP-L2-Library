# Changelog

All notable changes to the EMV SoftPOS SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-19

### Added

#### Core EMV Infrastructure
- `EmvTags.kt` - Comprehensive EMV tag definitions for all major payment networks
  - Visa-specific tags (TTQ, CVR, Form Factor Indicator, etc.)
  - Mastercard-specific tags (TIP, CTQ, Third Party Data, etc.)
  - Common EMV tags (AID, PAN, Track 2, Cryptogram, etc.)
  - Tag metadata including name, format, and description

- `DolParser.kt` - Production-grade DOL (Data Object List) parser
  - Parse PDOL, CDOL1, CDOL2, DDOL, TDOL formats
  - Build DOL data with proper tag-length-value encoding
  - Support for multi-byte tags and variable length fields
  - Validate DOL structure and completeness

- `TerminalVerificationResults.kt` - Complete TVR/TSI bit manipulation
  - All TVR bytes: Offline Data Auth, ICC Data, Terminal, Risk Management, CVM
  - Individual bit getters/setters for each condition
  - Support for terminal-initiated and card-initiated flags
  - TSI tracking for all transaction phases

#### Visa Kernel
- `VisaContactlessKernel.kt` - Full Visa qVSDC implementation
  - Entry Point processing per Visa specifications
  - Terminal Transaction Qualifiers (TTQ) handling
  - Visa-specific CVM rules
  - Online/offline decision logic
  - fDDA support for Visa cards
  - Complete outcome handling (Approved, Online, Declined, Try Another Interface)

- `VisaDataElements.kt` - Visa-specific data structures
  - Card Transaction Qualifiers (CTQ)
  - Customer Verification Results (CVR)
  - Form Factor Indicator parsing
  - Track 2 data extraction

#### Mastercard Kernel
- `MastercardContactlessKernel.kt` - Full M/Chip Advance implementation
  - EMV mode and Mag Stripe mode support
  - Terminal Interchange Profile (TIP) handling
  - Mastercard-specific CVM processing
  - Kernel 2 outcome generation
  - RRP (Relay Resistance Protocol) support structure

- `MastercardDataElements.kt` - Mastercard-specific data structures
  - Terminal Interchange Profile (TIP)
  - Card Transaction Qualifiers (CTQ)
  - Third Party Data parsing
  - Issuer Application Data parsing
  - Mastercard CVR interpretation

#### Cryptographic Operations
- `EmvCrypto.kt` - EMV cryptographic functions
  - Triple DES encryption/decryption
  - MAC generation (Algorithm 3, Method 2)
  - Key derivation functions
  - Session key generation
  - PAN hash computation

- `OfflineDataAuthentication.kt` - Complete ODA implementation
  - Static Data Authentication (SDA)
  - Dynamic Data Authentication (DDA)
  - Fast DDA (fDDA) for contactless
  - Combined DDA/AC Generation (CDA)
  - RSA certificate chain validation
  - CA public key recovery
  - Issuer public key recovery
  - ICC public key recovery

#### NFC Infrastructure
- `NfcCardReader.kt` - Android NFC handling
  - Foreground dispatch setup
  - IsoDep connection management
  - Tag technology detection
  - Timeout handling

- `CardTransceiver.kt` - APDU communication interface
  - Command/Response exchange
  - Status word interpretation
  - Logging support for debugging

#### Sample Application
- `MainActivity.kt` - Complete test transaction UI
  - Jetpack Compose interface
  - Transaction state management
  - Real-time APDU logging
  - AID detection display
  - Outcome visualization

### Technical Specifications

- **Minimum SDK**: Android API 26 (8.0 Oreo)
- **Target SDK**: Android API 34 (14)
- **Kotlin Version**: 1.9.22
- **Java Version**: 17
- **Compose BOM**: 2024.01.00

### Dependencies

```
kotlinx-coroutines-android:1.7.3
kotlinx-serialization-json:1.6.2
androidx.core:core-ktx:1.12.0
androidx.biometric:biometric:1.1.0
androidx.security:security-crypto:1.1.0-alpha06
com.google.android.play:integrity:1.3.0
com.jakewharton.timber:timber:5.0.1
```

### Known Limitations

- AmEx ExpressPay kernel: Architecture defined, implementation pending
- Discover D-PAS kernel: Architecture defined, implementation pending
- UnionPay QuickPass kernel: Architecture defined, implementation pending
- Online PIN entry UI: Placeholder only
- 2nd Generate AC: Structure present, issuer scripts not processed

### Certification Status

- EMVCo L2: Ready for test lab submission
- Visa: Pending certification
- Mastercard: Pending certification

---

## [Unreleased]

### Planned
- AmEx ExpressPay kernel implementation
- Discover D-PAS kernel implementation
- UnionPay QuickPass kernel implementation
- Issuer script processing (2nd GENERATE AC)
- Enhanced error recovery mechanisms
- Performance optimizations for high-volume testing
