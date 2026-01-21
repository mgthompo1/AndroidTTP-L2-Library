package com.atlas.softpos.core.tlv

/**
 * Complete EMV Tag Definitions
 *
 * Based on EMV Book 3, Annex A and network-specific specifications.
 * Each tag includes: hex value, name, source (card/terminal), format, and length constraints.
 */
object EmvTags {

    // ==================== PRIMITIVE TAGS ====================

    /** Application Identifier (AID) - Card */
    val AID = Tag(0x4F, "Application Identifier (AID)", Source.CARD, Format.BINARY, 5, 16)

    /** Application Label - Card */
    val APPLICATION_LABEL = Tag(0x50, "Application Label", Source.CARD, Format.ANS, 1, 16)

    /** Track 2 Equivalent Data - Card */
    val TRACK2_EQUIVALENT = Tag(0x57, "Track 2 Equivalent Data", Source.CARD, Format.BINARY, 0, 19)

    /** Primary Account Number (PAN) - Card */
    val PAN = Tag(0x5A, "Application PAN", Source.CARD, Format.CN, 0, 10)

    /** Cardholder Name - Card */
    val CARDHOLDER_NAME = Tag(0x5F20, "Cardholder Name", Source.CARD, Format.ANS, 2, 26)

    /** Application Expiration Date - Card */
    val APP_EXPIRY_DATE = Tag(0x5F24, "Application Expiration Date", Source.CARD, Format.N, 3, 3)

    /** Application Effective Date - Card */
    val APP_EFFECTIVE_DATE = Tag(0x5F25, "Application Effective Date", Source.CARD, Format.N, 3, 3)

    /** Issuer Country Code - Card */
    val ISSUER_COUNTRY_CODE = Tag(0x5F28, "Issuer Country Code", Source.CARD, Format.N, 2, 2)

    /** Transaction Currency Code - Terminal */
    val TRANSACTION_CURRENCY_CODE = Tag(0x5F2A, "Transaction Currency Code", Source.TERMINAL, Format.N, 2, 2)

    /** Language Preference - Card */
    val LANGUAGE_PREFERENCE = Tag(0x5F2D, "Language Preference", Source.CARD, Format.AN, 2, 8)

    /** Service Code - Card */
    val SERVICE_CODE = Tag(0x5F30, "Service Code", Source.CARD, Format.N, 2, 2)

    /** PAN Sequence Number - Card */
    val PAN_SEQUENCE_NUMBER = Tag(0x5F34, "PAN Sequence Number", Source.CARD, Format.N, 1, 1)

    /** Transaction Currency Exponent - Terminal */
    val TRANSACTION_CURRENCY_EXPONENT = Tag(0x5F36, "Transaction Currency Exponent", Source.TERMINAL, Format.N, 1, 1)

    // ==================== EMV TAGS (9XXX) ====================

    /** Application Interchange Profile (AIP) - Card */
    val AIP = Tag(0x82, "Application Interchange Profile", Source.CARD, Format.BINARY, 2, 2)

    /** Dedicated File (DF) Name - Card */
    val DF_NAME = Tag(0x84, "Dedicated File Name", Source.CARD, Format.BINARY, 5, 16)

    /** Command Template - Terminal */
    val COMMAND_TEMPLATE = Tag(0x83, "Command Template", Source.TERMINAL, Format.BINARY, 0, 255)

    /** Issuer Script Command - Issuer */
    val ISSUER_SCRIPT_COMMAND = Tag(0x86, "Issuer Script Command", Source.ISSUER, Format.BINARY, 0, 255)

    /** Application Priority Indicator - Card */
    val APP_PRIORITY_INDICATOR = Tag(0x87, "Application Priority Indicator", Source.CARD, Format.BINARY, 1, 1)

    /** Short File Identifier (SFI) - Card */
    val SFI = Tag(0x88, "Short File Identifier", Source.CARD, Format.BINARY, 1, 1)

    /** Authorization Code - Issuer */
    val AUTHORIZATION_CODE = Tag(0x89, "Authorization Code", Source.ISSUER, Format.AN, 6, 6)

    /** Authorization Response Code - Issuer */
    val AUTHORIZATION_RESPONSE_CODE = Tag(0x8A, "Authorization Response Code", Source.ISSUER, Format.AN, 2, 2)

    /** Card Risk Management Data Object List 1 (CDOL1) - Card */
    val CDOL1 = Tag(0x8C, "CDOL1", Source.CARD, Format.BINARY, 0, 252)

    /** Card Risk Management Data Object List 2 (CDOL2) - Card */
    val CDOL2 = Tag(0x8D, "CDOL2", Source.CARD, Format.BINARY, 0, 252)

    /** CVM List - Card */
    val CVM_LIST = Tag(0x8E, "CVM List", Source.CARD, Format.BINARY, 10, 252)

    /** CA Public Key Index - Card */
    val CA_PUBLIC_KEY_INDEX = Tag(0x8F, "CA Public Key Index", Source.CARD, Format.BINARY, 1, 1)

    /** Issuer Public Key Certificate - Card */
    val ISSUER_PK_CERTIFICATE = Tag(0x90, "Issuer PK Certificate", Source.CARD, Format.BINARY, 0, 255)

    /** Issuer Authentication Data - Issuer */
    val ISSUER_AUTH_DATA = Tag(0x91, "Issuer Authentication Data", Source.ISSUER, Format.BINARY, 8, 16)

    /** Issuer Public Key Remainder - Card */
    val ISSUER_PK_REMAINDER = Tag(0x92, "Issuer PK Remainder", Source.CARD, Format.BINARY, 0, 255)

    /** Signed Static Application Data - Card */
    val SSAD = Tag(0x93, "Signed Static Application Data", Source.CARD, Format.BINARY, 0, 255)

    /** Application File Locator (AFL) - Card */
    val AFL = Tag(0x94, "Application File Locator", Source.CARD, Format.BINARY, 0, 252)

    /** Terminal Verification Results (TVR) - Terminal */
    val TVR = Tag(0x95, "Terminal Verification Results", Source.TERMINAL, Format.BINARY, 5, 5)

    /** Transaction Certificate Data Object List (TDOL) - Card */
    val TDOL = Tag(0x97, "TDOL", Source.CARD, Format.BINARY, 0, 252)

    /** Transaction Certificate Hash Value - Terminal */
    val TC_HASH = Tag(0x98, "TC Hash Value", Source.TERMINAL, Format.BINARY, 20, 20)

    /** Transaction PIN Data - Terminal */
    val TXN_PIN_DATA = Tag(0x99, "Transaction PIN Data", Source.TERMINAL, Format.BINARY, 0, 255)

    /** Transaction Date - Terminal */
    val TRANSACTION_DATE = Tag(0x9A, "Transaction Date", Source.TERMINAL, Format.N, 3, 3)

    /** Transaction Status Information (TSI) - Terminal */
    val TSI = Tag(0x9B, "Transaction Status Information", Source.TERMINAL, Format.BINARY, 2, 2)

    /** Transaction Type - Terminal */
    val TRANSACTION_TYPE = Tag(0x9C, "Transaction Type", Source.TERMINAL, Format.N, 1, 1)

    /** Directory Definition File (DDF) Name - Card */
    val DDF_NAME = Tag(0x9D, "DDF Name", Source.CARD, Format.BINARY, 5, 16)

    // ==================== EMV TAGS (9FXXX) ====================

    /** Acquirer Identifier - Terminal */
    val ACQUIRER_ID = Tag(0x9F01, "Acquirer Identifier", Source.TERMINAL, Format.N, 6, 6)

    /** Amount Authorized (Numeric) - Terminal */
    val AMOUNT_AUTHORIZED = Tag(0x9F02, "Amount Authorized", Source.TERMINAL, Format.N, 6, 6)

    /** Amount Other (Numeric) - Terminal */
    val AMOUNT_OTHER = Tag(0x9F03, "Amount Other", Source.TERMINAL, Format.N, 6, 6)

    /** Amount Authorized (Binary) - Terminal */
    val AMOUNT_AUTHORIZED_BINARY = Tag(0x9F04, "Amount Authorized Binary", Source.TERMINAL, Format.BINARY, 4, 4)

    /** Application Discretionary Data - Card */
    val APP_DISCRETIONARY_DATA = Tag(0x9F05, "App Discretionary Data", Source.CARD, Format.BINARY, 1, 32)

    /** AID (Terminal) - Terminal */
    val AID_TERMINAL = Tag(0x9F06, "AID Terminal", Source.TERMINAL, Format.BINARY, 5, 16)

    /** Application Usage Control - Card */
    val AUC = Tag(0x9F07, "Application Usage Control", Source.CARD, Format.BINARY, 2, 2)

    /** Application Version Number (Card) - Card */
    val APP_VERSION_CARD = Tag(0x9F08, "App Version Number Card", Source.CARD, Format.BINARY, 2, 2)

    /** Application Version Number (Terminal) - Terminal */
    val APP_VERSION_TERMINAL = Tag(0x9F09, "App Version Number Terminal", Source.TERMINAL, Format.BINARY, 2, 2)

    /** Cardholder Name Extended - Card */
    val CARDHOLDER_NAME_EXTENDED = Tag(0x9F0B, "Cardholder Name Extended", Source.CARD, Format.ANS, 0, 45)

    /** Issuer Action Code - Default - Card */
    val IAC_DEFAULT = Tag(0x9F0D, "IAC Default", Source.CARD, Format.BINARY, 5, 5)

    /** Issuer Action Code - Denial - Card */
    val IAC_DENIAL = Tag(0x9F0E, "IAC Denial", Source.CARD, Format.BINARY, 5, 5)

    /** Issuer Action Code - Online - Card */
    val IAC_ONLINE = Tag(0x9F0F, "IAC Online", Source.CARD, Format.BINARY, 5, 5)

    /** Issuer Application Data - Card */
    val IAD = Tag(0x9F10, "Issuer Application Data", Source.CARD, Format.BINARY, 0, 32)

    /** Issuer Code Table Index - Card */
    val ISSUER_CODE_TABLE_INDEX = Tag(0x9F11, "Issuer Code Table Index", Source.CARD, Format.N, 1, 1)

    /** Application Preferred Name - Card */
    val APP_PREFERRED_NAME = Tag(0x9F12, "App Preferred Name", Source.CARD, Format.ANS, 1, 16)

    /** Last Online ATC Register - Card */
    val LAST_ONLINE_ATC = Tag(0x9F13, "Last Online ATC", Source.CARD, Format.BINARY, 2, 2)

    /** Lower Consecutive Offline Limit - Card */
    val LCOL = Tag(0x9F14, "Lower Consecutive Offline Limit", Source.CARD, Format.BINARY, 1, 1)

    /** Merchant Category Code - Terminal */
    val MCC = Tag(0x9F15, "Merchant Category Code", Source.TERMINAL, Format.N, 2, 2)

    /** Merchant Identifier - Terminal */
    val MERCHANT_ID = Tag(0x9F16, "Merchant Identifier", Source.TERMINAL, Format.ANS, 15, 15)

    /** PIN Try Counter - Card */
    val PIN_TRY_COUNTER = Tag(0x9F17, "PIN Try Counter", Source.CARD, Format.BINARY, 1, 1)

    /** Issuer Script Identifier - Issuer */
    val ISSUER_SCRIPT_ID = Tag(0x9F18, "Issuer Script Identifier", Source.ISSUER, Format.BINARY, 4, 4)

    /** Terminal Country Code - Terminal */
    val TERMINAL_COUNTRY_CODE = Tag(0x9F1A, "Terminal Country Code", Source.TERMINAL, Format.N, 2, 2)

    /** Terminal Floor Limit - Terminal */
    val TERMINAL_FLOOR_LIMIT = Tag(0x9F1B, "Terminal Floor Limit", Source.TERMINAL, Format.BINARY, 4, 4)

    /** Terminal Identification - Terminal */
    val TERMINAL_ID = Tag(0x9F1C, "Terminal Identification", Source.TERMINAL, Format.AN, 8, 8)

    /** Terminal Risk Management Data - Terminal */
    val TRM_DATA = Tag(0x9F1D, "Terminal Risk Management Data", Source.TERMINAL, Format.BINARY, 1, 8)

    /** Interface Device Serial Number - Terminal */
    val IFD_SERIAL_NUMBER = Tag(0x9F1E, "IFD Serial Number", Source.TERMINAL, Format.AN, 8, 8)

    /** Track 1 Discretionary Data - Card */
    val TRACK1_DISCRETIONARY = Tag(0x9F1F, "Track 1 Discretionary Data", Source.CARD, Format.ANS, 0, 255)

    /** Track 2 Discretionary Data - Card */
    val TRACK2_DISCRETIONARY = Tag(0x9F20, "Track 2 Discretionary Data", Source.CARD, Format.CN, 0, 255)

    /** Transaction Time - Terminal */
    val TRANSACTION_TIME = Tag(0x9F21, "Transaction Time", Source.TERMINAL, Format.N, 3, 3)

    /** Upper Consecutive Offline Limit - Card */
    val UCOL = Tag(0x9F23, "Upper Consecutive Offline Limit", Source.CARD, Format.BINARY, 1, 1)

    /** Application Cryptogram - Card */
    val APPLICATION_CRYPTOGRAM = Tag(0x9F26, "Application Cryptogram", Source.CARD, Format.BINARY, 8, 8)

    /** Cryptogram Information Data - Card */
    val CID = Tag(0x9F27, "Cryptogram Information Data", Source.CARD, Format.BINARY, 1, 1)

    /** ICC PIN Encipherment Public Key Certificate - Card */
    val ICC_PIN_PK_CERT = Tag(0x9F2D, "ICC PIN Encipherment PK Cert", Source.CARD, Format.BINARY, 0, 255)

    /** ICC PIN Encipherment Public Key Exponent - Card */
    val ICC_PIN_PK_EXP = Tag(0x9F2E, "ICC PIN Encipherment PK Exp", Source.CARD, Format.BINARY, 1, 3)

    /** ICC PIN Encipherment Public Key Remainder - Card */
    val ICC_PIN_PK_REM = Tag(0x9F2F, "ICC PIN Encipherment PK Rem", Source.CARD, Format.BINARY, 0, 255)

    /** Issuer Public Key Exponent - Card */
    val ISSUER_PK_EXPONENT = Tag(0x9F32, "Issuer PK Exponent", Source.CARD, Format.BINARY, 1, 3)

    /** Terminal Capabilities - Terminal */
    val TERMINAL_CAPABILITIES = Tag(0x9F33, "Terminal Capabilities", Source.TERMINAL, Format.BINARY, 3, 3)

    /** CVM Results - Terminal */
    val CVM_RESULTS = Tag(0x9F34, "CVM Results", Source.TERMINAL, Format.BINARY, 3, 3)

    /** Terminal Type - Terminal */
    val TERMINAL_TYPE = Tag(0x9F35, "Terminal Type", Source.TERMINAL, Format.N, 1, 1)

    /** Application Transaction Counter (ATC) - Card */
    val ATC = Tag(0x9F36, "Application Transaction Counter", Source.CARD, Format.BINARY, 2, 2)

    /** Unpredictable Number - Terminal */
    val UNPREDICTABLE_NUMBER = Tag(0x9F37, "Unpredictable Number", Source.TERMINAL, Format.BINARY, 4, 4)

    /** PDOL - Card */
    val PDOL = Tag(0x9F38, "PDOL", Source.CARD, Format.BINARY, 0, 252)

    /** Point-of-Service Entry Mode - Terminal */
    val POS_ENTRY_MODE = Tag(0x9F39, "POS Entry Mode", Source.TERMINAL, Format.N, 1, 1)

    /** Amount Reference Currency - Terminal */
    val AMOUNT_REF_CURRENCY = Tag(0x9F3A, "Amount Reference Currency", Source.TERMINAL, Format.BINARY, 4, 4)

    /** Application Reference Currency - Card */
    val APP_REF_CURRENCY = Tag(0x9F3B, "App Reference Currency", Source.CARD, Format.N, 2, 2)

    /** Transaction Reference Currency Code - Terminal */
    val TXN_REF_CURRENCY_CODE = Tag(0x9F3C, "Transaction Ref Currency Code", Source.TERMINAL, Format.N, 2, 2)

    /** Transaction Reference Currency Exponent - Terminal */
    val TXN_REF_CURRENCY_EXP = Tag(0x9F3D, "Transaction Ref Currency Exp", Source.TERMINAL, Format.N, 1, 1)

    /** Additional Terminal Capabilities - Terminal */
    val ADDITIONAL_TERMINAL_CAPS = Tag(0x9F40, "Additional Terminal Capabilities", Source.TERMINAL, Format.BINARY, 5, 5)

    /** Transaction Sequence Counter - Terminal */
    val TRANSACTION_SEQ_COUNTER = Tag(0x9F41, "Transaction Sequence Counter", Source.TERMINAL, Format.N, 4, 8)

    /** Application Currency Code - Card */
    val APP_CURRENCY_CODE = Tag(0x9F42, "Application Currency Code", Source.CARD, Format.N, 2, 2)

    /** Application Currency Exponent - Card */
    val APP_CURRENCY_EXPONENT = Tag(0x9F43, "Application Currency Exponent", Source.CARD, Format.N, 1, 1)

    /** Application Currency Exponent - Card */
    val APP_CURRENCY_EXP = Tag(0x9F44, "App Currency Exponent", Source.CARD, Format.N, 1, 1)

    /** Data Authentication Code - Card */
    val DAC = Tag(0x9F45, "Data Authentication Code", Source.CARD, Format.BINARY, 2, 2)

    /** ICC Public Key Certificate - Card */
    val ICC_PK_CERTIFICATE = Tag(0x9F46, "ICC PK Certificate", Source.CARD, Format.BINARY, 0, 255)

    /** ICC Public Key Exponent - Card */
    val ICC_PK_EXPONENT = Tag(0x9F47, "ICC PK Exponent", Source.CARD, Format.BINARY, 1, 3)

    /** ICC Public Key Remainder - Card */
    val ICC_PK_REMAINDER = Tag(0x9F48, "ICC PK Remainder", Source.CARD, Format.BINARY, 0, 255)

    /** DDOL - Card */
    val DDOL = Tag(0x9F49, "DDOL", Source.CARD, Format.BINARY, 0, 252)

    /** Static Data Authentication Tag List - Card */
    val SDA_TAG_LIST = Tag(0x9F4A, "SDA Tag List", Source.CARD, Format.BINARY, 0, 252)

    /** Signed Dynamic Application Data - Card */
    val SDAD = Tag(0x9F4B, "Signed Dynamic Application Data", Source.CARD, Format.BINARY, 0, 255)

    /** ICC Dynamic Number - Card */
    val ICC_DYNAMIC_NUMBER = Tag(0x9F4C, "ICC Dynamic Number", Source.CARD, Format.BINARY, 2, 8)

    /** Log Entry - Card */
    val LOG_ENTRY = Tag(0x9F4D, "Log Entry", Source.CARD, Format.BINARY, 2, 2)

    /** Merchant Name and Location - Terminal */
    val MERCHANT_NAME_LOCATION = Tag(0x9F4E, "Merchant Name and Location", Source.TERMINAL, Format.ANS, 0, 255)

    // ==================== VISA SPECIFIC TAGS ====================

    /** Terminal Transaction Qualifiers (TTQ) - Terminal */
    val TTQ = Tag(0x9F66, "Terminal Transaction Qualifiers", Source.TERMINAL, Format.BINARY, 4, 4)

    /** Card Transaction Qualifiers (CTQ) - Card */
    val CTQ = Tag(0x9F6C, "Card Transaction Qualifiers", Source.CARD, Format.BINARY, 2, 2)

    /** Form Factor Indicator - Card (Visa) - Note: 0x9F6E also used by Mastercard as Third Party Data */
    val FFI = Tag(0x9F6E, "Form Factor Indicator", Source.CARD, Format.BINARY, 4, 4)

    /** Customer Exclusive Data - Card */
    val CUSTOMER_EXCLUSIVE_DATA = Tag(0x9F7C, "Customer Exclusive Data", Source.CARD, Format.BINARY, 0, 32)

    // ==================== MASTERCARD SPECIFIC TAGS ====================

    /** Kernel Identifier - Terminal */
    val KERNEL_ID = Tag(0x9F2A, "Kernel Identifier", Source.TERMINAL, Format.BINARY, 1, 1)

    /** Card Authentication Related Data - Card */
    val CARD_AUTH_RELATED_DATA = Tag(0x9F69, "Card Auth Related Data", Source.CARD, Format.BINARY, 0, 255)

    /** Contactless Reader Capabilities - Terminal */
    val CL_READER_CAPS = Tag(0x9F6D, "CL Reader Capabilities", Source.TERMINAL, Format.BINARY, 1, 1)

    /** Third Party Data - Card (Mastercard) - Note: Same tag 0x9F6E as Visa FFI, interpretation depends on kernel */
    val THIRD_PARTY_DATA = Tag(0x9F6E, "Third Party Data", Source.CARD, Format.BINARY, 0, 32)

    /** DS Summary 1 - Card */
    val DS_SUMMARY_1 = Tag(0x9F7D, "DS Summary 1", Source.CARD, Format.BINARY, 0, 16)

    /** Offline Accumulator Balance - Card */
    val OFFLINE_ACCUM_BALANCE = Tag(0x9F50, "Offline Accumulator Balance", Source.CARD, Format.BINARY, 6, 6)

    // ==================== KERNEL DATABASE TAGS (DFXXX) ====================

    /** Kernel Configuration - Terminal */
    val KERNEL_CONFIG = Tag(0xDF8101, "Kernel Configuration", Source.TERMINAL, Format.BINARY, 1, 1)

    /** Contactless Floor Limit - Terminal */
    val CL_FLOOR_LIMIT = Tag(0xDF8123, "CL Floor Limit", Source.TERMINAL, Format.BINARY, 6, 6)

    /** CVM Required Limit - Terminal */
    val CVM_REQUIRED_LIMIT = Tag(0xDF8126, "CVM Required Limit", Source.TERMINAL, Format.BINARY, 6, 6)

    /** Reader Contactless Transaction Limit (On-device CVM) - Terminal */
    val CL_TXN_LIMIT_ODCVM = Tag(0xDF8124, "CL Txn Limit ODCVM", Source.TERMINAL, Format.BINARY, 6, 6)

    /** Reader Contactless Transaction Limit (No On-device CVM) - Terminal */
    val CL_TXN_LIMIT_NO_ODCVM = Tag(0xDF8125, "CL Txn Limit No ODCVM", Source.TERMINAL, Format.BINARY, 6, 6)

    /** Hold Time Value - Terminal */
    val HOLD_TIME = Tag(0xDF8130, "Hold Time Value", Source.TERMINAL, Format.BINARY, 1, 1)

    /** Outcome Parameter Set - Terminal */
    val OUTCOME_PARAMETER_SET = Tag(0xDF8129, "Outcome Parameter Set", Source.TERMINAL, Format.BINARY, 8, 8)

    /** Torn Transaction Log - Card */
    val TORN_TXN_LOG = Tag(0xDF8128, "Torn Transaction Log", Source.CARD, Format.BINARY, 0, 255)

    // ==================== TEMPLATE TAGS ====================

    /** Response Message Template Format 1 */
    val RESPONSE_FORMAT_1 = Tag(0x80, "Response Format 1", Source.CARD, Format.BINARY, 0, 255)

    /** Response Message Template Format 2 */
    val RESPONSE_FORMAT_2 = Tag(0x77, "Response Format 2", Source.CARD, Format.CONSTRUCTED, 0, 255)

    /** File Control Information Template */
    val FCI_TEMPLATE = Tag(0x6F, "FCI Template", Source.CARD, Format.CONSTRUCTED, 0, 255)

    /** FCI Proprietary Template */
    val FCI_PROPRIETARY = Tag(0xA5, "FCI Proprietary Template", Source.CARD, Format.CONSTRUCTED, 0, 255)

    /** Application Template / Directory Entry (same tag) */
    val APP_TEMPLATE = Tag(0x61, "Application Template", Source.CARD, Format.CONSTRUCTED, 0, 255)

    /** Alias for APP_TEMPLATE - Directory Entry uses same tag 0x61 */
    val DIRECTORY_ENTRY = APP_TEMPLATE

    /** Record Template */
    val RECORD_TEMPLATE = Tag(0x70, "Record Template", Source.CARD, Format.CONSTRUCTED, 0, 255)

    /** Issuer Script Template 1 */
    val ISSUER_SCRIPT_1 = Tag(0x71, "Issuer Script Template 1", Source.ISSUER, Format.CONSTRUCTED, 0, 255)

    /** Issuer Script Template 2 */
    val ISSUER_SCRIPT_2 = Tag(0x72, "Issuer Script Template 2", Source.ISSUER, Format.CONSTRUCTED, 0, 255)

    // ==================== LOOKUP ====================

    private val allTags: Map<Int, Tag> = mapOf(
        // Primitive tags
        0x4F to AID,
        0x50 to APPLICATION_LABEL,
        0x57 to TRACK2_EQUIVALENT,
        0x5A to PAN,
        0x5F20 to CARDHOLDER_NAME,
        0x5F24 to APP_EXPIRY_DATE,
        0x5F25 to APP_EFFECTIVE_DATE,
        0x5F28 to ISSUER_COUNTRY_CODE,
        0x5F2A to TRANSACTION_CURRENCY_CODE,
        0x5F2D to LANGUAGE_PREFERENCE,
        0x5F30 to SERVICE_CODE,
        0x5F34 to PAN_SEQUENCE_NUMBER,
        0x5F36 to TRANSACTION_CURRENCY_EXPONENT,

        // EMV tags (8X, 9X)
        0x82 to AIP,
        0x83 to COMMAND_TEMPLATE,
        0x84 to DF_NAME,
        0x86 to ISSUER_SCRIPT_COMMAND,
        0x87 to APP_PRIORITY_INDICATOR,
        0x88 to SFI,
        0x89 to AUTHORIZATION_CODE,
        0x8A to AUTHORIZATION_RESPONSE_CODE,
        0x8C to CDOL1,
        0x8D to CDOL2,
        0x8E to CVM_LIST,
        0x8F to CA_PUBLIC_KEY_INDEX,
        0x90 to ISSUER_PK_CERTIFICATE,
        0x91 to ISSUER_AUTH_DATA,
        0x92 to ISSUER_PK_REMAINDER,
        0x93 to SSAD,
        0x94 to AFL,
        0x95 to TVR,
        0x97 to TDOL,
        0x98 to TC_HASH,
        0x99 to TXN_PIN_DATA,
        0x9A to TRANSACTION_DATE,
        0x9B to TSI,
        0x9C to TRANSACTION_TYPE,
        0x9D to DDF_NAME,

        // EMV tags (9FXXX)
        0x9F01 to ACQUIRER_ID,
        0x9F02 to AMOUNT_AUTHORIZED,
        0x9F03 to AMOUNT_OTHER,
        0x9F04 to AMOUNT_AUTHORIZED_BINARY,
        0x9F05 to APP_DISCRETIONARY_DATA,
        0x9F06 to AID_TERMINAL,
        0x9F07 to AUC,
        0x9F08 to APP_VERSION_CARD,
        0x9F09 to APP_VERSION_TERMINAL,
        0x9F0B to CARDHOLDER_NAME_EXTENDED,
        0x9F0D to IAC_DEFAULT,
        0x9F0E to IAC_DENIAL,
        0x9F0F to IAC_ONLINE,
        0x9F10 to IAD,
        0x9F11 to ISSUER_CODE_TABLE_INDEX,
        0x9F12 to APP_PREFERRED_NAME,
        0x9F13 to LAST_ONLINE_ATC,
        0x9F14 to LCOL,
        0x9F15 to MCC,
        0x9F16 to MERCHANT_ID,
        0x9F17 to PIN_TRY_COUNTER,
        0x9F18 to ISSUER_SCRIPT_ID,
        0x9F1A to TERMINAL_COUNTRY_CODE,
        0x9F1B to TERMINAL_FLOOR_LIMIT,
        0x9F1C to TERMINAL_ID,
        0x9F1D to TRM_DATA,
        0x9F1E to IFD_SERIAL_NUMBER,
        0x9F1F to TRACK1_DISCRETIONARY,
        0x9F20 to TRACK2_DISCRETIONARY,
        0x9F21 to TRANSACTION_TIME,
        0x9F23 to UCOL,
        0x9F26 to APPLICATION_CRYPTOGRAM,
        0x9F27 to CID,
        0x9F2A to KERNEL_ID,
        0x9F2D to ICC_PIN_PK_CERT,
        0x9F2E to ICC_PIN_PK_EXP,
        0x9F2F to ICC_PIN_PK_REM,
        0x9F32 to ISSUER_PK_EXPONENT,
        0x9F33 to TERMINAL_CAPABILITIES,
        0x9F34 to CVM_RESULTS,
        0x9F35 to TERMINAL_TYPE,
        0x9F36 to ATC,
        0x9F37 to UNPREDICTABLE_NUMBER,
        0x9F38 to PDOL,
        0x9F39 to POS_ENTRY_MODE,
        0x9F3A to AMOUNT_REF_CURRENCY,
        0x9F3B to APP_REF_CURRENCY,
        0x9F3C to TXN_REF_CURRENCY_CODE,
        0x9F3D to TXN_REF_CURRENCY_EXP,
        0x9F40 to ADDITIONAL_TERMINAL_CAPS,
        0x9F41 to TRANSACTION_SEQ_COUNTER,
        0x9F42 to APP_CURRENCY_CODE,
        0x9F43 to APP_CURRENCY_EXPONENT,
        0x9F44 to APP_CURRENCY_EXP,
        0x9F45 to DAC,
        0x9F46 to ICC_PK_CERTIFICATE,
        0x9F47 to ICC_PK_EXPONENT,
        0x9F48 to ICC_PK_REMAINDER,
        0x9F49 to DDOL,
        0x9F4A to SDA_TAG_LIST,
        0x9F4B to SDAD,
        0x9F4C to ICC_DYNAMIC_NUMBER,
        0x9F4D to LOG_ENTRY,
        0x9F4E to MERCHANT_NAME_LOCATION,
        0x9F50 to OFFLINE_ACCUM_BALANCE,
        0x9F66 to TTQ,
        0x9F69 to CARD_AUTH_RELATED_DATA,
        0x9F6C to CTQ,
        0x9F6D to CL_READER_CAPS,
        0x9F6E to FFI,  // Note: Mastercard uses this as THIRD_PARTY_DATA
        0x9F7C to CUSTOMER_EXCLUSIVE_DATA,
        0x9F7D to DS_SUMMARY_1,

        // Template tags
        0x61 to APP_TEMPLATE,
        0x6F to FCI_TEMPLATE,
        0x70 to RECORD_TEMPLATE,
        0x71 to ISSUER_SCRIPT_1,
        0x72 to ISSUER_SCRIPT_2,
        0x77 to RESPONSE_FORMAT_2,
        0x80 to RESPONSE_FORMAT_1,
        0xA5 to FCI_PROPRIETARY,

        // Kernel database tags (DFXXX)
        0xDF8101 to KERNEL_CONFIG,
        0xDF8123 to CL_FLOOR_LIMIT,
        0xDF8124 to CL_TXN_LIMIT_ODCVM,
        0xDF8125 to CL_TXN_LIMIT_NO_ODCVM,
        0xDF8126 to CVM_REQUIRED_LIMIT,
        0xDF8128 to TORN_TXN_LOG,
        0xDF8129 to OUTCOME_PARAMETER_SET,
        0xDF8130 to HOLD_TIME
    )

    fun get(tagValue: Int): Tag? = allTags[tagValue]

    fun get(tagHex: String): Tag? {
        val value = tagHex.toIntOrNull(16) ?: return null
        return allTags[value]
    }

    /** Get all defined tags */
    fun all(): Collection<Tag> = allTags.values

    /** Check if a tag value is known */
    fun isKnown(tagValue: Int): Boolean = allTags.containsKey(tagValue)

    /** Check if a tag hex is known */
    fun isKnown(tagHex: String): Boolean = get(tagHex) != null
}

/**
 * EMV Tag definition
 */
data class Tag(
    val value: Int,
    val name: String,
    val source: Source,
    val format: Format,
    val minLength: Int,
    val maxLength: Int
) {
    /** Tag value as hex string (e.g., "9F66", "DF8101") */
    val hex: String get() = when {
        value > 0xFFFF -> "%06X".format(value)
        value > 0xFF -> "%04X".format(value)
        else -> "%02X".format(value)
    }

    /** Tag value as byte array for encoding */
    val bytes: ByteArray get() = when {
        value > 0xFFFF -> byteArrayOf(
            (value shr 16).toByte(),
            (value shr 8).toByte(),
            (value and 0xFF).toByte()
        )
        value > 0xFF -> byteArrayOf(
            (value shr 8).toByte(),
            (value and 0xFF).toByte()
        )
        else -> byteArrayOf(value.toByte())
    }

    /** Check if data length is valid for this tag */
    fun isValidLength(length: Int): Boolean = length in minLength..maxLength

    /** Check if data is valid for this tag */
    fun isValidData(data: ByteArray): Boolean = isValidLength(data.size)
}

enum class Source {
    CARD,
    TERMINAL,
    ISSUER
}

enum class Format {
    BINARY,
    CN,         // Compressed Numeric
    N,          // Numeric
    AN,         // Alphanumeric
    ANS,        // Alphanumeric Special
    CONSTRUCTED // Contains nested TLV
}
