package com.atlas.softpos.crypto

import com.atlas.softpos.kernel.common.CardTransceiver
import com.atlas.softpos.core.apdu.CommandApdu
import com.atlas.softpos.core.apdu.ResponseApdu
import timber.log.Timber

/**
 * Issuer Script Processor
 *
 * Handles authenticated execution of issuer scripts (Tag 71/72) with:
 * - Pre-execution authentication via Tag 91
 * - Command whitelist validation
 * - Proper error handling per EMV Book 3
 * - TVR updates on script failure
 *
 * Reference: EMV Book 3 Section 10.10 - Script Processing
 */
class IssuerScriptProcessor(
    private val transceiver: CardTransceiver
) {
    /**
     * Process issuer scripts with full authentication
     *
     * @param scripts Parsed script data from online response
     * @param authResult Issuer authentication result (must be Success)
     * @param tvr Current Terminal Verification Results (will be updated)
     * @param scriptType Whether this is pre or post second GENERATE AC
     * @return Processing result with execution details
     */
    suspend fun processScripts(
        scripts: IssuerScripts,
        authResult: IssuerScriptAuthenticator.IssuerAuthResult,
        tvr: ByteArray,
        scriptType: ScriptType
    ): ScriptProcessingResult {
        // Verify issuer was authenticated
        if (authResult !is IssuerScriptAuthenticator.IssuerAuthResult.Success) {
            Timber.w("Cannot execute scripts - issuer not authenticated")
            setTvrScriptFailed(tvr, scriptType)
            return ScriptProcessingResult.AuthenticationRequired
        }

        val scriptData = when (scriptType) {
            ScriptType.SCRIPT_71 -> scripts.script71
            ScriptType.SCRIPT_72 -> scripts.script72
        }

        if (scriptData == null || scriptData.isEmpty()) {
            Timber.d("No ${scriptType.name} scripts to process")
            return ScriptProcessingResult.NoScripts
        }

        // Parse script commands
        val commands = IssuerScriptAuthenticator.parseScriptTemplate(scriptData)
        if (commands.isEmpty()) {
            return ScriptProcessingResult.NoScripts
        }

        val results = mutableListOf<CommandResult>()
        var aborted = false

        for ((index, command) in commands.withIndex()) {
            // Skip disallowed commands
            if (!command.isAllowed) {
                Timber.w("Skipping disallowed command: ${command.instructionName}")
                results.add(CommandResult(
                    command = command,
                    status = CommandStatus.BLOCKED,
                    sw = 0
                ))
                continue
            }

            // Execute command
            val result = executeScriptCommand(command)
            results.add(result)

            // Check for abort conditions
            when {
                result.status == CommandStatus.ABORTED -> {
                    // SW=6985 on Tag 71 means abort remaining scripts
                    if (scriptType == ScriptType.SCRIPT_71) {
                        Timber.w("Script 71 aborted at command $index (SW=6985)")
                        aborted = true
                        break
                    }
                }
                result.status == CommandStatus.FAILED -> {
                    // Set TVR bit but continue processing
                    setTvrScriptFailed(tvr, scriptType)
                }
            }
        }

        val successCount = results.count { it.status == CommandStatus.SUCCESS }
        val totalCount = results.size

        Timber.d("Script processing complete: $successCount/$totalCount commands succeeded")

        return when {
            aborted -> {
                setTvrScriptFailed(tvr, scriptType)
                ScriptProcessingResult.Aborted(results)
            }
            successCount == totalCount -> ScriptProcessingResult.Success(results)
            successCount > 0 -> {
                setTvrScriptFailed(tvr, scriptType)
                ScriptProcessingResult.PartialSuccess(results)
            }
            else -> {
                setTvrScriptFailed(tvr, scriptType)
                ScriptProcessingResult.Failed(results)
            }
        }
    }

    /**
     * Execute a single script command
     */
    private suspend fun executeScriptCommand(
        command: IssuerScriptAuthenticator.ScriptCommand
    ): CommandResult {
        return try {
            // Build APDU from raw command data
            val apdu = buildApduFromRaw(command.data)
                ?: return CommandResult(command, CommandStatus.INVALID, 0)

            val response = transceiver.transceive(apdu)

            val status = when {
                response.isSuccess -> CommandStatus.SUCCESS
                response.sw == 0x6985 -> CommandStatus.ABORTED  // Conditions not satisfied
                response.sw == 0x6984 -> CommandStatus.FAILED   // Referenced data invalidated
                response.sw == 0x6A82 -> CommandStatus.FAILED   // File not found
                response.sw == 0x6A80 -> CommandStatus.FAILED   // Incorrect data
                else -> CommandStatus.FAILED
            }

            Timber.d("Script command ${command.instructionName}: SW=%04X, status=$status", response.sw)

            CommandResult(command, status, response.sw)
        } catch (e: Exception) {
            Timber.e(e, "Script command execution failed")
            CommandResult(command, CommandStatus.ERROR, 0)
        }
    }

    /**
     * Build CommandApdu from raw command bytes
     */
    private fun buildApduFromRaw(data: ByteArray): CommandApdu? {
        if (data.size < 4) return null

        val cla = data[0]
        val ins = data[1]
        val p1 = data[2]
        val p2 = data[3]

        return when {
            data.size == 4 -> {
                // Case 1: No data, no Le
                CommandApdu(cla, ins, p1, p2, null, null)
            }
            data.size == 5 -> {
                // Case 2: No data, Le present
                CommandApdu(cla, ins, p1, p2, null, data[4].toInt() and 0xFF)
            }
            else -> {
                // Case 3 or 4: Data present
                val lc = data[4].toInt() and 0xFF
                if (data.size < 5 + lc) return null

                val commandData = data.copyOfRange(5, 5 + lc)
                val le = if (data.size > 5 + lc) {
                    data[5 + lc].toInt() and 0xFF
                } else null

                CommandApdu(cla, ins, p1, p2, commandData, le)
            }
        }
    }

    /**
     * Set TVR script processing failed bit
     * TVR Byte 5, Bit 2 = Script processing failed after final GENERATE AC
     * TVR Byte 5, Bit 3 = Script processing failed before final GENERATE AC
     */
    private fun setTvrScriptFailed(tvr: ByteArray, scriptType: ScriptType) {
        if (tvr.size < 5) return

        when (scriptType) {
            ScriptType.SCRIPT_71 -> {
                // Bit 3 of byte 5 (before final GENERATE AC)
                tvr[4] = (tvr[4].toInt() or 0x08).toByte()
            }
            ScriptType.SCRIPT_72 -> {
                // Bit 2 of byte 5 (after final GENERATE AC)
                tvr[4] = (tvr[4].toInt() or 0x04).toByte()
            }
        }
    }

    /**
     * Script execution timing
     */
    enum class ScriptType {
        /** Tag 71 - Executed before second GENERATE AC */
        SCRIPT_71,
        /** Tag 72 - Executed after second GENERATE AC */
        SCRIPT_72
    }

    /**
     * Command execution status
     */
    enum class CommandStatus {
        SUCCESS,    // SW 9000
        FAILED,     // Non-success SW
        ABORTED,    // SW 6985 (conditions not satisfied)
        BLOCKED,    // Command not in whitelist
        INVALID,    // Invalid command format
        ERROR       // Exception during execution
    }

    /**
     * Result of single command execution
     */
    data class CommandResult(
        val command: IssuerScriptAuthenticator.ScriptCommand,
        val status: CommandStatus,
        val sw: Int
    )

    /**
     * Result of script processing
     */
    sealed class ScriptProcessingResult {
        /** All commands executed successfully */
        data class Success(val results: List<CommandResult>) : ScriptProcessingResult()

        /** Some commands succeeded, some failed */
        data class PartialSuccess(val results: List<CommandResult>) : ScriptProcessingResult()

        /** All commands failed */
        data class Failed(val results: List<CommandResult>) : ScriptProcessingResult()

        /** Script processing was aborted (SW=6985) */
        data class Aborted(val results: List<CommandResult>) : ScriptProcessingResult()

        /** No scripts to process */
        object NoScripts : ScriptProcessingResult()

        /** Issuer authentication required before script execution */
        object AuthenticationRequired : ScriptProcessingResult()
    }
}

/**
 * Parsed issuer scripts from online response
 */
data class IssuerScripts(
    /** Tag 71 - Issuer Script Template 1 (before second GENERATE AC) */
    val script71: ByteArray?,
    /** Tag 72 - Issuer Script Template 2 (after second GENERATE AC) */
    val script72: ByteArray?,
    /** Tag 91 - Issuer Authentication Data */
    val issuerAuthData: ByteArray?,
    /** Tag 8A - Authorization Response Code */
    val arc: ByteArray?
) {
    val hasScripts: Boolean
        get() = (script71?.isNotEmpty() == true) || (script72?.isNotEmpty() == true)

    val hasAuthData: Boolean
        get() = issuerAuthData?.isNotEmpty() == true

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IssuerScripts) return false
        return script71.contentEquals(other.script71) &&
                script72.contentEquals(other.script72) &&
                issuerAuthData.contentEquals(other.issuerAuthData)
    }

    override fun hashCode(): Int {
        var result = script71?.contentHashCode() ?: 0
        result = 31 * result + (script72?.contentHashCode() ?: 0)
        result = 31 * result + (issuerAuthData?.contentHashCode() ?: 0)
        return result
    }

    private fun ByteArray?.contentEquals(other: ByteArray?): Boolean {
        if (this == null && other == null) return true
        if (this == null || other == null) return false
        return this.contentEquals(other)
    }
}
