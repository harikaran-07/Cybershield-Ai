package com.cybershieldai.ai

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import com.cybershieldai.data.local.SettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * CyberShield AI chat controller (spec §4): fully on-device conversation state
 * around [LocalLlmRuntime]. No network is touched at any point (spec §1/§18).
 *
 * Lifecycle: create when the chat screen enters composition, call [dispose]
 * when it leaves — that releases model memory (spec §21).
 */
class CyberShieldChat(private val context: Context) {

    data class ChatMessage(
        val role: Role,
        val content: String,
        val timestamp: Long = System.currentTimeMillis()
    ) {
        enum class Role { USER, ASSISTANT }
    }

    enum class ModelState { NOT_INSTALLED, LOADING, READY, ERROR }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var genJob: Job? = null
    private var lastUserText: String? = null
    private var lastContext: String? = null

    private val _messages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val messages: StateFlow<List<ChatMessage>> = _messages

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy

    private val _modelState = MutableStateFlow(ModelState.NOT_INSTALLED)
    val modelState: StateFlow<ModelState> = _modelState

    private val _modelError = MutableStateFlow<String?>(null)
    val modelError: StateFlow<String?> = _modelError

    /** Compact system prompt (spec §5) — safety rails for the on-device model. */
    private val systemPrompt =
        "You are CyberShield AI, an offline cybersecurity assistant running directly " +
            "on the user's Android device. Explain security issues clearly and " +
            "conservatively. Use CyberShield's locally detected security information " +
            "when provided. Never request passwords, OTPs, PINs, CVVs, authentication " +
            "codes, or private keys. Do not claim certainty when evidence is " +
            "incomplete. Never claim to have accessed the Internet or an external " +
            "service. Provide safe defensive guidance."

    init {
        refreshModelState()
    }

    /** Re-check install state (real file existence, not a cached flag). */
    fun refreshModelState() {
        _modelState.value =
            if (AiModelManager.isInstalled(context)) ModelState.READY
            else ModelState.NOT_INSTALLED
    }

    /**
     * Send a user message and stream the on-device answer.
     * @param securityContext optional locally-detected context (reports,
     *   screening results) the model may reference — never invented content.
     */
    fun send(text: String, securityContext: String? = null) {
        val trimmed = text.trim()
        if (trimmed.isEmpty() || _busy.value) return
        lastUserText = trimmed
        lastContext = securityContext

        _messages.value += ChatMessage(ChatMessage.Role.USER, trimmed)
        _messages.value += ChatMessage(ChatMessage.Role.ASSISTANT, "")

        genJob = scope.launch { stream(trimmed, securityContext) }
    }

    /** Regenerate the answer for the last user message (spec §4 Retry). */
    fun retry() {
        val text = lastUserText ?: return
        if (_busy.value) return
        // Drop the previous assistant reply for this turn.
        val msgs = _messages.value.toMutableList()
        while (msgs.isNotEmpty() && msgs.last().role == ChatMessage.Role.ASSISTANT) {
            msgs.removeAt(msgs.size - 1)
        }
        _messages.value = msgs + ChatMessage(ChatMessage.Role.ASSISTANT, "")
        genJob = scope.launch { stream(text, lastContext) }
    }

    /** Stop the in-flight generation (spec §4 Stop). */
    fun stop() {
        genJob?.cancel()
        genJob = null
        _busy.value = false
        // Leave any partial text that already streamed — it is real output.
    }

    /** Copy a message to the clipboard (spec §4 Copy). */
    fun copy(context: Context, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("CyberShield AI", text))
    }

    /** Clear the conversation. */
    fun clear() {
        genJob?.cancel()
        genJob = null
        lastUserText = null
        lastContext = null
        _messages.value = emptyList()
        _modelError.value = null
    }

    /** Release the model — call when the chat screen leaves (spec §21). */
    fun dispose() {
        genJob?.cancel()
        scope.cancel()
        LocalLlmRuntime.release()
    }

    private suspend fun stream(userText: String, securityContext: String?) {
        _busy.value = true
        _modelError.value = null

        if (!AiModelManager.isInstalled(context)) {
            _modelState.value = ModelState.NOT_INSTALLED
            replaceLastAssistant(
                "Local AI is not installed yet. Install the model in AI Model " +
                    "Settings — CyberShield security protection remains active meanwhile."
            )
            _busy.value = false
            return
        }

        _modelState.value = ModelState.LOADING
        val loaded = LocalLlmRuntime.load(context)
        loaded.fold(
            onSuccess = { _modelState.value = ModelState.READY },
            onFailure = { t ->
                _modelState.value = ModelState.ERROR
                _modelError.value = t.message
                replaceLastAssistant(
                    "Local AI is unavailable on this device. " +
                        "CyberShield security protection remains active."
                )
                _busy.value = false
                return
            }
        )

        val prompt = buildPrompt(userText, securityContext)
        val sb = StringBuilder()
        try {
            LocalLlmRuntime.generate(prompt).collect { token ->
                sb.append(token)
                replaceLastAssistant(sb.toString())
            }
            if (sb.isBlank()) replaceLastAssistant(
                "(The model returned no output for this question. Try rephrasing.)"
            )
        } catch (t: Throwable) {
            if (sb.isBlank()) {
                _modelError.value = t.message
                replaceLastAssistant("Generation stopped.")
            }
        } finally {
            _busy.value = false
        }
    }

    private suspend fun buildPrompt(userText: String, securityContext: String?): String {
        val sb = StringBuilder(systemPrompt)
        if (!securityContext.isNullOrBlank()) {
            sb.append("\n\nLocal CyberShield security context (use only what is present, do not invent more):\n")
                .append(securityContext)
        }
        val explain = SettingsStore(context).aiExplainEnabled.first()
        if (explain) sb.append("\nAnswer in 2-4 short sentences.")
        sb.append("\n\nUser: ").append(userText.trim()).append("\nAssistant:")
        return sb.toString()
    }

    private fun replaceLastAssistant(text: String) {
        val msgs = _messages.value.toMutableList()
        for (i in msgs.indices.reversed()) {
            if (msgs[i].role == ChatMessage.Role.ASSISTANT) {
                msgs[i] = msgs[i].copy(content = text)
                break
            }
        }
        _messages.value = msgs
    }
}
