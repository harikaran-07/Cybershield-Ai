package com.cybershieldai.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybershieldai.data.model.*
import com.cybershieldai.data.repository.ScanRepository
import com.cybershieldai.utils.AppScanner
import com.cybershieldai.utils.NetworkStatsCollector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch

/** App-permission security overview (device-side collection + backend analysis). */
class SecurityViewModel(
    private val repository: ScanRepository = ScanRepository()
) : ViewModel() {

    sealed class AppState {
        data object Idle : AppState()
        data object Loading : AppState()
        data class Ready(val result: AppSecurityResult) : AppState()
        data class Unavailable(val reason: String) : AppState()
        data class Error(val message: String) : AppState()
    }

    private val _appState = MutableStateFlow<AppState>(AppState.Idle)
    val appState: StateFlow<AppState> = _appState

    sealed class NetState {
        data object Idle : NetState()
        data object Loading : NetState()
        data class Ready(val analysis: NetworkAnalysis) : NetState()
        data class Unavailable(val reason: String) : NetState()
        data class Error(val message: String) : NetState()
    }

    private val _netState = MutableStateFlow<NetState>(NetState.Idle)
    val netState: StateFlow<NetState> = _netState

    private val _aiContext = MutableStateFlow<Map<String, Any?>>(emptyMap())
    val aiContext: StateFlow<Map<String, Any?>> = _aiContext

    /** On-device LLM explanation of the riskiest app (§7) — evidence-only. */
    data class AppAiSummary(
        val appName: String,
        val text: String,
        val fromLlm: Boolean
    )

    private val _appAiSummary = MutableStateFlow<AppAiSummary?>(null)
    val appAiSummary: StateFlow<AppAiSummary?> = _appAiSummary

    /**
     * Run the on-device AI over the TOP flagged app's permission evidence.
     * Deterministic labels/scores are NOT changed — this only adds the plain-
     * language explanation (§3: LLM explains, engine decides).
     */
    fun loadAppAiSummary(context: android.content.Context) {
        val s = _appState.value as? AppState.Ready ?: return
        val top = s.result.apps.maxByOrNull { it.riskScore } ?: return
        viewModelScope.launch {
            try {
                val signals = com.cybershieldai.ai.ScannerAiAnalyzer.Signals(
                    type = "APP",
                    title = top.appName ?: top.packageName,
                    features = buildList {
                        add("package: ${top.packageName}")
                        add("risk_label: ${top.label}")
                        top.permissions.take(8).forEach {
                            add("permission: ${it.permission.substringAfterLast('.')} (${it.category})")
                        }
                    },
                    ruleClassification = top.label,
                    ruleRiskScore = top.riskScore,
                    ruleIndicators = top.notes.ifEmpty {
                        top.permissions.map { "${it.permission.substringAfterLast('.')} (${it.category})" }
                    }
                )
                val (verdict, engine) =
                    com.cybershieldai.ai.ScannerAiAnalyzer.analyze(context, signals)
                _appAiSummary.value = AppAiSummary(
                    appName = top.appName ?: top.packageName,
                    text = verdict.summary.ifEmpty {
                        "Review this app's permissions in Android Settings."
                    },
                    fromLlm = engine == com.cybershieldai.ai.ScannerAiAnalyzer.Engine.LOCAL_READY
                )
            } catch (_: Exception) {
                _appAiSummary.value = null // honest: no AI line on failure
            }
        }
    }

    fun loadAppSecurity(context: android.content.Context) {
        _appState.value = AppState.Loading
        viewModelScope.launch {
            val apps = AppScanner.collectInstalledApps(context)
            if (apps == null) {
                _appState.value = AppState.Unavailable(
                    "App list unavailable on this device. Grant 'Apps' access in Settings to enable this overview.")
                return@launch
            }
            // Fully on-device: PackageManager metadata analyzed by AppRiskAnalyzer
            // (+ the local LLM explanation). No backend exists to call.
            try {
                val analyses = apps.map { info ->
                    val r = com.cybershieldai.utils.AppRiskAnalyzer.analyze(context, info)
                    com.cybershieldai.data.model.AppAnalysis(
                        packageName = r.app.packageName,
                        appName = r.appName,
                        riskScore = r.overallScore,
                        label = r.status,
                        permissions = r.permissions.map { p ->
                            com.cybershieldai.data.model.PermissionInfo(
                                permission = p,
                                category = com.cybershieldai.utils.AppRiskAnalyzer
                                    .SENSITIVE[p] ?: "Other")
                        },
                        notes = r.findings
                    )
                }
                val risky = analyses.filter { it.label != com.cybershieldai.utils.AppRiskAnalyzer.SAFE }
                val result = com.cybershieldai.data.model.AppSecurityResult(
                    apps = analyses,
                    summary = com.cybershieldai.data.model.AppSummary(
                        totalApps = analyses.size,
                        riskyCount = risky.size,
                        topRisky = risky.sortedByDescending { it.riskScore }
                            .take(3).mapNotNull { it.appName ?: it.packageName },
                        avgRisk = if (analyses.isEmpty()) 0.0
                        else analyses.sumOf { it.riskScore }.toDouble() / analyses.size
                    ),
                    disclaimer = "On-device analysis of installed-app metadata " +
                        "(permissions, install source). CyberShield cannot see " +
                        "inside other apps' private data."
                )
                _appState.value = AppState.Ready(result)
                analyses.maxByOrNull { it.riskScore }?.let { worst ->
                    _aiContext.value = _aiContext.value + mapOf(
                        "highest_risk_app" to worst.packageName,
                        "highest_app_risk" to worst.riskScore
                    )
                }
            } catch (e: Exception) {
                _appState.value = AppState.Error(
                    "App analysis failed on this device: ${e.message ?: e.javaClass.simpleName}")
            }
        }
    }

    fun loadNetworkSecurity() {
        _netState.value = NetState.Loading
        viewModelScope.launch {
            val stats = NetworkStatsCollector.snapshot()
            if (stats == null) {
                _netState.value = NetState.Unavailable(
                    "Network metadata requires the optional VPN module. Enable it in Settings with your consent.")
                return@launch
            }
            // Fully on-device: transparent heuristics over connection metadata.
            try {
                val flagged = stats.filter { it.distinctPorts >= 8 }
                    .map { it.destination }
                val verdict = when {
                    flagged.isNotEmpty() -> "REVIEW"
                    else -> "NORMAL"
                }
                val analysis = com.cybershieldai.data.model.NetworkAnalysis(
                    verdict = verdict,
                    anomalyScore = if (stats.isEmpty()) 0.0
                        else (flagged.size.toDouble() / stats.size) * 100,
                    flaggedDestinations = flagged,
                    notes = listOf(
                        "On-device check of recent connection metadata " +
                            "(${stats.size} destinations). ${flagged.size} " +
                            "contacted many distinct ports — worth a quick review.",
                        "Metadata heuristics only — CyberShield does not " +
                            "intercept or inspect traffic content."
                    )
                )
                _netState.value = NetState.Ready(analysis)
                _aiContext.value = _aiContext.value + mapOf(
                    "network_verdict" to verdict,
                    "flagged_destinations" to flagged
                )
            } catch (e: Exception) {
                _netState.value = NetState.Error(
                    "Network analysis failed: ${e.message ?: e.javaClass.simpleName}")
            }
        }
    }
}

/** AI Security Assistant chat. */
class AssistantViewModel(
    private val repository: ScanRepository = ScanRepository()
) : ViewModel() {

    data class ChatMessage(val role: String, val text: String, val llmUsed: Boolean = false)

    data class ChatUiState(
        val messages: List<ChatMessage> = listOf(
            ChatMessage("assistant",
                "Ask me anything about your scans or general security topics. I explain threats in plain language.")
        ),
        val loading: Boolean = false
    )

    private val _state = MutableStateFlow(ChatUiState())
    val state: StateFlow<ChatUiState> = _state

    var scanContext: Map<String, Any?> = emptyMap()

    /** True once we learn the configured backend is unreachable and fell back. */
    private var usingFallback = false

    fun ask(question: String) {
        val q = question.trim()
        if (q.isEmpty() || _state.value.loading) return
        _state.value = _state.value.copy(
            messages = _state.value.messages + ChatMessage("user", q),
            loading = true
        )
        viewModelScope.launch {
            val answer = fetchAnswer(q)
            _state.value = _state.value.copy(
                messages = _state.value.messages + answer,
                loading = false)
        }
    }

    /**
     * Fully on-device answer path: built-in honest guidance so the assistant
     * NEVER dead-ends. No backend call exists anymore.
     */
    private suspend fun fetchAnswer(q: String): ChatMessage {
        usingFallback = true
        return ChatMessage("assistant", offlineAnswer(q), llmUsed = false)
    }

    /** Built-in guidance (mirrors the backend's honest offline tier). */
    private fun offlineAnswer(q: String): String {
        val t = q.lowercase()
        return when {
            listOf("otp", "one time password", "one-time password").any { it in t } ->
                "Never share an OTP with anyone — real banks, services and support " +
                    "teams will never ask for it. OTP requests are a hallmark of " +
                    "account-takeover scams. If you already shared one, change the " +
                    "account password immediately and enable two-factor authentication."
            listOf("scam", "fraud").any { it in t } ->
                "Common scam signals: urgency (\"act now\"), threats (account closure), " +
                    "payment requests (gift cards, UPI, crypto), unusual links, and " +
                    "requests for OTPs or passwords. Independently verify the sender " +
                    "through the organisation's official app or website before acting."
            listOf("phish").any { it in t } ->
                "Phishing links mimic trusted sites to steal credentials. Before " +
                    "entering anything: check the exact domain spelling, prefer the " +
                    "official app, never log in through links from unexpected " +
                    "messages. Use the URL Scanner for a full analysis."
            listOf("malware", "virus", "spyware").any { it in t } ->
                "Malware warning signs: apps requesting overlay + SMS permissions " +
                    "together, apps that install other apps, battery drain from an " +
                    "unknown process. A sensitive permission alone is NOT proof of " +
                    "malware — check Apps → [app] → detail for the full picture."
            listOf("permission").any { it in t } ->
                "Permissions show capability, not intent. Camera, location, SMS and " +
                    "accessibility are sensitive — review whether each permission " +
                    "makes sense for the app's purpose in Apps → app detail. " +
                    "Revoke anything that doesn't."
            listOf("score").any { it in t } ->
                "Your Security Score combines app findings, privacy exposure, and " +
                    "web/network events from the latest scan. Run SCAN NOW for the " +
                    "current breakdown — each factor is listed with its contribution."
            listOf("wi-fi", "wifi", "public").any { it in t } ->
                "On public Wi-Fi: prefer HTTPS sites, avoid banking on shared " +
                    "networks, disable auto-join for open networks, and use mobile " +
                    "data for anything sensitive."
            else ->
                "I'm offline right now, so here's built-in guidance instead: run a " +
                    "scan for current findings, review any apps flagged for privacy, " +
                    "and never share OTPs or passwords after an unexpected call or " +
                    "message. Detection features keep working offline — reconnect " +
                    "for full AI answers."
        }
    }
}
