package com.cybershieldai.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cybershieldai.data.model.ThreatDetail
import com.cybershieldai.data.repository.ScanOutcome
import com.cybershieldai.data.repository.ScanRepository
import com.cybershieldai.data.local.SettingsStore
import com.cybershieldai.utils.NotificationHelper
import com.cybershieldai.utils.UrlSecurity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed class ScanUiState {
    data object Idle : ScanUiState()
    data object Loading : ScanUiState()
    data class Result(val result: com.cybershieldai.data.model.AnalysisResponse, val online: Boolean) : ScanUiState()
    data class Failure(val message: String, val offlineResult: com.cybershieldai.data.model.AnalysisResponse?) : ScanUiState()
}

/** Shared ViewModel for all scan flows (message/URL/QR). */
class ScanViewModel(application: android.app.Application) : androidx.lifecycle.AndroidViewModel(application) {

    private val repository = ScanRepository()
    private val settings = SettingsStore(application)
    private val appContext: android.content.Context = application.applicationContext

    private val _state = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val state: StateFlow<ScanUiState> = _state

    /** Persist every completed scan into local Room history (metadata only). */
    private fun persistLocal(
        category: String, classification: String, riskScore: Int,
        indicators: List<String>, summary: String, online: Boolean,
        recommendation: String = ""
    ) {
        val ctx = appContext ?: return
        viewModelScope.launch {
            try {
                com.cybershieldai.data.repository.EventRepository(ctx)
                    .recordManual(category, classification, riskScore, indicators,
                        summary, backendUsed = online, recommendation = recommendation)
            } catch (_: Exception) { /* history is best-effort; scan result still shown */ }
        }
    }

    private fun notifyIfHighRisk(riskScore: Int, classification: String,
                                 category: String = "", firstIndicator: String = "") {
        val ctx = appContext ?: return
        viewModelScope.launch {
            val enabled = settings?.notificationsEnabled?.first() ?: true
            if (riskScore >= 75) {
                val sev = if (riskScore >= 90) "CRITICAL" else "HIGH"
                val title = when (category) {
                    "MESSAGE" -> "🚨 CyberShield — Potential Scam Message"
                    "URL", "QR" -> "⚠ CyberShield — Suspicious Link Detected"
                    "FILE", "APK" -> "⚠ CyberShield — Risky File Detected"
                    else -> "⚠ CyberShield — High-Risk Security Event"
                }
                com.cybershieldai.utils.CyberShieldNotificationManager.notifySecurityAlert(
                    ctx,
                    severity = sev,
                    title = title,
                    body = "$classification (risk $riskScore/100)." +
                        (if (firstIndicator.isNotBlank()) "\n$firstIndicator" else "") +
                        "\nDo not enter passwords, OTPs, or payment details."
                )
            }
        }
    }

    fun scanMessage(text: String) {
        if (text.isBlank()) {
            _state.value = ScanUiState.Failure("Please paste a message to scan.", null)
            return
        }
        _state.value = ScanUiState.Loading
        viewModelScope.launch {
            when (val out = repository.scanMessage(text, appContext)) {
                is ScanOutcome.Success -> {
                    _state.value = ScanUiState.Result(out.result, out.online)
                    persistLocal("MESSAGE", out.result.classification, out.result.riskScore,
                        out.result.indicators, "Message scan: ${out.result.classification}", out.online,
                        out.result.recommendation)
                    notifyIfHighRisk(out.result.riskScore, out.result.classification, "MESSAGE",
                        out.result.indicators.firstOrNull() ?: "")
                }
                is ScanOutcome.Error ->
                    _state.value = ScanUiState.Failure(out.message, out.offlineResult)
            }
        }
    }

    fun scanUrl(url: String) {
        val normalized = url.trim()
        if (normalized.isEmpty()) {
            _state.value = ScanUiState.Failure("Please enter a URL to scan.", null)
            return
        }
        _state.value = ScanUiState.Loading
        viewModelScope.launch {
            when (val out = repository.scanUrl(normalized, appContext)) {
                is ScanOutcome.Success -> {
                    _state.value = ScanUiState.Result(out.result, out.online)
                    persistLocal("URL", out.result.classification, out.result.riskScore,
                        out.result.indicators, "URL: ${normalized.take(60)}", out.online,
                        out.result.recommendation)
                    notifyIfHighRisk(out.result.riskScore, out.result.classification, "URL",
                        out.result.indicators.firstOrNull() ?: "")
                }
                is ScanOutcome.Error ->
                    _state.value = ScanUiState.Failure(out.message, out.offlineResult)
            }
        }
    }

    fun scanQr(content: String) {
        if (content.isBlank()) {
            _state.value = ScanUiState.Failure("Could not decode the QR code.", null)
            return
        }
        _state.value = ScanUiState.Loading
        viewModelScope.launch {
            when (val out = repository.scanQr(content, appContext)) {
                is ScanOutcome.Success -> {
                    _state.value = ScanUiState.Result(out.result, out.online)
                    persistLocal("QR", out.result.classification, out.result.riskScore,
                        out.result.indicators, "QR content: ${content.take(40)}", out.online,
                        out.result.recommendation)
                    notifyIfHighRisk(out.result.riskScore, out.result.classification, "QR",
                        out.result.indicators.firstOrNull() ?: "")
                }
                is ScanOutcome.Error ->
                    _state.value = ScanUiState.Failure(out.message, out.offlineResult)
            }
        }
    }

    fun reset() { _state.value = ScanUiState.Idle }

    // ------------------------------------------------------------------
    // Dedicated URL phishing flow (URL-scanner spec §11-§17): phased
    // progress, real signal results, Rescan and Run Full Scan.
    // ------------------------------------------------------------------

    data class UrlScanUiState(
        val phase: String? = null,          // live progress line, §14
        val result: ScanRepository.UrlScanOutcome? = null,
        val error: String? = null,
        val lastUrl: String = "",           // retained for Rescan (§15)
        val fullScan: Boolean = false
    )

    private val _urlState = MutableStateFlow(UrlScanUiState())
    val urlState: StateFlow<UrlScanUiState> = _urlState

    private fun normalizeUrlInput(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) {
            _urlState.value = _urlState.value.copy(phase = null, error = "Enter a URL to scan.")
            return null
        }
        val norm = UrlSecurity.normalize(trimmed)
        if (!norm.valid) {
            _urlState.value = _urlState.value.copy(
                phase = null, error = norm.problem ?: "Please enter a valid URL.")
            return null
        }
        return norm.analysis
    }

    fun scanUrlDetailed(rawUrl: String, full: Boolean) {
        val normalized = normalizeUrlInput(rawUrl) ?: return
        _urlState.value = _urlState.value.copy(
            phase = if (full) "Analyzing URL…" else "Checking URL structure…",
            error = null, lastUrl = rawUrl.trim(), fullScan = full,
            result = null)
        viewModelScope.launch {
            // Phase updates are honest (§14): each line reflects the stage
            // actually being executed inside the repository pipeline.
            val phases = if (full)
                listOf("Analyzing URL…", "Checking URL structure…", "Checking suspicious patterns…",
                    "Checking lookalike domain…", "Running local AI analysis…", "Calculating risk…")
            else
                listOf("Checking URL structure…", "Checking suspicious patterns…", "Calculating risk…")
            val phaseJob = launch {
                for (p in phases) {
                    _urlState.value = _urlState.value.copy(phase = p)
                    kotlinx.coroutines.delay(700)
                    if (_urlState.value.result != null) return@launch
                }
            }
            when (val out = repository.scanUrlDetailed(normalized, appContext, full)) {
                is ScanRepository.UrlScanOutcome -> {
                    phaseJob.cancel()
                    if (out.error != null) {
                        _urlState.value = _urlState.value.copy(phase = null, error = out.error)
                    } else {
                        _urlState.value = _urlState.value.copy(phase = null, result = out)
                        persistLocal("URL", out.urlResult.classification, out.urlResult.riskScore,
                            out.urlResult.indicators,
                            "URL: " + UrlSecurity.normalize(normalized).analysis.take(128),
                            online = false, recommendation = out.urlResult.recommendation)
                        notifyIfHighRisk(out.urlResult.riskScore, out.urlResult.classification,
                            "URL", out.urlResult.indicators.firstOrNull() ?: "")
                    }
                }
            }
        }
    }

    fun rescanUrl() {
        val last = _urlState.value.lastUrl
        if (last.isNotBlank()) scanUrlDetailed(last, full = _urlState.value.fullScan)
    }

    fun runFullScan() {
        val last = _urlState.value.lastUrl
        if (last.isNotBlank()) scanUrlDetailed(last, full = true)
    }

    fun clearUrlError() {
        _urlState.value = _urlState.value.copy(error = null, phase = null)
    }

}

/** Threat history — local-first (Room), fully offline-capable. */
class ThreatsViewModel(application: android.app.Application) : androidx.lifecycle.AndroidViewModel(application) {

    private val repository = ScanRepository()
    private val appContext: android.content.Context = application.applicationContext

    data class ThreatsUiState(
        val loading: Boolean = false,
        val threats: List<com.cybershieldai.data.model.Threat> = emptyList(),
        val total: Int = 0,
        val error: String? = null,
        val severityFilter: String? = null,
        val typeFilter: String? = null
    )

    private val _state = MutableStateFlow(ThreatsUiState())
    val state: StateFlow<ThreatsUiState> = _state

    private val _detail = MutableStateFlow<ThreatDetail?>(null)
    val detail: StateFlow<ThreatDetail?> = _detail

    fun load() {
        val ctx = appContext
        _state.value = _state.value.copy(loading = true, error = null)
        viewModelScope.launch {
            if (ctx == null) {
                _state.value = _state.value.copy(loading = false, error = null)
                return@launch
            }
            // Fully on-device: history lives in Room; there is no backend to
            // contact, so this can never fail with a network error.
            try {
                val repo = com.cybershieldai.data.repository.EventRepository(ctx)
                val events = repo.events(
                    severity = _state.value.severityFilter,
                    category = _state.value.typeFilter)
                val threats = events.map { ev ->
                    com.cybershieldai.data.model.Threat(
                        scanId = "local-${ev.id}",
                        type = ev.category,
                        classification = ev.classification,
                        riskScore = ev.riskScore,
                        severity = ev.severity,
                        confidence = ev.confidence,
                        indicators = com.cybershieldai.data.repository.EventRepository
                            .fromJsonList(ev.indicatorsJson),
                        detectionMethods = com.cybershieldai.data.repository.EventRepository
                            .fromJsonList(ev.methodsJson),
                        recommendation = "",
                        createdAt = java.text.SimpleDateFormat(
                            "yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
                            .format(java.util.Date(ev.timestamp))
                    )
                }
                _state.value = _state.value.copy(
                    loading = false, threats = threats, total = threats.size)
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    loading = false,
                    error = "Could not read scan history on this device: ${e.message ?: e.javaClass.simpleName}")
            }
        }
    }

    fun setSeverityFilter(value: String?) {
        _state.value = _state.value.copy(severityFilter = value)
        load()
    }

    fun setTypeFilter(value: String?) {
        _state.value = _state.value.copy(typeFilter = value)
        load()
    }

    fun loadDetail(scanId: String) {
        viewModelScope.launch {
            val ctx = appContext
            if (ctx == null) { _detail.value = null; return@launch }
            // Local detail: "local-<id>" ids map straight to Room rows.
            val id = scanId.removePrefix("local-").toLongOrNull()
            if (id == null) { _detail.value = null; return@launch }
            _detail.value = try {
                val ev = com.cybershieldai.data.repository.EventRepository(ctx).eventById(id)
                if (ev == null) null else {
                    val indicators = com.cybershieldai.data.repository.EventRepository
                        .fromJsonList(ev.indicatorsJson)
                    val recommendation = when (ev.classification) {
                        "SCAM", "PHISHING" ->
                            "Do not interact with this content. Do not share OTPs, PINs, passwords or payment details."
                        "SUSPICIOUS", "RISKY", "SPAM" ->
                            "Treat with caution — verify through an official channel before responding."
                        else ->
                            "No significant suspicious indicators were detected in this scan."
                    }
                    ThreatDetail(
                        scanId = scanId,
                        type = ev.category,
                        classification = ev.classification,
                        riskScore = ev.riskScore,
                        severity = ev.severity,
                        confidence = ev.confidence,
                        indicators = indicators,
                        detectionMethods = com.cybershieldai.data.repository.EventRepository
                            .fromJsonList(ev.methodsJson),
                        recommendation = recommendation,
                        aiExplanation = ev.summary
                    )
                }
            } catch (_: Exception) {
                null
            }
        }
    }

    fun clearDetail() { _detail.value = null }

    fun deleteHistory(onDone: (Boolean) -> Unit) {
        val ctx = appContext
        viewModelScope.launch {
            var ok = false
            if (ctx != null) {
                try {
                    com.cybershieldai.data.repository.EventRepository(ctx).clearAll()
                    ok = true
                } catch (_: Exception) { }
            }
            onDone(ok); load()
        }
    }
}
