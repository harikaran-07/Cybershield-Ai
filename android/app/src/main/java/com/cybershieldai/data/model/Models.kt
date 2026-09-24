package com.cybershieldai.data.model

import com.google.gson.annotations.SerializedName

/** Consistent API response envelope (mirrors backend AnalysisResponse). */
data class AnalysisResponse(
    @SerializedName("scan_id") val scanId: String,
    val type: String,
    @SerializedName("risk_score") val riskScore: Int,
    val severity: String,
    val classification: String,
    val confidence: Double,
    val indicators: List<String> = emptyList(),
    @SerializedName("detection_methods") val detectionMethods: List<String> = emptyList(),
    val recommendation: String = "",
    @SerializedName("ai_explanation") val aiExplanation: String? = null,
    val details: Map<String, Any?> = emptyMap()
)

data class MessageRequest(
    val text: String,
    @SerializedName("device_id") val deviceId: String? = null
)

data class UrlRequest(
    val url: String,
    @SerializedName("device_id") val deviceId: String? = null
)

data class QrRequest(
    val content: String,
    @SerializedName("qr_format") val qrFormat: String = "QR_CODE",
    @SerializedName("device_id") val deviceId: String? = null
)

data class AppInfo(
    @SerializedName("package_name") val packageName: String,
    @SerializedName("app_name") val appName: String? = null,
    val permissions: List<String> = emptyList(),
    @SerializedName("is_system_app") val isSystemApp: Boolean = false,
    @SerializedName("from_unknown_source") val fromUnknownSource: Boolean? = null,
    @SerializedName("accessibility_enabled") val accessibilityEnabled: Boolean? = null,
    @SerializedName("target_sdk") val targetSdk: Int? = null
)

data class AppSecurityRequest(
    @SerializedName("device_id") val deviceId: String?,
    val apps: List<AppInfo>
)

data class AppSecurityResult(
    val apps: List<AppAnalysis>,
    val summary: AppSummary,
    val disclaimer: String
)

data class AppAnalysis(
    @SerializedName("package_name") val packageName: String,
    @SerializedName("app_name") val appName: String? = null,
    @SerializedName("risk_score") val riskScore: Int,
    val label: String,
    val permissions: List<PermissionInfo> = emptyList(),
    val notes: List<String> = emptyList()
)

data class PermissionInfo(
    val permission: String,
    val category: String
)

data class AppSummary(
    @SerializedName("total_apps") val totalApps: Int,
    @SerializedName("risky_count") val riskyCount: Int,
    @SerializedName("top_risky") val topRisky: List<String> = emptyList(),
    @SerializedName("avg_risk") val avgRisk: Double = 0.0
)

data class NetworkStat(
    val destination: String,
    @SerializedName("connection_count") val connectionCount: Int = 0,
    @SerializedName("bytes_sent") val bytesSent: Long = 0,
    @SerializedName("bytes_received") val bytesReceived: Long = 0,
    @SerializedName("distinct_ports") val distinctPorts: Int = 0
)

data class NetworkRequest(
    @SerializedName("device_id") val deviceId: String?,
    @SerializedName("window_minutes") val windowMinutes: Int = 15,
    val stats: List<NetworkStat>
)

data class NetworkAnalysis(
    val verdict: String,
    @SerializedName("anomaly_score") val anomalyScore: Double,
    @SerializedName("flagged_destinations") val flaggedDestinations: List<String> = emptyList(),
    val notes: List<String> = emptyList()
)

data class Threat(
    @SerializedName("scan_id") val scanId: String,
    val type: String,
    val classification: String,
    @SerializedName("risk_score") val riskScore: Int,
    val severity: String,
    val confidence: Double,
    val indicators: List<String> = emptyList(),
    @SerializedName("detection_methods") val detectionMethods: List<String> = emptyList(),
    val recommendation: String = "",
    @SerializedName("created_at") val createdAt: String? = null
)

data class ThreatListResponse(
    val total: Int,
    val threats: List<Threat>
)

data class ThreatDetail(
    @SerializedName("scan_id") val scanId: String,
    val type: String,
    @SerializedName("risk_score") val riskScore: Int,
    val severity: String,
    val classification: String,
    val confidence: Double,
    val indicators: List<String>,
    @SerializedName("detection_methods") val detectionMethods: List<String>,
    val recommendation: String,
    @SerializedName("ai_explanation") val aiExplanation: String? = null,
    val timeline: List<TimelineEntry> = emptyList(),
    @SerializedName("correlated_chain") val correlatedChain: ChainInfo? = null
)

data class TimelineEntry(
    val time: String,
    @SerializedName("event_type") val eventType: String,
    val severity: String,
    @SerializedName("risk_score") val riskScore: Int,
    val detail: String
)

data class ChainInfo(
    @SerializedName("chain_types") val chainTypes: List<String>,
    @SerializedName("combined_risk") val combinedRisk: Int,
    val severity: String,
    val explanation: String
)

data class Dashboard(
    @SerializedName("total_scans") val totalScans: Int,
    @SerializedName("safe_count") val safeCount: Int,
    @SerializedName("threats_detected") val threatsDetected: Int,
    @SerializedName("high_risk_count") val highRiskCount: Int,
    @SerializedName("highest_risk") val highestRisk: Threat? = null,
    @SerializedName("lowest_risk") val lowestRisk: Threat? = null,
    @SerializedName("most_common_threat") val mostCommonThreat: String? = null,
    @SerializedName("threats_by_type") val threatsByType: Map<String, Int> = emptyMap(),
    @SerializedName("threats_by_severity") val threatsBySeverity: Map<String, Int> = emptyMap(),
    @SerializedName("scan_trend") val scanTrend: List<TrendPoint> = emptyList()
)

data class TrendPoint(
    val date: String,
    val count: Int
)

data class HealthResponse(
    val status: String,
    val version: String,
    val database: String,
    @SerializedName("nlp_model") val nlpModel: String,
    @SerializedName("url_model") val urlModel: String,
    @SerializedName("anomaly_model") val anomalyModel: String,
    val llm: String,
    @SerializedName("llm_model") val llmModel: String? = null
)

data class ChatRequest(
    val question: String,
    val context: Map<String, Any?> = emptyMap()
)

data class ChatResponse(
    val answer: String,
    @SerializedName("llm_used") val llmUsed: Boolean
)

data class ExplainRequest(
    @SerializedName("threat_type") val threatType: String,
    @SerializedName("risk_score") val riskScore: Int,
    val severity: String,
    val indicators: List<String>,
    @SerializedName("scan_id") val scanId: String? = null
)

data class ExplainResponse(
    val explanation: String,
    @SerializedName("llm_used") val llmUsed: Boolean
)
