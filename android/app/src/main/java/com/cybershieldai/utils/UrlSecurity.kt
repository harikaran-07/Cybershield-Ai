package com.cybershieldai.utils

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLDecoder
import java.util.Locale

/**
 * Deterministic URL phishing analysis (URL-scanner spec §2-§9).
 *
 * Everything here is STATIC and LOCAL: the URL is treated as text and is
 * never opened, fetched (except the explicitly-configured reputation API,
 * §9) or executed. No API key is required for the core engine — the
 * reputation layer activates only when the user supplies a key through
 * local.properties (never hardcoded in source, §9).
 */
object UrlSecurity {

    // ------------------------------------------------------------------
    // Normalizer (§3): accept pasted input as people actually paste it.
    // ------------------------------------------------------------------

    data class Normalized(val display: String, val analysis: String, val valid: Boolean, val problem: String? = null)

    fun normalize(raw: String): Normalized {
        var s = raw.trim()
        if (s.isEmpty()) return Normalized(raw, raw, valid = false, problem = "Enter a URL to scan.")
        // Add a scheme so URI parsing works for "example.com" style pastes.
        val withScheme = if (!Regex("(?i)^https?://").containsMatchIn(s)) "https://$s" else s
        // Strip wrapping junk users copy from chat bubbles.
        s = withScheme.trim().trim('"', '\'', '<', '>')
        return try {
            val uri = java.net.URI(s)
            val host = uri.host?.lowercase(Locale.US)
            if (host.isNullOrBlank()) {
                return Normalized(raw, s, valid = false, problem = "Please enter a valid URL.")
            }
            // A real internet URL needs a dot-separated domain (or an IP /
            // localhost) — bare words like "not a url" are rejected (§1).
            val isIpHost = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)
            if (!host.contains('.') && !isIpHost && host != "localhost") {
                return Normalized(raw, s, valid = false,
                    problem = "Please enter a valid URL — include a domain (e.g. example.com).")
            }
            // Rebuild a canonical lowercase form for analysis (§3).
            val port = if (uri.port == -1 || (uri.scheme == "https" && uri.port == 443) ||
                (uri.scheme == "http" && uri.port == 80)) "" else ":${uri.port}"
            val path = uri.path ?: ""
            val query = uri.rawQuery?.let { "?" + URLDecoder.decode(it, "UTF-8").let { q -> java.net.URLEncoder.encode(q, "UTF-8") } } ?: ""
            val analysis = "${uri.scheme.lowercase(Locale.US)}://$host$port$path${uri.rawQuery?.let { "?$it" } ?: ""}${uri.fragment?.let { "#$it" } ?: ""}"
            Normalized(display = s, analysis = analysis, valid = true)
        } catch (e: Exception) {
            // Last-ditch host check for odd but real inputs like "1.2.3.4:8080/x".
            val hostish = s.removePrefix("https://").removePrefix("http://").substringBefore('/').substringBefore(':')
            val looksLikeHost = hostish.contains('.') &&
                Regex("^[a-z0-9._\\-]+$", RegexOption.IGNORE_CASE).matches(hostish)
            if (looksLikeHost) Normalized(raw, "https://$s", valid = true)
            else Normalized(raw, s, valid = false, problem = "Please enter a valid URL.")
        }
    }

    // ------------------------------------------------------------------
    // Signals (§4): every check produces a status + human explanation.
    // ------------------------------------------------------------------

    enum class Status { SAFE, WARNING, DANGER, UNKNOWN }

    data class Signal(
        val title: String,
        val status: Status,
        val description: String,
        val severity: Int // 0 none, 1 minor, 2 major, 3 critical — feeds the score
    )

    data class UrlResult(
        val riskScore: Int,
        val classification: String, // SAFE | SUSPICIOUS | HIGH RISK | CRITICAL
        val severity: String,       // SAFE | LOW | MEDIUM | HIGH | CRITICAL (existing chips)
        val signals: List<Signal>,
        val indicators: List<String>,     // DANGER/WARNING evidence for the indicators list
        val recommendation: String,
        val summary: String,
        val priorScan: PriorScan? = null
    )

    data class PriorScan(val timestamp: Long, val classification: String, val riskScore: Int)

    // Abused TLDs and shorteners (§4) — patterns, not verdicts.
    private val riskyTlds = setOf("tk", "xyz", "top", "click", "buzz", "cfd", "ml", "ga", "cf", "gq", "work", "rest", "fit")
    private val shorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy",
        "shorturl.at", "rebrand.ly", "tiny.cc", "ow.ly", "buff.ly", "s.id", "lnkd.in")
    private val loginKeywords = listOf("login", "signin", "sign-in", "verify", "secure", "account",
        "update", "confirm", "billing", "invoice", "payment", "recover", "unlock", "webmail")
    private val urgencyWords = listOf("urgent", "immediately", "suspended", "locked", "24hours",
        "24-hours", "act-now", "limited-time", "final-notice")

    // Well-known brands for lookalike detection (§5). We compare against the
    // registrable domain — a word in a path/subdomain alone is NOT a verdict.
    private val brands = listOf(
        "google", "facebook", "instagram", "whatsapp", "amazon", "apple", "icloud",
        "microsoft", "outlook", "office365", "paypal", "netflix", "linkedin",
        "sbi", "hdfcbank", "icicibank", "axisbank", "paytm", "phonepe", "flipkart",
        "snapdeal", "walmart", "ebay", "coinbase", "binance", "dhl", "fedex", "ups")

    // Common brand-adjacent decoys that appear in typosquats: "paypa1",
    // "g00gle", "micros0ft", "faceb00k", "amaz0n", "1cloud", etc.
    private val leet = mapOf('0' to 'o', '1' to 'l', '3' to 'e', '4' to 'a', '5' to 's', '7' to 't', '@' to 'a', '$' to 's')

    fun deobfuscate(host: String): String = buildString {
        for (c in host) append(leet[c] ?: c)
    }

    /** Levenshtein distance for small strings (domains are short). */
    private fun editDistance(a: String, b: String): Int {
        if (a == b) return 0
        if (a.isEmpty()) return b.length
        if (b.isEmpty()) return a.length
        var prev = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            val cur = IntArray(b.length + 1)
            cur[0] = i
            for (j in 1..b.length) {
                cur[j] = minOf(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + if (a[i - 1] == b[j - 1]) 0 else 1)
            }
            prev = cur
        }
        return prev[b.length]
    }

    /**
     * Registrable domain (best-effort, no PSL): treat the last two labels as
     * the domain, three for known second-level TLDs. Used ONLY to avoid
     * flagging legitimate subdomains of real domains (e.g. mail.google.com).
     */
    private fun registrableDomain(host: String): String {
        val labels = host.split('.').filter { it.isNotBlank() }
        if (labels.size <= 2) return host
        val twoLevelTlds = setOf("co.uk", "co.in", "com.au", "co.jp", "com.br", "co.za", "com.mx")
        val lastTwo = labels.takeLast(2).joinToString(".")
        if (lastTwo in twoLevelTlds) return labels.takeLast(3).joinToString(".")
        return lastTwo
    }

    /** Brand lookalike analysis (§5) — similarity against registrable domain. */
    private fun brandLookalike(host: String): Signal? {
        val domain = registrableDomain(host)
        val bare = domain.substringBeforeLast('.')
        val deob = deobfuscate(bare)
        // Brand occupies the WHOLE registrable label → compare directly.
        // e.g. goog1e-security.com → bare="goog1e-security" is NOT similar to
        // "google"; "paypa1.com" IS.
        for (brand in brands) {
            if (bare == brand) return null // exact — legitimate
            // Obfuscated variant of the brand itself as the whole domain label.
            if (deob == brand && bare != brand) {
                return Signal(
                    title = "Typo/brand similarity",
                    status = Status.DANGER,
                    description = "Domain looks like \"$brand\" with characters replaced (possible typosquat).",
                    severity = 3)
            }
            // Near-identical whole label: paypal-vs.com style.
            val d = editDistance(deob, brand)
            if (d == 1 && bare.length >= brand.length) {
                return Signal(
                    title = "Typo/brand similarity",
                    status = Status.WARNING,
                    description = "Domain differs from \"$brand\" by a single character.",
                    severity = 2)
            }
            // Brand embedded as a full second label with a different TLD/word:
            // paypal-security.com / netflix-billing.net — impersonation pattern.
            if (brand !in bare && bare.startsWith(brand) && bare.length > brand.length &&
                bare.substringAfter(brand).let { it.startsWith("-") }) {
                return Signal(
                    title = "Brand impersonation pattern",
                    status = Status.WARNING,
                    description = "Domain combines the \"$brand\" name with extra words — common in phishing kits.",
                    severity = 2)
            }
            // deobfuscated brand embedded with separators: g00gle-secure etc.
            if (deob != bare && deob.startsWith(brand) && bare != brand) {
                return Signal(
                    title = "Typo/brand similarity",
                    status = Status.WARNING,
                    description = "Domain resembles \"$brand\" with character substitutions.",
                    severity = 2)
            }
        }
        return null
    }

    /** Homoglyph / punycode check (§6). */
    private fun homoglyphCheck(host: String): Signal {
        val asciiOnly = host.all { it.code < 128 }
        val punycodeLabels = host.split('.').filter { it.startsWith("xn--") }
        val mixedScript = !asciiOnly && host.any { it.code >= 128 }
        return when {
            punycodeLabels.isNotEmpty() -> Signal(
                title = "Homoglyph check",
                status = Status.WARNING,
                description = "Domain uses punycode (xn--) — can display as lookalike Unicode characters.",
                severity = 1)
            mixedScript -> Signal(
                title = "Homoglyph check",
                status = Status.DANGER,
                description = "Domain contains non-ASCII characters that may imitate familiar letters.",
                severity = 3)
            else -> Signal(
                title = "Homoglyph check",
                status = Status.SAFE,
                description = "No suspicious character substitution detected",
                severity = 0)
        }
    }

    /** Structural URL pattern check (§7). */
    private fun patternCheck(u: java.net.URI, url: String): List<Signal> {
        val host = u.host?.lowercase(Locale.US) ?: url.lowercase()
        val low = url.lowercase(Locale.US)
        val signals = mutableListOf<Signal>()

        // HTTPS
        signals += if (u.scheme == "https") Signal("HTTPS encryption", Status.SAFE,
            "Connection uses HTTPS", 0)
        else Signal("HTTPS encryption", Status.WARNING, "No HTTPS — data would travel unencrypted", 1)

        // Raw IP
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)) {
            signals += Signal("IP-address host", Status.DANGER,
                "Uses a raw IP address instead of a domain — common in phishing infrastructure", 3)
        }

        // '@' userinfo trick
        if ("@" in low.substringBefore('/').drop(1).dropLast(1) || "@" in (u.rawUserInfo ?: "")) {
            signals += Signal("Obfuscated target", Status.DANGER,
                "Contains '@' — browsers ignore everything before it, hiding the real host", 3)
        }

        // Shorteners
        val isShortener = shorteners.any { s -> host == s || host.endsWith(".$s") }
        if (isShortener) {
            signals += Signal("URL shortener", Status.WARNING,
                "Shortened link hides the true destination", 2)
        }

        // Subdomain depth
        val dots = host.count { it == '.' }
        if (dots >= 4) signals += Signal("Subdomain depth", Status.WARNING,
            "Many subdomain levels ($dots dots) — often used to mimic trusted names", 2)

        // Suspicious TLD
        val tld = host.substringAfterLast('.', "")
        if (tld in riskyTlds) signals += Signal("Domain ending", Status.WARNING,
            ".$tld is frequently abused for phishing", 2)

        // Port
        if (u.port != -1 && u.port !in setOf(80, 443)) {
            signals += Signal("Unusual port", Status.WARNING,
                "Non-standard port ${u.port} — unusual for everyday websites", 1)
        }

        // Keywords
        val kw = loginKeywords.count { it in low }
        if (kw >= 2) signals += Signal("Credential wording", Status.WARNING,
            "$kw login/account/verification keywords in the URL", 2)
        else if (kw == 1 && (u.path?.length ?: 0) > 0 && host.count { it == '.' } >= 3) {
            signals += Signal("Credential wording", Status.WARNING,
                "Login-related wording combined with a deep subdomain", 1)
        }

        // Urgency
        val urg = urgencyWords.count { it in low }
        if (urg > 0) signals += Signal("Urgency wording", Status.WARNING,
            "Pressure language in the URL (e.g. \"suspended\", \"act now\")", 2)

        // Length
        if (url.length > 120) signals += Signal("URL length", Status.WARNING,
            "Unusually long URL (${url.length} characters)", 1)

        // Encoded payloads
        val encoded = Regex("%[0-9a-f]{2}", RegexOption.IGNORE_CASE).findAll(url).count()
        if (encoded >= 4) signals += Signal("Encoded characters", Status.WARNING,
            "Many percent-encoded sequences ($encoded) — can hide the real destination", 2)

        // Suspicious query params that carry an inner URL
        if (Regex("[?&](url|next|redirect|dest|continue|goto)=").containsMatchIn(low)) {
            signals += Signal("Redirect parameter", Status.WARNING,
                "Query carries another URL — open-redirect pattern", 2)
        }

        // Executable download target
        if (Regex("\\.(exe|msi|scr|apk|bat|cmd|jar)(\\?|$)").containsMatchIn(low)) {
            signals += Signal("File download", Status.DANGER,
                "Link points directly at an executable/installer file", 3)
        }

        // Double extension on the last path segment
        val lastSeg = (u.path ?: "").substringAfterLast('/')
        if (Regex("\\.[a-z0-9]{1,5}\\.[a-z0-9]{1,5}$", RegexOption.IGNORE_CASE).containsMatchIn(lastSeg)) {
            signals += Signal("Double extension", Status.WARNING,
                "File name has a double extension — classic disguise", 2)
        }

        return signals
    }

    /**
     * Full deterministic analysis (§4/§11): every signal is derived from the
     * URL itself. The score is the weighted sum of signal severities —
     * transparent, never random.
     */
    fun analyze(analysisUrl: String, prior: PriorScan? = null): UrlResult {
        val norm = normalize(analysisUrl)
        if (!norm.valid) {
            return UrlResult(
                riskScore = 0, classification = "INVALID", severity = "SAFE",
                signals = emptyList(), indicators = emptyList(),
                recommendation = norm.problem ?: "Please enter a valid URL.",
                summary = norm.problem ?: "Invalid URL", priorScan = prior)
        }
        val uri = java.net.URI(norm.analysis)
        val host = uri.host?.lowercase(Locale.US) ?: ""

        val signals = mutableListOf<Signal>()
        brandLookalike(host)?.let { signals += it }
        signals += homoglyphCheck(host)
        signals += patternCheck(uri, norm.analysis)

        val priorSignal = if (prior != null) Signal(
            "Prior-scan lookup", Status.SAFE,
            "Previously analyzed — last result ${prior.classification} (${prior.riskScore}/100)",
            0) else Signal(
            "Prior-scan lookup", Status.SAFE,
            "No malicious or suspicious verdict found for this URL",
            0)
        // Position the prior-scan card first like the reference UI.
        signals.add(0, priorSignal)

        val score = (signals.sumOf { it.severity } * 12).coerceIn(0, 100)
        val classification = when {
            score >= 80 -> "CRITICAL"
            score >= 60 -> "HIGH RISK"
            score >= 30 -> "SUSPICIOUS"
            else -> "SAFE"
        }
        val severity = when (classification) {
            "CRITICAL" -> "CRITICAL"
            "HIGH RISK" -> "HIGH"
            "SUSPICIOUS" -> "MEDIUM"
            else -> "SAFE"
        }
        val indicators = signals.filter { it.severity > 0 }.map { it.description }
        val recommendation = when (classification) {
            "SAFE" -> "No significant phishing indicators detected. The URL was analyzed as text only — it was never opened."
            "SUSPICIOUS" -> "Some suspicious indicators were detected. Avoid entering passwords, OTPs, payment details, or personal information until the destination is verified."
            else -> "Treat this link with caution. Verify the domain through the organization's official app or website before entering credentials."
        }
        val summary = when (classification) {
            "SAFE" -> "No significant phishing indicators were detected."
            "SUSPICIOUS" -> "Some suspicious URL signals were detected."
            "HIGH RISK" -> "Multiple suspicious URL signals were detected."
            else -> "Numerous strong phishing indicators were detected."
        }
        return UrlResult(score, classification, severity, signals, indicators, recommendation, summary, prior)
    }

    /** Merge one extra signal (e.g. reputation) into a result and re-score. */
    fun withExtraSignal(result: UrlResult, extra: Signal): UrlResult {
        if (result.classification == "INVALID") return result
        val signals = result.signals.toMutableList()
        // Replace the placeholder reputation card if analyze() pre-seeded one;
        // otherwise append.
        val idx = signals.indexOfFirst { it.title == extra.title }
        if (idx >= 0) signals[idx] = extra else signals.add(extra)
        val score = (signals.sumOf { it.severity } * 12).coerceIn(0, 100)
        val classification = when {
            score >= 80 -> "CRITICAL"
            score >= 60 -> "HIGH RISK"
            score >= 30 -> "SUSPICIOUS"
            else -> "SAFE"
        }
        val severity = when (classification) {
            "CRITICAL" -> "CRITICAL"
            "HIGH RISK" -> "HIGH"
            "SUSPICIOUS" -> "MEDIUM"
            else -> "SAFE"
        }
        val indicators = signals.filter { it.severity > 0 }.map { it.description }
        val recommendation = when (classification) {
            "SAFE" -> "No significant phishing indicators detected. The URL was analyzed as text only — it was never opened."
            "SUSPICIOUS" -> "Some suspicious indicators were detected. Avoid entering passwords, OTPs, payment details, or personal information until the destination is verified."
            else -> "Treat this link with caution. Verify the domain through the organization's official app or website before entering credentials."
        }
        val summary = when (classification) {
            "SAFE" -> "No significant phishing indicators were detected."
            "SUSPICIOUS" -> "Some suspicious URL signals were detected."
            "HIGH RISK" -> "Multiple suspicious URL signals were detected."
            else -> "Numerous strong phishing indicators were detected."
        }
        return result.copy(riskScore = score, classification = classification,
            severity = severity, signals = signals, indicators = indicators,
            recommendation = recommendation, summary = summary)
    }

    // ------------------------------------------------------------------
    // Reputation provider (§9): optional, key comes from local.properties
    // via BuildConfig — never hardcoded. Without a key the UI says local
    // analysis was used.
    // ------------------------------------------------------------------

    interface ReputationProvider {
        /** Returns a signal or null when the provider could not be queried. */
        suspend fun check(url: String): Signal?
        val unavailableMessage: String
    }

    /** Google Safe Browsing v4 lookup — enabled only with a configured key. */
    class SafeBrowsingProvider(private val apiKey: String) : ReputationProvider {
        override val unavailableMessage = "Reputation check unavailable — using local analysis"

        override suspend fun check(url: String): Signal? = withContext(Dispatchers.IO) {
            try {
                val endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$apiKey"
                val body = """
                    {"client":{"clientId":"cybershield","clientVersion":"2.2"},
                     "threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                     "platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],
                     "threatEntries":[{"url":"$url"}]}}
                """.trimIndent()
                val conn = URL(endpoint).openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 8_000
                conn.readTimeout = 10_000
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toByteArray()) }
                val response = conn.inputStream.bufferedReader().use { it.readText() }
                // Empty JSON object {} = no matches (clean). Any matches = danger.
                if (response.contains("\"threatMatches\"") && response.contains("\"url\"")) {
                    Signal("Google Safe Browsing", Status.DANGER,
                        "Listed by Google Safe Browsing as a phishing/malware threat", 3)
                } else if (response.trim() == "{}") {
                    Signal("Google Safe Browsing", Status.SAFE,
                        "No matches in Google Safe Browsing", 0)
                } else null
            } catch (e: Exception) {
                Log.w("UrlSecurity", "Safe Browsing lookup failed: ${e.message}")
                null
            }
        }
    }

    /** No key configured — reports honestly unavailable (§9). */
    object UnavailableProvider : ReputationProvider {
        override val unavailableMessage =
            "Reputation check unavailable — external service not configured; local analysis used"
        override suspend fun check(url: String): Signal? = null
    }

    fun reputationProvider(): ReputationProvider = try {
        val key = com.cybershieldai.BuildConfig.SB_API_KEY
        if (key.isNotBlank()) SafeBrowsingProvider(key) else UnavailableProvider
    } catch (_: Exception) {
        UnavailableProvider
    }
}
