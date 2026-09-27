package com.cybershieldai.utils

import kotlin.math.min

data class OfflineResult(
    val type: String,
    val riskScore: Int,
    val severity: String,
    val classification: String,
    val indicators: List<String>,
    val recommendation: String
)

/**
 * Offline protection mode — lightweight local checks when the backend is
 * unreachable. Honest about its limits: this is NOT full ML analysis.
 */
object OfflineAnalyzer {

    // ACCURACY RULES (wrong-answer fixes):
    //  - match multi-word PHRASES on word boundaries, never bare substrings;
    //    "account" alone must not flag a legitimate message.
    //  - credential requests score highest: a bare OTP/password request is
    //    suspicious by itself, even without links or urgency language.
    //  - "verify" is normal English — it only contributes WITH a link.
    private val urgencyPhrases = listOf(
        "urgent", "immediately", "suspended", "locked", "final notice",
        "act now", "24 hours", "last warning", "limited time", "expire"
    )
    private val credentialPhrases = listOf(
        "password", "otp", "one-time", "one time code", "cvv", "card number",
        "seed phrase", "verification code", "pin code", "atm pin", "upi pin",
        "net banking", "internet banking", "credit card", "debit card", "ssn"
    )
    private val rewardPhrases = listOf(
        "you have won", "claim your prize", "free gift", "lottery", "lucky draw",
        "cash prize", "you are a winner"
    )
    private val verifyAction = Regex("\\b(verif(y|ication)|confirm your|unlock|reactivat\\w*|log ?in to)\\b")
    private val riskyTlds = listOf("tk", "xyz", "top", "click", "buzz", "cfd", "ml", "ga")
    private val shorteners = listOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd")
    private val urlKeywords = listOf("login", "verify", "secure", "account", "banking", "confirm")
    private val dangerousExtensions = setOf(
        "exe", "msi", "scr", "bat", "cmd", "vbs", "js", "apk", "jar", "dll", "com", "ps1"
    )

    private fun anyPhrase(low: String, phrases: List<String>): Boolean =
        phrases.any { Regex("\\b${Regex.escape(it)}\\b").containsMatchIn(low) }

    fun analyzeMessage(text: String): OfflineResult? {
        val t = text.trim()
        if (t.isEmpty()) return null
        val low = t.lowercase()
        val indicators = mutableListOf<String>()
        var score = 0
        val hasLink = Regex("(https?://|www\\.)[^\\s]+", RegexOption.IGNORE_CASE).containsMatchIn(t)

        if (anyPhrase(low, urgencyPhrases)) {
            score += 25
            indicators += "Urgent or pressure language"
        }
        // Credential REQUEST: a credential term preceded by a request verb
        // within the same sentence. A bare MENTION ("I forgot my password")
        // is normal conversation — only requests to hand them over count.
        // Warnings ("never share your OTP") are excluded.
        val credentialRequest = Regex(
            "\\b(share|send|provide|enter|give|confirm|update|reveal|reply with|tell me|text me)\\b[^.!?]{0,40}?\\b(password|otp|one[- ]time( code)?|cvv|card number|seed phrase|verification code|pin code|atm pin|upi pin|net banking|internet banking|credit card|debit card|ssn)\\b"
        )
        val credMatch = credentialRequest.find(low)
        val credentialAsked = credMatch != null && run {
            val before = low.substring(
                maxOf(0, credMatch.range.first - 14), credMatch.range.first)
            !before.contains("never") && !before.contains("don't") &&
                !before.contains("do not") && !before.contains("avoid")
        }
        if (credentialAsked) {
            score += 40
            indicators += "Requests credentials or codes"
        }
        val rewardHit = anyPhrase(low, rewardPhrases)
        if (rewardHit) {
            score += 30
            indicators += "Too-good-to-be-true reward language"
        }
        if (verifyAction.containsMatchIn(low) && hasLink) {
            score += 25
            indicators += "Asks to verify or confirm account details through a link"
        }
        if (hasLink) {
            indicators += "Contains a link: " +
                Regex("(https?://|www\\.)[^\\s]+", RegexOption.IGNORE_CASE).find(t)!!.value.take(60)
            score += 10
        }
        // Classic prize-bait: reward language PLUS a link to "claim" it.
        if (rewardHit && hasLink) {
            score += 25
            indicators += "Prize bait combined with a link"
        }
        // 3+ independent signals → scam consensus escalation.
        if (indicators.size >= 3) score = min(100, score + 10)
        score = min(100, score)
        val classification = when {
            score >= 65 -> "SCAM"
            score >= 40 -> "SUSPICIOUS"
            else -> "SAFE"
        }
        return OfflineResult(
            type = "SMS", riskScore = score, severity = severityFor(score),
            classification = classification,
            indicators = indicators.ifEmpty { listOf("No obvious scam indicators found offline") },
            recommendation = when {
                score >= 40 ->
                    "Do not open links or reply. Verify via the organization's official app or website."
                indicators.isNotEmpty() ->
                    "Some general risk signals were found, but nothing clearly indicating a " +
                        "scam. Stay cautious with links and never share OTPs or passwords."
                else ->
                    "Offline check found no obvious scam signs. Analysis completed entirely on this device."
            }
        )
    }

    fun analyzeUrl(url: String): OfflineResult {
        val low = url.lowercase()
        val indicators = mutableListOf<String>()
        var score = 0
        if (!low.startsWith("https://")) { score += 15; indicators += "No HTTPS" }
        // Strip the scheme, then split BEFORE the first '/' so credentials
        // ('@'), host and path are each analyzed correctly — never the whole
        // URL as one string (which flagged legitimate share links).
        val rest = low.substringAfter("://")
        val host = rest.substringBefore('/').substringAfterLast('@')
        val pathAndQuery = rest.substringAfter('/', "").substringBefore('@')
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)) {
            score += 25; indicators += "Raw IP address instead of a domain"
        }
        // Credential trick: '@' only matters in the AUTHORITY (before the
        // first '/'). '@' inside a query string (emails in share links) is
        // normal and must NOT flag the URL.
        if ("@" in rest.substringBefore('/')) {
            score += 20; indicators += "Contains '@' in the address (browser ignores text before it)"
        }
        if (shorteners.any { host == it || host.endsWith(".$it") }) {
            score += 15; indicators += "Shortened URL hides the destination"
        }
        val tld = host.substringAfterLast('.', "")
        if (tld in riskyTlds) { score += 15; indicators += "Frequently-abused domain ending (.$tld)" }
        val registrable = host.substringBefore(':').split('.').takeLast(2).joinToString(".")
        // Keyword counting over SUBDOMAIN + path/query only. The registrable
        // domain itself ("accounts.google.com") must not self-flag; phishing
        // keywords in subdomains ("login-verify.paypal.example.tk") are real
        // signals.
        val sub = host.removeSuffix(registrable)
        val kw = urlKeywords.count { (sub + " " + pathAndQuery).contains(it) }
        if (kw >= 2) { score += 20; indicators += "$kw phishing-related keywords in the URL" }
        else if (kw == 1 && tld in riskyTlds) {
            score += 10; indicators += "Phishing-related keyword combined with an abused domain ending"
        }
        // Brand-impersonation: a KNOWN brand inside the HOST while the
        // registrable domain is NOT that brand (e.g. paypal-secure.example.com).
        val brands = listOf("paypal", "google", "facebook", "amazon", "apple", "microsoft",
            "netflix", "whatsapp", "instagram", "sbi", "hdfc", "icici", "paytm")
        val brandInHost = brands.firstOrNull {
            host.contains(it) && registrable != "$it.com" && !registrable.startsWith("$it.")
        }
        if (brandInHost != null) {
            score += 20
            indicators += "Brand name ($brandInHost) in the address but the domain is not the official $brandInHost site"
            // A well-known brand name on a frequently-abused domain ending is
            // a near-certain phishing pattern — combine the two signals.
            if (tld in riskyTlds) {
                score += 10
                indicators += "Impersonated brand combined with an abused domain ending"
            }
        }
        if (url.length > 100) { score += 10; indicators += "Unusually long URL" }
        if (host.count { it == '.' } >= 4) { score += 10; indicators += "Many subdomain levels" }
        score = min(100, score)
        val classification = when {
            score >= 65 -> "PHISHING"
            score >= 40 -> "SUSPICIOUS"
            else -> "SAFE"
        }
        return OfflineResult(
            type = "URL", riskScore = score, severity = severityFor(score),
            classification = classification,
            indicators = indicators.ifEmpty { listOf("No structural phishing indicators found offline") },
            recommendation = if (score >= 40)
                "Avoid this link. Do not enter passwords or codes. Type the official address yourself."
            else
                "Offline check found no structural red flags. Full ML analysis runs when online."
        )
    }

    fun analyzeFile(fileName: String, sizeBytes: Int): OfflineResult {
        val indicators = mutableListOf<String>()
        var score = 0
        val name = fileName.lowercase()
        val ext = name.substringAfterLast('.', "")
        if (ext in dangerousExtensions) {
            score += 40
            indicators += "Executable/script file type (.$ext) — handle with care"
        }
        if (Regex("\\.[a-z0-9]{1,5}\\.[a-z0-9]{1,5}$").containsMatchIn(name)) {
            score += 25
            indicators += "Double file extension"
        }
        if (sizeBytes == 0) { score += 10; indicators += "File is empty" }
        if (sizeBytes > 50 * 1024 * 1024) { score += 10; indicators += "Unusually large file" }
        score = min(100, score)
        val classification = when {
            score >= 60 -> "RISKY"
            score >= 30 -> "SUSPICIOUS"
            else -> "SAFE"
        }
        return OfflineResult(
            type = "FILE", riskScore = score, severity = severityFor(score),
            classification = classification,
            indicators = indicators.ifEmpty { listOf("No filename-based risk indicators offline") },
            recommendation = if (score >= 30)
                "Do not open or install this file unless you fully trust the source."
            else
                "Offline check found no filename red flags. Full static analysis runs when online."
        )
    }

    fun severityFor(score: Int): String = when {
        score >= 90 -> "CRITICAL"
        score >= 75 -> "HIGH"
        score >= 50 -> "MEDIUM"
        score >= 25 -> "LOW"
        else -> "SAFE"
    }
}
