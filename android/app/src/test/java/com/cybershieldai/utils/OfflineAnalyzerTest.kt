package com.cybershieldai.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Accuracy regression tests for the offline rule engine.
 * Each case corresponds to a real wrong-answer bug that was fixed:
 * the engine must NOT flag legitimate messages/URLs and MUST flag
 * credential-harvesting scams even without links.
 */
class OfflineAnalyzerTest {

    // ---------- Messages: must NOT flag (previous false positives) ----------

    @Test fun `legitimate bank notification is SAFE`() {
        // Contains "account" twice + "banking"-adjacent words — the old
        // substring matcher scored this 35+ (SUSPICIOUS).
        val r = OfflineAnalyzer.analyzeMessage(
            "Your account XX1234 was credited with Rs 500. " +
                "The updated balance is available in your account statement."
        )!!
        assertEquals("Account-balance SMS must stay SAFE", "SAFE", r.classification)
        assertTrue("risk should be low, was ${r.riskScore}", r.riskScore < 40)
    }

    @Test fun `normal delivery notification is SAFE`() {
        val r = OfflineAnalyzer.analyzeMessage(
            "Your order #48213 has been shipped and will arrive on Friday. " +
                "Track it in your account."
        )!!
        assertEquals("SAFE", r.classification)
    }

    @Test fun `friend mentioning passwords is SAFE`() {
        val r = OfflineAnalyzer.analyzeMessage(
            "I forgot my password again lol. How do I recover my email account?"
        )!!
        assertEquals("Mentioning 'password' without requesting it must stay SAFE",
            "SAFE", r.classification)
    }

    // ---------- Messages: MUST flag (previous false negatives) ----------

    @Test fun `bare OTP request is flagged even without a link`() {
        val r = OfflineAnalyzer.analyzeMessage(
            "Share the OTP you received with our executive to complete verification."
        )!!
        assertTrue("OTP harvesting must be flagged, got ${r.classification}",
            r.classification == "SUSPICIOUS" || r.classification == "SCAM")
    }

    @Test fun `urgent verify-through-link scam is flagged`() {
        val r = OfflineAnalyzer.analyzeMessage(
            "URGENT: Your account will be suspended in 24 hours. " +
                "Verify your identity at http://secure-login.example.tk now"
        )!!
        assertEquals("SCAM", r.classification)
    }

    @Test fun `reward bait with link is flagged`() {
        val r = OfflineAnalyzer.analyzeMessage(
            "Congratulations! You have won a cash prize. Claim your prize at http://bit.ly/prize"
        )!!
        assertTrue(r.riskScore >= 65)
    }

    // ---------- URLs: must NOT flag (previous false positives) ----------

    @Test fun `google home page is SAFE`() {
        val r = OfflineAnalyzer.analyzeUrl("https://www.google.com")
        assertEquals("SAFE", r.classification)
    }

    @Test fun `accounts google signin is SAFE`() {
        // Old engine counted "account"+"secure" from the HOST → 40 SUSPICIOUS.
        val r = OfflineAnalyzer.analyzeUrl("https://accounts.google.com/signin/v2/identifier")
        assertEquals("Legitimate Google signin must be SAFE", "SAFE", r.classification)
    }

    @Test fun `email in query string must not flag`() {
        // '@' is inside the QUERY, not the authority — share links do this.
        val r = OfflineAnalyzer.analyzeUrl(
            "https://mail.google.com/mail/u/0/?to=newfriend@example.com&subject=hi"
        )
        assertEquals("SAFE", r.classification)
    }

    // ---------- URLs: MUST flag ----------

    @Test fun `brand+abused tld+keywords is PHISHING`() {
        val r = OfflineAnalyzer.analyzeUrl("http://paypal-secure.login-verify.tk/step2")
        assertTrue("expected PHISHING, got ${r.classification} (${r.riskScore})",
            r.classification == "PHISHING")
    }

    @Test fun `userinfo credential trick is flagged`() {
        val r = OfflineAnalyzer.analyzeUrl("http://real-bank.com@evil-example.xyz/account")
        assertTrue("expected SUSPICIOUS or PHISHING, got ${r.classification}",
            r.riskScore >= 40)
    }

    @Test fun `raw ip host is flagged`() {
        val r = OfflineAnalyzer.analyzeUrl("http://192.168.13.37/login")
        assertTrue(r.riskScore >= 25)
    }
}
