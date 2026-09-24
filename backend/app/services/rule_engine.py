"""Rule-based detection engine.

Pure-Python heuristics — no ML. Responsibilities:
- Extract lexical/structural URL features for XGBoost
- Message rules (urgency, credential requests, threats)
- Interpret ML feature vectors as human-readable indicators
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

# ---------------------------------------------------------------------------
# Keyword lists (extendable; deliberately broad but explainable)
# ---------------------------------------------------------------------------
SUSPICIOUS_TLD = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "country",
    "work", "link", "fit", "rest", "surf", "cam", "monster", "quest", "cfd",
}
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "rebrand.ly", "ow.ly", "buff.ly", "t.ly",
}
URL_SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "banking", "wallet", "password", "credential", "webscr", "invoice",
    "payment", "billing", "recover", "unlock", "suspended", "alert", "gift",
    "bonus", "winner", "free", "prize", "crypto", "airdrop", "seed",
}
BRAND_IMPERSONATION = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
    "google", "gmail", "amazon", "netflix", "facebook", "instagram",
    "whatsapp", "binance", "coinbase", "metamask", "dhl", "fedex", "ups",
    "hsbc", "chase", "wellsfargo", "santander", "revolut", "steam",
}
MESSAGE_URGENCY = [
    "urgent", "immediately", "right now", "asap", "act now", "final notice",
    "last warning", "expires today", "within 24 hours", "24 hours",
    "suspended", "suspend", "locked", "blocked", "terminated", "deactivated",
]
MESSAGE_AUTHORITY = [
    "bank", "irs", "tax office", "police", "government", "support team",
    "security team", "administrator", "customer care", "delivery",
    "verification team", "it department",
]
MESSAGE_CREDENTIAL_SEEKING = [
    "verify your account", "confirm your identity", "enter your password",
    "provide your", "your otp", "one-time code", "verification code",
    "cvv", "card number", "seed phrase", "recovery phrase", "ssn",
    "social security", "update your payment", "billing information",
    "click the link to verify", "login to your account",
    "verify immediately", "verify now", "account verification",
]
MESSAGE_REWARD_BAIT = [
    "you have won", "congratulations", "lucky winner", "claim your prize",
    "free gift", "cash reward", "lottery", "inheritance", "investment returns",
    "double your", "guaranteed profit", "passive income",
]
MESSAGE_MALICIOUS_ACTION = [
    "download the apk", "install the app", "enable notifications",
    "disable antivirus", "allow accessibility", "grant permission",
    "scan the qr", "open the attachment", "enable macros",
]
MESSAGE_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"          # scheme/www URLs
    r"|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>\"']*)?",  # bare domains
    re.IGNORECASE,
)
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PUNYCODE_MARK = "xn--"
HEX_ENTITY_RE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)


@dataclass
class UrlFeatures:
    """Structural URL features — exactly the vector XGBoost was trained on."""
    url_length: int = 0
    hostname_length: int = 0
    num_subdomains: int = 0
    num_dots: int = 0
    num_special_chars: int = 0
    num_digits: int = 0
    digit_ratio: float = 0.0
    has_https: int = 0
    has_ip_host: int = 0
    has_punycode: int = 0
    num_encoded_chars: int = 0
    num_query_params: int = 0
    path_depth: int = 0
    suspicious_keywords: int = 0
    brand_in_path: int = 0
    is_shortener: int = 0
    suspicious_tld: int = 0
    uses_at_sign: int = 0
    double_slash_in_path: int = 0

    def to_vector(self) -> list[float]:
        return [
            self.url_length, self.hostname_length, self.num_subdomains,
            self.num_dots, self.num_special_chars, self.num_digits,
            self.digit_ratio, self.has_https, self.has_ip_host,
            self.has_punycode, self.num_encoded_chars, self.num_query_params,
            self.path_depth, self.suspicious_keywords, self.brand_in_path,
            self.is_shortener, self.suspicious_tld, self.uses_at_sign,
            self.double_slash_in_path,
        ]


FEATURE_NAMES = [
    "url_length", "hostname_length", "num_subdomains", "num_dots",
    "num_special_chars", "num_digits", "digit_ratio", "has_https",
    "has_ip_host", "has_punycode", "num_encoded_chars", "num_query_params",
    "path_depth", "suspicious_keywords", "brand_in_path", "is_shortener",
    "suspicious_tld", "uses_at_sign", "double_slash_in_path",
]


@dataclass
class RuleHit:
    code: str
    description: str
    weight: int  # 0–100 contribution hint for the risk engine


@dataclass
class MessageRules:
    hits: list[RuleHit] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    urgency_score: int = 0

    @property
    def rule_score(self) -> int:
        """Weighted-capped rule score 0–100."""
        if not self.hits:
            return 0
        raw = sum(h.weight for h in self.hits)
        return min(100, int(raw * 0.8))


def extract_url_features(url: str) -> UrlFeatures:
    """Safe static analysis — never fetches the URL."""
    url = (url or "").strip()
    f = UrlFeatures()
    if not url:
        return f
    # Normalize: assume http if no scheme so urlparse splits correctly
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    f.url_length = len(url)
    f.hostname_length = len(host)
    f.num_dots = host.count(".")
    f.num_subdomains = max(0, f.num_dots - 1)
    f.num_special_chars = sum(1 for c in full if c in "@%-_=~?&+;:,!$'#*()[]{}|\\/<>")
    digits = sum(1 for c in full if c.isdigit())
    f.num_digits = digits
    f.digit_ratio = round(digits / max(1, len(full)), 3)
    f.has_https = int(parsed.scheme == "https")
    f.has_ip_host = int(bool(IP_HOST_RE.match(host)))
    f.has_punycode = int(PUNYCODE_MARK in host)
    f.num_encoded_chars = len(HEX_ENTITY_RE.findall(url))
    f.num_query_params = len(parse_qs(query))
    f.path_depth = max(0, path.count("/") - 1)
    f.suspicious_keywords = sum(1 for kw in URL_SUSPICIOUS_KEYWORDS if kw in full)
    f.brand_in_path = sum(1 for b in BRAND_IMPERSONATION if b in path.lower() or b in query.lower())
    f.is_shortener = int(host in SHORTENER_HOSTS)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    f.suspicious_tld = int(tld in SUSPICIOUS_TLD)
    f.uses_at_sign = int("@" in full)
    f.double_slash_in_path = int("//" in path[1:])
    return f


def describe_features(f: UrlFeatures) -> list[RuleHit]:
    """Turn an activated feature vector into human-readable indicators."""
    hits: list[RuleHit] = []
    add = hits.append
    if f.has_ip_host:
        add(RuleHit("IP_HOST", "Host is a raw IP address instead of a domain name", 35))
    if f.has_punycode:
        add(RuleHit("PUNYCODE", "Punycode (xn--) hostname — may imitate another domain", 30))
    if f.uses_at_sign:
        add(RuleHit("AT_SIGN", "URL contains '@' — text before it is ignored by browsers", 30))
    if f.num_subdomains >= 4:
        add(RuleHit("MANY_SUBDOMAINS", f"Many subdomain levels ({f.num_subdomains})", 20))
    if f.suspicious_keywords >= 3:
        add(RuleHit("KEYWORDS", f"{f.suspicious_keywords} phishing-related keywords in URL", 25))
    if f.brand_in_path and not f.has_https:
        add(RuleHit("BRAND_NO_HTTPS", "Brand name in path without HTTPS", 25))
    elif f.brand_in_path:
        add(RuleHit("BRAND_PATH", "Brand name appears outside the real domain", 15))
    if f.is_shortener:
        add(RuleHit("SHORTENER", "Shortened URL — final destination is hidden", 20))
    if f.suspicious_tld:
        add(RuleHit("TLD", "Domain uses a TLD frequently abused in phishing", 20))
    if f.num_encoded_chars >= 3:
        add(RuleHit("ENCODED", "Multiple percent-encoded characters", 15))
    if f.double_slash_in_path:
        add(RuleHit("DOUBLE_SLASH", "Double slash inside the path", 10))
    if f.url_length > 100:
        add(RuleHit("LONG_URL", f"Unusually long URL ({f.url_length} chars)", 10))
    if f.digit_ratio > 0.35 and f.url_length > 20:
        add(RuleHit("DIGIT_HEAVY", "High proportion of digits in URL", 15))
    return hits


def analyze_message_rules(text: str) -> MessageRules:
    """Rule analysis of message text. Returns hits, extracted URLs, urgency."""
    result = MessageRules()
    low = (text or "").lower()

    for url in MESSAGE_URL_RE.findall(text or ""):
        candidate = url.rstrip(".,;:!?)\"'")
        if candidate not in result.urls:
            result.urls.append(candidate)

    if any(k in low for k in MESSAGE_URGENCY):
        result.hits.append(RuleHit("URGENT", "Urgent or pressure language", 25))
        result.urgency_score += 40
    if any(k in low for k in MESSAGE_CREDENTIAL_SEEKING):
        result.hits.append(RuleHit("CREDENTIAL_SEEK", "Requests credentials, codes, or payment details", 40))
        result.urgency_score += 25
    if any(k in low for k in MESSAGE_REWARD_BAIT):
        result.hits.append(RuleHit("REWARD_BAIT", "Too-good-to-be-true reward language", 25))
    if any(k in low for k in MESSAGE_MALICIOUS_ACTION):
        result.hits.append(RuleHit("HARMFUL_ACTION", "Asks user to install apps or change device settings", 35))
    if any(k in low for k in MESSAGE_AUTHORITY) and result.urgency_score >= 25:
        result.hits.append(RuleHit("AUTHORITY_PRESSURE", "Claims authority combined with urgency", 20))
    if result.urls:
        result.hits.append(RuleHit("CONTAINS_URL", "Contains one or more URLs", 10))
    if len(text or "") > 300 and result.urgency_score >= 40:
        result.hits.append(RuleHit("LONG_PRESSURE", "Long message with sustained pressure language", 10))

    result.urgency_score = min(100, result.urgency_score)
    return result
