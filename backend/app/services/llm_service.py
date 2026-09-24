"""LLM service — explanation layer (NEVER detection).

RULE 4: the LLM only rephrases structured detection evidence produced by the
detection engines. It cannot override, inflate, or create risk decisions.
Failures degrade gracefully — detection results remain fully usable.

Provider chain (first available wins):
  1. Hosted OpenAI-compatible API (LLM_API_KEY set → works on Vercel serverless)
  2. Local Ollama runtime (dev machines / VPS with `ollama serve`)
  3. Deterministic grounded templates (always available, honestly labeled)
"""
from __future__ import annotations

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cybersecurity education assistant.

Explain the detected threat in simple language.
Use ONLY the evidence provided.
Do not invent technical evidence.
Do not provide offensive hacking instructions.

Give:
1. What was detected
2. Why it may be dangerous
3. What the user should do
4. What the user should avoid

Keep the answer concise and understandable."""


def _build_prompt(threat_type: str, risk_score: int, severity: str,
                  indicators: list[str], question: str | None = None) -> str:
    evidence = {
        "threat_type": threat_type,
        "risk_score": risk_score,
        "severity": severity,
        "indicators": indicators[:12],
    }
    base = (f"{SYSTEM_PROMPT}\n\nEvidence (structured detection output):\n"
            f"{evidence}\n\n")
    if question:
        base += f"The user asks: \"{question}\"\nAnswer using ONLY the evidence above."
    else:
        base += ("Produce the four-part explanation now. Use short paragraphs and "
                 "plain language. Do not add any facts not present in the evidence.")
    return base


def _fallback_explanation(threat_type: str, risk_score: int, severity: str,
                          indicators: list[str]) -> str:
    """Template explanation when no LLM is reachable — honest and useful."""
    ind = "\n".join(f"• {i}" for i in indicators[:6]) or "• No specific indicators listed"
    urgency = ("This looks like a serious threat." if severity in ("HIGH", "CRITICAL")
               else "This shows some warning signs." if severity == "MEDIUM"
               else "No major danger signs were found.")
    return (
        f"What was detected:\n{threat_type} with risk {risk_score}/100 ({severity}).\n\n"
        f"Why it may be dangerous:\n{urgency}\n{ind}\n\n"
        f"What to do:\nDo not open links or attachments from this source. "
        f"Verify through the organization's official app or website.\n\n"
        f"Avoid:\nDo not enter passwords, one-time codes, card details, or other "
        f"sensitive information.\n\n"
        f"(Offline explanation — AI assistant unavailable; deterministic guidance shown.)"
    )


# ---------------------------------------------------------------------------
# Provider 1: hosted OpenAI-compatible API (Vercel-compatible)
# ---------------------------------------------------------------------------

def _hosted_available() -> bool:
    return bool(settings.LLM_API_KEY)


def _hosted_chat(messages: list[dict], temperature: float, max_tokens: int) -> str:
    """Chat completion against any OpenAI-compatible endpoint."""
    url = settings.LLM_BASE_URL.rstrip("/") + "/chat/completions"
    with httpx.Client(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
        resp = client.post(url, headers={
            "Authorization": f"Bearer {settings.LLM_API_KEY}",
            "Content-Type": "application/json",
        }, json={
            "model": settings.LLM_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        })
        resp.raise_for_status()
        text = ((resp.json().get("choices") or [{}])[0].get("message", {}) or {}).get("content") or ""
        text = text.strip()
        if not text:
            raise ValueError("Empty hosted-LLM response")
        return text


# ---------------------------------------------------------------------------
# Provider 2: local Ollama runtime
# ---------------------------------------------------------------------------

def ollama_available(base_url: str | None = None) -> bool:
    """Cheap health check against the Ollama runtime."""
    url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


def _ollama_chat(messages: list[dict], temperature: float, max_tokens: int) -> str:
    with httpx.Client(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
        resp = client.post(f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/chat", json={
            "model": settings.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        })
        resp.raise_for_status()
        text = (resp.json().get("message", {}).get("content") or "").strip()
        if not text:
            raise ValueError("Empty Ollama response")
        return text


# ---------------------------------------------------------------------------
# Aggregate status (for /health and app Settings → AI status)
# ---------------------------------------------------------------------------

def llm_status() -> tuple[str, str | None]:
    """Return (status_string, model_or_None) describing the live LLM tier."""
    if _hosted_available():
        return ("available", settings.LLM_MODEL)
    if ollama_available():
        return ("available", settings.OLLAMA_MODEL)
    return ("unavailable (template explanations in use)", None)


def llm_available() -> bool:
    return _hosted_available() or ollama_available()


def _chat(messages: list[dict], temperature: float, max_tokens: int,
          question_kind: str) -> str:
    """Try hosted, then Ollama. Raises to let caller fall back to templates."""
    if _hosted_available():
        return _hosted_chat(messages, temperature, max_tokens)
    if ollama_available():
        return _ollama_chat(messages, temperature, max_tokens)
    raise RuntimeError(f"No LLM provider reachable for {question_kind}")


# ---------------------------------------------------------------------------
# Public API (unchanged signatures for existing callers)
# ---------------------------------------------------------------------------

def explain_threat(threat_type: str, risk_score: int, severity: str,
                   indicators: list[str], question: str | None = None) -> dict:
    """Return {explanation, llm_used}. Detection result is never modified."""
    if not settings.LLM_EXPLANATIONS_ENABLED:
        return {"explanation": _fallback_explanation(threat_type, risk_score, severity, indicators),
                "llm_used": False}

    prompt = _build_prompt(threat_type, risk_score, severity, indicators, question)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    try:
        text = _chat(messages, temperature=0.3, max_tokens=400, question_kind="explanation")
        return {"explanation": text, "llm_used": True}
    except Exception as exc:
        logger.info("LLM unavailable for explanation (%s); using template", type(exc).__name__)
        return {"explanation": _fallback_explanation(threat_type, risk_score, severity, indicators),
                "llm_used": False}


def chat_response(question: str, context: dict | None = None) -> dict:
    """AI Security Assistant. Grounded in current scan context when provided."""
    q = (question or "").strip()
    if not q:
        return {"answer": "Please ask a question about a scan or a security topic.", "llm_used": False}

    ctx_lines = []
    if context:
        ctx_lines = [f"{k}: {v}" for k, v in context.items() if v not in (None, "", [])]

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"Current scan context (structured evidence):\n" + "\n".join(ctx_lines) + "\n\n"
            if ctx_lines else "No scan context available.\n\n"
        ) + f"User question: {q}\n\nAnswer using only the context above and general "
            "security education. Give practical defensive advice. Do not provide any "
            "hacking, credential-theft, or malware instructions."},
    ]
    try:
        text = _chat(messages, temperature=0.4, max_tokens=350, question_kind="chat")
        return {"answer": text, "llm_used": True}
    except Exception as exc:
        logger.info("LLM unavailable for chat (%s); using grounded template", type(exc).__name__)

    # Offline fallback: context-aware canned guidance
    low = q.lower()
    if "phishing" in low:
        answer = ("Phishing is when attackers impersonate a trusted organization to trick "
                  "you into opening a link or giving up credentials. Check the sender, "
                  "hover before clicking, and verify via official apps.")
    elif any(w in low for w in ("scam", "sms", "message", "spam")):
        answer = ("How to spot a scam SMS or message:\n"
                  "• Urgency and pressure — 'act within 24 hours', 'account will be suspended'.\n"
                  "• Requests for OTPs, passwords, PINs or card details — no legitimate "
                  "organization asks for these by message.\n"
                  "• Too-good-to-be-true rewards — prizes, refunds, lotteries you never entered.\n"
                  "• Links that don't match the official domain (check spelling carefully).\n"
                  "• Threats or scare language about payments or legal action.\n\n"
                  "What to do: don't reply, don't tap links, and verify through the "
                  "organization's official app or website. Scan the message here in "
                  "CyberShield for a full risk analysis.")
    elif any(w in low for w in ("otp", "one-time", "verification code", "pin")):
        answer = ("Never share OTPs or verification codes with anyone — no bank, delivery "
                  "service, or support agent will ever ask for one. If you receive an OTP "
                  "you didn't request, someone may be trying to access your account: "
                  "change the password on that account and enable two-factor authentication.")
    elif "password" in low:
        answer = ("Use a long, unique password for every important account, ideally from a "
                  "password manager. Never reuse your email password anywhere, and turn on "
                  "two-factor authentication wherever it is offered.")
    elif "score" in low or "risk" in low:
        answer = ("Your risk score combines NLP, URL analysis, rules, and correlation "
                  "signals. High scores mean several independent signals agreed. Each "
                  "scan's detail screen shows exactly which signals contributed.")
    elif "secure" in low and ("phone" in low or "device" in low):
        answer = ("Basics: keep the OS updated, install apps only from Play Store, review "
                  "app permissions quarterly, disable installs from unknown sources, and "
                  "use a screen lock with biometrics.")
    elif any(w in low for w in ("malware", "virus", "trojan", "spyware", "infected")):
        answer = ("About malware on phones:\n"
                  "• It usually arrives via sideloaded APKs, fake updates, or links that "
                  "push you to install something outside the Play Store.\n"
                  "• Warning signs: an app requesting overlay + SMS permissions, apps "
                  "that install other apps, sudden unknown apps appearing.\n"
                  "• A sensitive permission alone is NOT proof of malware — many "
                  "legitimate apps need camera or location.\n"
                  "• What to do: uninstall the app in Android Settings, run a CyberShield "
                  "app scan, and change important passwords if you entered them on a "
                  "suspicious screen.\n"
                  "• CyberShield flags evidence-based indicators; it does not claim a "
                  "device is 'infected' without actual detection evidence.")
    elif "permission" in low or ("app" in low and any(w in low for w in ("access", "why", "camera", "location", "microphone"))):
        answer = ("Why apps ask for permissions:\n"
                  "• Permissions are capabilities — camera, location, contacts — that an "
                  "app says it needs. Granting one is a privacy decision, not a virus.\n"
                  "• Reasonable: a maps app needing location; a camera app needing camera.\n"
                  "• Worth reviewing: a simple game asking for contacts or SMS.\n"
                  "• You control this: CyberShield → Apps → tap the app → 'Review in "
                  "Android Settings' shows and revokes each permission. Revoking never "
                  "breaks Android itself.")
    elif "qr" in low:
        answer = ("QR codes can encode anything — including links to phishing pages or "
                  "payment prompts. Treat a QR from a poster, sticker or stranger like a "
                  "link from a stranger: scan it with CyberShield's QR Scanner first, "
                  "check the decoded URL's domain letter-by-letter, and never enter "
                  "passwords or payment details on a page you reached through a QR you "
                  "cannot verify.")
    elif any(w in low for w in ("wifi", "wi-fi", "public network", "hotspot")):
        answer = ("On public Wi-Fi:\n"
                  "• Prefer mobile data for banking or payments; hotel/cafe networks can "
                  "be monitored by strangers.\n"
                  "• Make sure sites use HTTPS (the address starts with https://) — never "
                  "enter credentials on a plain-http login page.\n"
                  "• Turn off auto-join for open networks, and forget networks you no "
                  "longer use.\n"
                  "• CyberShield's network checks work with the metadata Android exposes; "
                  "it does not inspect other apps' traffic.")
    elif "breach" in low or "leaked" in low or "pwned" in low:
        answer = ("After a suspected data breach:\n"
                  "• Change the password of the affected service first, then anywhere you "
                  "reused that password.\n"
                  "• Enable two-factor authentication — an app-based code or security "
                  "key, not SMS if you can avoid it.\n"
                  "• Watch for phishing that references the breach; attackers use leaked "
                  "details to sound convincing.\n"
                  "• CyberShield never sends your credentials anywhere; breach checking "
                  "would only ever process account metadata you explicitly submit.")
    else:
        answer = ("Answering with built-in guidance (the generative AI layer is not "
                  "configured, but the security backend is up): don't open links or "
                  "attachments from suspicious sources, never share one-time codes, and "
                  "verify organizations through their official app or website. For "
                  "specific results, ask about scams, phishing, malware, permissions, "
                  "QR codes, public Wi-Fi, or your security score — or run a scan and "
                  "ask about its findings.")
    return {"answer": answer, "llm_used": False}
