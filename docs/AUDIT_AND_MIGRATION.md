# CyberShield AI — Project Audit & Android Security-Manager Migration Plan

## 1. Audit of existing codebase (verified on disk, Sept 2026)

### Components
| Layer | Location | Status |
|---|---|---|
| Android app | `android/` — Kotlin, Compose M3, MVVM, Retrofit, ML Kit QR, 22 Kotlin files | Working code; **cannot be compiled in this environment** (no JDK/Android SDK installed) |
| Backend | `backend/` — FastAPI, 34 Python modules, 15/15 tests green | Working, verified live |
| Web Console | `web/index.html` on Vercel (cybershield-two-rho.vercel.app) | Working, deployed & verified (HTTP 200) |
| Database | SQLAlchemy: users, devices, scan_results, messages, urls, files, threat_events, threat_chains, security_alerts, app_security_results, network_anomalies | Working; SQLite dev / PostgreSQL prod |
| Auth | None by design — anonymous random device UUID | Intentional, privacy-first |
| Env vars | `backend/.env.example` (DB, Ollama, model paths, weights) | Present, no secrets committed |
| Deployment | `vercel.json` (web) + `backend/Dockerfile` + `docker-compose.yml` | Working |

### Detection stack (existing, preserved)
- **Rule engine**: 19-feature URL extractor, message rules (urgency/credential/reward/harmful-action)
- **NLP**: RoBERTa interface with transparent keyword fallback (`/health` reports model status honestly)
- **URL ML**: XGBoost interface + rule fallback (URLs never fetched)
- **Anomaly**: Isolation Forest interface + statistical fallback
- **File**: static-only (SHA-256, magic bytes, double extensions, archive traversal, PDF JS flags)
- **QR**: ML Kit decode → payload triage (URL/Wi-Fi/EMVCo payment — read-only)
- **App security**: PackageManager permission categorization LOW/MEDIUM/HIGH
- **Risk engine**: transparent weighted combination, per-signal breakdown, corroboration boost
- **Threat correlation**: 30-min window, chain ordering, strong-pair/host escalation, persisted chains
- **LLM**: Ollama/Qwen, evidence-only explanations, never overrides detection

### Broken / non-functional (honest list)
1. **Android compilation** — no JDK/Android SDK in this environment; verified via backend tests + careful API usage instead.
2. **Web console is offline-only** — Vercel serves static heuristics; full ML runs only where the FastAPI backend is reachable.
3. **No trained model binaries** — by design; fallbacks are labeled, not faked.
4. **No device-local persistence on Android** — history lived only on the backend (migrating to Room, below).
5. **No background monitoring** — Android app was scan-triggered only (migrating, below).

### Fake/demo results audit
None found. All fallback paths are explicitly labeled ("fallback (no trained model loaded)",
"Offline Rules", "template explanations"). Nothing to remove.

## 2. Migration plan (executed in this upgrade)

### Android (primary client — phone-side monitoring)
| # | Change | Files |
|---|---|---|
| A1 | Room persistence for security events (local-first history, retention-aware) | `data/local/*` |
| A2 | Local ThreatEngine: risk scoring + correlation on-device (works with backend offline) | `engine/*` |
| A3 | Background monitor: NotificationListener (opt-in), package add/remove via BroadcastReceiver, 6h WorkManager hygiene scan | `monitor/*` |
| A4 | APK static analyzer (ZIP listing, manifest permission extraction, never executes) | `utils/ApkAnalyzer.kt` |
| A5 | Privacy Manager screen (dangerous-grant review + Settings intents) | `ui/privacy/PrivacyScreen.kt` |
| A6 | Network Security screen (Wi-Fi security, VPN status — observable signals only) | `ui/network/NetworkScreen.kt` |
| A7 | Protection Setup screen (explain-before-request permission UX) | `ui/settings/ProtectionSetupScreen.kt` |
| A8 | AI Assistant screen (backend-grounded, graceful offline) | `ui/assistant/AssistantScreen.kt` |
| A9 | Dashboard driven by real local Room data (no fake stats; empty-state honest) | `ui/home/HomeScreen.kt` |
| A10 | Navigation expanded: Home/Scan/Threats/Apps/Privacy/Network/Assistant/Settings | `ui/CyberShieldApp.kt` |

### Backend (extends, does not replace)
| # | Change | Files |
|---|---|---|
| B1 | New endpoints: `/api/url/analyze`, `/api/text/analyze`, `/api/file/analyze`, `/api/apk/analyze`, `/api/threat/correlate`, `/api/security/events`, `/api/security/summary` | `api/routes_v2.py` |
| B2 | APK static analyzer: ZIP traversal, AndroidManifest permission extraction, dangerous-combination rules | `services/apk_service.py` |

### Web Console (repurposed per spec §23)
| # | Change | Files |
|---|---|---|
| C1 | Rebranded "CyberShield Security Console": console positioning, backend-events view, honest disclaimer that phone monitoring happens on Android | `web/index.html` |
| C2 | Redeploy to Vercel, verify production URL | — |

### Explicit non-goals (Android limitations, per spec §31)
No SMS permission (Play-policy + share-intent flow instead), no accessibility-service scraping,
no packet capture/HTTPS inspection, no reading other apps' private storage, no OTP/password collection,
no destructive auto-actions. All limitation boundaries are communicated in-app.
