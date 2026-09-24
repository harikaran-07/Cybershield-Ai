# Privacy

CyberShield AI is defensive and privacy-first by design.

## What is analyzed
- Message/SMS/email text you explicitly submit (paste or share)
- URLs you submit or that are contained in submitted text / decoded QR codes
- QR code content decoded locally on your device by ML Kit
- Files you explicitly select (metadata, header bytes, hashes — never executed)
- App permission lists (from PackageManager, when you open App Security)
- Network connection metadata (only if you enable the optional VPN module)

## What is stored (backend)
- Scan results: type, classification, risk score, severity, indicators, methods, recommendation
- Structured events with minimal evidence (hostnames, labels) for correlation
- App-level summaries for risky apps you chose to analyze

## What is NOT stored by default
- Raw SMS/message content (`STORE_RAW_CONTENT=false` — the default)
- File contents (only name, size, SHA-256 hash, indicators)
- Passwords, OTPs, authentication tokens, or session cookies — never, ever

## What remains local
- QR decoding (ML Kit, on-device)
- Offline protection checks (rules run on-device when backend is unreachable)
- Your settings (DataStore) and anonymous device UUID
- Camera frames (processed in-memory during QR scanning only; never saved)

## What is sent to the backend
- The text/URL/QR/file metadata you choose to scan
- An anonymous random device UUID (generated locally, not a hardware ID)
- App permission lists when you open App Security
- Network destination metadata only when the VPN module is enabled by you

## Deleting your data
- **Settings → Delete Scan History** — removes scans, events, and chains
- **Settings → Delete All Local Data** — clears local settings/history
- Backend: `DELETE /api/v1/threats/history?device_id=<id>`

## Permissions and why
| Permission | Why | When |
|---|---|---|
| INTERNET | Talk to your own backend | Always |
| CAMERA | QR scanning | Only when the scanner is open |
| POST_NOTIFICATIONS | Optional high-risk alerts | Only on Android 13+, opt-in |

SMS integration: CyberShield does **not** request `READ_SMS`. Google Play
policy restricts SMS access to specific app categories; instead you share
messages into CyberShield from any SMS app (Share → CyberShield AI), which
needs no sensitive permission at all.

## Cookies
Cookie attribute analysis (Secure/HttpOnly/SameSite/expiry) requires a browser
integration Android does not generically provide. When unavailable the app
says so explicitly. CyberShield never bypasses browser security to read cookies.
