"""App Security service — permission risk categorization.

Analyzes permission lists reported by the Android client. Permission names come
from the device via legitimate PackageManager APIs. A permission never proves an
app is malware — it only raises privacy risk depending on usage.
"""
from __future__ import annotations

# Android permission -> risk category + plain-language note
PERMISSION_RISK: dict[str, tuple[str, str]] = {
    # HIGH
    "android.permission.READ_SMS": ("HIGH", "Can read all SMS messages, including bank OTPs"),
    "android.permission.RECEIVE_SMS": ("HIGH", "Can intercept incoming SMS codes"),
    "android.permission.SEND_SMS": ("HIGH", "Can send SMS, possibly premium numbers"),
    "android.permission.ACCESSIBILITY_SERVICES": ("HIGH", "Accessibility can read screen content and capture input"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("HIGH", "Can draw overlays that fake login screens"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("HIGH", "Can install apps from outside the Play Store"),
    "android.permission.READ_CALL_LOG": ("HIGH", "Exposes who you call and when"),
    "android.permission.CALL_PHONE": ("HIGH", "Can place calls without confirmation"),
    "android.permission.BODY_SENSORS": ("HIGH", "Reads health sensor data"),
    "android.permission.READ_CONTACTS": ("MEDIUM", "Exposes your contact list"),
    # MEDIUM
    "android.permission.CAMERA": ("MEDIUM", "Can take photos/video when in use"),
    "android.permission.RECORD_AUDIO": ("MEDIUM", "Can record audio when in use"),
    "android.permission.ACCESS_FINE_LOCATION": ("MEDIUM", "Precise location history risk"),
    "android.permission.ACCESS_COARSE_LOCATION": ("MEDIUM", "Approximate location risk"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("HIGH", "Location tracking when app is closed"),
    "android.permission.READ_MEDIA_IMAGES": ("MEDIUM", "Can read your photos"),
    "android.permission.READ_MEDIA_VIDEO": ("MEDIUM", "Can read your videos"),
    "android.permission.READ_EXTERNAL_STORAGE": ("MEDIUM", "Can read shared files"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("MEDIUM", "Can modify shared files"),
    "android.permission.BLUETOOTH_CONNECT": ("MEDIUM", "Bluetooth device access"),
    "android.permission.POST_NOTIFICATIONS": ("LOW", "Shows notifications"),
    # LOW
    "android.permission.INTERNET": ("LOW", "Needs network access"),
    "android.permission.ACCESS_NETWORK_STATE": ("LOW", "Checks connectivity"),
    "android.permission.VIBRATE": ("LOW", "Vibration feedback"),
    "android.permission.NFC": ("LOW", "Near-field communication"),
    "android.permission.FOREGROUND_SERVICE": ("LOW", "Runs while in use"),
    "android.permission.WAKE_LOCK": ("LOW", "Keeps device awake"),
    "android.permission.USE_BIOMETRIC": ("LOW", "Biometric unlock"),
}

DEFAULT_CATEGORY = ("MEDIUM", "Unrecognized permission — review manually")
UNKNOWN_SOURCE_NOTE = ("App installed from outside an official store — verify its source "
                       "before granting sensitive permissions.")
ACCESSIBILITY_NOTE = ("Accessibility service enabled — this can read screen content; "
                      "grant only to apps you fully trust.")


def analyze_app(app: dict) -> dict:
    """Risk-assess one app's permission list. Detection is conservative."""
    perms: list[dict] = []
    high = med = 0
    for p in app.get("permissions", []):
        cat, note = PERMISSION_RISK.get(p, DEFAULT_CATEGORY)
        if cat == "HIGH":
            high += 1
        elif cat == "MEDIUM":
            med += 1
        perms.append({"permission": p, "category": cat})

    notes: list[str] = []
    if app.get("from_unknown_source"):
        notes.append(UNKNOWN_SOURCE_NOTE)
    if app.get("accessibility_enabled"):
        notes.append(ACCESSIBILITY_NOTE)

    # Score: conservative — a permission alone is NOT evidence of malware
    score = high * 15 + med * 5
    if app.get("from_unknown_source"):
        score += 15
    if app.get("accessibility_enabled"):
        score += 10
    score = min(100, score)

    label = "RISKY" if score >= 60 else "CAUTION" if score >= 30 else "SAFE"
    return {
        "package_name": app.get("package_name", "unknown"),
        "app_name": app.get("app_name"),
        "risk_score": score,
        "label": label,
        "permissions": perms,
        "notes": notes or ["Permissions reviewed — no elevated privacy flags"],
    }


def analyze_apps(apps: list[dict]) -> dict:
    """Batch analysis with device-level summary."""
    results = [analyze_app(a) for a in apps]
    risky = sorted([r for r in results if r["label"] != "SAFE"],
                   key=lambda r: -r["risk_score"])
    return {
        "apps": results,
        "summary": {
            "total_apps": len(results),
            "risky_count": len(risky),
            "top_risky": [r["package_name"] for r in risky[:10]],
            "avg_risk": round(sum(r["risk_score"] for r in results) / max(1, len(results)), 1),
        },
        "disclaimer": ("A permission only increases privacy risk depending on how the "
                       "application uses it — it does not prove an app is malware."),
    }
