"""APK static analysis service — safe inspection only.

NEVER executes, installs, or extracts APKs to disk. Reads the ZIP structure
and the binary AndroidManifest string pool for permission strings, then
applies the same permission-risk rules as app-security analysis.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import zipfile

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_CONTACTS",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.BODY_SENSORS",
}
OVERLAY_PERMISSIONS = {"android.permission.SYSTEM_ALERT_WINDOW",
                       "android.permission.BIND_ACCESSIBILITY_SERVICE"}

_PERM_RE = re.compile(rb"android\.permission\.[A-Z_]+")
_PERM_TEXT_RE = re.compile(r"android\.permission\.[A-Z_]+")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_permissions(manifest: bytes) -> list[str]:
    """Scan the binary manifest string pool for permission strings.
    Handles both UTF-8 and UTF-16LE pools (APKs use either)."""
    seen: list[str] = []
    # UTF-8 / ASCII pools appear as raw bytes
    for m in _PERM_RE.finditer(manifest):
        try:
            perm = m.group(0).decode("ascii")
        except Exception:
            continue
        if perm not in seen:
            seen.append(perm)
    # UTF-16LE pools appear as interleaved NUL bytes
    try:
        text = manifest.decode("utf-16-le", errors="ignore")
        for m in _PERM_TEXT_RE.finditer(text):
            if m.group(0) not in seen:
                seen.append(m.group(0))
    except Exception:
        pass
    return seen


def analyze_apk(filename: str, data: bytes) -> dict:
    """Static APK analysis. Never executes the package."""
    indicators: list[str] = []
    methods = ["ZIP Structure", "Manifest Extraction", "Permission Rules", "Hashing"]

    sha = _sha256(data)
    entry_count = 0
    dex_count = 0
    has_native = False
    manifest_bytes: bytes | None = None

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for entry in zf.namelist()[:2000]:
                entry_count += 1
                if entry == "AndroidManifest.xml" and manifest_bytes is None:
                    manifest_bytes = zf.read(entry)
                elif entry.endswith(".dex"):
                    dex_count += 1
                elif entry.startswith("lib/"):
                    has_native = True
                if ".." in entry:
                    indicators.append(f"ZIP entry path traversal pattern: {entry}")
    except zipfile.BadZipFile:
        indicators.append("Not a valid ZIP/APK archive — structure is unreadable")
        methods = ["Hashing"]
    except Exception as exc:
        indicators.append(f"Archive could not be fully inspected ({type(exc).__name__})")

    permissions = _extract_permissions(manifest_bytes) if manifest_bytes else []
    if manifest_bytes is None:
        indicators.append("AndroidManifest.xml missing or unreadable")

    dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    if dangerous:
        indicators.append(
            f"{len(dangerous)} high-risk permission(s) requested: " +
            ", ".join(p.rsplit(".", 1)[-1] for p in dangerous[:5]))

    perm_set = set(permissions)
    if perm_set & OVERLAY_PERMISSIONS and (perm_set & {"android.permission.READ_SMS",
                                                        "android.permission.RECEIVE_SMS"}):
        indicators.append("Overlay/accessibility combined with SMS access — "
                          "classic credential-capture pattern")
    if dex_count > 3:
        indicators.append(f"Multiple DEX files ({dex_count}) — dynamic loading is common")
    if has_native:
        indicators.append("Contains native libraries")

    score = min(100, len(dangerous) * 15 + len(indicators) * 8)
    severity = ("CRITICAL" if score >= 90 else "HIGH" if score >= 75 else
                "MEDIUM" if score >= 50 else "LOW" if score >= 25 else "SAFE")
    label = "RISKY" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE"
    recommendation = ("Do not install this APK unless you fully trust its source. "
                      "Compare the permission list with what the app claims to do."
                      if label != "SAFE" else
                      "No suspicious static indicators found. Verify the source before installing.")

    return {
        "filename": filename,
        "sha256": sha,
        "size_bytes": len(data),
        "package_name": None,
        "permissions": permissions,
        "dangerous_permissions": dangerous,
        "indicators": indicators or ["No suspicious static indicators found"],
        "risk_score": score,
        "severity": severity,
        "classification": label,
        "entry_count": entry_count,
        "dex_count": dex_count,
        "has_native_libs": has_native,
        "detection_methods": methods,
        "recommendation": recommendation,
        "note": "Static analysis only — the APK was never executed or installed.",
    }
