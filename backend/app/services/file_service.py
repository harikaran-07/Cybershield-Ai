"""File analysis service — safe static inspection only.

NEVER executes files. NEVER installs files. Only reads bytes to hash and
inspects name/MIME/metadata. Supports: images, PDF, ZIP, JSON, text.

Returns FileAnalysisOut-compatible dict.
"""
from __future__ import annotations

import hashlib
import logging
import struct
import zlib
from pathlib import Path

from app.core.security import is_double_extension, sanitize_filename, validate_mime_type

logger = logging.getLogger(__name__)

_EXECUTABLE_EXTS = {".exe", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".apk", ".dll"}
_SCRIPTY_EXTS = {".hta", ".lnk", ".wsf", ".sh"}
_ARCHIVE_EXTS = {".zip", ".apk", ".jar", ".docx", ".xlsx", ".pptx", ".epub"}

# Magic bytes: extension -> (expected magic, description)
_MAGIC = {
    ".png": (b"\x89PNG\r\n\x1a\n", "PNG image"),
    ".jpg": (b"\xff\xd8\xff", "JPEG image"),
    ".jpeg": (b"\xff\xd8\xff", "JPEG image"),
    ".gif": (b"GIF8", "GIF image"),
    ".pdf": (b"%PDF-", "PDF document"),
    ".zip": (b"PK\x03\x04", "ZIP archive"),
    ".apk": (b"PK\x03\x04", "Android package (ZIP)"),
    ".jar": (b"PK\x03\x04", "Java archive (ZIP)"),
    ".exe": (b"MZ", "Windows executable"),
    ".docx": (b"PK\x03\x04", "Office document (ZIP)"),
    ".xlsx": (b"PK\x03\x04", "Office spreadsheet (ZIP)"),
}

EXECUTABLE_NOTE = "Executable/script file type — treat as high risk unless you expected it."


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_magic(ext: str, head: bytes) -> str | None:
    if ext in _MAGIC:
        expected, desc = _MAGIC[ext]
        if not head.startswith(expected):
            return f"File header does not match expected {desc} format"
    return None


def _archive_entry_names(data: bytes) -> list[str] | None:
    """Safely list entries of a ZIP archive (read-only, no extraction)."""
    import io
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return zf.namelist()[:100]
    except Exception:
        return None


def _suspicious_archive_entries(names: list[str]) -> list[str]:
    flags: list[str] = []
    for n in names:
        low = n.lower()
        if low.endswith(_EXECUTABLE_EXTS | _SCRIPTY_EXTS):
            flags.append(f"Archive contains executable/script entry: {n}")
        if ".." in n or n.startswith("/"):
            flags.append(f"Archive entry escapes its folder (path traversal): {n}")
    return flags


def _pdf_metadata_flags(data: bytes) -> list[str]:
    flags: list[str] = []
    if b"/JavaScript" in data or b"/JS" in data:
        flags.append("PDF contains embedded JavaScript")
    if b"/OpenAction" in data or b"/AA" in data:
        flags.append("PDF has automatic-action entries (OpenAction/AA)")
    if b"/EmbeddedFile" in data:
        flags.append("PDF embeds an attached file")
    if b"/Launch" in data:
        flags.append("PDF can launch external applications")
    return flags


def analyze_file(filename: str, data: bytes, declared_mime: str | None = None) -> dict:
    """Static analysis only. Never executes, extracts, or installs anything."""
    safe_name = sanitize_filename(filename)
    ext = Path(safe_name).suffix.lower()
    size = len(data)
    sha = _sha256(data)
    head = data[:512]

    indicators: list[str] = []
    method = ["Rule Engine", "Hashing", "Metadata"]

    # --- Name/extension checks ---
    if is_double_extension(safe_name):
        indicators.append("Double file extension (e.g. invoice.pdf.exe)")
    if ext in _EXECUTABLE_EXTS or ext in _SCRIPTY_EXTS:
        indicators.append(EXECUTABLE_NOTE)
    # Executable hidden as document/image
    disguise_map = {".exe", ".scr", ".msi", ".bat", ".cmd", ".apk", ".jar", ".vbs", ".js"}
    if ext in disguise_map and any(e in safe_name.lower() for e in (".pdf", ".jpg", ".png", ".doc", ".txt")):
        indicators.append("Filename contains an embedded document/image extension")

    # --- MIME validation ---
    mime_sus, mime_reason = validate_mime_type(declared_mime, ext)
    if mime_sus:
        indicators.append(mime_reason)
        method.append("MIME Validation")

    # --- Magic-byte check (extension vs real content) ---
    mismatch = False
    magic_reason = _check_magic(ext, head)
    if magic_reason:
        mismatch = True
        indicators.append(magic_reason)
        method.append("Content Header Inspection")

    # --- Metadata inspection ---
    metadata_notes: list[str] = []
    if ext in _ARCHIVE_EXTS and head.startswith(b"PK"):
        names = _archive_entry_names(data)
        if names is None:
            indicators.append("ZIP-based file is corrupted or not readable")
        else:
            flags = _suspicious_archive_entries(names)
            indicators.extend(flags)
            metadata_notes.append(f"Archive contains {len(names)} entries")
    elif ext == ".pdf":
        indicators.extend(_pdf_metadata_flags(data))
        metadata_notes.append("PDF metadata inspected (static scan)")

    # --- Risk scoring ---
    score = min(100, len(indicators) * 18 + (25 if ext in _EXECUTABLE_EXTS else 0) +
                (15 if mismatch else 0))
    if size == 0:
        indicators.append("File is empty (0 bytes)")
        score = min(100, score + 10)

    label = ("RISKY" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE")
    severity = ("CRITICAL" if score >= 90 else "HIGH" if score >= 75 else
                "MEDIUM" if score >= 50 else "LOW" if score >= 25 else "SAFE")
    recommendation = ("Do not open or install this file unless you fully trust the source. "
                      if label != "SAFE" else
                      "No major static risk indicators. Still only open files you expect.")

    return {
        "filename": safe_name,
        "mime_type": declared_mime,
        "size_bytes": size,
        "sha256": sha,
        "extension_mismatch": mismatch,
        "double_extension": is_double_extension(safe_name),
        "indicators": indicators or ["No suspicious characteristics detected"],
        "metadata_notes": metadata_notes,
        "risk_score": score,
        "severity": severity,
        "label": label,
        "detection_methods": method,
        "recommendation": recommendation,
        "note": "Static analysis only — the file was never executed or installed.",
    }
