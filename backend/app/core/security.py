"""Security helpers: request-size limits, filename sanitization, MIME validation."""
import re
import unicodedata
from pathlib import Path

# Known-good MIME type whitelist for scanning
ALLOWED_MIME_PREFIXES = ("image/", "text/", "application/pdf", "application/zip",
                         "application/x-zip-compressed", "application/json", "application/msword",
                         "application/vnd.openxmlformats", "application/vnd.ms-excel",
                         "application/octet-stream", "audio/", "video/")
MAX_FILENAME_LEN = 255

_DOUBLE_EXT_RE = re.compile(r"\.[a-z0-9]{1,5}\.[a-z0-9]{1,5}$", re.IGNORECASE)
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_filename(name: str) -> str:
    """Return a safe filename: strips paths, control chars, normalizes unicode."""
    if not name:
        return "unnamed"
    # Normalize unicode, strip directory components
    name = unicodedata.normalize("NFKD", name)
    name = name.replace("\\", "/").split("/")[-1]
    name = _CTRL_RE.sub("", name).strip().strip(".")
    if len(name) > MAX_FILENAME_LEN:
        # Keep extension intact
        root, ext = Path(name).stem[:MAX_FILENAME_LEN - 10], Path(name).suffix
        name = root + ext
    return name or "unnamed"


def validate_mime_type(mime: str | None, file_ext: str) -> tuple[bool, str]:
    """Validate declared MIME against extension. Returns (is_suspicious, reason)."""
    if not mime:
        return False, ""
    mime = mime.lower().split(";")[0].strip()
    ext = file_ext.lower().lstrip(".")
    # Extension/MIME mismatch table (common dangerous cases)
    mismatches = {
        (".exe", "image/"), (".exe", "application/pdf"), (".pdf", "image/"),
        (".jpg", "application/"), (".png", "application/"), (".txt", "application/octet-stream"),
        (".apk", "image/"), (".doc", "application/zip"),
    }
    for (bad_ext, bad_prefix) in mismatches:
        if ext == bad_ext.lstrip(".") and mime.startswith(bad_prefix):
            return True, f"MIME type '{mime}' does not match '.{ext}' extension"
    if not any(mime.startswith(p) for p in ALLOWED_MIME_PREFIXES):
        return True, f"Unusual MIME type: {mime}"
    return False, ""


def is_double_extension(filename: str) -> bool:
    return bool(_DOUBLE_EXT_RE.search(filename))


def max_body_guard(content_length: int | None) -> bool:
    """Return True if request exceeds configured body limit."""
    from app.core.config import settings
    return content_length is not None and content_length > settings.MAX_BODY_BYTES
