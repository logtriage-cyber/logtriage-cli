# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
CEF (Common Event Format) log parser.

Covers: Palo Alto, Check Point, Fortinet, ArcSight, CrowdStrike, and any vendor
that outputs syslog in CEF format.

Format:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Extension is a space-delimited set of key=value pairs.

Reference: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/
           cef-implementation-standard/
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

_HASH_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_HASH_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")

logger = logging.getLogger(__name__)

# CEF header: CEF:version|vendor|product|version|sigID|name|severity|extension
_CEF_HEADER_RE = re.compile(
    r"^CEF:(\d+)\|"          # version
    r"([^|]*)\|"              # Device Vendor
    r"([^|]*)\|"              # Device Product
    r"([^|]*)\|"              # Device Version
    r"([^|]*)\|"              # Signature ID
    r"([^|]*)\|"              # Name
    r"([^|]*)"                # Severity (0-10)
    r"(?:\|(.*))?$",          # Extension (optional)
    re.DOTALL,
)

# Extension key=value parser — value extends until next \s+key= or end of string
_EXT_PAIR_RE = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)", re.DOTALL)

# CEF outcome → HTTP-like status code
_OUTCOME_STATUS: dict[str, int] = {
    "allow": 200,
    "success": 200,
    "0": 200,
    "permit": 200,
    "deny": 403,
    "block": 403,
    "drop": 403,
    "reset": 400,
    "fail": 500,
    "failure": 500,
}

# Epoch timestamp if rt value is numeric (ms since epoch)
_EPOCH_THRESHOLD = 1_000_000_000_000  # > this → milliseconds


def _parse_cef_extension(ext_str: str) -> dict[str, str]:
    return {m.group(1): m.group(2).strip() for m in _EXT_PAIR_RE.finditer(ext_str)}


def _parse_cef_timestamp(ext: dict[str, str]) -> datetime:
    """Parse rt / deviceReceiptTime / start / end from extension."""
    raw = ext.get("rt") or ext.get("deviceReceiptTime") or ext.get("start") or ext.get("end")
    if not raw:
        return datetime.now(timezone.utc)
    raw = raw.strip()
    # Epoch milliseconds
    try:
        ms = int(raw)
        epoch_s = ms / 1000 if ms > _EPOCH_THRESHOLD else float(ms)
        return datetime.fromtimestamp(epoch_s, tz=timezone.utc)
    except ValueError:
        pass
    # ISO-8601 or similar
    for fmt in (
        "%b %d %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _parse_status(ext: dict[str, str], severity: str) -> int | None:
    """Derive HTTP-like status from outcome, act, or CEF severity."""
    outcome = (ext.get("outcome") or ext.get("act") or "").lower().strip()
    if outcome in _OUTCOME_STATUS:
        return _OUTCOME_STATUS[outcome]
    # High CEF severity (7-10) → treat as error
    try:
        sev = int(severity)
        if sev >= 7:
            return 400
    except (ValueError, TypeError):
        pass
    return None


def _parse_cef_line(line: str) -> LogEvent | None:
    line = line.strip()
    if not line:
        return None

    # Strip optional syslog prefix before CEF:
    cef_idx = line.find("CEF:")
    if cef_idx < 0:
        return None
    line = line[cef_idx:]

    m = _CEF_HEADER_RE.match(line)
    if not m:
        logger.debug("CEF parser: no header match: %r", line[:120])
        return None

    severity = m.group(7).strip()
    ext_str = m.group(8) or ""
    ext = _parse_cef_extension(ext_str)

    # IP address — src preferred, fall back to sourceAddress / dvc
    ip = (
        ext.get("src")
        or ext.get("sourceAddress")
        or ext.get("shost")
        or ext.get("dvc")
    )

    # User — destination user preferred, then source user
    user = (
        ext.get("duser")
        or ext.get("destinationUserName")
        or ext.get("suser")
        or ext.get("sourceUserName")
    )

    # User-Agent
    ua = ext.get("requestClientApplication") or ext.get("cs1")

    # Path / URL
    path = ext.get("request") or ext.get("requestURL") or ext.get("filePath")

    # HTTP method
    method = ext.get("requestMethod") or ext.get("method")

    # File hash — standard CEF key is fileHash; vendors also use sha256/md5/cs5
    _hash_raw = (
        ext.get("fileHash")
        or ext.get("sha256")
        or ext.get("md5")
        or ext.get("cs5")
    )
    file_hash: str | None = None
    if _hash_raw:
        h = _hash_raw.strip().lower()
        if _HASH_SHA256_RE.match(h) or _HASH_MD5_RE.match(h):
            file_hash = h

    # Bytes transferred — bytesIn/Out are most common; cnt is a packet count fallback
    _bytes_raw = ext.get("bytesIn") or ext.get("bytesOut") or ext.get("cnt")
    response_size: int | None = None
    if _bytes_raw:
        try:
            response_size = int(_bytes_raw)
        except (ValueError, TypeError):
            pass

    # Vendor/product string → resource_display_name
    vendor = m.group(2).strip()
    product = m.group(3).strip()
    resource = f"{vendor}/{product}" if vendor or product else None

    return LogEvent(
        source_format=LogFormat.CEF,
        raw_line=line,
        timestamp=_parse_cef_timestamp(ext),
        ip_address=ip or None,
        user_agent=ua or None,
        user_principal_name=user or None,
        http_method=(method or "").upper() or None,
        path=path or None,
        status_code=_parse_status(ext, severity),
        response_size_bytes=response_size,
        resource_display_name=resource,
        file_hash=file_hash,
    )


def parse_cef(raw_text: str) -> list[LogEvent]:
    """Parse CEF-formatted log file (one event per line). Returns list of LogEvent."""
    events: list[LogEvent] = []
    skipped = 0
    for line in raw_text.splitlines():
        if not line.strip():
            continue
        event = _parse_cef_line(line)
        if event:
            events.append(event)
        else:
            skipped += 1
    logger.info("CEF parser: %d events, %d skipped lines", len(events), skipped)
    return events


class CefParser(BaseParser):
    """Plugin-registry entry for CEF (Common Event Format) logs."""

    format_name = "cef"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        for line in content.splitlines():
            stripped_line = line.strip()
            if stripped_line:
                # Allow syslog-prefixed CEF: <priority>timestamp host CEF:...
                return "CEF:" in stripped_line
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_cef(content)
