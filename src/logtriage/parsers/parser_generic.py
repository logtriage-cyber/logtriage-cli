# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Generic fallback parser for CSV and NDJSON (newline-delimited JSON) log formats.

Expected columns / fields (case-insensitive, flexible naming):
  timestamp  / time / time_local / date / created_at
  ip_address / ip / remote_ip / remote_addr / client_ip / src_ip
  http_method / method / verb / request_method
  path       / url / endpoint / uri / request_uri
  status_code / status / response / response_code / code
  response_size_bytes / bytes / bytes_sent / body_bytes_sent / size
  user_agent / ua / agent / useragent / http_user_agent
  referrer   / referer / http_referer
  user_principal_name / user / username / user_email / upn / email

Special handling:
  request field "GET /path HTTP/1.1" is split into http_method + path.
  nginx "-" placeholder values are normalised to None.
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Field name aliases → canonical name
_FIELD_MAP: dict[str, str] = {
    # Timestamp
    "time":             "timestamp",
    "time_local":       "timestamp",        # nginx $time_local
    "date":             "timestamp",
    "created_at":       "timestamp",
    "datetime":         "timestamp",
    # IP address
    "ip":               "ip_address",
    "remote_ip":        "ip_address",       # nginx JSON log_format
    "remote_addr":      "ip_address",       # nginx $remote_addr
    "client_ip":        "ip_address",
    "clientip":         "ip_address",       # Logstash ECS
    "source_ip":        "ip_address",
    "src_ip":           "ip_address",
    # HTTP method
    "method":           "http_method",
    "verb":             "http_method",
    "request_method":   "http_method",      # nginx $request_method
    # Path
    "url":              "path",
    "endpoint":         "path",
    "uri":              "path",
    "request_uri":      "path",             # nginx $request_uri
    # Status code
    "status":           "status_code",
    "response_code":    "status_code",
    "response":         "status_code",      # nginx JSON "response" field
    "code":             "status_code",
    # Response size
    "bytes":            "response_size_bytes",  # nginx JSON "bytes" field
    "bytes_sent":       "response_size_bytes",
    "body_bytes_sent":  "response_size_bytes",  # nginx $body_bytes_sent
    "size":             "response_size_bytes",
    # User-agent
    "ua":               "user_agent",
    "agent":            "user_agent",       # nginx JSON "agent" field
    "useragent":        "user_agent",
    "http_user_agent":  "user_agent",       # nginx $http_user_agent
    # Referrer
    "referer":          "referrer",
    "http_referer":     "referrer",         # nginx $http_referer
    # User / identity
    "user":             "user_principal_name",
    "username":         "user_principal_name",
    "user_email":       "user_principal_name",
    "upn":              "user_principal_name",
    "email":            "user_principal_name",
}

# Nginx uses "-" as a placeholder for missing optional fields; strip these.
def _clean(val: Any) -> Any:
    """Return None for nginx '-' placeholders and empty strings."""
    if isinstance(val, str) and val.strip() in ("-", ""):
        return None
    return val or None


def _normalise_keys(record: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in record.items():
        canonical = _FIELD_MAP.get(k.lower().strip(), k.lower().strip())
        out[canonical] = v

    # Handle nginx-style request line: "GET /path HTTP/1.1" → method + path
    request_line = out.pop("request", None)
    if isinstance(request_line, str) and request_line.strip():
        parts = request_line.split()
        if len(parts) >= 2 and not out.get("http_method"):
            out["http_method"] = parts[0]
        if len(parts) >= 2 and not out.get("path"):
            out["path"] = parts[1]

    return out


def _parse_ts(raw: Any) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    s = str(raw).strip().replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",         # nginx $time_local: "17/May/2015:08:05:32 +0000"
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _record_to_event(record: dict[str, Any], source_format: LogFormat = LogFormat.GENERIC_JSON) -> LogEvent | None:
    norm = _normalise_keys(record)

    def _int(key: str) -> int | None:
        raw = norm.get(key)
        if raw is None:
            return None
        try:
            return int(raw)
        except (ValueError, TypeError):
            return None

    return LogEvent(
        source_format=source_format,
        timestamp=_parse_ts(norm.get("timestamp")),
        ip_address=_clean(norm.get("ip_address")),
        user_agent=_clean(norm.get("user_agent")),
        http_method=_clean(norm.get("http_method")),
        path=_clean(norm.get("path")),
        status_code=_int("status_code"),
        response_size_bytes=_int("response_size_bytes"),
        referrer=_clean(norm.get("referrer")),
        user_principal_name=_clean(norm.get("user_principal_name")),
    )


def parse_ndjson(raw_text: str) -> list[LogEvent]:
    """Parse newline-delimited JSON (one JSON object per line)."""
    events: list[LogEvent] = []
    for i, line in enumerate(raw_text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if event := _record_to_event(record):
                events.append(event)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("NDJSON line %d skipped: %s", i + 1, exc)
    logger.info("NDJSON parser: %d events", len(events))
    return events


def parse_csv(raw_text: str) -> list[LogEvent]:
    """Parse generic CSV with auto-detected header row."""
    reader = csv.DictReader(io.StringIO(raw_text))
    events: list[LogEvent] = []
    for i, row in enumerate(reader):
        try:
            if event := _record_to_event(dict(row), source_format=LogFormat.GENERIC_CSV):
                events.append(event)
        except Exception as exc:
            logger.debug("CSV row %d skipped: %s", i + 1, exc)
    logger.info("CSV parser: %d events", len(events))
    return events


class GenericCsvParser(BaseParser):
    """Plugin-registry entry for generic CSV logs."""

    format_name = "generic_csv"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename.lower().endswith(".csv"):
            return True
        stripped = content.strip()
        # CSV: first line has commas and does not start with a digit (nginx lines start with IP)
        # and does not look like JSON
        if stripped.startswith(("{", "[")):
            return False
        lines = [line for line in stripped.splitlines() if line.strip()]
        if lines:
            first = lines[0]
            return "," in first and not first[0].isdigit()
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_csv(content)


class GenericJsonParser(BaseParser):
    """Plugin-registry entry for generic JSON array / NDJSON logs."""

    format_name = "generic_json"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        stripped = content.strip()
        if stripped.startswith(("{", "[")):
            return True
        # NDJSON — first non-empty line is a JSON object
        for line in stripped.splitlines():
            if line.strip():
                try:
                    return isinstance(json.loads(line), dict)
                except (json.JSONDecodeError, ValueError):
                    return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_ndjson(content)
