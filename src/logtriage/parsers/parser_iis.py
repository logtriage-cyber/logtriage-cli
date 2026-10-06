# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Microsoft IIS W3C Extended Log Format parser.

Format: space-delimited; `#` lines are directives.
`#Fields:` specifies column names dynamically.

Common fields: date, time, c-ip, cs-username, cs-method, cs-uri-stem,
cs-uri-query, sc-status, sc-bytes, cs-bytes, time-taken, cs(User-Agent),
cs(Referer), cs-host, s-ip, s-port.

Reference:
  https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_COMMON_IIS_FIELDS = frozenset({
    "cs-method", "sc-status", "cs-uri-stem", "c-ip", "cs(user-agent)",
})


def _parse_ts(date_str: str, time_str: str) -> datetime:
    try:
        return datetime.fromisoformat(f"{date_str}T{time_str}+00:00")
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_body(content: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    fields: list[str] = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#Fields:"):
            fields = stripped[len("#Fields:"):].strip().lower().split()
            continue
        if stripped.startswith("#"):
            continue
        if not fields:
            continue
        parts = stripped.split()
        if len(parts) < len(fields):
            continue
        row = dict(zip(fields, parts))

        date_str = row.get("date", "")
        time_str = row.get("time", "")
        ts = _parse_ts(date_str, time_str) if date_str and time_str else datetime.now(timezone.utc)

        status_raw = row.get("sc-status", "-")
        status: int | None = None
        try:
            status = int(status_raw) if status_raw != "-" else None
        except ValueError:
            pass

        events.append(LogEvent(
            source_format=LogFormat.IIS,
            timestamp=ts,
            ip_address=row.get("c-ip") if row.get("c-ip") != "-" else None,
            http_method=row.get("cs-method") if row.get("cs-method") != "-" else None,
            path=row.get("cs-uri-stem") if row.get("cs-uri-stem") != "-" else None,
            status_code=status,
            user_agent=row.get("cs(user-agent)") if row.get("cs(user-agent)", "-") != "-" else None,
            user_principal_name=row.get("cs-username") if row.get("cs-username", "-") != "-" else None,
            resource_display_name=row.get("s-sitename") or row.get("cs-host"),
            raw_line=line,
        ))
    return events


class IisParser(BaseParser):
    format_name = "iis"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if fn.endswith(".log") and ("iis" in fn or "w3c" in fn or "u_ex" in fn):
                return True
        has_fields = False
        has_software = False
        for line in content.splitlines()[:10]:
            stripped = line.strip()
            if stripped.startswith("#Software: Microsoft Internet Information"):
                has_software = True
            if stripped.startswith("#Fields:"):
                # At least one IIS-specific column name present
                field_names = stripped[len("#Fields:"):].strip().lower()
                if any(f in field_names for f in ("cs-method", "sc-status", "cs-uri-stem")):
                    has_fields = True
        return has_fields or has_software

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events = _parse_body(content)
        logger.info("IIS parser: %d events", len(events))
        return events
