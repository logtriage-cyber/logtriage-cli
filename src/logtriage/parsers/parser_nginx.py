# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
nginx / Apache combined log format parser.

Standard combined format:
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Example:
  192.168.1.1 - - [15/Jan/2024:10:23:45 +0000] "GET /api/v1/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0 ..."
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Regex for nginx/Apache combined log format
_COMBINED_RE = re.compile(
    r'(?P<ip>\S+)'           # remote_addr
    r'\s+\S+'                # ident (usually -)
    r'\s+\S+'                # auth user (usually -)
    r'\s+\[(?P<time>[^\]]+)\]'   # [time_local]
    r'\s+"(?P<request>[^"]*)"'   # "request line"
    r'\s+(?P<status>\d{3})'      # status code
    r'\s+(?P<bytes>\S+)'         # body_bytes_sent (can be -)
    r'(?:\s+"(?P<referrer>[^"]*)")?'  # "$http_referer" (optional)
    r'(?:\s+"(?P<ua>[^"]*)")?',       # "$http_user_agent" (optional)
)

# nginx time_local format: 15/Jan/2024:10:23:45 +0000
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_timestamp(raw: str) -> datetime:
    try:
        return datetime.strptime(raw.strip(), _TIME_FORMAT)
    except ValueError:
        logger.debug("Could not parse nginx timestamp: %r", raw)
        return datetime.now(timezone.utc)


def _parse_request(request_line: str) -> tuple[str | None, str | None]:
    """Split 'GET /path HTTP/1.1' into (method, path)."""
    parts = request_line.strip().split(" ", 2)
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None, None


def _parse_line(line: str) -> LogEvent | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _COMBINED_RE.match(line)
    if not m:
        logger.debug("nginx parser: no match for line: %r", line[:120])
        return None

    method, path = _parse_request(m.group("request") or "")
    bytes_raw = m.group("bytes")
    try:
        resp_bytes = int(bytes_raw) if bytes_raw and bytes_raw != "-" else None
    except ValueError:
        resp_bytes = None

    referrer = m.group("referrer")
    if referrer == "-":
        referrer = None

    return LogEvent(
        source_format=LogFormat.NGINX,
        raw_line=line,
        timestamp=_parse_timestamp(m.group("time")),
        ip_address=m.group("ip"),
        http_method=method,
        path=path,
        status_code=int(m.group("status")),
        response_size_bytes=resp_bytes,
        referrer=referrer,
        user_agent=m.group("ua"),
    )


def parse_nginx(raw_text: str) -> list[LogEvent]:
    """Parse nginx combined log format. Returns list of LogEvent."""
    lines = raw_text.splitlines()
    events: list[LogEvent] = []
    skipped = 0
    for line in lines:
        event = _parse_line(line)
        if event:
            events.append(event)
        elif line.strip():
            skipped += 1

    logger.info("nginx parser: %d events, %d skipped lines", len(events), skipped)
    return events


class NginxParser:
    """Plugin-registry entry for nginx / Apache combined log format."""

    format_name = "nginx"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        stripped = content.strip()
        # Skip JSON files — handled by other parsers
        if stripped.startswith(("{", "[")):
            return False
        # Skip CEF files
        for line in stripped.splitlines():
            if line.strip():
                if line.strip().startswith("CEF:"):
                    return False
                break
        # Nginx is the catch-all for unrecognised text logs
        return True

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_nginx(content)
