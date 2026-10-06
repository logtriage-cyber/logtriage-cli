# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
HAProxy syslog access log parser.

HAProxy logs via syslog. Two main formats:
  - HTTP mode: contains method + URL + status code in curly-brace fields
  - TCP mode: no HTTP fields, just connection info

Detection: syslog lines with "haproxy[" or common HAProxy log structure
(frontend/backend names, termination state codes like "--").

Reference:
  https://www.haproxy.com/documentation/haproxy/latest/management/logging/log-formats/
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Jan  1 00:00:00 hostname haproxy[pid]: ...  OR  syslog with PRI prefix
_HAPROXY_RE = re.compile(
    r"(?:<\d+>)?(?:\w{3}\s+\d+\s+[\d:]+\s+\S+\s+)?haproxy\[(\d+)\]:\s+(.*)",
    re.DOTALL,
)

# HTTP log: client:port [date] frontend backend/server Tq/Tw/Tc/Tr/Tt
#   status bytes cookie termstate actconn/feconn {req_hdrs} {resp_hdrs} "method url protocol"
_HTTP_LOG_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+\[([^\]]+)\]\s+\S+\s+\S+/\S+"
    r"\s+[\d/+-]+\s+(\d{3})\s+(\d+)"  # timings + status + bytes
    r'[^"]*'                            # skip cookie, flags, connection counts
    r'"([A-Z]+)\s+(\S+)\s+HTTP/[\d.]+"',
    re.IGNORECASE,
)

# TCP log: client:port [date] frontend backend/server time1/time2/time3 bytes termstate
_TCP_LOG_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+\[([^\]]+)\]\s+\S+\s+\S+/\S+"
    r"\s+[\d/+-]+\s+(\d+)\s+[A-Z-]{2}"
)

# HAProxy date: "01/Jan/2024:12:00:00.000"
_TS_RE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})")
_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_ts(raw: str) -> datetime:
    m = _TS_RE.match(raw.strip())
    if m:
        day, mon, year, time_str = m.groups()
        mon_num = _MONTHS.get(mon, "01")
        try:
            return datetime.fromisoformat(f"{year}-{mon_num}-{day}T{time_str}+00:00")
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _parse_line(line: str) -> LogEvent | None:
    m = _HAPROXY_RE.match(line.strip())
    if not m:
        return None
    body = m.group(2)

    # Try HTTP log first
    hm = _HTTP_LOG_RE.search(body)
    if hm:
        client_ip, date_str, status_str, _bytes, method, url = hm.groups()
        try:
            status = int(status_str)
        except ValueError:
            status = None
        return LogEvent(
            source_format=LogFormat.HAPROXY,
            timestamp=_parse_ts(date_str),
            ip_address=client_ip,
            http_method=method.upper() if method else None,
            path=url,
            status_code=status,
            raw_line=line,
        )

    # TCP log
    tm = _TCP_LOG_RE.search(body)
    if tm:
        client_ip, date_str, _bytes = tm.groups()
        return LogEvent(
            source_format=LogFormat.HAPROXY,
            timestamp=_parse_ts(date_str),
            ip_address=client_ip,
            status_code=None,
            raw_line=line,
        )

    return None


class HaproxyParser(BaseParser):
    format_name = "haproxy"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "haproxy" in filename.lower():
            return True
        for line in content.splitlines()[:20]:
            if _HAPROXY_RE.match(line.strip()):
                return True
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in content.splitlines():
            if not line.strip():
                continue
            if ev := _parse_line(line):
                events.append(ev)
        logger.info("HAProxy parser: %d events", len(events))
        return events
