# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Syslog parser — RFC 5424 and RFC 3164.

RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APPNAME PROCID MSGID [SD] MESSAGE
RFC 3164: <PRI>Mon DD HH:MM:SS HOSTNAME TAG[PID]: MESSAGE
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# RFC 5424 full line
_RFC5424_RE = re.compile(
    r"^<(\d+)>1\s+"                    # <PRI>version
    r"(\S+)\s+"                         # timestamp
    r"(\S+)\s+"                         # hostname
    r"(\S+)\s+"                         # appname
    r"(\S+)\s+"                         # procid
    r"(\S+)"                            # msgid
    r"(?:\s+(?:\S+|\[[^\]]*\]))?"       # structured data or - ([^\]]*] avoids .*? ReDoS)
    r"(?:\s+(.+))?$",                   # message
    re.DOTALL,
)

# RFC 3164: <PRI>Mon DD HH:MM:SS hostname tag[pid]: message
_RFC3164_RE = re.compile(
    r"^<(\d+)>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s*"
    r"(.*)",
)

# IP address in message (e.g. "from 1.2.3.4", "SRC=1.2.3.4", "address 1.2.3.4")
_IP_RE = re.compile(
    r"(?:from|src=|source=|address|SRC=)\s*(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# User in message (e.g. "for user john", "user=john", "for john from")
_USER_RE = re.compile(
    r"(?:for(?: user| invalid user)?\s+(\S+)\s+from|user=(\S+))",
    re.IGNORECASE,
)

# Syslog severity (lower 3 bits of priority)
_SEVERITY_STATUS = {0: 500, 1: 500, 2: 500, 3: 500, 4: 400, 5: 200, 6: 200, 7: 200}

_RFC3164_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def _parse_5424_ts(ts: str) -> datetime:
    ts = ts.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _parse_3164_ts(ts: str) -> datetime:
    # "Oct 11 22:14:15" — no year, assume current year
    parts = ts.split()
    if len(parts) < 3:
        return datetime.now(timezone.utc)
    try:
        month = _RFC3164_MONTHS.get(parts[0].lower(), 1)
        day = int(parts[1])
        h, m, s = (int(x) for x in parts[2].split(":"))
        year = datetime.now(timezone.utc).year
        return datetime(year, month, day, h, m, s, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return datetime.now(timezone.utc)


def _extract_ip(msg: str) -> str | None:
    m = _IP_RE.search(msg)
    return m.group(1) if m else None


def _extract_user(msg: str) -> str | None:
    m = _USER_RE.search(msg)
    if m:
        return m.group(1) or m.group(2)
    return None


_MSG_MAX = 2000  # cap message field length to bound backtracking on adversarial input


def _parse_5424_line(line: str) -> LogEvent | None:
    m = _RFC5424_RE.match(line)
    if not m:
        return None
    pri, ts_raw, hostname, appname, _procid, _msgid, msg = m.groups()
    msg = (msg or "")[:_MSG_MAX]
    try:
        severity = int(pri) & 0x7
    except (ValueError, TypeError):
        severity = 6
    status = _SEVERITY_STATUS.get(severity, 200)
    ts = _parse_5424_ts(ts_raw) if ts_raw != "-" else datetime.now(timezone.utc)
    return LogEvent(
        source_format=LogFormat.SYSLOG,
        timestamp=ts,
        ip_address=_extract_ip(msg),
        user_principal_name=_extract_user(msg),
        path=f"{appname}: {msg[:120]}" if appname != "-" else msg[:120],
        status_code=status,
        resource_display_name=hostname if hostname != "-" else None,
        raw_line=line,
    )


def _parse_3164_line(line: str) -> LogEvent | None:
    m = _RFC3164_RE.match(line)
    if not m:
        return None
    pri, ts_raw, hostname, tag, _pid, msg = m.groups()
    msg = (msg or "")[:_MSG_MAX]
    try:
        severity = int(pri) & 0x7
    except (ValueError, TypeError):
        severity = 6
    status = _SEVERITY_STATUS.get(severity, 200)
    return LogEvent(
        source_format=LogFormat.SYSLOG,
        timestamp=_parse_3164_ts(ts_raw),
        ip_address=_extract_ip(msg),
        user_principal_name=_extract_user(msg),
        path=f"{tag}: {msg[:120]}",
        status_code=status,
        resource_display_name=hostname,
        raw_line=line,
    )


class SyslogParser(BaseParser):
    format_name = "syslog"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        first = content.lstrip().split("\n")[0]
        return bool(re.match(r"<\d+>", first))

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            ev = _parse_5424_line(line) or _parse_3164_line(line)
            if ev:
                events.append(ev)
            else:
                logger.debug("syslog parser: unmatched line: %r", line[:80])
        logger.info("syslog: parsed %d events from %s", len(events), filename)
        return events
