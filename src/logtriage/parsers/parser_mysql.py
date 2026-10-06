# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
MySQL log parser — supports two formats in the same file or separate files:

  1. Error log: timestamp [ERROR|Warning|Note] message
     Format variants: '2023-01-01T00:00:01.000000Z 0 [ERROR] ...'
     or old format:   '231001 12:00:00 [ERROR] ...'

  2. Slow query log:
       # Time: 2023-01-01T00:00:01.000000Z
       # User@Host: user[user] @ hostname [ip]
       # Query_time: 2.345  Lock_time: 0.001  Rows_sent: 0  Rows_examined: 100000
       SET timestamp=...;
       SELECT ...;

Detection: at least one slow query `# User@Host:` line, or mysqld error log
timestamp pattern with [ERROR]/[Warning].

Reference:
  https://dev.mysql.com/doc/refman/8.0/en/server-logs.html
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Error log: "2023-01-01T12:00:00.000000Z NNN [LEVEL] [MY-XXXXXX] [Server] message"
_ERR_NEW_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+\d+\s+\[(\w+)\]"
)
# Old error log: "231001 12:00:00 [ERROR]"
_ERR_OLD_RE = re.compile(r"(\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+\[(\w+)\]")

# Slow query header lines
_SLOW_TIME_RE = re.compile(r"#\s*Time:\s*(\S+)")
_SLOW_USER_RE = re.compile(r"#\s*User@Host:\s*(\S+)\[(\S*)\]\s*@\s*(\S*)\s*\[(\S*)\]")
_SLOW_QUERY_RE = re.compile(
    r"#\s*Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)"
)

_ERROR_LEVELS = {"error", "err"}
_WARN_LEVELS = {"warning", "warn", "note"}


def _parse_ts_iso(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _parse_ts_old(raw: str) -> datetime:
    """231001 12:00:00 → 2023-10-01 12:00:00"""
    try:
        parts = raw.split()
        ymd = parts[0]
        hms = parts[1] if len(parts) > 1 else "00:00:00"
        year = "20" + ymd[:2]
        month = ymd[2:4]
        day = ymd[4:6]
        return datetime.fromisoformat(f"{year}-{month}-{day}T{hms}+00:00")
    except (ValueError, IndexError):
        return datetime.now(timezone.utc)


def _parse_error_log(content: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in content.splitlines():
        stripped = line.strip()
        m = _ERR_NEW_RE.match(stripped)
        if m:
            ts = _parse_ts_iso(m.group(1))
            level = m.group(2).lower()
            status = 403 if level in _ERROR_LEVELS else 400
            events.append(LogEvent(
                source_format=LogFormat.MYSQL,
                timestamp=ts,
                status_code=status,
                path="/mysql/error",
                resource_display_name="mysqld",
                failure_reason=stripped[m.end():].strip()[:200] if status == 403 else None,
                raw_line=line,
            ))
            continue
        m = _ERR_OLD_RE.match(stripped)
        if m:
            ts = _parse_ts_old(m.group(1))
            level = m.group(2).lower()
            status = 403 if level in _ERROR_LEVELS else 400
            events.append(LogEvent(
                source_format=LogFormat.MYSQL,
                timestamp=ts,
                status_code=status,
                path="/mysql/error",
                resource_display_name="mysqld",
                raw_line=line,
            ))
    return events


def _parse_slow_log(content: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        tm = _SLOW_TIME_RE.match(line)
        if not tm:
            i += 1
            continue
        ts = _parse_ts_iso(tm.group(1))
        i += 1
        if i >= len(lines):
            break
        um = _SLOW_USER_RE.match(lines[i].strip())
        if not um:
            continue
        user = um.group(1)
        host_ip = um.group(4)
        i += 1
        query_time = 0.0
        if i < len(lines):
            qm = _SLOW_QUERY_RE.match(lines[i].strip())
            if qm:
                query_time = float(qm.group(1))
                i += 1
        # Skip SET timestamp and collect SQL
        sql_lines: list[str] = []
        while i < len(lines):
            ln = lines[i].strip()
            if ln.startswith("#") and (_SLOW_TIME_RE.match(ln) or _SLOW_USER_RE.match(ln)):
                break
            if ln and not ln.startswith("SET timestamp="):
                sql_lines.append(ln)
            i += 1
        sql = " ".join(sql_lines)[:200]
        # slow queries over 5s are suspicious
        status = 403 if query_time >= 5.0 else 200
        events.append(LogEvent(
            source_format=LogFormat.MYSQL,
            timestamp=ts,
            ip_address=host_ip if host_ip and host_ip != "" else None,
            path="/mysql/slow_query",
            status_code=status,
            user_principal_name=user,
            resource_display_name="mysql-slow",
            raw_line=sql or line,
        ))
    return events


class MysqlParser(BaseParser):
    format_name = "mysql"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if "mysql" in fn or "slow" in fn and fn.endswith(".log"):
                return True
        for line in content.splitlines()[:30]:
            stripped = line.strip()
            if _SLOW_USER_RE.match(stripped) or _SLOW_TIME_RE.match(stripped):
                return True
            if _ERR_NEW_RE.match(stripped) or _ERR_OLD_RE.match(stripped):
                return True
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        has_slow = any(
            _SLOW_USER_RE.match(line.strip()) for line in content.splitlines()
        )
        if has_slow:
            events = _parse_slow_log(content)
        else:
            events = _parse_error_log(content)
        logger.info("MySQL parser: %d events", len(events))
        return events
