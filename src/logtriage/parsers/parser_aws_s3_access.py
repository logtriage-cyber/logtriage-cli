# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS S3 Server Access Log parser.

Format: space-delimited with quoted strings; date in [DD/Mon/YYYY:HH:MM:SS +ZZZZ] brackets.
Operations follow the pattern: REST.GET.OBJECT, WEBSITE.GET.OBJECT, REST.PUT.*, etc.

Reference:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html
"""
from __future__ import annotations

import logging
import re
import shlex
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# [06/Feb/2023:18:54:11 +0000]
_DATE_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
_OP_RE = re.compile(r"\b(?:REST|WEBSITE|BATCH)\.\w+\.\w+\b")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

_WRITE_OPS = frozenset({
    "REST.PUT.OBJECT", "REST.DELETE.OBJECT", "REST.COPY.OBJECT",
    "REST.PUT.ACL", "REST.DELETE.BUCKET", "REST.PUT.BUCKET",
    "REST.MULTI_OBJECT_DELETE", "REST.PUT.POLICY",
})


def _parse_ts(raw: str) -> datetime:
    # "06/Feb/2023:18:54:11 +0000"
    try:
        day, rest = raw.split("/", 1)
        mon, rest2 = rest.split("/", 1)
        year, rest3 = rest2.split(":", 1)
        time_str, tz_str = rest3.rsplit(" ", 1)
        mon_num = _MONTHS.get(mon, "01")
        iso = f"{year}-{mon_num}-{day}T{time_str}{tz_str[:3]}:{tz_str[3:]}"
        return datetime.fromisoformat(iso)
    except Exception:
        return datetime.now(timezone.utc)


def _parse_line(line: str) -> LogEvent | None:
    m = _DATE_RE.search(line)
    if not m:
        return None
    ts = _parse_ts(m.group(1))

    # Split the portion before the bracket for bucket_owner + bucket + ip
    before = line[:m.start()].strip()
    try:
        head = shlex.split(before)
    except ValueError:
        head = before.split()

    bucket = head[1] if len(head) >= 2 else None
    remote_ip = head[3] if len(head) >= 4 else None

    # Split portion after the bracket
    after = line[m.end():].strip()
    try:
        tail = shlex.split(after)
    except ValueError:
        tail = after.split()

    # After bracket: requester request_id operation key "request_uri" http_status ...
    key = tail[3] if len(tail) >= 4 else None
    request_uri = tail[4] if len(tail) >= 5 else None
    http_status_raw = tail[5] if len(tail) >= 6 else None
    ua = tail[13] if len(tail) >= 14 else None

    http_status: int | None = None
    try:
        if http_status_raw and http_status_raw != "-":
            http_status = int(http_status_raw)
    except ValueError:
        pass

    method = path = None
    if request_uri and request_uri != "-":
        parts = request_uri.split(" ", 2)
        method = parts[0] if parts else None
        if len(parts) >= 2:
            path = parts[1]

    # fall back to key as path
    if not path and key and key != "-":
        path = "/" + key

    return LogEvent(
        source_format=LogFormat.AWS_S3_ACCESS,
        timestamp=ts,
        ip_address=remote_ip if remote_ip != "-" else None,
        http_method=method,
        path=path,
        status_code=http_status,
        user_agent=ua if ua and ua != "-" else None,
        resource_display_name=f"s3://{bucket}" if bucket else None,
        raw_line=line,
    )


def _is_s3_line(line: str) -> bool:
    if not _DATE_RE.search(line):
        return False
    return bool(_OP_RE.search(line))


class AwsS3AccessParser(BaseParser):
    format_name = "aws_s3_access"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if "s3" in fn and ("access" in fn or "server" in fn):
                return True
        matched = 0
        for line in content.splitlines()[:20]:
            line = line.strip()
            if line and _is_s3_line(line):
                matched += 1
                if matched >= 2:
                    return True
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            if ev := _parse_line(line):
                events.append(ev)
        logger.info("S3 Access parser: %d events", len(events))
        return events
