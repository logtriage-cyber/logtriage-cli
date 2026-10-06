# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS Application Load Balancer (ALB) / Classic ELB access log parser.

Format: space-delimited, quoted strings for multi-word fields.
First token is connection type: http | https | h2 | grpcs | ws | wss

Reference:
  https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
"""
from __future__ import annotations

import logging
import re
import shlex
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_ALB_TYPES = frozenset({"http", "https", "h2", "grpcs", "ws", "wss"})
# ISO-8601 timestamp at position 1
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _parse_ts(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _parse_line(line: str) -> LogEvent | None:
    try:
        # shlex handles quoted fields correctly
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    if len(parts) < 12:
        return None
    conn_type = parts[0].lower()
    if conn_type not in _ALB_TYPES:
        return None
    try:
        ts = _parse_ts(parts[1])
        elb_name = parts[2]
        client_port = parts[3]          # ip:port
        client_ip = client_port.rsplit(":", 1)[0] if ":" in client_port else client_port
        elb_status = int(parts[8]) if parts[8] != "-" else None
        request = parts[12] if len(parts) > 12 else "-"
        ua = parts[13] if len(parts) > 13 else None

        method = path = None
        if request and request != "-":
            req_parts = request.split(" ", 2)
            method = req_parts[0] if len(req_parts) >= 1 else None
            if len(req_parts) >= 2:
                url = req_parts[1]
                # strip scheme://host from URL to get path
                m = re.search(r"https?://[^/]+(/.*)$", url)
                path = m.group(1) if m else url

        return LogEvent(
            source_format=LogFormat.AWS_ALB,
            timestamp=ts,
            ip_address=client_ip,
            http_method=method,
            path=path,
            status_code=elb_status,
            user_agent=ua if ua != "-" else None,
            resource_display_name=elb_name,
            raw_line=line,
        )
    except Exception as exc:
        logger.debug("ALB: skipping line: %s", exc)
        return None


def _is_alb_line(line: str) -> bool:
    parts = line.split(" ", 3)
    if len(parts) < 3:
        return False
    if parts[0].lower() not in _ALB_TYPES:
        return False
    return bool(_TS_RE.match(parts[1]))


class AwsAlbParser(BaseParser):
    format_name = "aws_alb"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if "alb" in fn or "elb" in fn or "_lb" in fn:
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        return _is_alb_line(line)
        for line in content.splitlines()[:10]:
            line = line.strip()
            if line and _is_alb_line(line):
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
        logger.info("ALB parser: %d events", len(events))
        return events
