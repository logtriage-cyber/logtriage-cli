# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Traefik reverse proxy log parser.

Supports two output formats:
  1. JSON (structured access logs) — fields: RequestPath, RequestMethod,
     DownstreamStatus, RouterName, ServiceName, ClientHost, Duration, time
  2. CLF/combined (text) — similar to nginx combined log format

Detection: JSON with RouterName + ServiceName + DownstreamStatus,
or CLF with Traefik-style fields.

Reference:
  https://doc.traefik.io/traefik/observability/access-logs/
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# CLF: ip - user [date] "method path proto" status size "referer" "ua"
_CLF_RE = re.compile(
    r'(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d+)\s+(\d+|-)'
    r'\s+"([^"]*)"\s+"([^"]*)"',
)

_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    # JSON ISO
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        pass
    # CLF: "02/Jan/2006:15:04:05 -0700"
    m = re.match(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})\s+([+-]\d{4})", raw)
    if m:
        day, mon, year, time_str, tz = m.groups()
        mon_num = _MONTHS.get(mon, "01")
        tz_fmt = f"{tz[:3]}:{tz[3:]}"
        try:
            return datetime.fromisoformat(f"{year}-{mon_num}-{day}T{time_str}{tz_fmt}")
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _json_to_log(obj: dict[str, Any]) -> LogEvent | None:
    try:
        status_raw = obj.get("DownstreamStatus") or obj.get("downstream_status")
        ts_raw = obj.get("time") or obj.get("StartUTC") or obj.get("start_utc")
        client_ip = (
            obj.get("ClientHost")
            or obj.get("client_host")
            or obj.get("ClientAddr", "").split(":")[0]
        )
        method = obj.get("RequestMethod") or obj.get("request_method")
        path = obj.get("RequestPath") or obj.get("request_path") or obj.get("RequestURI")
        ua = obj.get("request_User-Agent") or obj.get("RequestUserAgent")
        router = obj.get("RouterName") or obj.get("router_name")
        service = obj.get("ServiceName") or obj.get("service_name")

        status: int | None = None
        try:
            status = int(status_raw) if status_raw is not None else None
        except (ValueError, TypeError):
            pass

        return LogEvent(
            source_format=LogFormat.TRAEFIK,
            timestamp=_parse_ts(str(ts_raw) if ts_raw else None),
            ip_address=client_ip or None,
            http_method=method,
            path=path,
            status_code=status,
            user_agent=ua,
            resource_display_name=service or router,
            raw_line=json.dumps(obj),
        )
    except Exception as exc:
        logger.debug("Traefik JSON: skipping: %s", exc)
        return None


def _clf_to_log(line: str) -> LogEvent | None:
    m = _CLF_RE.match(line.strip())
    if not m:
        return None
    ip, _user, date_str, method, path, status_str, _size, _ref, ua = m.groups()
    try:
        status = int(status_str)
    except ValueError:
        status = None
    return LogEvent(
        source_format=LogFormat.TRAEFIK,
        timestamp=_parse_ts(date_str),
        ip_address=ip if ip != "-" else None,
        http_method=method,
        path=path,
        status_code=status,
        user_agent=ua if ua != "-" else None,
        raw_line=line,
    )


def _is_traefik_json(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and ("RouterName" in obj or "router_name" in obj or "ServiceName" in obj)
        and ("DownstreamStatus" in obj or "downstream_status" in obj or "RequestPath" in obj)
    )


class TraefikParser(BaseParser):
    format_name = "traefik"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "traefik" in filename.lower():
            return True
        stripped = content.strip()
        # JSON mode
        for line in stripped.splitlines()[:5]:
            line = line.strip()
            if not line or not line.startswith("{"):
                break
            try:
                if _is_traefik_json(json.loads(line)):
                    return True
            except json.JSONDecodeError:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if ev := _json_to_log(obj):
                        events.append(ev)
                    continue
                except json.JSONDecodeError:
                    pass
            if ev := _clf_to_log(line):
                events.append(ev)
        logger.info("Traefik parser: %d events", len(events))
        return events
