# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Suricata EVE JSON log parser.

Suricata writes one JSON object per line (NDJSON) or as a JSON array.
Each object has an event_type field: alert, http, dns, flow, tls, etc.

Reference: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Suricata alert severity: 1=critical, 2=high, 3=medium, 4=low, 5=info
_SEVERITY_STATUS: dict[int, int] = {1: 403, 2: 401, 3: 400, 4: 200, 5: 200}


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        # Normalize "+0000" (no colon) that fromisoformat rejects in Python < 3.11
        normalized = raw.replace("+0000", "+00:00").replace("-0000", "+00:00")
        return datetime.fromisoformat(normalized)
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _event_to_log(evt: dict[str, Any]) -> LogEvent | None:
    try:
        etype = evt.get("event_type", "")
        src_ip = evt.get("src_ip")
        ts = _parse_ts(evt.get("timestamp"))

        if etype == "alert":
            alert = evt.get("alert", {})
            http = evt.get("http", {})
            severity = int(alert.get("severity", 3))
            blocked = alert.get("action") == "blocked"
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=alert.get("signature"),
                resource_display_name=alert.get("category"),
                status_code=403 if blocked else _SEVERITY_STATUS.get(severity, 400),
                http_method=evt.get("proto"),
                user_agent=http.get("http_user_agent"),
                raw_line=json.dumps(evt),
            )

        if etype == "http":
            http = evt.get("http", {})
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=http.get("url"),
                resource_display_name=http.get("hostname"),
                http_method=http.get("http_method"),
                status_code=http.get("status"),
                user_agent=http.get("http_user_agent"),
                response_size_bytes=http.get("response_bodylen") or http.get("length"),
                raw_line=json.dumps(evt),
            )

        if etype == "dns":
            dns = evt.get("dns", {})
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=dns.get("rrname"),
                http_method=dns.get("type", "query").upper(),
                resource_display_name=dns.get("rrtype"),
                status_code=200,
                raw_line=json.dumps(evt),
            )

        if etype == "flow":
            flow = evt.get("flow", {})
            dest_ip = evt.get("dest_ip", "")
            dest_port = evt.get("dest_port", "")
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=f"{dest_ip}:{dest_port}" if dest_ip else None,
                http_method=evt.get("proto"),
                status_code=200,
                response_size_bytes=flow.get("bytes_toclient"),
                raw_line=json.dumps(evt),
            )

        if etype == "tls":
            tls = evt.get("tls", {})
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=tls.get("sni") or tls.get("subject"),
                resource_display_name=tls.get("issuerdn"),
                status_code=200,
                raw_line=json.dumps(evt),
            )

        # stats, fileinfo, anomaly, etc. — skip
        return None

    except Exception as exc:
        logger.debug("Suricata: skipping event (type=%s): %s", evt.get("event_type"), exc)
        return None


def parse_suricata(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    stripped = raw_text.strip()

    # JSON array
    if stripped.startswith("["):
        try:
            records = json.loads(stripped)
            for r in records:
                if isinstance(r, dict):
                    if e := _event_to_log(r):
                        events.append(e)
            logger.info("Suricata parser: %d events from JSON array", len(events))
            return events
        except json.JSONDecodeError:
            pass

    # NDJSON — one object per line
    for line in stripped.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
            if e := _event_to_log(record):
                events.append(e)
        except json.JSONDecodeError:
            continue

    logger.info("Suricata parser: %d events from NDJSON", len(events))
    return events


class SuricataParser(BaseParser):
    """Plugin-registry entry for Suricata EVE JSON logs."""

    format_name = "suricata"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(h in filename.lower() for h in ("suricata", "eve.json", "eve-")):
            return True
        stripped = content.strip()
        # First non-empty line must be a JSON object with event_type + src_ip
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                obj = json.loads(line)
                return isinstance(obj, dict) and "event_type" in obj and "src_ip" in obj
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_suricata(content)
