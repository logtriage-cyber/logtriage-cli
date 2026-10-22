# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Suricata EVE JSON log parser.

Suricata writes one JSON object per line (NDJSON); exports may be a JSON array.
Each object has an event_type field: alert, http, dns, flow, tls, fileinfo,
anomaly, and one per application protocol (ssh, smtp, smb, …). Every record
with a source address becomes an event; stats records are skipped.

Reference: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers import json_input
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

        if not src_ip:  # stats and other engine records describe no connection
            return None

        dest = f"{evt.get('dest_ip', '')}:{evt.get('dest_port', '')}".strip(":")

        if etype == "fileinfo":
            info = evt.get("fileinfo", {})
            digest = info.get("sha256") or info.get("md5")
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=info.get("filename") or dest,
                resource_display_name=(evt.get("http") or {}).get("hostname") or evt.get("app_proto"),
                http_method=evt.get("proto"),
                status_code=200,
                file_hash=digest if isinstance(digest, str) and len(digest) in (32, 64) else None,
                raw_line=json.dumps(evt),
            )

        if etype == "anomaly":
            anomaly = evt.get("anomaly", {})
            return LogEvent(
                source_format=LogFormat.SURICATA,
                timestamp=ts,
                ip_address=src_ip,
                path=anomaly.get("event") or anomaly.get("type") or dest,
                resource_display_name=f"anomaly ({anomaly.get('layer') or anomaly.get('type') or 'protocol'})",
                http_method=evt.get("proto"),
                status_code=400,
                raw_line=json.dumps(evt),
            )

        # Protocol records (ssh, smtp, smb, ftp, rdp, krb5, mqtt, pgsql, …): who talked to what
        return LogEvent(
            source_format=LogFormat.SURICATA,
            timestamp=ts,
            ip_address=src_ip,
            path=f"{etype}://{dest}" if etype else dest,
            resource_display_name=etype or None,
            http_method=evt.get("proto"),
            status_code=200,
            raw_line=json.dumps(evt),
        )

    except Exception as exc:
        logger.debug("Suricata: skipping event (type=%s): %s", evt.get("event_type"), exc)
        return None


def _is_eve(obj: dict[str, Any]) -> bool:
    return "event_type" in obj and "timestamp" in obj and ("src_ip" in obj or obj.get("event_type") == "stats")


def parse_suricata(raw_text: str) -> list[LogEvent]:
    events = [e for r in json_input.records(raw_text) if (e := _event_to_log(r))]
    logger.info("Suricata parser: %d events", len(events))
    return events


class SuricataParser(BaseParser):
    """Plugin-registry entry for Suricata EVE JSON logs."""

    format_name = "suricata"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content)
        return bool(head) and sum(_is_eve(r) for r in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_suricata(content)
