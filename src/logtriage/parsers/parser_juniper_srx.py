# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Juniper SRX (ScreenOS / Junos) RT_FLOW log parser.

SRX emits structured syslog messages for session events:
  RT_FLOW_SESSION_CREATE  — new session allowed
  RT_FLOW_SESSION_CLOSE   — session terminated
  RT_FLOW_SESSION_DENY    — session blocked by policy

Message body format (space-separated key-value pairs):
  RT_FLOW_SESSION_CREATE: session created <proto> <src>/<sport>-><dst>/<dport> …
  RT_FLOW_SESSION_DENY:   session denied <proto> <src>/<sport>-><dst>/<dport> …

ScreenOS legacy format also supported:
  NetScreen device_id=… traffic …: src=IP dst=IP action=Deny|Permit

Reference:
  https://www.juniper.net/documentation/us/en/software/junos/flow-packet-processing/
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Syslog prefix (optional PRI + timestamp + hostname)
_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
)

_TS_ISO_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

# RT_FLOW line markers
_RTFLOW_MARKERS = frozenset({"RT_FLOW_SESSION_CREATE", "RT_FLOW_SESSION_CLOSE", "RT_FLOW_SESSION_DENY"})

# Matches src/sport->dst/dport pattern
_FLOW_IP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})/(\d+)"
)

# ScreenOS key=value format
_SCREENOS_KV_RE = re.compile(r"(\w+)=([^\s]+)")


def _parse_ts(line: str) -> datetime:
    m = _TS_ISO_RE.search(line)
    if m:
        try:
            return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    # Try BSD syslog timestamp at start
    m2 = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    if m2:
        # BSD syslog has no year. Inject a year before parsing so the strptime
        # default (1900, a non-leap year) doesn't reject a valid "Feb 29".
        # Prefer the current year; if it isn't a leap year a Feb-29 timestamp
        # won't fit, so fall back to the nearest preceding leap year.
        year = datetime.now(timezone.utc).year
        for candidate in (year, year - (year % 4 or 4)):
            try:
                dt = datetime.strptime(f"{candidate} {m2.group(1)}", "%Y %b %d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _parse_rtflow_line(line: str) -> LogEvent | None:
    ts = _parse_ts(line)
    stripped = _SYSLOG_PREFIX_RE.sub("", line, count=1)

    # Identify event type
    event_type = None
    for marker in _RTFLOW_MARKERS:
        if marker in stripped:
            event_type = marker
            break

    if event_type is None:
        # ScreenOS NetScreen format
        if "NetScreen" not in stripped and "device_id=" not in stripped:
            return None
        kv: dict[str, str] = {}
        for m in _SCREENOS_KV_RE.finditer(stripped):
            kv[m.group(1)] = m.group(2)
        src_ip = kv.get("src")
        action = kv.get("action", "").lower()
        status = 403 if action in ("deny", "reject", "drop") else 200
        return LogEvent(
            source_format=LogFormat.JUNIPER_SRX,
            timestamp=ts,
            ip_address=src_ip,
            path=kv.get("service") or kv.get("policy_name") or "ScreenOS",
            status_code=status,
            resource_display_name="Juniper/ScreenOS",
        )

    status = 403 if event_type == "RT_FLOW_SESSION_DENY" else 200

    # Extract protocol
    proto_m = re.search(r"\b(TCP|UDP|ICMP|GRE|ESP|AH)\b", stripped, re.I)
    proto = proto_m.group(1).upper() if proto_m else None

    # Extract src/sport->dst/dport
    ip_m = _FLOW_IP_RE.search(stripped)
    src_ip = ip_m.group(1) if ip_m else None
    dport = ip_m.group(4) if ip_m else None
    dst_ip = ip_m.group(3) if ip_m else None

    path = f"{dst_ip}:{dport}" if dst_ip and dport else (dst_ip or event_type)

    return LogEvent(
        source_format=LogFormat.JUNIPER_SRX,
        timestamp=ts,
        ip_address=src_ip,
        http_method=proto,
        path=path,
        status_code=status,
        resource_display_name="Juniper/SRX",
    )


def parse_juniper_srx(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        if not line.strip():
            continue
        try:
            # Only process lines with RT_FLOW or NetScreen markers
            if not any(m in line for m in (*_RTFLOW_MARKERS, "NetScreen", "device_id=")):
                continue
            e = _parse_rtflow_line(line)
            if e:
                events.append(e)
        except Exception as exc:
            logger.debug("JuniperSRX: skipping line: %s", exc)
    logger.info("JuniperSRX parser: %d events", len(events))
    return events


class JuniperSrxParser(BaseParser):
    format_name = "juniper_srx"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("srx", "juniper", "screenos", "netscreen")):
            pass
        count = 0
        for line in content.splitlines():
            if not line.strip():
                continue
            if any(m in line for m in _RTFLOW_MARKERS):
                return True
            if "NetScreen" in line and "device_id=" in line:
                return True
            count += 1
            if count >= 30:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_juniper_srx(content)
