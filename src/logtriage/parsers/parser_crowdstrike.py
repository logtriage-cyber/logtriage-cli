# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
CrowdStrike Falcon Data Replicator (FDR) log parser.

FDR streams raw sensor events as NDJSON. Each line is a JSON object with
an `event_simpleName` field identifying the event type, plus `cid` (customer
ID) and `aid` (agent/sensor ID) as discriminators.

Common event types handled:
  ProcessRollup2 / SyntheticProcessRollup2 — process execution
  NetworkConnectIP4 / NetworkReceiveAcceptIP4 — network connections
  DnsRequest — DNS lookups
  UserLogon / UserLogoff — authentication events
  SuspiciousActivity / DetectionSummaryEvent — alert/detection

References:
  https://falcon.crowdstrike.com/documentation/93/falcon-data-replicator
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# event_simpleName values that indicate malicious / suspicious activity
_HIGH_RISK_EVENTS = frozenset({
    "SuspiciousActivity",
    "DetectionSummaryEvent",
    "CriticalFileAccessed",
    "MalwareDetected",
    "ProcessBlockedEvent",
    "NetworkContainmentStateChanged",
})

_AUTH_FAIL_EVENTS = frozenset({
    "UserLogonFailed2",
    "ServiceInstallationDetected",
})


def _parse_ts(raw: str | int | float | None) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    try:
        # FDR timestamps are epoch milliseconds (13-digit) or epoch seconds (10-digit)
        ts_val = float(raw)
        if ts_val > 1e12:
            ts_val /= 1000.0
        return datetime.fromtimestamp(ts_val, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return datetime.now(timezone.utc)


def _status_from_event(event_name: str, obj: dict) -> int:
    if event_name in _HIGH_RISK_EVENTS:
        return 403
    if event_name in _AUTH_FAIL_EVENTS:
        return 401
    # NetworkConnect events with external IPs are suspicious but not blocked
    if "LogonFailed" in event_name or obj.get("Success") == "0":
        return 401
    if "Block" in event_name or "Detect" in event_name:
        return 403
    return 200


def _obj_to_log(obj: dict) -> LogEvent | None:
    event_name = obj.get("event_simpleName") or obj.get("EventSimpleName", "")
    if not event_name:
        return None

    ts = _parse_ts(
        obj.get("timestamp") or obj.get("ContextTimeStamp") or obj.get("ProcessStartTime")
    )

    # IP address: prefer remote IP for network events, else agent IP
    ip = (
        obj.get("RemoteAddressIP4")
        or obj.get("LocalAddressIP4")
        or obj.get("aip")  # agent IP
        or obj.get("SourceIpAddress")
    )

    user = (
        obj.get("UserName")
        or obj.get("SubjectUserName")
        or obj.get("TargetUserName")
        or obj.get("DetectName")  # detection name as fallback identifier
    )

    # Path: use ImageFileName for process events, query for DNS, URL for web
    path = (
        obj.get("ImageFileName")
        or obj.get("TargetFileName")
        or obj.get("DomainName")       # DNS events
        or obj.get("RemotePort") and f"{obj.get('RemoteAddressIP4', '')}:{obj.get('RemotePort')}"
        or event_name
    )
    if isinstance(path, int):
        path = str(path)

    # Hash: SHA256 preferred, then MD5
    file_hash = obj.get("SHA256HashData") or obj.get("MD5HashData")
    if file_hash and len(file_hash) not in (32, 64):
        file_hash = None

    ua = obj.get("UserAgent")
    hostname = obj.get("ComputerName") or obj.get("HostName")

    return LogEvent(
        source_format=LogFormat.CROWDSTRIKE,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=user or None,
        user_agent=ua or None,
        path=path or None,
        http_method=event_name,
        status_code=_status_from_event(event_name, obj),
        resource_display_name=hostname or "CrowdStrike/Falcon",
        file_hash=file_hash or None,
    )


def parse_crowdstrike(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        e = _obj_to_log(item)
                        if e:
                            events.append(e)
            elif isinstance(obj, dict):
                e = _obj_to_log(obj)
                if e:
                    events.append(e)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("CrowdStrike: skipping line: %s", exc)
    logger.info("CrowdStrike parser: %d events", len(events))
    return events


def _is_crowdstrike(obj: dict) -> bool:
    return bool(
        obj.get("event_simpleName") or obj.get("EventSimpleName")
    ) and bool(
        obj.get("cid") or obj.get("aid") or obj.get("ComputerName")
    )


class CrowdStrikeParser(BaseParser):
    format_name = "crowdstrike"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("crowdstrike", "falcon", "fdr")):
            pass
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, list) and obj:
                    obj = obj[0]
                if isinstance(obj, dict) and _is_crowdstrike(obj):
                    return True
            except (json.JSONDecodeError, Exception):
                pass
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_crowdstrike(content)
