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
  UserLogon / UserLogoff / UserLogonFailed2 — authentication events
  Detections — streaming-API events, which carry no event_simpleName: in LogScale/FLTR data
    a flat record with ExternalApiType=Event_DetectionSummaryEvent (CrowdStrike's own queries:
    "These events don't have an #event_simpleName tag"), AgentIdString and CustomerIdString;
    from the Event Streams API an envelope {"metadata": {"eventType": "DetectionSummaryEvent"},
    "event": {...}}. Fields per Panther's DetectionSummary schema (from CrowdStrike's streaming
    API documentation).

Event names and fields follow marketing/src/data/reference/crowdstrike-events-official.json:
CrowdStrike's own public queries (github.com/CrowdStrike/logscale-community-content), Panther's
FDR schemas and Splunk's ProcessRollup2 data source. A 2026-10-28 check against them removed
event names nobody documents (SuspiciousActivity, MalwareDetected, ProcessBlockedEvent,
NetworkContainmentStateChanged, ServiceInstallationDetected, CriticalFileAccessed); on
2026-10-29 the sample's detection, written with an event_simpleName no source uses, became the
documented ExternalApiType record.

References:
  https://falcon.crowdstrike.com/documentation/93/falcon-data-replicator
  https://docs.panther.com/data-onboarding/supported-logs/crowdstrike/falcon-data-replicator
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers import json_input
from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Detection event types: the Event Streams API's eventType, and the ExternalApiType values
# CrowdStrike's own queries filter on in LogScale data.
_HIGH_RISK_EVENTS = frozenset({
    "DetectionSummaryEvent",            # Event Streams API metadata.eventType
    "Event_DetectionSummaryEvent",      # ExternalApiType, as CrowdStrike's own queries name them
    "Event_EppDetectionSummaryEvent",
    "Event_IdpDetectionSummaryEvent",
})

# API responses wrap records as {"resources": [...]}
_ENVELOPES = ("resources", "events", "data")

_AUTH_FAIL_EVENTS = frozenset({
    "UserLogonFailed",
    "UserLogonFailed2",
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


def _status_from_event(event_name: str, obj: dict[str, Any]) -> int:
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


def _unwrap(obj: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """(event type, the record's fields): sensor events name themselves in event_simpleName,
    streaming-API events in ExternalApiType (LogScale) or metadata.eventType (Event Streams)."""
    meta, body = obj.get("metadata"), obj.get("event")
    if isinstance(meta, dict) and isinstance(body, dict) and meta.get("eventType"):
        return str(meta["eventType"]), {**body, "timestamp": body.get("timestamp") or meta.get("eventCreationTime")}
    name = obj.get("event_simpleName") or obj.get("EventSimpleName") or obj.get("ExternalApiType") or ""
    return str(name), obj


def _obj_to_log(raw: dict[str, Any]) -> LogEvent | None:
    event_name, obj = _unwrap(raw)
    if not event_name:
        return None

    ts = _parse_ts(
        obj.get("timestamp") or obj.get("UTCTimestamp") or obj.get("ContextTimeStamp") or obj.get("ProcessStartTime")
    )

    # IP address: prefer remote IP for network events, else agent IP
    ip = (
        obj.get("RemoteAddressIP4")
        or obj.get("LocalAddressIP4")
        or obj.get("LocalIP")  # detections: the host's address
        or obj.get("aip")  # agent IP
        or obj.get("SourceIpAddress")
    )

    user = (
        obj.get("UserName")
        or obj.get("SubjectUserName")
        or obj.get("TargetUserName")
    )  # never DetectName: a detection's name ("Cobalt Strike Beacon") is not a user

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
    # Sensor events carry *HashData; detections (DetectionSummaryEvent) carry *String.
    file_hash = obj.get("SHA256HashData") or obj.get("SHA256String") or obj.get("MD5HashData") or obj.get("MD5String")
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
    for obj in json_input.records(raw_text, _ENVELOPES):
        try:
            e = _obj_to_log(obj)
        except Exception as exc:
            logger.debug("CrowdStrike: skipping record: %s", exc)
            continue
        if e:
            events.append(e)
    logger.info("CrowdStrike parser: %d events", len(events))
    return events


def _is_crowdstrike(obj: dict[str, Any]) -> bool:
    if obj.get("event_simpleName") or obj.get("EventSimpleName"):
        return bool(obj.get("cid") or obj.get("aid") or obj.get("ComputerName"))
    # Streaming-API records: LogScale's flat form, or the Event Streams envelope
    if str(obj.get("ExternalApiType", "")).startswith("Event_"):
        return bool(obj.get("AgentIdString") or obj.get("CustomerIdString"))
    meta, body = obj.get("metadata"), obj.get("event")
    return (isinstance(meta, dict) and isinstance(body, dict) and bool(meta.get("eventType"))
            and bool(meta.get("customerIDString") or "offset" in meta))


class CrowdStrikeParser(BaseParser):
    format_name = "crowdstrike"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        return any(_is_crowdstrike(r) for r in json_input.sample(content, _ENVELOPES))

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_crowdstrike(content)
