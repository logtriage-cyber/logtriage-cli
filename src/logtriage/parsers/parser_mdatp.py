# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Microsoft Defender for Endpoint (MDE / MDATP) log parser.

Supports two export schemas:

1. Alerts — the Alerts API (`GET /api/alerts`, camelCase):
   {"id": "da637…", "machineId": "…", "computerDnsName": "…",
    "severity": "High", "category": "Malware", "title": "…",
    "alertCreationTime": "…", "mitreTechniques": ["T1059"],
    "relatedUser": {"userName": "…", "domainName": "…"},
    "evidence": [{"entityType": "File", "sha256": "…"}, …]}
   and the older PascalCase exports (`AlertId`, `MachineId`, `AlertTime`, …).
   Field names are matched case-insensitively.

2. Advanced Hunting (DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents,
   DeviceLogonEvents, DeviceAlertEvents) — flat JSON/NDJSON:
   {"Timestamp": "…", "DeviceId": "…", "DeviceName": "…",
    "ActionType": "ProcessCreated", "FileName": "…",
    "RemoteIP": "…", "AccountName": "…", "SHA256": "…", …}

Discriminators:
  Alert format:  `AlertId` + `MachineId`, or `id` + `machineId` + `alertCreationTime`
  Advanced Hunt: `DeviceId` + `ActionType` (or `ReportId`)

References:
  https://learn.microsoft.com/en-us/defender-endpoint/api/get-alerts
  https://learn.microsoft.com/en-us/defender-endpoint/api/alerts
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers import json_input
from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_HIGH_SEVERITY = frozenset({"Critical", "High"})
_BLOCK_ACTIONS = frozenset({
    "AntivirusDetection", "AntivirusBlock", "ExploitGuardBlockedConnection",
    "FirewallInboundConnectionBlocked", "FirewallOutboundConnectionBlocked",
    "SmartScreenUrlWarning", "SmartScreenAppWarning",
    "MalwareDetected", "SuspiciousActivity",
})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        raw = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)


def _lower_keys(obj: dict[str, Any]) -> dict[str, Any]:
    return {str(k).lower(): v for k, v in obj.items()}


def _evidence(obj: dict[str, Any]) -> list[dict[str, Any]]:
    items = obj.get("evidence")
    return [_lower_keys(e) for e in items if isinstance(e, dict)] if isinstance(items, list) else []


def _alert_to_log(raw: dict[str, Any]) -> LogEvent | None:
    obj = _lower_keys(raw)
    evidence = _evidence(obj)
    ts = _parse_ts(
        obj.get("alertcreationtime") or obj.get("alerttime")
        or obj.get("lasteventtime") or obj.get("firsteventtime")
    )
    entity_ip = obj.get("evidenceentityvalue") if str(obj.get("evidenceentitytype", "")).lower() == "ip" else None
    ip = (
        obj.get("relatedip")
        or entity_ip
        or obj.get("ipaddress")
        or next((e["ipaddress"] for e in evidence if e.get("ipaddress")), None)
        or obj.get("localipaddress")
    )

    hostname = obj.get("computerdnsname") or obj.get("devicename") or obj.get("machinename")
    user = (
        next((e["userprincipalname"] for e in evidence if e.get("userprincipalname")), None)
        or obj.get("loggedonusers") or obj.get("relateduser") or obj.get("username")
    )
    if isinstance(user, list):
        user = user[0] if user else None
    if isinstance(user, dict):
        u = _lower_keys(user)
        name = u.get("username")
        user = u.get("domainandusername") or (
            f"{u['domainname']}\\{name}" if name and u.get("domainname") else name
        )

    severity = str(obj.get("severity") or "").capitalize()
    status = 403 if severity in _HIGH_SEVERITY else (401 if severity == "Medium" else 400)

    title = obj.get("title") or obj.get("alerttitle") or obj.get("category") or "MDE/Alert"
    sha256 = (
        obj.get("sha256") or obj.get("filesha256")
        or next((e["sha256"] for e in evidence if e.get("sha256")), None)
    )
    file_hash = sha256 if isinstance(sha256, str) and len(sha256) == 64 else None

    return LogEvent(
        source_format=LogFormat.MDATP,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=str(user) if user else None,
        path=title,
        http_method="ALERT",
        status_code=status,
        resource_display_name=hostname or "MDE",
        file_hash=file_hash,
    )


def _hunt_to_log(obj: dict) -> LogEvent | None:
    ts = _parse_ts(obj.get("Timestamp"))
    ip = obj.get("RemoteIP") or obj.get("LocalIP") or obj.get("PublicIP")
    hostname = obj.get("DeviceName")
    user = obj.get("AccountName") or obj.get("InitiatingProcessAccountName")
    action = obj.get("ActionType", "")
    sha256 = obj.get("SHA256") or obj.get("InitiatingProcessSHA256")
    file_hash = sha256 if sha256 and len(sha256) == 64 else None

    path = (
        obj.get("RemoteUrl")
        or obj.get("FolderPath")
        or obj.get("FileName")
        or obj.get("ProcessCommandLine")
        or action
    )

    status = 403 if action in _BLOCK_ACTIONS else 200

    return LogEvent(
        source_format=LogFormat.MDATP,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=user or None,
        path=path or None,
        http_method=action or None,
        status_code=status,
        resource_display_name=hostname or "MDE",
        file_hash=file_hash,
    )


def _is_alert(obj: dict[str, Any]) -> bool:
    keys = {str(k).lower(): v for k, v in obj.items()}
    if keys.get("alertid") and (keys.get("machineid") or keys.get("deviceid") or keys.get("computerdnsname")):
        return True
    # Alerts API: "id" + "machineId" + its own creation timestamp
    return bool(keys.get("id") and keys.get("machineid") and keys.get("alertcreationtime"))


def _obj_to_log(obj: dict) -> LogEvent | None:
    if _is_alert(obj):
        return _alert_to_log(obj)
    if obj.get("ActionType") and (obj.get("DeviceId") or obj.get("DeviceName")):
        return _hunt_to_log(obj)
    return None


# Alerts API / Graph responses: {"value": [...]}; advanced hunting API: {"Schema": ..., "Results": [...]}
_ENVELOPES = ("value", "Results", "results", "data", "alerts")


def parse_mdatp(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for obj in json_input.records(raw_text, _ENVELOPES):
        try:
            e = _obj_to_log(obj)
        except Exception as exc:
            logger.debug("MDATP: skipping record: %s", exc)
            continue
        if e:
            events.append(e)
    logger.info("MDATP parser: %d events", len(events))
    return events


def _is_mdatp(obj: dict) -> bool:
    return (
        _is_alert(obj) or
        (bool(obj.get("ActionType")) and bool(obj.get("DeviceId") or obj.get("DeviceName")) and bool(obj.get("Timestamp"))) or
        (bool(obj.get("ReportId")) and bool(obj.get("DeviceName")))
    )


class MdatpParser(BaseParser):
    format_name = "mdatp"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content, _ENVELOPES, n=1)
        return bool(head) and _is_mdatp(head[0])

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_mdatp(content)
