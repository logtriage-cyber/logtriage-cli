# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Microsoft Defender for Endpoint (MDE / MDATP) log parser.

Supports two export schemas:

1. Alert API format:
   {"MachineId": "…", "ComputerDnsName": "…", "AlertId": "…",
    "Severity": "High", "Category": "Malware", "Title": "…",
    "MitreTechniques": ["T1059"], "EvidenceEntityType": "…", …}

2. Advanced Hunting (DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents,
   DeviceLogonEvents, DeviceAlertEvents) — flat JSON/NDJSON:
   {"Timestamp": "…", "DeviceId": "…", "DeviceName": "…",
    "ActionType": "ProcessCreated", "FileName": "…",
    "RemoteIP": "…", "AccountName": "…", "SHA256": "…", …}

Discriminators:
  Alert format:  `MachineId` + `AlertId`
  Advanced Hunt: `DeviceId` + `ActionType` (or `ReportId`)

References:
  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

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


def _alert_to_log(obj: dict) -> LogEvent | None:
    ts = _parse_ts(obj.get("AlertCreationTime") or obj.get("LastEventTime") or obj.get("FirstEventTime"))
    ip = (
        obj.get("RelatedIp")
        or obj.get("EvidenceEntityValue") if obj.get("EvidenceEntityType") == "Ip" else None
    ) or obj.get("LocalIpAddress")

    hostname = obj.get("ComputerDnsName") or obj.get("DeviceName")
    user = obj.get("LoggedOnUsers") or obj.get("RelatedUser")
    if isinstance(user, list):
        user = user[0] if user else None
    if isinstance(user, dict):
        user = user.get("UserName") or user.get("DomainAndUserName")

    severity = obj.get("Severity", "")
    status = 403 if severity in _HIGH_SEVERITY else (401 if severity == "Medium" else 400)

    title = obj.get("Title") or obj.get("Category") or "MDE/Alert"
    sha256 = obj.get("Sha256") or obj.get("FileSha256")
    file_hash = sha256 if sha256 and len(sha256) == 64 else None

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


def _obj_to_log(obj: dict) -> LogEvent | None:
    if obj.get("AlertId") and obj.get("MachineId"):
        return _alert_to_log(obj)
    if obj.get("ActionType") and (obj.get("DeviceId") or obj.get("DeviceName")):
        return _hunt_to_log(obj)
    return None


def parse_mdatp(raw_text: str) -> list[LogEvent]:
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
                for key in ("data", "alerts", "results", "value"):
                    inner = obj.get(key)
                    if isinstance(inner, list):
                        for item in inner:
                            if isinstance(item, dict):
                                e = _obj_to_log(item)
                                if e:
                                    events.append(e)
                        break
                else:
                    e = _obj_to_log(obj)
                    if e:
                        events.append(e)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("MDATP: skipping line: %s", exc)
    logger.info("MDATP parser: %d events", len(events))
    return events


def _is_mdatp(obj: dict) -> bool:
    return (
        (bool(obj.get("AlertId")) and bool(obj.get("MachineId"))) or
        (bool(obj.get("ActionType")) and bool(obj.get("DeviceId") or obj.get("DeviceName")) and bool(obj.get("Timestamp"))) or
        (bool(obj.get("ReportId")) and bool(obj.get("DeviceName")))
    )


class MdatpParser(BaseParser):
    format_name = "mdatp"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("mdatp", "defender", "mde_", "atp_")):
            pass
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    for key in ("data", "alerts", "results", "value"):
                        inner = obj.get(key)
                        if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                            obj = inner[0]
                            break
                    if _is_mdatp(obj):
                        return True
                elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                    if _is_mdatp(obj[0]):
                        return True
            except (json.JSONDecodeError, Exception):
                pass
            return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_mdatp(content)
