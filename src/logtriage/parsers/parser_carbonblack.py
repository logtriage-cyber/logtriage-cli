# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
VMware Carbon Black EDR (formerly CB Response) and CBC (Cloud) log parser.

CB EDR streams events over a message bus or exports them as NDJSON.
Each event has a `type` field with "ingress.event." prefix and
`sensor_id` / `computer_name` fields.

CB Cloud (CBC) uses a different schema: `deviceInfo`, `processDetails`,
`netConn` nested objects.

Discriminators:
  EDR:   `type` starting with "ingress.event." or "watchlist."
  Cloud: `deviceInfo` + `eventAction` fields

Reference:
  https://developer.carbonblack.com/reference/carbon-black-cloud/
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_EDR_PREFIX = "ingress.event."
_WATCHLIST_PREFIX = "watchlist."

# EDR event types → approximate status codes
_EDR_STATUS: dict[str, int] = {
    "ingress.event.ingress.event.netconn": 200,
    "ingress.event.filemod": 200,
    "ingress.event.regmod": 200,
    "ingress.event.process": 200,
    "ingress.event.childproc": 200,
    "ingress.event.moduleload": 200,
    "ingress.event.alert": 403,
    "ingress.event.tamper": 403,
    "watchlist.hit.ingress.event.process": 403,
    "watchlist.hit.ingress.event.netconn": 401,
}


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        raw = raw.rstrip("Z").replace(" ", "T")
        if "+" not in raw and raw.endswith(("Z",)):
            raw = raw[:-1]
        return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _edr_to_log(obj: dict) -> LogEvent | None:
    event_type = obj.get("type", "")
    ts = _parse_ts(obj.get("timestamp") or obj.get("start_timestamp"))
    ip = obj.get("remote_ip") or obj.get("local_ip") or obj.get("srcip")
    user = obj.get("username") or obj.get("user") or obj.get("parent_username")
    hostname = obj.get("computer_name") or obj.get("hostname")
    path = (
        obj.get("path")
        or obj.get("cmdline")
        or obj.get("domain")   # netconn events
        or obj.get("md5")
        or event_type
    )
    md5 = obj.get("md5")
    sha256 = obj.get("sha256")
    file_hash = (sha256 if sha256 and len(sha256) == 64 else None) or (
        md5 if md5 and len(md5) == 32 else None
    )

    status = _EDR_STATUS.get(event_type, 403 if event_type.startswith(_WATCHLIST_PREFIX) else 200)

    return LogEvent(
        source_format=LogFormat.CARBONBLACK,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=user or None,
        path=path or None,
        http_method=event_type.split(".")[-1].upper() if event_type else None,
        status_code=status,
        resource_display_name=hostname or "CarbonBlack/EDR",
        file_hash=file_hash,
    )


def _cbc_to_log(obj: dict) -> LogEvent | None:
    device = obj.get("deviceInfo") or {}
    process = obj.get("processDetails") or {}
    net = obj.get("netConn") or {}
    ts = _parse_ts(obj.get("eventTime") or obj.get("createTime"))

    ip = net.get("remoteIP") or device.get("internalIpAddress") or device.get("externalIpAddress")
    user = device.get("email") or device.get("deviceOwner")
    hostname = device.get("deviceName") or device.get("deviceHostName")
    path = (
        process.get("commandLine")
        or process.get("applicationName")
        or net.get("remoteDomain")
        or obj.get("eventAction", "")
    )

    severity = (obj.get("severity") or "").lower()
    action = (obj.get("eventAction") or "").lower()
    if "deny" in action or "block" in action or severity in ("critical", "high"):
        status = 403
    elif "warn" in action or severity == "medium":
        status = 401
    else:
        status = 200

    sha256 = process.get("sha256") or obj.get("sha256")
    file_hash = sha256 if sha256 and len(sha256) == 64 else None

    return LogEvent(
        source_format=LogFormat.CARBONBLACK,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=user or None,
        path=path or None,
        http_method=(obj.get("eventAction") or "EVENT").upper() or None,
        status_code=status,
        resource_display_name=hostname or "CarbonBlack/Cloud",
        file_hash=file_hash,
    )


def _obj_to_log(obj: dict) -> LogEvent | None:
    event_type = obj.get("type", "")
    if event_type.startswith(_EDR_PREFIX) or event_type.startswith(_WATCHLIST_PREFIX):
        return _edr_to_log(obj)
    if "deviceInfo" in obj:
        return _cbc_to_log(obj)
    # Fallback: try EDR style
    if obj.get("sensor_id") or obj.get("cb_server") or obj.get("computer_name"):
        return _edr_to_log(obj)
    return None


def parse_carbonblack(raw_text: str) -> list[LogEvent]:
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
                for key in ("data", "events", "alerts"):
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
            logger.debug("CarbonBlack: skipping line: %s", exc)
    logger.info("CarbonBlack parser: %d events", len(events))
    return events


def _is_carbonblack(obj: dict) -> bool:
    t = obj.get("type", "")
    return (
        t.startswith(_EDR_PREFIX) or
        t.startswith(_WATCHLIST_PREFIX) or
        ("deviceInfo" in obj and "eventAction" in obj) or
        (obj.get("sensor_id") is not None and obj.get("computer_name") is not None)
    )


class CarbonBlackParser(BaseParser):
    format_name = "carbonblack"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("carbonblack", "cb_", "cbr", "cbc_")):
            pass
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    inner = obj.get("data") or obj.get("events") or obj.get("alerts")
                    if isinstance(inner, list) and inner and isinstance(inner[0], dict):
                        obj = inner[0]
                    if _is_carbonblack(obj):
                        return True
                elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                    if _is_carbonblack(obj[0]):
                        return True
            except (json.JSONDecodeError, Exception):
                pass
            return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_carbonblack(content)
