# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Azure Resource Manager (ARM) Activity Log parser.

Accepts:
  - {"value": [...]} — Azure Monitor / Log Analytics export
  - JSON array of activity records
  - NDJSON

Key discriminator: records contain operationName (e.g. "Microsoft.Compute/virtualMachines/delete"),
resourceProvider, subscriptionId, and status (Succeeded/Failed/Started).

Risk mapping:
  status=Failed → 401
  operationName contains /delete / /write and status=Succeeded → 403 (destructive change)
  Others → 200

Reference:
  https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_DESTRUCTIVE_VERBS = frozenset({"delete", "deallocate", "purge", "revoke", "disable"})
_WRITE_VERBS = frozenset({"write", "create", "update", "patch"})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _record_status(operation_name: str, status: str) -> int:
    op_lower = operation_name.lower()
    verb = op_lower.split("/")[-1] if "/" in op_lower else op_lower
    status_lower = status.lower()
    if status_lower == "failed":
        return 401
    if verb in _DESTRUCTIVE_VERBS and status_lower == "succeeded":
        return 403
    if verb in _WRITE_VERBS and status_lower == "succeeded":
        return 401
    return 200


def _record_to_log(record: dict[str, Any]) -> LogEvent | None:
    try:
        op_name = record.get("operationName") or ""
        if isinstance(op_name, dict):
            op_name = op_name.get("value") or op_name.get("localizedValue") or ""
        status = record.get("status") or ""
        if isinstance(status, dict):
            status = status.get("value") or status.get("localizedValue") or ""
        caller = record.get("caller")
        resource_id = record.get("resourceId") or record.get("id")
        resource_provider = record.get("resourceProviderName") or record.get("resourceProvider") or ""
        if isinstance(resource_provider, dict):
            resource_provider = resource_provider.get("value") or resource_provider.get("localizedValue") or ""
        ts_raw = record.get("eventTimestamp") or record.get("time") or record.get("timestamp")

        return LogEvent(
            source_format=LogFormat.AZURE_ACTIVITY,
            timestamp=_parse_ts(ts_raw),
            ip_address=record.get("httpRequest", {}).get("clientIpAddress") if isinstance(record.get("httpRequest"), dict) else None,
            path=resource_id,
            http_method=record.get("httpRequest", {}).get("method") if isinstance(record.get("httpRequest"), dict) else None,
            status_code=_record_status(op_name, status),
            user_principal_name=caller,
            resource_display_name=resource_provider or op_name.split("/")[0],
            failure_reason=record.get("properties", {}).get("statusMessage") if isinstance(record.get("properties"), dict) else None,
            raw_line=json.dumps(record),
        )
    except Exception as exc:
        logger.debug("Azure Activity: skipping record: %s", exc)
        return None


def _is_azure_activity(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and ("operationName" in obj or "resourceProvider" in obj)
        and ("subscriptionId" in obj or "subscription" in obj)
        and ("eventTimestamp" in obj or "time" in obj or "timestamp" in obj)
        and "caller" in obj
    )


class AzureActivityParser(BaseParser):
    format_name = "azure_activity"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if ("azure" in fn or "arm" in fn) and ("activity" in fn or "audit" in fn):
                return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                items = data.get("value")
                if isinstance(items, list) and items:
                    return _is_azure_activity(items[0])
                return _is_azure_activity(data)
            if isinstance(data, list) and data:
                return _is_azure_activity(data[0])
        except json.JSONDecodeError:
            pass
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_azure_activity(json.loads(line))
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        stripped = content.strip()
        try:
            data = json.loads(stripped)
            items: list[Any] = []
            if isinstance(data, dict):
                items = data.get("value", []) or ([data] if _is_azure_activity(data) else [])
            elif isinstance(data, list):
                items = data
            for rec in items:
                if ev := _record_to_log(rec):
                    events.append(ev)
        except json.JSONDecodeError:
            for line in stripped.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    if ev := _record_to_log(obj):
                        events.append(ev)
                except json.JSONDecodeError:
                    continue

        logger.info("Azure Activity parser: %d events", len(events))
        return events
