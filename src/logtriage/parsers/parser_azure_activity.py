# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Azure Resource Manager (ARM) Activity Log parser.

Accepts:
  - {"value": [...]} — REST API / `az monitor activity-log list` output, or a bare array
  - {"records": [...]} — diagnostic-setting exports to a storage account or Event Hub
    (resource-log schema: time, resultType, callerIpAddress, identity.claims)
  - NDJSON of either

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

from logtriage.parsers import json_input
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


_UPN_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"


def _claims_caller(identity: Any) -> str | None:
    """The caller of a resource-log record (storage / Event Hub export): its token claims."""
    claims = identity.get("claims") if isinstance(identity, dict) else None
    if not isinstance(claims, dict):
        return None
    return claims.get(_UPN_CLAIM) or claims.get("name") or claims.get("appid")


def _record_to_log(record: dict[str, Any]) -> LogEvent | None:
    try:
        op_name = record.get("operationName") or ""
        if isinstance(op_name, dict):
            op_name = op_name.get("value") or op_name.get("localizedValue") or ""
        status = record.get("status") or record.get("resultType") or ""
        if isinstance(status, dict):
            status = status.get("value") or status.get("localizedValue") or ""
        if status.lower() == "success":  # resource-log schema says Success/Failure/Start
            status = "Succeeded"
        elif status.lower() == "failure":
            status = "Failed"
        caller = record.get("caller") or _claims_caller(record.get("identity"))
        http_request = record.get("httpRequest")
        http: dict[str, Any] = http_request if isinstance(http_request, dict) else {}
        ip = http.get("clientIpAddress") or record.get("callerIpAddress")
        resource_id = record.get("resourceId") or record.get("id")
        resource_provider = record.get("resourceProviderName") or record.get("resourceProvider") or ""
        if isinstance(resource_provider, dict):
            resource_provider = resource_provider.get("value") or resource_provider.get("localizedValue") or ""
        ts_raw = record.get("eventTimestamp") or record.get("time") or record.get("timestamp")

        return LogEvent(
            source_format=LogFormat.AZURE_ACTIVITY,
            timestamp=_parse_ts(ts_raw),
            ip_address=ip or None,
            path=resource_id,
            http_method=http.get("method"),
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
    """REST / `az monitor activity-log list` records (caller, subscriptionId, status)
    and resource-log records from diagnostic settings (time, resourceId, resultType,
    identity) — the same rule as the free analyzer's Azure Activity adapter."""
    if not isinstance(obj, dict) or "operationName" not in obj:
        return False
    category = obj.get("category")
    category = category.get("value", "") if isinstance(category, dict) else str(category or "")
    if "signin" in category.lower() or "flowevent" in category.lower():
        return False
    return "caller" in obj or "callerIpAddress" in obj or "resourceId" in obj


# REST API: {"value": [...]}; diagnostic settings to storage / Event Hub: {"records": [...]}
_ENVELOPES = ("value", "records")


class AzureActivityParser(BaseParser):
    format_name = "azure_activity"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content, _ENVELOPES)
        return bool(head) and sum(_is_azure_activity(r) for r in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events = [ev for rec in json_input.records(content, _ENVELOPES) if (ev := _record_to_log(rec))]
        logger.info("Azure Activity parser: %d events", len(events))
        return events
