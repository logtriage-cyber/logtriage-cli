# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Microsoft 365 Unified Audit Log (UAL) parser.

Input: JSON array of UAL records exported from Microsoft Purview / Office 365
Management Activity API, or CSV export from the M365 compliance portal.
JSON format preferred; CSV fallback is handled via generic parser.

Reference:
  https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema

Key fields mapped:
  CreationTime    → timestamp
  ClientIP        → ip_address
  UserId          → user_principal_name
  UserAgent       → user_agent (not always present)
  Operation       → path  (e.g. /m365/SharePoint/FileDownloaded)
  Workload        → resource_display_name
  ResultStatus    → status_code (Succeeded/Success→200, Failed→401, etc.)
  ObjectId        → appended to path as resource identifier
  RecordType      → used for detection; not mapped to LogEvent

High-risk operations flagged by failure_reason:
  - Add member to role, Remove member from role
  - Set-TransportRule, New-TransportRule  (email forwarding = BEC)
  - External sharing events
  - MFADenied / UserLoginFailed
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_RESULT_STATUS: dict[str, int] = {
    "succeeded": 200,
    "success": 200,
    "true": 200,
    "partiallysucceeded": 206,
    "failed": 401,
    "false": 401,
}

# Operations that map to admin/privilege changes → path prefix /m365/admin
_ADMIN_OPS = {
    "add member to role", "remove member from role", "update role",
    "add role member to role", "add application.",
    "set-transportrule", "new-transportrule", "set-mailboxautoreplyconfiguration",
    "set-inboxrule", "new-inboxrule", "set-owaMailboxPolicy",
    "add-unifiedgrouplinks", "set-unifiedgroup",
    "new-managementroleassignment", "add-rolegroupmember",
}

# Operations that indicate external sharing / data exfiltration risk
_EXFIL_OPS = {
    "sharinginvitationcreated", "sharinginvitationaccepted",
    "filedownloaded", "filesyncdownloadedfull", "pageviewed",
    "mailitemsaccessed", "sendas", "sendonbehalf",
    "new-inboxrule", "set-inboxrule",
    "searchqueryperformed",
}


def _ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _operation_to_path(workload: str | None, operation: str | None) -> str:
    wl = (workload or "M365").replace(" ", "")
    op = (operation or "unknown").replace(" ", "")
    return f"/m365/{wl}/{op}"


def _is_admin_op(operation: str | None) -> bool:
    if not operation:
        return False
    op_lower = operation.lower()
    return any(op_lower.startswith(a) or op_lower == a for a in _ADMIN_OPS)


def _parse_record(raw: dict[str, Any]) -> LogEvent | None:
    try:
        operation: str | None = raw.get("Operation")
        workload: str | None = raw.get("Workload")
        user_id: str | None = raw.get("UserId") or raw.get("UserKey")
        client_ip: str | None = raw.get("ClientIP") or raw.get("ActorIpAddress")
        result_raw: str | None = str(raw.get("ResultStatus") or "")
        ua: str | None = raw.get("UserAgent")

        status_code = _RESULT_STATUS.get(result_raw.lower(), 200)

        failure_reason: str | None = None
        if _is_admin_op(operation):
            failure_reason = f"Admin operation: {operation}"
        elif operation and operation.lower() in _EXFIL_OPS:
            if status_code >= 400:
                failure_reason = f"Failed {operation}"

        path = _operation_to_path(workload, operation)
        resource = workload or "Microsoft 365"

        # System/service accounts add noise — skip pure machine identities
        if user_id and user_id.lower() in ("app@sharepoint", "sharepoint"):
            return None

        return LogEvent(
            source_format=LogFormat.M365_AUDIT,
            timestamp=_ts(raw.get("CreationTime")),
            ip_address=client_ip if client_ip and client_ip != "<null>" else None,
            user_agent=ua,
            http_method="POST" if _is_admin_op(operation) else "GET",
            path=path,
            status_code=status_code,
            user_principal_name=user_id,
            resource_display_name=resource,
            failure_reason=failure_reason,
        )
    except Exception as exc:
        logger.debug("Skipping malformed M365 audit record: %s", exc)
        return None


def parse_m365(content: str) -> list[LogEvent]:
    """Parse Microsoft 365 Unified Audit Log JSON into LogEvents."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"M365 parser: invalid JSON — {exc}") from exc

    if isinstance(data, dict):
        records = data.get("value") or data.get("records") or [data]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("M365 parser: expected JSON array or object")

    result = [e for e in (_parse_record(r) for r in records if isinstance(r, dict)) if e is not None]
    logger.info("M365 audit parser: %d/%d events parsed", len(result), len(records))
    return result


class M365AuditParser(BaseParser):
    format_name = "m365_audit"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if any(x in filename.lower() for x in ("m365", "o365", "office365", "unified_audit", "ual")):
            stripped = content.strip()
            return stripped.startswith("[") or stripped.startswith("{")
        head = content.strip()[:3000]
        return (
            '"Workload"' in head and '"Operation"' in head and '"UserId"' in head
        ) or (
            '"RecordType"' in head and '"ResultStatus"' in head and '"CreationTime"' in head
            and '"UserId"' in head
        )

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_m365(content)
