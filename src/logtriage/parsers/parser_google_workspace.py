# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Google Workspace Admin SDK Reports API — Activity log parser.

Accepts:
  - {"kind": "admin#reports#activities", "items": [...]} — API response
  - JSON array of activity objects

Each item has: kind, id.time, id.applicationName, actor.email,
events[].type, events[].name, events[].parameters[].

Risk mapping:
  ADMIN / LOGIN events  → 403 if FAILED / SUSPENDED
  USER_ACCOUNTS changes → 401
  Others                → 200

Reference:
  https://developers.google.com/admin-sdk/reports/v1/reference/activities
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_HIGH_RISK_EVENTS = frozenset({
    "SUSPICIOUS_LOGIN", "SUSPICIOUS_LOGIN_LESS_SECURE_APP",
    "ACCOUNT_DISABLED_SPAMMING", "ACCOUNT_DISABLED_GENERIC",
    "PASSWORD_EDIT", "RECOVERY_EMAIL_EDIT", "RECOVERY_PHONE_EDIT",
    "2SV_DISABLE", "ADMIN_ROLE_ASSIGNMENT", "SUPER_ADMIN_ADD",
    "CREATE_APPLICATION_SETTING", "DELETE_USER", "SUSPEND_USER",
    "ADMIN_TAKEOUT_FAILURE", "CHROME_OS_DEVICE_DISABLED",
})

_MED_RISK_EVENTS = frozenset({
    "CREATE_USER", "RENAME_USER", "CHANGE_PASSWORD",
    "GRANT_ADMIN_PRIVILEGE", "REVOKE_ADMIN_PRIVILEGE",
    "ADD_GROUP_MEMBER", "REMOVE_GROUP_MEMBER",
    "LOGIN_FAILURE", "LOGOUT",
})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _event_name_to_status(event_name: str) -> int:
    upper = event_name.upper()
    if any(h in upper for h in ("FAIL", "SUSPEND", "DISABLE", "DELETE", "SUSPICIOUS")):
        return 403
    if upper in _HIGH_RISK_EVENTS:
        return 403
    if upper in _MED_RISK_EVENTS:
        return 401
    return 200


def _param_value(param: dict[str, Any]) -> str | None:
    for key in ("value", "intValue", "boolValue", "multiValue"):
        v = param.get(key)
        if v is not None:
            return str(v)
    return None


def _activity_to_logs(item: dict[str, Any]) -> list[LogEvent]:
    results: list[LogEvent] = []
    try:
        id_block = item.get("id", {})
        actor = item.get("actor", {})
        ts = _parse_ts(id_block.get("time"))
        app = id_block.get("applicationName", "")
        email = actor.get("email") or actor.get("profileId")
        ip = item.get("ipAddress")
        events = item.get("events", [{}])

        for ev in events:
            event_name = ev.get("name", app)
            params = {p.get("name"): _param_value(p) for p in ev.get("parameters", [])}
            resource = params.get("RESOURCE_NAME") or params.get("DOC_TITLE") or app
            results.append(LogEvent(
                source_format=LogFormat.GOOGLE_WORKSPACE,
                timestamp=ts,
                ip_address=ip,
                path=f"/{app}/{event_name}",
                http_method="POST",
                status_code=_event_name_to_status(event_name),
                user_principal_name=email,
                resource_display_name=resource,
                raw_line=json.dumps(item),
            ))
    except Exception as exc:
        logger.debug("Google Workspace: skipping item: %s", exc)
    return results


def _is_workspace_item(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "actor" in obj
        and "id" in obj
        and isinstance(obj.get("id"), dict)
        and ("applicationName" in obj.get("id", {}) or "kind" in obj)
        and "events" in obj
    )


class GoogleWorkspaceParser(BaseParser):
    format_name = "google_workspace"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if "google" in fn or "workspace" in fn or "gsuite" in fn:
                return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                if data.get("kind", "").startswith("admin#reports"):
                    return True
                items = data.get("items")
                if isinstance(items, list) and items:
                    return _is_workspace_item(items[0])
            if isinstance(data, list) and data:
                return _is_workspace_item(data[0])
        except json.JSONDecodeError:
            pass
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        stripped = content.strip()
        try:
            data = json.loads(stripped)
            items: list[Any] = []
            if isinstance(data, dict):
                items = data.get("items", [])
                if not items and _is_workspace_item(data):
                    items = [data]
            elif isinstance(data, list):
                items = data
            for item in items:
                events.extend(_activity_to_logs(item))
        except json.JSONDecodeError:
            pass
        logger.info("Google Workspace parser: %d events", len(events))
        return events
