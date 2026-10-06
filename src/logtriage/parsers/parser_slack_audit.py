# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Slack Audit Logs API parser.

Accepts:
  - {"entries": [...]} — Audit Logs API response
  - JSON array of entry objects
  - NDJSON

Key discriminator: entries contain action, actor (with type/user sub-object),
entity (with type/entity_payload), and date_create (Unix epoch).

Risk mapping:
  file_download / member_left_workspace / member_deactivated → 403
  message_shared_externally / ekm_* / app_* privileged → 401
  Others (invite, upload, login) → 200

Reference:
  https://api.slack.com/admins/audit-logs
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_HIGH_RISK_ACTIONS = frozenset({
    "user_deactivated", "member_deactivated", "guest_deactivated",
    "ekm_enrolled", "ekm_disenrolled", "ekm_key_revoked",
    "file_downloaded", "message_filed_away", "app_uninstalled",
    "app_scopes_expanded", "workspace_export_started",
    "owner_transferred", "workspace_deleted",
    "role_change_to_admin", "role_change_to_owner",
    "bulk_session_invalidation_by_admin",
})

_MED_RISK_ACTIONS = frozenset({
    "user_login", "user_logout", "file_public_link_created",
    "message_shared_externally", "app_installed", "app_requested",
    "channel_joined", "channel_created", "channel_deleted",
    "member_left_workspace", "guest_created",
})


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _action_status(action: str) -> int:
    if action in _HIGH_RISK_ACTIONS:
        return 403
    if action in _MED_RISK_ACTIONS:
        return 401
    return 200


def _entry_to_log(obj: dict[str, Any]) -> LogEvent | None:
    try:
        action = obj.get("action", "")
        actor = obj.get("actor", {})
        entity = obj.get("entity", {})
        context = obj.get("context", {})

        # actor can be {type: "user", user: {name: ..., email: ...}}
        actor_user = actor.get("user", {}) if isinstance(actor, dict) else {}
        username = actor_user.get("email") or actor_user.get("name") or actor_user.get("id")
        ip = context.get("ip_address") if isinstance(context, dict) else None

        entity_type = entity.get("type", "") if isinstance(entity, dict) else ""
        entity_name = ""
        ep = entity.get(entity_type, {}) if isinstance(entity, dict) else {}
        if isinstance(ep, dict):
            entity_name = ep.get("name") or ep.get("id") or ""

        return LogEvent(
            source_format=LogFormat.SLACK_AUDIT,
            timestamp=_parse_ts(obj.get("date_create") or obj.get("timestamp")),
            ip_address=ip,
            path=f"/audit/{action}",
            http_method="POST",
            status_code=_action_status(action),
            user_principal_name=username,
            resource_display_name=entity_name or entity_type or "slack",
            raw_line=json.dumps(obj),
        )
    except Exception as exc:
        logger.debug("Slack audit: skipping: %s", exc)
        return None


def _is_slack_entry(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "action" in obj
        and "actor" in obj
        and "entity" in obj
        and ("date_create" in obj or "id" in obj)
    )


class SlackAuditParser(BaseParser):
    format_name = "slack_audit"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "slack" in filename.lower():
            return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                entries = data.get("entries")
                if isinstance(entries, list) and entries:
                    return _is_slack_entry(entries[0])
                return _is_slack_entry(data)
            if isinstance(data, list) and data:
                return _is_slack_entry(data[0])
        except json.JSONDecodeError:
            pass
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_slack_entry(json.loads(line))
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
                items = data.get("entries", []) or ([data] if _is_slack_entry(data) else [])
            elif isinstance(data, list):
                items = data
            for obj in items:
                if ev := _entry_to_log(obj):
                    events.append(ev)
        except json.JSONDecodeError:
            for line in stripped.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    if ev := _entry_to_log(obj):
                        events.append(ev)
                except json.JSONDecodeError:
                    continue

        logger.info("Slack audit parser: %d events", len(events))
        return events
