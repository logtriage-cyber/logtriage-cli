# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Duo Security Admin API log parser.

Accepts Auth Log v2 and Admin Log JSON (both JSON array / NDJSON).

Auth Log v2 discriminators: result (ALLOW/DENY/FRAUD), factor, user.name,
  access_device, application.name, event_type.
Admin Log discriminators: action, username, timestamp (int epoch), object.

Risk mapping:
  result=FRAUD → 403
  result=DENY / factor=bypass → 403
  result=ALLOW but from anomalous country → 401 (signalled by reason fields)
  Admin: user deletion/policy changes → 403

Reference:
  https://duo.com/docs/adminapi#logs
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_DENY_RESULTS = frozenset({"deny", "fraud", "denied"})
_HIGH_RISK_ADMIN_ACTIONS = frozenset({
    "user_delete", "user_update", "policy_update", "policy_delete",
    "integration_delete", "group_update", "settings_update",
    "admin_login_error", "bypass_create", "bypass_delete",
    "activation_link_viewed_by_admin", "user_bulk_delete",
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


def _auth_to_log(obj: dict[str, Any]) -> LogEvent | None:
    try:
        result = (obj.get("result") or "").lower()
        factor = obj.get("factor") or obj.get("auth_device", {}).get("type", "")
        user = obj.get("user", {})
        username = user.get("name") or obj.get("username")
        ip = obj.get("access_device", {}).get("ip") or obj.get("device", {}).get("ip")
        app = obj.get("application", {}).get("name") or obj.get("service")
        reason = obj.get("reason") or ""
        ua = obj.get("access_device", {}).get("browser")

        if result in _DENY_RESULTS or "bypass" in factor.lower():
            status = 403
        elif "anomalous" in reason.lower() or "error" in reason.lower():
            status = 401
        else:
            status = 200

        return LogEvent(
            source_format=LogFormat.DUO,
            timestamp=_parse_ts(obj.get("timestamp") or obj.get("isotimestamp")),
            ip_address=ip,
            path=f"/auth/{factor}" if factor else "/auth",
            http_method="POST",
            status_code=status,
            user_principal_name=username,
            user_agent=ua,
            resource_display_name=app,
            failure_reason=reason if result in _DENY_RESULTS else None,
            raw_line=json.dumps(obj),
        )
    except Exception as exc:
        logger.debug("Duo auth: skipping: %s", exc)
        return None


def _admin_to_log(obj: dict[str, Any]) -> LogEvent | None:
    try:
        action = (obj.get("action") or "").lower()
        username = obj.get("username") or obj.get("user")
        ip = obj.get("ip") or obj.get("host")
        description = obj.get("description") or obj.get("object", "")

        status = 403 if action in _HIGH_RISK_ADMIN_ACTIONS else 200

        return LogEvent(
            source_format=LogFormat.DUO,
            timestamp=_parse_ts(obj.get("timestamp")),
            ip_address=ip,
            path=f"/admin/{action}",
            http_method="POST",
            status_code=status,
            user_principal_name=username,
            resource_display_name="duo-admin",
            failure_reason=description if status == 403 else None,
            raw_line=json.dumps(obj),
        )
    except Exception as exc:
        logger.debug("Duo admin: skipping: %s", exc)
        return None


def _is_duo_auth(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and ("result" in obj or "factor" in obj)
        and ("user" in obj or "username" in obj)
        and ("access_device" in obj or "application" in obj or "event_type" in obj)
    )


def _is_duo_admin(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "action" in obj
        and ("username" in obj or "user" in obj)
        and "timestamp" in obj
        and "action" in obj
        and not ("result" in obj and "access_device" in obj)
    )


def _is_duo(obj: Any) -> bool:
    return _is_duo_auth(obj) or _is_duo_admin(obj)


def _parse_items(items: list[Any]) -> list[LogEvent]:
    events: list[LogEvent] = []
    for obj in items:
        if _is_duo_auth(obj):
            if ev := _auth_to_log(obj):
                events.append(ev)
        elif _is_duo_admin(obj):
            if ev := _admin_to_log(obj):
                events.append(ev)
    return events


class DuoParser(BaseParser):
    format_name = "duo"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "duo" in filename.lower():
            return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, list) and data:
                return _is_duo(data[0])
            if isinstance(data, dict):
                # Duo API wraps in {"authlogs": {"items": [...]}, "metadata": {...}}
                al = data.get("authlogs", {})
                items = al.get("items") if isinstance(al, dict) else None
                if isinstance(items, list) and items:
                    return _is_duo(items[0])
                items = data.get("items") or data.get("logs")
                if isinstance(items, list) and items:
                    return _is_duo(items[0])
                return _is_duo(data)
        except json.JSONDecodeError:
            pass
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_duo(json.loads(line))
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
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                al = data.get("authlogs", {})
                if isinstance(al, dict):
                    items = al.get("items", [])
                if not items:
                    items = data.get("items") or data.get("logs") or ([data] if _is_duo(data) else [])
            events = _parse_items(items)
        except json.JSONDecodeError:
            for line in stripped.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    if _is_duo_auth(obj):
                        if ev := _auth_to_log(obj):
                            events.append(ev)
                    elif _is_duo_admin(obj):
                        if ev := _admin_to_log(obj):
                            events.append(ev)
                except json.JSONDecodeError:
                    continue

        logger.info("Duo parser: %d events", len(events))
        return events
