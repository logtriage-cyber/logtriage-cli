# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
JumpCloud Directory Insights event parser.

Accepts:
  - JSON array: [{...}, ...]
  - NDJSON: one event per line

Key discriminator: events contain service (directory / ldap / sso / radius /
mdm / systems), event_type (or type), initiated_by (object with sub-fields),
and timestamp (ISO-8601). JumpCloud also embeds geoip data in the event.

Risk mapping:
  event_type admin_login_attempt_failed / password_recovery → 403
  sso / mfa failures → 403
  admin events (service=directory, type=admin_*) → 401
  success events → 200

Reference:
  https://docs.jumpcloud.com/api/insights/directory/v1/overview
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_JUMPCLOUD_SERVICES = frozenset({
    "directory", "ldap", "sso", "radius", "mdm", "systems",
    "password_manager", "saml", "jumpcloud_protect",
})

_FAIL_TYPES = frozenset({
    "admin_login_attempt_failed", "login_attempt_failed",
    "password_recovery_attempt", "mfa_failed",
    "user_locked_out", "sso_auth_failure", "radius_auth_failure",
    "ldap_bind_failed", "system_auth_failure",
})

_HIGH_ADMIN_TYPES = frozenset({
    "admin_created", "admin_deleted", "admin_password_reset",
    "user_deleted", "user_suspended", "mfa_exclusion_added",
    "policy_created", "policy_updated", "policy_deleted",
    "system_deleted", "application_deleted",
})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _event_status(event_type: str, success: Any) -> int:
    et = event_type.lower()
    if et in _FAIL_TYPES or success is False:
        return 403
    if et in _HIGH_ADMIN_TYPES:
        return 403
    if "admin" in et or "policy" in et:
        return 401
    return 200


def _event_to_log(obj: dict[str, Any]) -> LogEvent | None:
    try:
        service = obj.get("service", "")
        event_type = obj.get("event_type") or obj.get("type") or ""
        initiated_by = obj.get("initiated_by", {})
        success = obj.get("success")

        # actor identity
        username = None
        if isinstance(initiated_by, dict):
            username = (
                initiated_by.get("email")
                or initiated_by.get("username")
                or initiated_by.get("id")
            )

        # geoip
        geoip = obj.get("geoip", {})
        ip = obj.get("connection", {}).get("ip") if isinstance(obj.get("connection"), dict) else None
        if not ip and isinstance(geoip, dict):
            ip = geoip.get("ip")

        return LogEvent(
            source_format=LogFormat.JUMPCLOUD,
            timestamp=_parse_ts(obj.get("timestamp")),
            ip_address=ip,
            path=f"/{service}/{event_type}",
            http_method="POST",
            status_code=_event_status(event_type, success),
            user_principal_name=username,
            resource_display_name=service or "jumpcloud",
            raw_line=json.dumps(obj),
        )
    except Exception as exc:
        logger.debug("JumpCloud: skipping event: %s", exc)
        return None


def _is_jumpcloud(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and ("service" in obj or "event_type" in obj)
        and ("initiated_by" in obj or "geoip" in obj)
        and "timestamp" in obj
        and (
            obj.get("service") in _JUMPCLOUD_SERVICES
            or "jumpcloud" in str(obj.get("service", "")).lower()
        )
    )


class JumpCloudParser(BaseParser):
    format_name = "jumpcloud"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "jumpcloud" in filename.lower():
            return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, list) and data:
                return _is_jumpcloud(data[0])
            if isinstance(data, dict):
                items = data.get("events") or data.get("results")
                if isinstance(items, list) and items:
                    return _is_jumpcloud(items[0])
                return _is_jumpcloud(data)
        except json.JSONDecodeError:
            pass
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_jumpcloud(json.loads(line))
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
                items = data.get("events") or data.get("results") or ([data] if _is_jumpcloud(data) else [])
            for obj in items:
                if ev := _event_to_log(obj):
                    events.append(ev)
        except json.JSONDecodeError:
            for line in stripped.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                    if ev := _event_to_log(obj):
                        events.append(ev)
                except json.JSONDecodeError:
                    continue

        logger.info("JumpCloud parser: %d events", len(events))
        return events
