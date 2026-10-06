# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Okta System Log parser.

Input: JSON array of Okta System Log events (from /api/v1/logs REST endpoint
or bulk export). Accepts both bare arrays and {"logs": [...]} wrapper.

Reference: https://developer.okta.com/docs/reference/api/system-log/

Key fields mapped:
  published            → timestamp
  actor.alternateId    → user_principal_name
  client.ipAddress     → ip_address
  client.userAgent.rawUserAgent → user_agent
  eventType            → path  (e.g. /okta/user/session/start)
  outcome.result       → status_code (SUCCESS→200, FAILURE→401, DENIED→403)
  outcome.reason       → failure_reason
  displayMessage       → resource_display_name
  client.geographicalContext → location
  securityContext.asNumber   → asn hint
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LocationDetail, LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Okta outcome.result → HTTP status code
_OUTCOME_STATUS: dict[str, int] = {
    "SUCCESS": 200,
    "FAILURE": 401,
    "SKIPPED": 200,
    "ALLOW": 200,
    "DENY": 403,
    "DENIED": 403,
    "CHALLENGE": 401,
    "UNKNOWN": 0,
}

# eventType prefix → normalised path segment
_EVENTTYPE_PATH: dict[str, str] = {
    "user.session.start": "/okta/user/session/start",
    "user.session.end": "/okta/user/session/end",
    "user.authentication.sso": "/okta/user/auth/sso",
    "user.authentication.auth_via_mfa": "/okta/user/auth/mfa",
    "user.authentication.authn_via_mfa": "/okta/user/auth/mfa",
    "user.mfa.factor.activate": "/okta/user/mfa/activate",
    "user.mfa.factor.deactivate": "/okta/user/mfa/deactivate",
    "user.mfa.factor.reset_all": "/okta/user/mfa/reset",
    "user.account.lock": "/okta/user/account/lock",
    "user.account.reset_password": "/okta/user/account/reset_password",
    "user.account.update_password": "/okta/user/account/update_password",
    "user.lifecycle.create": "/okta/admin/user/create",
    "user.lifecycle.activate": "/okta/admin/user/activate",
    "user.lifecycle.deactivate": "/okta/admin/user/deactivate",
    "user.lifecycle.suspend": "/okta/admin/user/suspend",
    "policy.lifecycle.create": "/okta/admin/policy/create",
    "policy.lifecycle.update": "/okta/admin/policy/update",
    "policy.evaluate_sign_on": "/okta/policy/sign_on",
    "application.lifecycle.create": "/okta/admin/app/create",
    "application.user_membership.add": "/okta/admin/app/assign_user",
    "group.user_membership.add": "/okta/admin/group/add_member",
    "group.user_membership.remove": "/okta/admin/group/remove_member",
    "system.agent.start": "/okta/system/agent",
    "system.api_token.create": "/okta/admin/api_token/create",
    "system.api_token.revoke": "/okta/admin/api_token/revoke",
}


def _ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _eventtype_to_path(event_type: str | None) -> str:
    if not event_type:
        return "/okta/unknown"
    for prefix, path in _EVENTTYPE_PATH.items():
        if event_type.startswith(prefix):
            return path
    # Generic fallback: /okta/<dot-separated parts>
    return "/okta/" + event_type.replace(".", "/")


def _parse_location(geo: dict[str, Any] | None) -> LocationDetail | None:
    if not geo:
        return None
    return LocationDetail(
        city=geo.get("city"),
        state=geo.get("state"),
        country_or_region=geo.get("country"),
    )


def _parse_event(raw: dict[str, Any]) -> LogEvent | None:
    try:
        event_type: str | None = raw.get("eventType")
        actor: dict[str, Any] = raw.get("actor") or {}
        client: dict[str, Any] = raw.get("client") or {}
        outcome: dict[str, Any] = raw.get("outcome") or {}
        security_ctx: dict[str, Any] = raw.get("securityContext") or {}
        ua_obj: dict[str, Any] = client.get("userAgent") or {}
        geo: dict[str, Any] | None = client.get("geographicalContext")

        outcome_result: str = (outcome.get("result") or "UNKNOWN").upper()
        status_code = _OUTCOME_STATUS.get(outcome_result, 0)
        failure_reason = outcome.get("reason") if outcome_result not in ("SUCCESS", "ALLOW", "SKIPPED") else None

        upn = actor.get("alternateId") or actor.get("login")
        ip = client.get("ipAddress")
        ua = ua_obj.get("rawUserAgent")
        path = _eventtype_to_path(event_type)
        resource = raw.get("displayMessage") or event_type or "Okta System Log"

        return LogEvent(
            source_format=LogFormat.OKTA,
            timestamp=_ts(raw.get("published")),
            ip_address=ip,
            user_agent=ua,
            http_method="POST",
            path=path,
            status_code=status_code if status_code else None,
            user_principal_name=upn,
            resource_display_name=resource,
            failure_reason=failure_reason,
            location=_parse_location(geo),
            asn=str(security_ctx["asNumber"]) if security_ctx.get("asNumber") else None,
        )
    except Exception as exc:
        logger.debug("Skipping malformed Okta event: %s", exc)
        return None


def parse_okta(content: str) -> list[LogEvent]:
    """Parse Okta System Log JSON into LogEvents."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Okta parser: invalid JSON — {exc}") from exc

    if isinstance(data, dict):
        records = data.get("logs") or data.get("value") or data.get("events") or []
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Okta parser: expected JSON array or object")

    events: list[LogEvent] = []
    for rec in records:
        if isinstance(rec, dict):
            ev = _parse_event(rec)
            if ev:
                events.append(ev)

    logger.info("Okta parser: %d/%d events parsed", len(events), len(records))
    return events


class OktaParser(BaseParser):
    format_name = "okta"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if "okta" in filename.lower():
            stripped = content.strip()
            return stripped.startswith("[") or stripped.startswith("{")
        head = content.strip()[:3000]
        if not (head.startswith("[") or head.startswith("{")):
            return False
        return (
            '"eventType"' in head and '"actor"' in head and '"outcome"' in head
        ) or (
            '"displayMessage"' in head and '"published"' in head and '"securityContext"' in head
        )

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_okta(content)
