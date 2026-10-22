# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
GitHub Audit Log parser (Organization / Enterprise audit stream).

Accepts:
  - JSON array: [{...}, ...]
  - NDJSON: one event per line

Key discriminator fields: action (e.g. "repo.create"), actor, created_at,
and at least one of: org, repo, business, user (GitHub-specific context).

Actions of interest: repo.destroy, team.add_member, org.invite_member,
protected_branch.*, secret_scanning.*, dependabot.*, audit_log_streaming.*

Reference:
  https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise
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

_HIGH_RISK_ACTIONS = frozenset({
    "repo.destroy", "org.remove_member", "team.remove_member",
    "protected_branch.policy_override", "org.invite_member",
    "org.add_member", "business.add_admin", "hook.create",
    "hook.destroy", "integration.create", "oauth_application.create",
    "personal_access_token.create", "secret_scanning_alert.create",
    "dependabot_alerts.disable", "audit_log_streaming.destroy",
    "two_factor_authentication.disabled",
})

_MED_RISK_ACTIONS_PREFIXES = ("repo.", "org.", "team.", "hook.", "integration.")


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, (int, float)):
        # GitHub uses ms epoch in @timestamp field
        ts_sec = raw / 1000 if raw > 1e10 else raw
        return datetime.fromtimestamp(ts_sec, tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _action_status(action: str) -> int:
    if action in _HIGH_RISK_ACTIONS:
        return 403
    if any(action.startswith(p) for p in _MED_RISK_ACTIONS_PREFIXES):
        return 401
    return 200


def _event_to_log(obj: dict[str, Any]) -> LogEvent | None:
    try:
        action = obj.get("action", "")
        actor = obj.get("actor") or obj.get("actor_id")
        ip = obj.get("actor_ip") or obj.get("_document_id")  # actor_ip for enterprise
        ip = obj.get("actor_ip")
        repo = obj.get("repo") or obj.get("repository")
        org = obj.get("org") or obj.get("organization")
        ts_raw = obj.get("created_at") or obj.get("@timestamp") or obj.get("timestamp")

        return LogEvent(
            source_format=LogFormat.GITHUB_AUDIT,
            timestamp=_parse_ts(ts_raw),
            ip_address=ip,
            path=f"/{action.replace('.', '/')}",
            http_method="POST",
            status_code=_action_status(action),
            user_principal_name=str(actor) if actor else None,
            resource_display_name=repo or org or "github",
            raw_line=json.dumps(obj),
        )
    except Exception as exc:
        logger.debug("GitHub audit: skipping event: %s", exc)
        return None


def _is_github_event(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "action" in obj
        and ("actor" in obj or "actor_id" in obj)
        and ("org" in obj or "repo" in obj or "business" in obj
             or "created_at" in obj or "@timestamp" in obj)
    )


class GitHubAuditParser(BaseParser):
    format_name = "github_audit"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content)
        return bool(head) and sum(_is_github_event(r) for r in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events = [ev for obj in json_input.records(content) if (ev := _event_to_log(obj))]
        logger.info("GitHub audit parser: %d events", len(events))
        return events
