# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Elastic Common Schema (ECS) log parser.

ECS is used by Filebeat, Auditbeat, Winlogbeat, Elastic SIEM, and many
third-party integrations. The discriminating field is `@timestamp` combined
with nested ECS namespace objects (`event`, `source`, `destination`, `user`,
`host`, `agent`, `network`).

Supports NDJSON and JSON array formats.

Reference:
  https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_BLOCK_OUTCOMES = frozenset({"failure", "denied", "blocked"})
_BLOCK_ACTIONS = frozenset({
    "denied", "blocked", "dropped", "reject", "authentication_failure",
    "login_failed", "connection_denied",
})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        raw = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)


def _nested(obj: dict, *keys: str) -> str | None:
    """Walk a dotted path through nested dicts."""
    cur: object = obj
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return str(cur) if cur is not None else None


def _obj_to_log(obj: dict) -> LogEvent | None:
    ts = _parse_ts(obj.get("@timestamp"))

    # ECS source/destination
    src_ip = _nested(obj, "source", "ip") or _nested(obj, "client", "ip")
    # Prefer source over destination for attacker attribution
    ip = src_ip or _nested(obj, "destination", "ip")

    user = (
        _nested(obj, "user", "name")
        or _nested(obj, "user", "email")
        or _nested(obj, "source", "user", "name")
    )

    ua = _nested(obj, "user_agent", "original")
    hostname = _nested(obj, "host", "name") or _nested(obj, "host", "hostname")

    # Event fields
    event = obj.get("event") or {}
    action = event.get("action") or ""
    outcome = (event.get("outcome") or "").lower()
    category = event.get("category") or []
    if isinstance(category, str):
        category = [category]

    # URL / path
    path = (
        _nested(obj, "url", "full")
        or _nested(obj, "url", "path")
        or _nested(obj, "http", "request", "body", "content")
        or _nested(obj, "dns", "question", "name")
        or _nested(obj, "file", "path")
        or action
        or None
    )

    method = (
        _nested(obj, "http", "request", "method")
        or (action.upper() if action else None)
        or None
    )

    status: int
    http_status = _nested(obj, "http", "response", "status_code")
    if http_status and http_status.isdigit():
        status = int(http_status)
    elif outcome in _BLOCK_OUTCOMES or action.lower() in _BLOCK_ACTIONS:
        status = 403
    elif "authentication" in category and outcome == "failure":
        status = 401
    else:
        status = 200

    # File hash
    sha256 = _nested(obj, "file", "hash", "sha256") or _nested(obj, "process", "hash", "sha256")
    file_hash = sha256 if sha256 and len(sha256) == 64 else None

    agent_type = _nested(obj, "agent", "type")
    resource = (hostname or "") + (f"/{agent_type}" if agent_type else "") or "ECS"

    return LogEvent(
        source_format=LogFormat.ECS,
        timestamp=ts,
        ip_address=ip or None,
        user_principal_name=user or None,
        user_agent=ua or None,
        http_method=method,
        path=path,
        status_code=status,
        resource_display_name=resource or "ECS",
        file_hash=file_hash,
    )


def parse_ecs(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict) and item.get("@timestamp"):
                        e = _obj_to_log(item)
                        if e:
                            events.append(e)
            elif isinstance(obj, dict) and obj.get("@timestamp"):
                e = _obj_to_log(obj)
                if e:
                    events.append(e)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("ECS: skipping line: %s", exc)
    logger.info("ECS parser: %d events", len(events))
    return events


def _is_ecs(obj: dict) -> bool:
    if not obj.get("@timestamp"):
        return False
    # Must have at least one ECS namespace object
    ecs_namespaces = ("event", "source", "destination", "host", "user", "network", "file", "process", "dns")
    return any(isinstance(obj.get(ns), dict) for ns in ecs_namespaces)


class EcsParser(BaseParser):
    format_name = "ecs"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and any(s in filename.lower() for s in ("ecs_", "filebeat", "auditbeat", "winlogbeat", "elastic")):
            pass
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and _is_ecs(obj):
                    return True
                if isinstance(obj, list) and obj and isinstance(obj[0], dict) and _is_ecs(obj[0]):
                    return True
            except (json.JSONDecodeError, Exception):
                pass
            return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_ecs(content)
