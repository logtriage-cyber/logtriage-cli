# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Wazuh HIDS alert log parser.

Wazuh writes alerts as JSON objects — one per line (NDJSON) or wrapped in a
top-level {"alerts": [...]} envelope. Each alert contains:
  rule.level       — 0-15 severity (≥12 = critical, ≥7 = high, ≥3 = medium)
  rule.description — human-readable rule name
  rule.groups[]    — tags (authentication_failures, web, etc.)
  rule.mitre       — embedded MITRE ATT&CK IDs when available
  agent.name / agent.ip — the monitored host
  data.srcip       — attacker source IP (when extracted by Wazuh decoders)
  full_log         — raw syslog/event line that triggered the rule

Reference: https://documentation.wazuh.com/current/user-manual/api/reference.html
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

# rule.level → HTTP status analogue
# 0-2=info, 3-6=low, 7-11=medium, 12-15=critical
def _level_to_status(level: int) -> int:
    if level >= 12:
        return 403
    if level >= 7:
        return 401
    if level >= 3:
        return 400
    return 200


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00").replace("+0000", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _alert_to_log(alert: dict[str, Any]) -> LogEvent | None:
    try:
        rule: dict[str, Any] = alert.get("rule", {})
        agent: dict[str, Any] = alert.get("agent", {})
        data: dict[str, Any] = alert.get("data", {})

        level = int(rule.get("level", 0))

        # Source IP: prefer decoded data.srcip, fall back to agent IP
        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("win", {}).get("system", {}).get("computer")  # not an IP, skip via or
            or agent.get("ip")
        )
        # Validate it looks like an IP (basic check)
        if src_ip and not _looks_like_ip(src_ip):
            src_ip = agent.get("ip")

        return LogEvent(
            source_format=LogFormat.WAZUH,
            timestamp=_parse_ts(alert.get("timestamp")),
            ip_address=src_ip,
            path=rule.get("description"),
            resource_display_name=agent.get("name"),
            user_principal_name=data.get("srcuser") or data.get("dstuser"),
            status_code=_level_to_status(level),
            raw_line=alert.get("full_log") or json.dumps(alert),
        )
    except Exception as exc:
        logger.debug("Wazuh: skipping alert id=%s: %s", alert.get("id", "?"), exc)
        return None


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# Wazuh API responses: {"data": {"affected_items": [...]}}; archives: {"alerts": [...]}
_ENVELOPES = ("alerts", "data.affected_items")


def parse_wazuh(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for obj in json_input.records(raw_text, _ENVELOPES):
        if e := _alert_to_log(obj):
            events.append(e)
    logger.info("Wazuh parser: %d alerts", len(events))
    return events


def _is_wazuh(obj: dict[str, Any]) -> bool:
    return (
        isinstance(obj, dict)
        and "rule" in obj
        and isinstance(obj["rule"], dict)
        and "level" in obj["rule"]
        and "agent" in obj
    )


class WazuhParser(BaseParser):
    """Plugin-registry entry for Wazuh HIDS alert logs."""

    format_name = "wazuh"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content, _ENVELOPES, n=1)
        return bool(head) and _is_wazuh(head[0])

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_wazuh(content)
