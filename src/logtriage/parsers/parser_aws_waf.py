# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS WAF v2 log parser.

WAF writes one JSON object per line (NDJSON). Each object contains:
  timestamp   — Unix epoch milliseconds
  action      — ALLOW | BLOCK | COUNT | CAPTCHA
  httpRequest — {clientIp, country, headers[], uri, httpMethod, ...}
  terminatingRuleId — the rule that made the final decision

Reference: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_BLOCK_ACTIONS = {"BLOCK", "CAPTCHA"}


def _parse_ts(raw: Any) -> datetime:
    if raw is None:
        return datetime.now(timezone.utc)
    try:
        # WAF timestamp is Unix epoch milliseconds
        return datetime.fromtimestamp(int(raw) / 1000, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return datetime.now(timezone.utc)


def _header_value(headers: list[dict[str, str]], name: str) -> str | None:
    name_lower = name.lower()
    for h in headers:
        if h.get("name", "").lower() == name_lower:
            return h.get("value")
    return None


def _record_to_log(rec: dict[str, Any]) -> LogEvent | None:
    try:
        action: str = rec.get("action", "ALLOW").upper()
        http_req: dict[str, Any] = rec.get("httpRequest", {})
        headers: list[dict[str, str]] = http_req.get("headers", [])
        rule_id = rec.get("terminatingRuleId") or rec.get("terminatingRuleType")

        return LogEvent(
            source_format=LogFormat.AWS_WAF,
            timestamp=_parse_ts(rec.get("timestamp")),
            ip_address=http_req.get("clientIp"),
            user_agent=_header_value(headers, "user-agent"),
            path=http_req.get("uri"),
            http_method=http_req.get("httpMethod"),
            resource_display_name=rule_id,
            # BLOCK/CAPTCHA → 403; COUNT/ALLOW → 200
            status_code=403 if action in _BLOCK_ACTIONS else 200,
            raw_line=json.dumps(rec),
        )
    except Exception as exc:
        logger.debug("AWS WAF: skipping record: %s", exc)
        return None


def parse_aws_waf(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if e := _record_to_log(obj):
                events.append(e)
        except json.JSONDecodeError:
            continue
    logger.info("AWS WAF parser: %d records parsed", len(events))
    return events


def _is_waf(obj: dict[str, Any]) -> bool:
    return isinstance(obj, dict) and "httpRequest" in obj and (
        "terminatingRuleId" in obj or "action" in obj
    ) and "clientIp" in obj.get("httpRequest", {})


class AwsWafParser(BaseParser):
    """Plugin-registry entry for AWS WAF v2 NDJSON logs."""

    format_name = "aws_waf"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and ("waf" in filename.lower() or "aws-waf" in filename.lower()):
            return True
        for line in content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_waf(json.loads(line))
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_aws_waf(content)
