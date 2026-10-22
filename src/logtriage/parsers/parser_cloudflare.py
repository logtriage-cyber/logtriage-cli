# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Cloudflare Logs parser.

Accepts Cloudflare Logpush output (WAF events, HTTP request logs, Access logs).
Input: NDJSON (one event per line) or JSON array.

Supported datasets:
  - firewall_events_adaptive  (WAF + rate-limit blocks) — Action + RuleID present
  - http_requests             (all requests) — EdgeResponseStatus present
  - access_requests           (Cloudflare Access / Zero Trust) — AppDomain present

Reference: https://developers.cloudflare.com/logs/reference/

Key fields mapped:
  datetime / Datetime       → timestamp
  ClientIP                  → ip_address
  ClientASN                 → asn (hint for enrichment)
  ClientRequestUserAgent    → user_agent
  ClientRequestMethod       → http_method
  ClientRequestPath         → path
  EdgeResponseStatus        → status_code  (or 403 if Action=block)
  Action                    → if "block"/"drop" → status_code=403, failure_reason
  RuleMessage               → resource_display_name (WAF rule that fired)
  ClientRequestQuery        → appended to path if present
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers import json_input
from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_BLOCK_ACTIONS = {"block", "drop", "jschallenge", "managed_challenge", "challenge"}


def _ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        # Cloudflare uses RFC3339: "2024-03-15T10:01:00Z" or Unix ns int
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(int(raw) / 1e9, tz=timezone.utc)
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, AttributeError, OSError):
        return datetime.now(timezone.utc)


def _parse_event(raw: dict[str, Any]) -> LogEvent | None:
    try:
        action: str | None = (raw.get("Action") or raw.get("action") or "").lower()
        edge_status: int | None = raw.get("EdgeResponseStatus") or raw.get("EdgeResponseCode")
        rule_msg: str | None = raw.get("RuleMessage") or raw.get("Source")
        rule_id: str | None = raw.get("RuleID") or raw.get("RuleId")

        is_blocked = action in _BLOCK_ACTIONS
        status_code = 403 if is_blocked else (int(edge_status) if edge_status else None)
        failure_reason: str | None = None
        if is_blocked:
            failure_reason = f"Cloudflare {action.capitalize()}"
            if rule_id:
                failure_reason += f" (rule {rule_id})"

        path = raw.get("ClientRequestPath") or raw.get("ClientRequestURI") or "/"
        query = raw.get("ClientRequestQuery") or ""
        if query and not query.startswith("?"):
            query = f"?{query}"
        if query:
            path = f"{path}{query}"

        ip = raw.get("ClientIP") or raw.get("ClientIPClass")
        asn_raw = raw.get("ClientASN")
        asn = f"AS{asn_raw}" if asn_raw else None
        ua = raw.get("ClientRequestUserAgent") or raw.get("UserAgent")
        method = raw.get("ClientRequestMethod") or "GET"
        upn = raw.get("Email") or raw.get("UserEmail")  # Cloudflare Access
        resource = rule_msg or raw.get("AppDomain") or "Cloudflare"

        ts_raw = raw.get("datetime") or raw.get("Datetime") or raw.get("EdgeStartTimestamp")

        return LogEvent(
            source_format=LogFormat.CLOUDFLARE,
            timestamp=_ts(ts_raw),
            ip_address=ip,
            asn=asn,
            user_agent=ua,
            http_method=method.upper(),
            path=path,
            status_code=status_code,
            user_principal_name=upn,
            resource_display_name=resource,
            failure_reason=failure_reason,
        )
    except Exception as exc:
        logger.debug("Skipping malformed Cloudflare event: %s", exc)
        return None


def _is_cloudflare(record: dict[str, Any]) -> bool:
    if "ClientIP" not in record:
        return False
    return (
        "EdgeResponseStatus" in record
        or ("ClientRequestMethod" in record and "ClientASN" in record)
        or ("Action" in record and "RuleID" in record)
    )


def parse_cloudflare(content: str) -> list[LogEvent]:
    """Parse Cloudflare Logpush NDJSON (or a JSON array / document) into LogEvents."""
    records = json_input.records(content, ("result",))
    result = [e for e in (_parse_event(r) for r in records) if e is not None]
    logger.info("Cloudflare parser: %d/%d events parsed", len(result), len(records))
    return result


class CloudflareParser(BaseParser):
    format_name = "cloudflare"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = json_input.sample(content, ("result",))
        return bool(head) and sum(_is_cloudflare(r) for r in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_cloudflare(content)
