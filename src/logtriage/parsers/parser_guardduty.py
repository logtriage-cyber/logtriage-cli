# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS GuardDuty findings parser.

Accepts two shapes:
  - S3 export:  {"findings": [...]}
  - EventBridge / NDJSON: one finding JSON object per line

Each finding has a type (e.g. "Recon:EC2/PortProbeUnprotectedPort"),
severity (1.0-10.0), and a nested service.action block that contains the
remote IP address for network-based findings.

Severity mapping (GuardDuty scale → HTTP status analogue):
  7.0-10.0 HIGH    → 403
  4.0-6.9  MEDIUM  → 401
  1.0-3.9  LOW     → 400

Reference: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _severity_to_status(severity: float) -> int:
    if severity >= 7.0:
        return 403
    if severity >= 4.0:
        return 401
    return 400


def _extract_remote_ip(service: dict[str, Any]) -> str | None:
    """Walk the action sub-tree to find the remote IP for network-based findings."""
    action = service.get("action", {})
    for action_key in ("portProbeAction", "networkConnectionAction"):
        sub = action.get(action_key, {})
        # portProbeAction has portProbeDetails[]; networkConnectionAction has remoteIpDetails
        details_list = sub.get("portProbeDetails")
        if isinstance(details_list, list) and details_list:
            ip = details_list[0].get("remoteIpDetails", {}).get("ipAddressV4")
            if ip:
                return ip
        remote = sub.get("remoteIpDetails", {})
        if "ipAddressV4" in remote:
            return remote["ipAddressV4"]
    # awsApiCallAction — the caller rather than a remote probe
    api_action = action.get("awsApiCallAction", {})
    return api_action.get("remoteIpDetails", {}).get("ipAddressV4")


def _finding_to_log(finding: dict[str, Any]) -> LogEvent | None:
    try:
        severity = float(finding.get("severity", 5.0))
        service: dict[str, Any] = finding.get("service", {})
        account_id = finding.get("accountId")
        finding_type = finding.get("type", "")
        title = finding.get("title") or finding_type

        return LogEvent(
            source_format=LogFormat.GUARDDUTY,
            timestamp=_parse_ts(finding.get("updatedAt") or finding.get("createdAt")),
            ip_address=_extract_remote_ip(service),
            path=title,
            resource_display_name=finding_type,
            # accountId is the closest thing to a user identity in GuardDuty
            user_principal_name=account_id,
            status_code=_severity_to_status(severity),
            raw_line=json.dumps(finding),
        )
    except Exception as exc:
        logger.debug("GuardDuty: skipping finding %s: %s", finding.get("id", "?"), exc)
        return None


def parse_guardduty(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    stripped = raw_text.strip()

    # S3 bulk export: {"findings": [...]}
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            findings = data.get("findings") if isinstance(data, dict) else None
            if isinstance(findings, list):
                for f in findings:
                    if e := _finding_to_log(f):
                        events.append(e)
                logger.info("GuardDuty parser: %d findings from bulk export", len(events))
                return events
        except json.JSONDecodeError:
            pass

        # Single finding object
        try:
            data = json.loads(stripped)
            if isinstance(data, dict) and "type" in data and "severity" in data:
                if e := _finding_to_log(data):
                    events.append(e)
                logger.info("GuardDuty parser: 1 finding (single object)")
                return events
        except json.JSONDecodeError:
            pass

    # NDJSON — one finding per line
    for line in stripped.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if e := _finding_to_log(obj):
                events.append(e)
        except json.JSONDecodeError:
            continue

    logger.info("GuardDuty parser: %d findings from NDJSON", len(events))
    return events


def _is_guardduty(obj: dict[str, Any]) -> bool:
    """Return True if obj looks like a GuardDuty finding."""
    return (
        isinstance(obj, dict)
        and "severity" in obj
        and "type" in obj
        and ("accountId" in obj or "service" in obj)
        and "arn" in obj
    )


class GuardDutyParser(BaseParser):
    """Plugin-registry entry for AWS GuardDuty findings."""

    format_name = "guardduty"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "guardduty" in filename.lower():
            return True
        stripped = content.strip()
        # Bulk export shape
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    findings = data.get("findings")
                    if isinstance(findings, list) and findings:
                        return _is_guardduty(findings[0])
                    return _is_guardduty(data)
            except json.JSONDecodeError:
                pass
        # NDJSON
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_guardduty(json.loads(line))
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_guardduty(content)
