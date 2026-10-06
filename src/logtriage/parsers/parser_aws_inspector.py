# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS Inspector v2 findings parser.

Accepts:
  - {"findings": [...]} — API list response
  - NDJSON — one finding per line

Key discriminator: findings contain inspectorScore (float 0.0-10.0) plus
packageVulnerabilityDetails or networkReachabilityDetails.

Inspector severity: CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0, LOW < 4.0

Reference:
  https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html
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


def _score_to_status(score: float) -> int:
    if score >= 7.0:
        return 403
    if score >= 4.0:
        return 401
    return 400


def _finding_to_log(finding: dict[str, Any]) -> LogEvent | None:
    try:
        score = float(finding.get("inspectorScore", 5.0))
        account_id = finding.get("awsAccountId")
        description = finding.get("description", "")
        finding_type = finding.get("type", "")
        title = finding.get("title") or description[:120]

        # Extract resource identifiers
        resources = finding.get("resources", [])
        resource_id = None
        ip_address = None
        if resources:
            r = resources[0]
            resource_id = r.get("id") or r.get("name")
            details = r.get("details", {})
            inst = details.get("awsEc2Instance", {})
            ip_address = inst.get("ipV4Addresses", [None])[0] or inst.get("ipV6Addresses", [None])[0]

        # CVE / CVSS info
        pkg = finding.get("packageVulnerabilityDetails", {})
        cve_id = pkg.get("vulnerabilityId")
        path = f"/cve/{cve_id}" if cve_id else f"/{finding_type}"

        return LogEvent(
            source_format=LogFormat.AWS_INSPECTOR,
            timestamp=_parse_ts(finding.get("updatedAt") or finding.get("firstObservedAt")),
            ip_address=ip_address,
            path=path,
            status_code=_score_to_status(score),
            user_principal_name=account_id,
            resource_display_name=resource_id,
            failure_reason=title,
            raw_line=json.dumps(finding),
        )
    except Exception as exc:
        logger.debug("Inspector: skipping finding: %s", exc)
        return None


def _is_inspector(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "inspectorScore" in obj
        and ("awsAccountId" in obj or "resources" in obj)
        and (
            "packageVulnerabilityDetails" in obj
            or "networkReachabilityDetails" in obj
            or "type" in obj
        )
    )


class AwsInspectorParser(BaseParser):
    format_name = "aws_inspector"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "inspector" in filename.lower():
            return True
        stripped = content.strip()
        if not stripped.startswith("{") and not stripped.startswith("["):
            return False
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                findings = data.get("findings")
                if isinstance(findings, list) and findings:
                    return _is_inspector(findings[0])
                return _is_inspector(data)
        except json.JSONDecodeError:
            pass
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                return False
            try:
                return _is_inspector(json.loads(line))
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        stripped = content.strip()

        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                findings = data.get("findings")
                if isinstance(findings, list):
                    for f in findings:
                        if ev := _finding_to_log(f):
                            events.append(ev)
                    logger.info("Inspector parser: %d findings", len(events))
                    return events
                if _is_inspector(data):
                    if ev := _finding_to_log(data):
                        events.append(ev)
                    return events
        except json.JSONDecodeError:
            pass

        for line in stripped.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if ev := _finding_to_log(obj):
                    events.append(ev)
            except json.JSONDecodeError:
                continue

        logger.info("Inspector parser: %d findings (NDJSON)", len(events))
        return events
