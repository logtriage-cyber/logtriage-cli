# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS Security Hub — ASFF (Amazon Security Finding Format) parser.

Accepts:
  - {"Findings": [...]} — bulk export / API response
  - NDJSON — one finding per line

Each finding has SchemaVersion, ProductArn, GeneratorId, Severity.Label/Normalized,
Types, Resources, Title, Description, Remediation, etc.

Severity mapping (ASFF Normalized 0-100 → HTTP status):
  ≥ 70 CRITICAL/HIGH → 403
  ≥ 40 MEDIUM        → 401
  < 40 LOW/INFO      → 400

Reference:
  https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
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

_HIGH_LABELS = frozenset({"CRITICAL", "HIGH"})


def _parse_ts(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _severity_to_status(severity: dict[str, Any]) -> int:
    label = severity.get("Label", "").upper()
    if label in _HIGH_LABELS:
        return 403
    normalized = severity.get("Normalized", 0)
    if isinstance(normalized, (int, float)):
        if normalized >= 70:
            return 403
        if normalized >= 40:
            return 401
    if label == "MEDIUM":
        return 401
    return 400


def _extract_ip(resources: list[dict[str, Any]]) -> str | None:
    for res in resources:
        details = res.get("Details", {})
        for key in ("AwsEc2Instance", "AwsEksCluster", "AwsEcsTask"):
            inst = details.get(key, {})
            ips = inst.get("IpV4Addresses") or inst.get("NetworkInterfaces", [{}])
            if isinstance(ips, list) and ips:
                first = ips[0]
                if isinstance(first, str):
                    return first
                if isinstance(first, dict):
                    ip = first.get("PublicIpAddress") or first.get("PrivateIpAddress")
                    if ip:
                        return ip
    return None


def _finding_to_log(finding: dict[str, Any]) -> LogEvent | None:
    try:
        resources: list[dict[str, Any]] = finding.get("Resources", [])
        severity: dict[str, Any] = finding.get("Severity", {})
        account_id = finding.get("AwsAccountId")
        title = finding.get("Title") or finding.get("GeneratorId", "")
        product_arn = finding.get("ProductArn", "")
        # Best effort: extract resource ARN as path
        path = None
        if resources:
            path = resources[0].get("Id") or resources[0].get("Type")

        return LogEvent(
            source_format=LogFormat.AWS_SECURITYHUB,
            timestamp=_parse_ts(finding.get("UpdatedAt") or finding.get("CreatedAt")),
            ip_address=_extract_ip(resources),
            path=path,
            status_code=_severity_to_status(severity),
            user_principal_name=account_id,
            resource_display_name=product_arn.split(":")[-1] if product_arn else None,
            failure_reason=title,
            raw_line=json.dumps(finding),
        )
    except Exception as exc:
        logger.debug("SecurityHub: skipping finding: %s", exc)
        return None


def _is_asff(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and "SchemaVersion" in obj
        and ("ProductArn" in obj or "GeneratorId" in obj)
        and "AwsAccountId" in obj
    )


def _findings(content: str) -> list[dict[str, Any]]:
    """ASFF findings from `get-findings` ({"Findings": [...]}), NDJSON, and EventBridge
    events ({"source": "aws.securityhub", "detail": {"findings": [...]}})."""
    out: list[dict[str, Any]] = []
    for record in json_input.records(content, ("Findings", "findings")):
        detail = record.get("detail")
        if isinstance(detail, dict) and isinstance(detail.get("findings"), list):
            out.extend(f for f in detail["findings"] if isinstance(f, dict))
        else:
            out.append(record)
    return out


class AwsSecurityHubParser(BaseParser):
    format_name = "aws_securityhub"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = _findings(content)[:5]
        return bool(head) and sum(_is_asff(f) for f in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events = [ev for f in _findings(content) if (ev := _finding_to_log(f))]
        logger.info("SecurityHub parser: %d findings", len(events))
        return events
