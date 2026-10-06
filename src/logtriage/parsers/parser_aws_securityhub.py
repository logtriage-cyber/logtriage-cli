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


class AwsSecurityHubParser(BaseParser):
    format_name = "aws_securityhub"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "securityhub" in filename.lower().replace("-", "").replace("_", ""):
            return True
        stripped = content.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    findings = data.get("Findings") or data.get("findings")
                    if isinstance(findings, list) and findings:
                        return _is_asff(findings[0])
                    return _is_asff(data)
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
                return _is_asff(json.loads(line))
            except json.JSONDecodeError:
                return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        stripped = content.strip()

        def _from_list(findings: list[Any]) -> None:
            for f in findings:
                if ev := _finding_to_log(f):
                    events.append(ev)

        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                findings = data.get("Findings") or data.get("findings") if isinstance(data, dict) else None
                if isinstance(findings, list):
                    _from_list(findings)
                    logger.info("SecurityHub parser: %d findings", len(events))
                    return events
                if _is_asff(data):
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

        logger.info("SecurityHub parser: %d findings (NDJSON)", len(events))
        return events
