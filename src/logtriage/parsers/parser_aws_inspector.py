# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
AWS Inspector v2 findings parser.

Accepts:
  - {"findings": [...]} — ListFindings API response / console export
  - EventBridge events ({"source": "aws.inspector2", "detail": {finding}})
  - a JSON array or NDJSON of findings

Key discriminator: an Inspector v2 finding ARN (arn:aws:inspector2:…) or an
inspectorScore, plus package / code / network-reachability details or a type.
Code-vulnerability findings, and many EventBridge examples, carry no
inspectorScore — their severity comes from the `severity` field.

Inspector severity: CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0, LOW < 4.0

Reference:
  https://docs.aws.amazon.com/inspector/latest/user/findings-understanding.html
  https://docs.aws.amazon.com/inspector/latest/user/eventbridge-integration.html
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

# EventBridge events write timestamps the way Java's Date.toString() does:
# "Wed Sep 04 16:50:37.627 UTC 2024"
_JAVA_DATE_FORMATS = ("%a %b %d %H:%M:%S.%f %Z %Y", "%a %b %d %H:%M:%S %Z %Y")

# Severity label → a representative inspectorScore, for findings without one
_SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFORMATIONAL": 0.0, "UNTRIAGED": 0.0}

_DETAIL_KEYS = ("packageVulnerabilityDetails", "codeVulnerabilityDetails", "networkReachabilityDetails", "type")


def _parse_ts(raw: Any) -> datetime:
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw / 1000 if raw > 1e11 else raw, tz=timezone.utc)
    if not raw or not isinstance(raw, str):
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in _JAVA_DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _score_to_status(score: float) -> int:
    if score >= 7.0:
        return 403
    if score >= 4.0:
        return 401
    return 400


def _score(finding: dict[str, Any]) -> float:
    raw = finding.get("inspectorScore")
    if isinstance(raw, (int, float)):
        return float(raw)
    return _SEVERITY_SCORE.get(str(finding.get("severity") or "").upper(), 5.0)


def _finding_to_log(finding: dict[str, Any]) -> LogEvent | None:
    try:
        score = _score(finding)
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

        # CVE for package findings; the detector (and its CWEs) for code findings
        pkg = finding.get("packageVulnerabilityDetails") or {}
        code = finding.get("codeVulnerabilityDetails") or {}
        cve_id = pkg.get("vulnerabilityId")
        if cve_id:
            path = f"/cve/{cve_id}"
        elif code.get("detectorId") or code.get("detectorName"):
            path = f"/code/{code.get('detectorId') or code.get('detectorName')}"
        else:
            path = f"/{finding_type}"

        return LogEvent(
            source_format=LogFormat.AWS_INSPECTOR,
            timestamp=_parse_ts(finding.get("updatedAt") or finding.get("lastObservedAt") or finding.get("firstObservedAt")),
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
        and ("inspectorScore" in obj or ":inspector2:" in str(obj.get("findingArn", "")))
        and ("awsAccountId" in obj or "resources" in obj)
        and any(k in obj for k in _DETAIL_KEYS)
    )


def _findings(content: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for record in json_input.records(content, ("findings",)):
        detail = record.get("detail")
        if record.get("source") == "aws.inspector2" and isinstance(detail, dict):
            record = detail
        out.append(record)
    return out


class AwsInspectorParser(BaseParser):
    format_name = "aws_inspector"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        head = _findings(content)[:5]
        return bool(head) and sum(_is_inspector(f) for f in head) * 2 > len(head)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events = [ev for f in _findings(content) if (ev := _finding_to_log(f))]
        logger.info("Inspector parser: %d findings", len(events))
        return events
