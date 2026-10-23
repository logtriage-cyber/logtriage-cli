# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Format registry — ordered list of parser classes.

Detection priority (most specific first):
  1.  CloudTrail      — JSON {"Records": [...]} with eventSource/eventName
  2.  LEEF            — lines starting with LEEF:1.0| or LEEF:2.0| (IBM QRadar)
  3.  CEF             — lines containing "CEF:" prefix (Palo Alto, Fortinet, etc.)
  4.  Azure           — JSON {"value": [...]} or array with Azure discriminator fields
  5.  AzureNSG        — JSON {"records": [...]} with NetworkSecurityGroupFlowEvent category
  6.  AzureActivity   — JSON {"value": [...]} with operationName + subscriptionId + caller
  7.  Okta            — JSON array with eventType + actor + outcome fields
  8.  K8sAudit        — JSON/NDJSON with objectRef + verb + sourceIPs (or apiVersion audit.k8s.io)
  9.  GcpAudit        — JSON/NDJSON with protoPayload.authenticationInfo + requestMetadata
  10. Cloudflare      — JSON/NDJSON with ClientIP + EdgeResponseStatus (or Action + RuleID)
  11. M365Audit       — JSON array with Workload + Operation + UserId
  12. GoogleWorkspace — JSON {"kind": "admin#reports#activities", "items": [...]}
  13. GitHubAudit     — JSON array / NDJSON with action + actor + (org|repo|business)
  14. SlackAudit      — JSON {"entries": [...]} with action + actor + entity + date_create
  15. Duo             — JSON array / NDJSON with result/factor + user + access_device (auth log)
  16. JumpCloud       — JSON array / NDJSON with service + event_type + initiated_by + geoip
  17. AwsSecurityHub  — JSON {"Findings": [...]} with SchemaVersion + ProductArn + AwsAccountId
  18. AwsInspector    — JSON {"findings": [...]} with inspectorScore + resources
  19. AwsConfig       — JSON {"configurationItems": [...]} or configurationItem with resourceType
  20. GuardDuty       — JSON {"findings": [...]} or NDJSON with severity + type + accountId + arn
  21. AwsWaf          — NDJSON with httpRequest.clientIp + terminatingRuleId/action
  22. Sysmon          — XML with Microsoft-Windows-Sysmon provider (before generic EVTX)
  23. EVTX            — XML with Windows event log namespace or EventID/EventData elements
  24. VpcFlow         — space-delimited with srcaddr/dstaddr/action header
  25. AwsAlb          — space-delimited ALB/ELB: type(http/https/h2) + ISO timestamp + elb name
  26. AwsS3Access     — space-delimited S3 access logs with [DD/Mon/YYYY:...] bracket + REST.* op
  27. Suricata        — NDJSON with event_type + src_ip (EVE JSON)
  28. Wazuh           — JSON/NDJSON with rule.level + agent fields
  29. CrowdStrike     — JSON/NDJSON with event_simpleName + cid/aid fields (FDR)
  30. SentinelOne     — JSON with threatInfo + agentDetectionInfo fields
  31. CarbonBlack     — JSON with type="ingress.event.*" or deviceInfo + eventAction
  32. MDATP           — JSON with MachineId+AlertId or DeviceId+ActionType (MDE)
  33. ECS             — JSON with @timestamp + an event object + another ECS namespace (Elastic)
  34. CiscoAsa        — syslog lines containing %ASA-N-mnemonic: or %FTD-N-mnemonic:
  35. PanOS           — PAN-OS native CSV with log type field (TRAFFIC/THREAT/AUTH/...)
  36. FortiGate       — space-separated kv pairs with devid=FG... or devname= + logid=
  37. F5Asm           — syslog kv lines with ip_client= and request_status=/attack_type=
  38. JuniperSrx      — syslog lines with RT_FLOW_SESSION_* or NetScreen device_id=
  39. HAProxy         — syslog lines with haproxy[pid]: and HTTP/TCP access log structure
  40. Traefik         — NDJSON with RouterName + ServiceName + DownstreamStatus
  41. IIS             — W3C text with #Fields: cs-method/sc-status/cs-uri-stem header
  42. Auditd          — Linux audit records: type=<TYPE> msg=audit(<epoch>.<ms>:<serial>):
  43. Syslog          — lines starting with <PRI> (RFC 5424 or RFC 3164)
  44. AuthLog         — BSD syslog lines without <PRI>, or files named auth.log/secure
  45. Zeek            — TSV starting with #separator header line
  46. Snort           — text lines containing [**] [gid:sid:rev] pattern
  47. MySQL           — slow query # User@Host: lines or mysqld error log timestamps
  48. PostgreSQL      — CSV log with 23+ columns, log_time + error_severity
  49. GenericCSV      — .csv extension or comma-separated header
  50. GenericJSON     — JSON array, object, or NDJSON
  51. Nginx           — catch-all for unrecognised text/log files
"""
from __future__ import annotations

import logging
import re

from logtriage.parsers import json_input
from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent

logger = logging.getLogger(__name__)

# Populated once on first call to detect_and_parse()
_REGISTRY: list[type[BaseParser]] = []


def _build_registry() -> list[type[BaseParser]]:
    # Local imports keep the module load order explicit and prevent circular deps
    from logtriage.parsers.parser_cloudtrail import CloudTrailParser
    from logtriage.parsers.parser_leef import LeefParser
    from logtriage.parsers.parser_cef import CefParser
    from logtriage.parsers.parser_azure import AzureParser
    from logtriage.parsers.parser_azure_nsg import AzureNsgParser
    from logtriage.parsers.parser_azure_activity import AzureActivityParser
    from logtriage.parsers.parser_okta import OktaParser
    from logtriage.parsers.parser_k8s import K8sAuditParser
    from logtriage.parsers.parser_gcp import GcpAuditParser
    from logtriage.parsers.parser_cloudflare import CloudflareParser
    from logtriage.parsers.parser_m365 import M365AuditParser
    from logtriage.parsers.parser_google_workspace import GoogleWorkspaceParser
    from logtriage.parsers.parser_github_audit import GitHubAuditParser
    from logtriage.parsers.parser_slack_audit import SlackAuditParser
    from logtriage.parsers.parser_duo import DuoParser
    from logtriage.parsers.parser_jumpcloud import JumpCloudParser
    from logtriage.parsers.parser_aws_securityhub import AwsSecurityHubParser
    from logtriage.parsers.parser_aws_inspector import AwsInspectorParser
    from logtriage.parsers.parser_aws_config import AwsConfigParser
    from logtriage.parsers.parser_guardduty import GuardDutyParser
    from logtriage.parsers.parser_aws_waf import AwsWafParser
    from logtriage.parsers.parser_sysmon import SysmonParser
    from logtriage.parsers.parser_evtx import EvtxParser
    from logtriage.parsers.parser_vpc_flow import VpcFlowParser
    from logtriage.parsers.parser_aws_alb import AwsAlbParser
    from logtriage.parsers.parser_aws_s3_access import AwsS3AccessParser
    from logtriage.parsers.parser_suricata import SuricataParser
    from logtriage.parsers.parser_wazuh import WazuhParser
    from logtriage.parsers.parser_crowdstrike import CrowdStrikeParser
    from logtriage.parsers.parser_sentinelone import SentinelOneParser
    from logtriage.parsers.parser_carbonblack import CarbonBlackParser
    from logtriage.parsers.parser_mdatp import MdatpParser
    from logtriage.parsers.parser_cisco_asa import CiscoAsaParser
    from logtriage.parsers.parser_panos import PanosParser
    from logtriage.parsers.parser_fortigate import FortiGateParser
    from logtriage.parsers.parser_f5_asm import F5AsmParser
    from logtriage.parsers.parser_juniper_srx import JuniperSrxParser
    from logtriage.parsers.parser_haproxy import HaproxyParser
    from logtriage.parsers.parser_traefik import TraefikParser
    from logtriage.parsers.parser_iis import IisParser
    from logtriage.parsers.parser_auditd import AuditdParser
    from logtriage.parsers.parser_syslog import SyslogParser
    from logtriage.parsers.parser_authlog import AuthLogParser
    from logtriage.parsers.parser_zeek import ZeekParser
    from logtriage.parsers.parser_snort import SnortParser
    from logtriage.parsers.parser_mysql import MysqlParser
    from logtriage.parsers.parser_postgresql import PostgresqlParser
    from logtriage.parsers.parser_ecs import EcsParser
    from logtriage.parsers.parser_generic import GenericCsvParser, GenericJsonParser
    from logtriage.parsers.parser_nginx import NginxParser

    return [
        CloudTrailParser,
        LeefParser,
        CefParser,
        AzureParser,
        AzureNsgParser,
        AzureActivityParser,
        OktaParser,
        K8sAuditParser,
        GcpAuditParser,
        CloudflareParser,
        M365AuditParser,
        GoogleWorkspaceParser,
        GitHubAuditParser,
        SlackAuditParser,
        DuoParser,
        JumpCloudParser,
        AwsSecurityHubParser,
        AwsInspectorParser,
        AwsConfigParser,
        GuardDutyParser,
        AwsWafParser,
        SysmonParser,
        EvtxParser,
        VpcFlowParser,
        AwsAlbParser,
        AwsS3AccessParser,
        SuricataParser,
        WazuhParser,
        CrowdStrikeParser,
        SentinelOneParser,
        CarbonBlackParser,
        MdatpParser,
        EcsParser,
        CiscoAsaParser,
        PanosParser,
        FortiGateParser,
        F5AsmParser,
        JuniperSrxParser,
        HaproxyParser,
        TraefikParser,
        IisParser,
        AuditdParser,
        SyslogParser,
        AuthLogParser,
        ZeekParser,
        SnortParser,
        MysqlParser,
        PostgresqlParser,
        GenericCsvParser,
        GenericJsonParser,
        NginxParser,
    ]


# A grep file-name prefix, then ":" and optionally "line:" (grep -n). The last path segment
# must contain a letter (auth.log.1, /var/log/secure) — "01/15-14:32:01" (Snort) or
# "15/Jan/2024:10:00" are times, not files — and the whole must contain a dot or slash.
_GREP_PREFIX_RE = re.compile(
    r"""^((?:[^\s:"'{}\[\]<>/]*/)*[^\s:"'{}\[\]<>/]*[A-Za-z][^\s:"'{}\[\]<>/]*):(?:\d+:)?(?=.)"""
)


def strip_grep_prefix(content: str) -> str | None:
    """`grep -H` output (grep over several files) → the original lines.

    Only when nearly every line carries a prefix and the prefixes are a few distinct
    names (files), not per-line values such as addresses. The free analyzer applies
    the same rule (stripGrepPrefix in marketing/src/lib/analyzer/index.mjs).
    """
    sample = [line for line in content[: 1 << 20].split("\n") if line.strip()][:20]
    if len(sample) == 1:  # one line: only a one-line JSON document after the prefix
        m = _GREP_PREFIX_RE.match(sample[0])
        rest = sample[0][m.end():].lstrip() if m else ""
        if not (m and ("." in m.group(1) or "/" in m.group(1)) and rest[:1] in ("[", "{")):
            return None
    elif not sample:
        return None
    prefixes = [
        m.group(1) for line in sample if (m := _GREP_PREFIX_RE.match(line)) and ("." in m.group(1) or "/" in m.group(1))
    ]
    if len(prefixes) < 0.9 * len(sample) or len(set(prefixes)) > max(3, len(sample) / 4):
        return None
    return "\n".join(_GREP_PREFIX_RE.sub("", line, count=1) for line in content.split("\n"))


def detect_and_parse(content: str, filename: str = "") -> tuple[list[LogEvent], str]:
    """
    Iterate the registry in priority order, calling can_parse() on each parser.
    Returns (events, format_name) from the first matching parser that reads events.

    A parser that claims the file but raises or reads nothing passes it on to the
    next parser that claims it: a wrong claim must cost the customer a format, not
    the analysis (2026-10-20, a `grep -H` K8s audit export failed outright). When
    every claimant reads nothing, the first one's empty result is returned; when
    every claimant raised, its error is.
    Raises ValueError if no parser matches.
    """
    global _REGISTRY
    if not _REGISTRY:
        _REGISTRY = _build_registry()

    content = strip_grep_prefix(content) or content
    empty: tuple[list[LogEvent], str] | None = None
    first_error: Exception | None = None
    try:
        for parser_cls in _REGISTRY:
            if not parser_cls.can_parse(content, filename):
                continue
            logger.info("Detected format: %s (filename=%r)", parser_cls.format_name, filename)
            try:
                events = parser_cls.parse(content, filename)
            except Exception as exc:  # any parser bug falls through to the next claimant
                logger.warning("%s parser failed on %r, trying the next parser: %s", parser_cls.format_name, filename, exc)
                first_error = first_error or exc
                continue
            if events:
                return events, parser_cls.format_name
            logger.warning("%s parser read no events from %r, trying the next parser", parser_cls.format_name, filename)
            empty = empty or (events, parser_cls.format_name)
    finally:
        json_input.release()

    if empty is not None:
        return empty
    if first_error is not None:
        raise first_error

    raise ValueError(
        f"No parser could handle file {filename!r}. "
        "Supported formats: nginx/Apache/HAProxy/Traefik/IIS, "
        "Azure AD Sign-In, Azure NSG Flow, Azure ARM Activity, "
        "AWS CloudTrail, VPC Flow, ALB/ELB, S3 Access, GuardDuty, WAF, Security Hub, Config, Inspector, "
        "CEF, Syslog (RFC5424/3164), Linux auth.log, MySQL, PostgreSQL, "
        "Okta, JumpCloud, Duo, Kubernetes Audit, GCP Cloud Audit, Cloudflare, "
        "Microsoft 365 UAL, GitHub Audit, Google Workspace, Slack Audit, "
        "Windows Event Log XML / Sysmon, "
        "Suricata EVE JSON, Zeek, Snort, Wazuh HIDS, "
        "Cisco ASA/FTD, PAN-OS, FortiGate, F5 BIG-IP ASM, Juniper SRX, IBM LEEF, "
        "CrowdStrike Falcon, SentinelOne, Carbon Black, Microsoft Defender, "
        "Elastic ECS, Linux auditd, CSV, NDJSON."
    )
