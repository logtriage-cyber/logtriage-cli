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
  33. CiscoAsa        — syslog lines containing %ASA-N-mnemonic: or %FTD-N-mnemonic:
  34. PanOS           — PAN-OS native CSV with log type field (TRAFFIC/THREAT/AUTH/...)
  35. FortiGate       — space-separated kv pairs with devid=FG... or devname= + logid=
  36. F5Asm           — syslog kv lines with ip_client= and request_status=/attack_type=
  37. JuniperSrx      — syslog lines with RT_FLOW_SESSION_* or NetScreen device_id=
  38. HAProxy         — syslog lines with haproxy[pid]: and HTTP/TCP access log structure
  39. Traefik         — NDJSON with RouterName + ServiceName + DownstreamStatus
  40. IIS             — W3C text with #Fields: cs-method/sc-status/cs-uri-stem header
  41. Syslog          — lines starting with <PRI> (RFC 5424 or RFC 3164)
  42. AuthLog         — BSD syslog lines without <PRI>, or files named auth.log/secure
  43. Zeek            — TSV starting with #separator header line
  44. Snort           — text lines containing [**] [gid:sid:rev] pattern
  45. MySQL           — slow query # User@Host: lines or mysqld error log timestamps
  46. PostgreSQL      — CSV log with 23+ columns, log_time + error_severity
  47. ECS             — NDJSON/JSON with @timestamp + ECS namespace objects (Elastic)
  48. GenericCSV      — .csv extension or comma-separated header
  49. GenericJSON     — JSON array, object, or NDJSON
  50. Nginx           — catch-all for unrecognised text/log files
"""
from __future__ import annotations

import logging

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
        CiscoAsaParser,
        PanosParser,
        FortiGateParser,
        F5AsmParser,
        JuniperSrxParser,
        HaproxyParser,
        TraefikParser,
        IisParser,
        SyslogParser,
        AuthLogParser,
        ZeekParser,
        SnortParser,
        MysqlParser,
        PostgresqlParser,
        EcsParser,
        GenericCsvParser,
        GenericJsonParser,
        NginxParser,
    ]


def detect_and_parse(content: str, filename: str = "") -> tuple[list[LogEvent], str]:
    """
    Iterate the registry in priority order, calling can_parse() on each parser.
    Returns (events, format_name) for the first matching parser.
    Raises ValueError if no parser matches.
    """
    global _REGISTRY
    if not _REGISTRY:
        _REGISTRY = _build_registry()

    for parser_cls in _REGISTRY:
        if parser_cls.can_parse(content, filename):
            logger.info(
                "Detected format: %s (filename=%r)", parser_cls.format_name, filename
            )
            return parser_cls.parse(content, filename), parser_cls.format_name

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
        "Elastic ECS, CSV, NDJSON."
    )
