"""Catalogue of the supported log formats.

One entry per parser: ``id`` is the parser's format name (the value used with
``--format`` and shown by ``logtriage detect``); ``slug``, ``name`` and
``category`` match the format list published at
https://logtriage.app/reference/log-formats/.

A test checks that this catalogue and the parser registry list exactly the
same formats, so a parser cannot be added or removed without updating it.
This module is plain data with no imports beyond the standard library.
"""
from __future__ import annotations

from typing import NamedTuple


class Format(NamedTuple):
    id: str
    slug: str
    name: str
    category: str


FORMATS: tuple[Format, ...] = (
    Format("auth_log", "auth-log", "Linux auth.log / secure", "Endpoint"),
    Format("aws_alb", "aws-alb", "AWS ALB / ELB", "Cloud"),
    Format("aws_config", "aws-config", "AWS Config", "Cloud"),
    Format("aws_inspector", "aws-inspector", "AWS Inspector v2", "Cloud Security"),
    Format("aws_s3_access", "aws-s3-access", "AWS S3 Server Access Logs", "Cloud"),
    Format("aws_securityhub", "aws-securityhub", "AWS Security Hub", "Cloud Security"),
    Format("aws_waf", "aws-waf", "AWS WAF", "WAF"),
    Format("azure_activity", "azure-activity", "Azure ARM Activity Log", "Cloud"),
    Format("azure_nsg", "azure-nsg", "Azure NSG Flow Logs", "Cloud Network"),
    Format("azure_signin", "azure-ad-signin", "Azure AD Sign-In Logs", "Identity"),
    Format("carbonblack", "carbonblack", "Carbon Black", "EDR"),
    Format("cef", "cef", "CEF (Common Event Format)", "Network & Firewall"),
    Format("cisco_asa", "cisco-asa", "Cisco ASA / FTD", "Firewall"),
    Format("cloudflare", "cloudflare", "Cloudflare Logs", "Network & CDN"),
    Format("cloudtrail", "cloudtrail", "AWS CloudTrail", "Cloud"),
    Format("crowdstrike", "crowdstrike", "CrowdStrike Falcon", "EDR"),
    Format("duo", "duo", "Duo Security", "Identity"),
    Format("ecs", "ecs", "Elastic Common Schema", "SIEM"),
    Format("evtx", "evtx", "Windows Event Log", "Endpoint"),
    Format("f5_asm", "f5-asm", "F5 BIG-IP ASM", "WAF"),
    Format("fortigate", "fortigate", "FortiGate", "Firewall"),
    Format("gcp_audit", "gcp-audit", "GCP Cloud Audit Log", "Cloud"),
    Format("generic_csv", "generic-csv", "Generic CSV", "Generic"),
    Format("generic_json", "generic-json", "Generic JSON / NDJSON", "Generic"),
    Format("github_audit", "github-audit", "GitHub Audit Log", "SaaS"),
    Format("google_workspace", "google-workspace", "Google Workspace", "SaaS"),
    Format("guardduty", "guardduty", "AWS GuardDuty", "Cloud Security"),
    Format("haproxy", "haproxy", "HAProxy", "Network"),
    Format("iis", "iis", "IIS W3C Extended", "Web"),
    Format("jumpcloud", "jumpcloud", "JumpCloud Directory", "Identity"),
    Format("juniper_srx", "juniper-srx", "Juniper SRX", "Firewall"),
    Format("k8s_audit", "k8s-audit", "Kubernetes Audit Log", "Cloud-Native"),
    Format("leef", "leef", "IBM LEEF", "SIEM"),
    Format("m365_audit", "m365", "Microsoft 365 Unified Audit Log", "SaaS"),
    Format("mdatp", "mdatp", "Microsoft Defender for Endpoint", "EDR"),
    Format("mysql", "mysql", "MySQL", "Database"),
    Format("nginx", "nginx", "nginx / Apache Combined", "Web"),
    Format("okta", "okta", "Okta System Log", "Identity"),
    Format("panos", "panos", "PAN-OS Native CSV", "Firewall"),
    Format("postgresql", "postgresql", "PostgreSQL", "Database"),
    Format("sentinelone", "sentinelone", "SentinelOne", "EDR"),
    Format("slack_audit", "slack-audit", "Slack Audit Log", "SaaS"),
    Format("snort", "snort", "Snort", "IDS/IPS"),
    Format("suricata", "suricata", "Suricata", "IDS/IPS"),
    Format("syslog", "syslog", "Syslog (RFC 5424 / 3164)", "Network"),
    Format("sysmon", "sysmon", "Sysmon", "Endpoint"),
    Format("traefik", "traefik", "Traefik", "Network"),
    Format("vpc_flow", "vpc-flow", "AWS VPC Flow Logs", "Cloud Network"),
    Format("wazuh", "wazuh", "Wazuh", "HIDS"),
    Format("zeek", "zeek", "Zeek", "IDS/IPS"),
)

BY_ID: dict[str, Format] = {f.id: f for f in FORMATS}

# Parsers that accept almost anything and are tried last. When one of them
# "detects" a file but produces no events, the format was not recognised.
CATCH_ALL: frozenset[str] = frozenset({"generic_csv", "generic_json", "nginx"})


def display_name(format_id: str) -> str:
    """Human-readable name for a parser id (falls back to the id itself)."""
    entry = BY_ID.get(format_id)
    return entry.name if entry else format_id
