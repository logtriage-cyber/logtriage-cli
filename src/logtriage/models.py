# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class LogFormat(str, Enum):
    NGINX = "nginx"
    AZURE_SIGNIN = "azure_signin"
    GENERIC_JSON = "generic_json"
    GENERIC_CSV = "generic_csv"
    CLOUDTRAIL = "cloudtrail"
    CEF = "cef"
    EVTX = "evtx"
    OKTA = "okta"
    K8S_AUDIT = "k8s_audit"
    GCP_AUDIT = "gcp_audit"
    CLOUDFLARE = "cloudflare"
    M365_AUDIT = "m365_audit"
    SYSLOG = "syslog"
    VPC_FLOW = "vpc_flow"
    AZURE_NSG = "azure_nsg"
    AUTH_LOG = "auth_log"
    SURICATA = "suricata"
    ZEEK = "zeek"
    SNORT = "snort"
    GUARDDUTY = "guardduty"
    AWS_WAF = "aws_waf"
    WAZUH = "wazuh"
    LEEF = "leef"
    CISCO_ASA = "cisco_asa"
    PANOS = "panos"
    FORTIGATE = "fortigate"
    F5_ASM = "f5_asm"
    JUNIPER_SRX = "juniper_srx"
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    CARBONBLACK = "carbonblack"
    MDATP = "mdatp"
    SYSMON = "sysmon"
    ECS = "ecs"
    # P18 — AWS Cloud Security
    AWS_ALB = "aws_alb"
    AWS_S3_ACCESS = "aws_s3_access"
    AWS_SECURITYHUB = "aws_securityhub"
    AWS_CONFIG = "aws_config"
    AWS_INSPECTOR = "aws_inspector"
    # P19 — Identity & SaaS Audit
    IIS = "iis"
    GITHUB_AUDIT = "github_audit"
    GOOGLE_WORKSPACE = "google_workspace"
    DUO = "duo"
    SLACK_AUDIT = "slack_audit"
    JUMPCLOUD = "jumpcloud"
    # P20 — Web, DB & Observability
    AZURE_ACTIVITY = "azure_activity"
    HAPROXY = "haproxy"
    TRAEFIK = "traefik"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"


class DeviceDetail(BaseModel):
    display_name: str | None = None
    operating_system: str | None = None
    browser: str | None = None
    is_compliant: bool | None = None
    is_managed: bool | None = None
    trust_type: str | None = None


class LocationDetail(BaseModel):
    city: str | None = None
    state: str | None = None
    country_or_region: str | None = None
    geo_coordinates: dict[str, float] | None = None


class ConditionalAccessDetail(BaseModel):
    status: str | None = None  # success | failure | notApplied
    policies_not_satisfied: list[str] = Field(default_factory=list)


class LogEvent(BaseModel):
    """Normalised representation of a single log entry across all formats."""

    # Identity
    source_format: LogFormat
    raw_line: str | None = None  # preserved for debugging

    # Timing
    timestamp: datetime

    # Network
    ip_address: str | None = None
    asn: str | None = None
    user_agent: str | None = None

    # Request
    http_method: str | None = None
    path: str | None = None
    status_code: int | None = None
    response_size_bytes: int | None = None
    referrer: str | None = None

    # Identity / auth (Azure-specific, optional for nginx)
    user_principal_name: str | None = None
    user_id: str | None = None
    app_display_name: str | None = None
    resource_display_name: str | None = None
    client_app_used: str | None = None  # e.g. "Browser", "Mobile Apps and Desktop clients"

    # Azure Sign-In specific
    correlation_id: str | None = None
    error_code: int | None = None
    failure_reason: str | None = None
    mfa_detail: dict[str, Any] | None = None
    conditional_access: ConditionalAccessDetail | None = None
    device: DeviceDetail | None = None
    location: LocationDetail | None = None
    risk_level_aggregated: str | None = None  # none | low | medium | high
    risk_level_during_signin: str | None = None
    is_interactive: bool | None = None

    # File hash extracted by parser (P14 — CEF fileHash / EVTX 4688 Hashes)
    file_hash: str | None = None  # SHA256 (64 hex chars) or MD5 (32 hex chars)

    @model_validator(mode="after")
    def _require_timestamp(self) -> "LogEvent":
        if self.timestamp is None:
            raise ValueError("timestamp is required on all LogEvent instances")
        return self
