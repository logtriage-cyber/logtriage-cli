# LogTriage CLI

`logtriage` reads security logs on your own machine. It recognises 50 log formats (AWS CloudTrail, Entra ID / Azure AD sign-ins, Windows Security events, Sysmon, Okta, nginx/Apache, firewalls, EDR exports and more), converts every record to one normalised schema, and gives you a quick triage summary in the terminal or the events as JSON, NDJSON or CSV.

The parsers are the ones the hosted [LogTriage](https://logtriage.app) service runs, synced into this repository.

**Nothing leaves your machine** unless you run `logtriage analyze`, the one command that uploads a file (to the hosted service, for an AI-written threat report). The other commands make no network connections and collect no telemetry.

## Install

```sh
pip install logtriage
```

Until the PyPI release is published, install from GitHub:

```sh
pip install git+https://github.com/logtriage-cyber/logtriage-cli
```

Python 3.10 or newer. Dependencies: `pydantic` and `defusedxml`. Reading binary Windows `.evtx` files needs one optional extra:

```sh
pip install "logtriage[evtx]"
```

## Usage

The examples below run against the sample logs in [`tests/data/`](https://github.com/logtriage-cyber/logtriage-cli/tree/HEAD/tests/data), so you can reproduce them from a clone of this repository.

### Identify files

```console
$ logtriage detect tests/data/*
FORMAT       EVENTS  FILE
auth_log         20  tests/data/authlog_normal.log
cisco_asa         6  tests/data/cisco_asa_normal.log
cloudtrail        4  tests/data/cloudtrail_normal_operations.json
generic_csv      12  tests/data/generic_normal_api.csv
m365_audit        6  tests/data/m365_normal_activity.json
nginx            15  tests/data/nginx_api_developer.log
syslog           14  tests/data/syslog_normal.log
vpc_flow         10  tests/data/vpc_flow_benign.log
evtx              7  tests/data/windows_normal_logons.xml
zeek              5  tests/data/zeek_normal_http.log
```

### Triage a file in the terminal

```console
$ logtriage summary tests/data/authlog_normal.log --top 5
tests/data/authlog_normal.log
  format      auth_log (Linux auth.log / secure)
  events      20
  time range  2026-03-15 08:00:01 UTC -> 2026-03-15 16:00:05 UTC  (8h 00m)
  unique      3 source IPs, 4 users

Outcome
  18   90.0%  success (status < 400)
   2   10.0%  failure (status >= 400)

Status codes
  18   90.0%  200
   2   10.0%  401

Top source IPs
  1    5.0%  10.10.1.5
  1    5.0%  192.168.1.100
  1    5.0%  10.10.2.10

Top users
  3   15.0%  admin
  2   10.0%  deploy
  2   10.0%  root
  2   10.0%  jenkins

Top failure reasons
  1    5.0%  pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost= user=badpass
  1    5.0%  FAILED LOGIN 1 FROM /dev/tty1 FOR badpass, Authentication failure

Top user agents
  (none)

Top paths / actions
  1    5.0%  sshd: Accepted publickey for deploy from 10.10.1.5 port 43210 ssh2: RSA SHA256:abc123
  1    5.0%  sshd: pam_unix(sshd:session): session opened for user deploy by (uid=0)
  1    5.0%  sudo: root COMMAND=/usr/bin/systemctl restart nginx
  1    5.0%  su: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)
  1    5.0%  su: pam_unix(sudo:session): session closed for user root
```

`--top N` sets the length of each list (default 10); `--json` prints the same summary as JSON.

### Normalise to JSON, NDJSON or CSV

```console
$ logtriage parse tests/data/cloudtrail_normal_operations.json --output ndjson --limit 2
{"source_format": "cloudtrail", "timestamp": "2024-01-15T09:05:12Z", "ip_address": "203.0.113.10", "user_agent": "aws-cli/2.13.0 Python/3.11.4 Darwin/22.6.0", "path": "ListBuckets", "status_code": 200, "user_principal_name": "arn:aws:iam::123456789012:user/alice", "resource_display_name": "s3.amazonaws.com"}
{"source_format": "cloudtrail", "timestamp": "2024-01-15T09:06:03Z", "ip_address": "203.0.113.10", "user_agent": "aws-cli/2.13.0 Python/3.11.4 Darwin/22.6.0", "path": "GetObject", "status_code": 200, "user_principal_name": "arn:aws:iam::123456789012:user/alice", "resource_display_name": "s3.amazonaws.com"}
```

`--output json` (the default) writes a JSON array, `ndjson` one object per line, `csv` a header plus one row per event with a fixed set of columns. JSON output leaves out empty fields; `--include-raw` adds the original log line where the parser keeps it.

Because every format lands in the same schema, one query works across sources:

```sh
# Source IPs with failed requests or sign-ins, across every log in a folder
for f in logs/*; do logtriage parse "$f" --output ndjson; done \
  | jq -r 'select(.status_code >= 400) | .ip_address // empty' | sort | uniq -c | sort -rn

# Entra ID sign-ins into a spreadsheet
logtriage parse signins.json --output csv > signins.csv
```

### List the supported formats

```console
$ logtriage formats
50 supported formats. Detection is automatic; --format ID forces a parser.

ID                FORMAT                           CATEGORY
aws_alb           AWS ALB / ELB                    Cloud
cloudtrail        AWS CloudTrail                   Cloud
aws_config        AWS Config                       Cloud
guardduty         AWS GuardDuty                    Cloud Security
...
```

### Inputs

- Text logs in UTF-8, or UTF-16/UTF-32 with a byte-order mark (for example files written by PowerShell). Undecodable bytes are replaced, not fatal.
- gzip-compressed files (`.gz`) are decompressed on the fly.
- Windows event logs: XML exports work out of the box (`wevtutil qe Security /f:xml /e:Events > security.xml`). Binary `.evtx` files need the `[evtx]` extra and are read for Windows Security events; for other channels such as Sysmon, export to XML first (`wevtutil qe Sysmon.evtx /lf:true /f:xml /e:Events > sysmon.xml`).
- Detection is automatic. If a file is detected as the wrong format, force the parser with `--format ID` (IDs from `logtriage formats`).

### The normalised schema

Each event has the same fields whatever the source; a field is empty when the source has nothing to put in it.

| Field | Meaning |
|---|---|
| `timestamp` | When the event happened |
| `source_format` | Format id of the parser that produced the event |
| `ip_address` | Client or source address |
| `user_principal_name`, `user_id` | User, account or principal |
| `user_agent` | User agent, client application or workstation |
| `http_method`, `path` | Request method and path; for non-HTTP sources the action (CloudTrail `eventName`, Windows event type, ...) |
| `status_code` | HTTP status; other sources map their outcome onto one (for example 401 for a failed sign-in, 403 for a denied or blocked action) |
| `failure_reason`, `error_code` | Why an action failed, where the source says |
| `app_display_name`, `resource_display_name` | Application and target resource or service |
| `file_hash` | SHA-256 or MD5 of a file, for EDR and process events |
| `mfa_detail`, `conditional_access`, `device`, `location`, `risk_level_*`, `is_interactive` | Entra ID sign-in details |

`summary` counts `status_code` below 400 as success and 400 or above as failure.

Timestamps keep the offset the source gives. Formats without one (Microsoft 365 audit records, for example) are written as is and treated as UTC by `summary`. Classic syslog and `auth.log` lines carry no year, so the current year is assumed. When a record's timestamp cannot be read at all, most parsers substitute the time of parsing, so a `summary` time range that ends "now" is worth a second look.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error: unreadable file, parser failure, network or service error |
| 2 | Usage error |
| 3 | Format not recognised, or no events could be parsed |
| 4 | `analyze` timed out waiting for the result (the analysis keeps running on the server) |

## Supported formats

<!-- formats-table:start -->
50 formats, detected automatically. Linked names have a field-by-field reference page on logtriage.app.

| Format | Category | `--format` id | What it is |
|---|---|---|---|
| AWS ALB / ELB | Cloud | `aws_alb` | Access logs from AWS Application and Elastic Load Balancers. |
| AWS CloudTrail | Cloud | `cloudtrail` | AWS API call history — every console, SDK, and CLI action against your account. |
| AWS Config | Cloud | `aws_config` | Configuration change history for AWS resources. |
| AWS S3 Server Access Logs | Cloud | `aws_s3_access` | Request-level access logs for Amazon S3 buckets. |
| Azure ARM Activity Log | Cloud | `azure_activity` | Subscription-level control-plane operations across Azure Resource Manager. |
| GCP Cloud Audit Log | Cloud | `gcp_audit` | Admin activity and data access events across Google Cloud Platform services. |
| [AWS VPC Flow Logs](https://logtriage.app/reference/log-formats/vpc-flow/) | Cloud Network | `vpc_flow` | IP traffic metadata for every accepted and rejected connection in an AWS VPC. |
| Azure NSG Flow Logs | Cloud Network | `azure_nsg` | Allow/deny decisions for traffic through Azure Network Security Groups. |
| AWS GuardDuty | Cloud Security | `guardduty` | Managed threat detection findings from AWS GuardDuty. |
| AWS Inspector v2 | Cloud Security | `aws_inspector` | Vulnerability and package findings from AWS Inspector. |
| AWS Security Hub | Cloud Security | `aws_securityhub` | Aggregated security findings (ASFF) from across AWS security services. |
| Kubernetes Audit Log | Cloud-Native | `k8s_audit` | Every request made to the Kubernetes API server, including who did what to which resource. |
| MySQL | Database | `mysql` | Slow query and error logs from MySQL/MariaDB. |
| PostgreSQL | Database | `postgresql` | CSV-format error and connection logs from PostgreSQL. |
| Carbon Black | EDR | `carbonblack` | Endpoint event and detection data from Carbon Black EDR and Cloud. |
| [CrowdStrike Falcon](https://logtriage.app/reference/log-formats/crowdstrike/) | EDR | `crowdstrike` | Process, network, and detection telemetry from the CrowdStrike Falcon Data Replicator. |
| Microsoft Defender for Endpoint | EDR | `mdatp` | Alerts and advanced hunting events from Microsoft Defender ATP. |
| SentinelOne | EDR | `sentinelone` | Threat detections and agent telemetry from the SentinelOne endpoint platform. |
| Linux auth.log / secure | Endpoint | `auth_log` | SSH, sudo, and PAM authentication events from Linux hosts. |
| Sysmon | Endpoint | `sysmon` | Deep Windows process, network, and file-system telemetry from Microsoft Sysinternals Sysmon. |
| Windows Event Log | Endpoint | `evtx` | Native Windows Event Log XML and binary .evtx exports. |
| Cisco ASA / FTD | Firewall | `cisco_asa` | Connection and threat events from Cisco ASA and Firepower Threat Defense appliances. |
| FortiGate | Firewall | `fortigate` | Fortinet FortiGate UTM/NGFW traffic and security event logs. |
| Juniper SRX | Firewall | `juniper_srx` | Session creation, close, and deny events from Juniper SRX and ScreenOS firewalls. |
| PAN-OS Native CSV | Firewall | `panos` | Palo Alto Networks native traffic, threat, and URL filtering logs. |
| Generic CSV | Generic | `generic_csv` | Any comma-separated access or application log with recognizable column headers. |
| Generic JSON / NDJSON | Generic | `generic_json` | Any structured JSON or newline-delimited JSON application log. |
| Wazuh | HIDS | `wazuh` | Host-based intrusion detection alerts from the Wazuh agent platform. |
| [Azure AD Sign-In Logs](https://logtriage.app/reference/log-formats/azure-ad-signin/) | Identity | `azure_signin` | Every interactive and non-interactive sign-in to Microsoft Entra ID, with conditional access and MFA detail. |
| Duo Security | Identity | `duo` | Multi-factor authentication events from Cisco Duo. |
| JumpCloud Directory | Identity | `jumpcloud` | Directory, SSO, and LDAP events from JumpCloud. |
| Okta System Log | Identity | `okta` | Authentication, admin, and lifecycle events from the Okta identity platform. |
| Snort | IDS/IPS | `snort` | Alert logs from the Snort network intrusion detection system. |
| Suricata | IDS/IPS | `suricata` | EVE JSON alert, flow, and protocol logs from the Suricata network IDS/IPS. |
| Zeek | IDS/IPS | `zeek` | Network connection and protocol logs from the Zeek (Bro) network monitor. |
| HAProxy | Network | `haproxy` | HTTP and TCP access logs from the HAProxy load balancer. |
| Syslog (RFC 5424 / 3164) | Network | `syslog` | The universal network device and application logging standard. |
| Traefik | Network | `traefik` | Structured access logs from the Traefik reverse proxy. |
| Cloudflare Logs | Network & CDN | `cloudflare` | Edge HTTP requests, WAF actions, and firewall rule matches at the Cloudflare edge. |
| CEF (Common Event Format) | Network & Firewall | `cef` | Vendor-neutral event format used by Palo Alto, Check Point, ArcSight, and most enterprise firewalls/SIEMs. |
| GitHub Audit Log | SaaS | `github_audit` | Organization, repository, and security event history from GitHub. |
| Google Workspace | SaaS | `google_workspace` | Admin console and application activity from Google Workspace. |
| Microsoft 365 Unified Audit Log | SaaS | `m365_audit` | Cross-workload audit trail spanning Exchange, SharePoint, Teams, and Entra ID. |
| Slack Audit Log | SaaS | `slack_audit` | Workspace administration and access events from Slack's Enterprise Audit Log. |
| Elastic Common Schema | SIEM | `ecs` | Normalized event schema used by Filebeat, Auditbeat, and Winlogbeat in the Elastic Stack. |
| IBM LEEF | SIEM | `leef` | Log Event Extended Format used for QRadar integrations. |
| AWS WAF | WAF | `aws_waf` | Web ACL allow/block decisions from AWS WAF. |
| F5 BIG-IP ASM | WAF | `f5_asm` | Application-layer attack detections from F5's web application firewall module. |
| IIS W3C Extended | Web | `iis` | Microsoft Internet Information Services extended logging format. |
| nginx / Apache Combined | Web | `nginx` | The standard combined access log format used by nginx and Apache. |
<!-- formats-table:end -->

## Hosted analysis: `logtriage analyze`

`analyze` uploads one file to the hosted LogTriage service and prints its verdict. The service adds what a local parser cannot: IP reputation and threat-intelligence lookups (AbuseIPDB, AlienVault OTX, ThreatFox and others), attack-pattern detection such as credential stuffing and impossible travel, MITRE ATT&CK mapping, and an AI-written report with remediation steps.

```sh
export LOGTRIAGE_API_KEY=ltk_...      # or pass --api-key
logtriage analyze auth.log
```

Example output (the verdict and summary text here are illustrative):

```console
$ logtriage analyze auth.log
logtriage: uploading auth.log (412.6 KB) to https://api.logtriage.app; the file leaves this machine for analysis.
logtriage: job 3f0c9e2a-7d41-4c55-9a7e-2b6f1d8c0e91
logtriage: status: queued
logtriage: status: enriching
logtriage: status: analyzing
logtriage: status: complete
Severity        HIGH (confidence HIGH, risk score 82/100)
Attack pattern  SSH Brute Force
Model           claude-sonnet-4-6
Events          5,214 (auth_log)
Report          https://app.logtriage.app/app/report/3f0c9e2a-7d41-4c55-9a7e-2b6f1d8c0e91

Over 40 minutes, 3 hosts made 4,870 failed SSH logins against 61 account
names, then one of them logged in as 'deploy'. Treat the deploy account as
compromised: rotate its keys and review what it ran after 02:14 UTC.
```

- Create an API key in the app under Integrations ([app.logtriage.app/app/integrations](https://app.logtriage.app/app/integrations)). An analysis uses credits from your plan (one for a file under 10 MB); credits for a failed analysis are refunded.
- The file goes over HTTPS to `https://api.logtriage.app`. Files up to 100 MB are accepted; decompress `.gz` files first.
- `--timeout SECONDS` (default 600) sets how long to wait; the analysis continues on the server after a timeout and the report link stays valid.
- `--json` prints the job summary and the full report as JSON.

## Privacy

- `formats`, `detect`, `parse` and `summary` run entirely on your machine. They read only the files you name and make no network connections.
- `analyze` uploads the file you name, and only that file. The hosted service deletes uploaded files automatically after 7 days (the parsed results and report stay in your account until you delete the analysis) and does not train models on your data. Questions: hello@logtriage.app.

## Related

- [Log format reference](https://logtriage.app/reference/log-formats/): field-by-field guides to the formats above.
- [Free in-browser log analyzer](https://logtriage.app/tools/log-analyzer/).
- [LogTriage detection rules](https://github.com/logtriage-cyber/logtriage-detection-rules): Sigma rules validated against the same sample logs.
- [LogTriage](https://logtriage.app): the hosted service behind `analyze`.

## Contributing

Bug reports are the most useful contribution: the command you ran, what you expected, and a few sample lines with real addresses and names replaced (documentation ranges such as `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` work well).

The parsers (`src/logtriage/parsers/`) and the event model (`src/logtriage/models.py`) are synced from the LogTriage service, which runs the same code. Fixes to those files are made there and arrive here with the next sync, so pull requests that touch them are applied upstream rather than merged directly. Changes to the CLI, tests and docs are welcome as regular pull requests.

To run the tests:

```sh
pip install -e ".[test]"
pytest
```

## License

Apache License 2.0. See [LICENSE](https://github.com/logtriage-cyber/logtriage-cli/blob/HEAD/LICENSE).
