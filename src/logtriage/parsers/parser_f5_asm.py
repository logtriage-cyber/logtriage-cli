# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
F5 BIG-IP ASM (Application Security Manager) log parser.

ASM logs can be delivered as:
  - Syslog with comma-separated key=value pairs: ip_client=, request_status=, attack_type=, …
  - ArcSight CEF (handled by parser_cef.py — not needed here)
  - Plain key=value syslog lines (same format, no commas between pairs)

Values are quoted (ip_client="203.0.113.5"); attack_type is "N/A" when the request matched
no attack signature; the original client behind a load balancer is in
x_forwarded_for_header_value; there is no user-agent field — the header is part of the raw
request, whose line breaks are written as the characters \\r\\n.

Discriminator: presence of "ip_client=" and ("request_status=" or "attack_type=").

Reference:
  https://techdocs.f5.com/en-us/bigip-16-1-0/big-ip-asm-implementations/
  https://community.f5.com/kb/technicalarticles/asm-remote-logging-to-a-syslog-server/
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+"
)

_KV_RE = re.compile(r'([\w.]+)=(?:"([^"]*)"|((?:[^,\s]|,(?!\s*\w+=))+))')

# The User-Agent header inside the raw request; F5 writes line breaks as the four characters \r\n.
_REQUEST_UA_RE = re.compile(r"User-Agent:\s*(.+?)(?:\\r\\n|\r?\n|$)", re.I)

_BLOCK_STATUSES = frozenset({"blocked", "block", "dropped", "alerted"})
_PASS_STATUSES = frozenset({"passed", "allowed", "pass"})


def _is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def _parse_ts(raw: str) -> datetime:
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _parse_line(line: str) -> LogEvent | None:
    line = _SYSLOG_PREFIX_RE.sub("", line.strip(), count=1)
    if not line:
        return None

    kv: dict[str, str] = {}
    for m in _KV_RE.finditer(line):
        val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        kv[m.group(1)] = val.strip()

    ip = kv.get("ip_client") or kv.get("client_ip")
    if not ip:
        return None
    # Behind a load balancer ip_client is the balancer; F5 logs the original client in
    # x_forwarded_for_header_value (its first address).
    xff = (kv.get("x_forwarded_for_header_value") or "").split(",")[0].strip()
    if xff and xff != "N/A" and _is_private(ip):
        ip = xff

    request_status = kv.get("request_status", "").lower()
    attack_type = kv.get("attack_type", "")
    if attack_type == "N/A":
        attack_type = ""
    severity = kv.get("severity", "").lower()
    uri = kv.get("uri") or kv.get("url")
    if not uri:
        req_m = re.match(r"[A-Z]+\s+(\S+)", kv.get("request", ""))
        uri = req_m.group(1) if req_m else None
    elif kv.get("query_string") and "?" not in uri:
        uri = f"{uri}?{kv['query_string']}"
    method = (kv.get("method") or kv.get("request_method") or "").upper() or None
    user = kv.get("username") or kv.get("user")
    if user == "N/A":
        user = None
    ua = kv.get("user_agent") or kv.get("useragent")
    if not ua:
        ua_m = _REQUEST_UA_RE.search(kv.get("request", ""))
        ua = ua_m.group(1).strip() if ua_m else None
    date_s = kv.get("date_time") or kv.get("datetime") or kv.get("date") or ""

    ts = _parse_ts(date_s) if date_s else datetime.now(timezone.utc)

    response_code = kv.get("response_code", "")
    if request_status in ("blocked", "block", "dropped"):
        status = 403
    elif response_code.isdigit() and 100 <= int(response_code) <= 599:
        # Passed and alerted requests reached the application; F5 logs its response code.
        status = int(response_code)
    elif request_status in _BLOCK_STATUSES:
        status = 403
    elif attack_type and request_status not in _PASS_STATUSES:
        if severity in ("critical", "high", "error"):
            status = 403
        else:
            status = 400
    else:
        status = 200

    return LogEvent(
        source_format=LogFormat.F5_ASM,
        timestamp=ts,
        ip_address=ip,
        user_principal_name=user or None,
        user_agent=ua or None,
        http_method=method,
        path=uri or attack_type or None,
        status_code=status,
        resource_display_name=f"F5-ASM/{kv.get('vs_name', 'unknown')}",
    )


def parse_f5_asm(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in raw_text.splitlines():
        if not line.strip():
            continue
        try:
            e = _parse_line(line)
            if e:
                events.append(e)
        except Exception as exc:
            logger.debug("F5-ASM: skipping line: %s", exc)
    logger.info("F5-ASM parser: %d events", len(events))
    return events


class F5AsmParser(BaseParser):
    format_name = "f5_asm"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        count = 0
        for line in content.splitlines():
            stripped = _SYSLOG_PREFIX_RE.sub("", line.strip(), count=1)
            if not stripped:
                continue
            if "ip_client=" in stripped and (
                "request_status=" in stripped or "attack_type=" in stripped
            ):
                return True
            count += 1
            if count >= 10:
                break
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_f5_asm(content)
