# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
F5 BIG-IP ASM (Application Security Manager) log parser.

ASM logs can be delivered as:
  - Syslog with comma-separated key=value pairs: ip_client=, request_status=, attack_type=, …
  - ArcSight CEF (handled by parser_cef.py — not needed here)
  - Plain key=value syslog lines (same format, no commas between pairs)

Discriminator: presence of "ip_client=" and ("request_status=" or "attack_type=").

Reference:
  https://techdocs.f5.com/en-us/bigip-16-1-0/big-ip-asm-implementations/
"""
from __future__ import annotations

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

_BLOCK_STATUSES = frozenset({"blocked", "block", "dropped", "alerted"})
_PASS_STATUSES = frozenset({"passed", "allowed", "pass"})


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

    request_status = kv.get("request_status", "").lower()
    attack_type = kv.get("attack_type", "")
    severity = kv.get("severity", "").lower()
    uri = kv.get("uri") or kv.get("request") or kv.get("url")
    method = (kv.get("method") or kv.get("request_method") or "").upper() or None
    user = kv.get("username") or kv.get("user")
    ua = kv.get("user_agent") or kv.get("useragent")
    date_s = kv.get("date_time") or kv.get("datetime") or kv.get("date") or ""

    ts = _parse_ts(date_s) if date_s else datetime.now(timezone.utc)

    if request_status in _BLOCK_STATUSES:
        status = 403
    elif attack_type and request_status not in _PASS_STATUSES:
        if severity in ("critical", "high"):
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
        if filename and any(s in filename.lower() for s in ("f5", "bigip", "asm")):
            pass
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
