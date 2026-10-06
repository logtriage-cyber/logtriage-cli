# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Zeek (formerly Bro) unified log parser.

Zeek writes TSV logs with a metadata header block. The #path line identifies
the log type (http, conn, dns, ssl, files, weird, notice, etc.) and #fields
lists the column names dynamically, so one parser handles all Zeek log types.

Reference: https://docs.zeek.org/en/master/log-formats.html
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_EMPTY = {"-", "(empty)", ""}

# Zeek conn_state codes → approximate HTTP status
_CONN_STATE_STATUS: dict[str, int] = {
    "SF":     200,   # Normal established + FIN close
    "S0":     408,   # SYN only, no response
    "REJ":    403,   # RST reply to SYN
    "RSTOS0": 400,
    "RSTRH":  400,
    "SH":     408,   # Half-open (SYN + SYN-ACK, no final ACK)
    "SHR":    408,
    "RSTO":   400,   # RST by originator
    "RSTR":   400,   # RST by responder
    "OTH":    200,
}


def _safe_int(val: str | None) -> int | None:
    if val is None or val in _EMPTY:
        return None
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return None


def _parse_ts(raw: str | None) -> datetime:
    if not raw or raw in _EMPTY:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    except (ValueError, OSError):
        return datetime.now(timezone.utc)


def _field(f: dict[str, str | None], *keys: str) -> str | None:
    for k in keys:
        v = f.get(k)
        if v is not None:
            return v
    return None


def _row_to_log(path: str, fields: list[str], values: list[str]) -> LogEvent | None:
    try:
        # Build dict; replace Zeek empty/unset markers with None
        f: dict[str, str | None] = {
            k: (None if v in _EMPTY else v)
            for k, v in zip(fields, values)
        }

        ts = _parse_ts(f.get("ts"))
        src_ip = _field(f, "id.orig_h", "orig_h")

        if path == "http":
            return LogEvent(
                source_format=LogFormat.ZEEK,
                timestamp=ts,
                ip_address=src_ip,
                path=f.get("uri"),
                resource_display_name=f.get("host"),
                http_method=f.get("method"),
                status_code=_safe_int(f.get("status_code")),
                user_agent=f.get("user_agent"),
                response_size_bytes=_safe_int(f.get("response_body_len")),
                referrer=f.get("referrer"),
            )

        if path == "conn":
            resp_h = f.get("id.resp_h")
            resp_p = f.get("id.resp_p")
            conn_state = f.get("conn_state") or ""
            return LogEvent(
                source_format=LogFormat.ZEEK,
                timestamp=ts,
                ip_address=src_ip,
                path=f"{resp_h}:{resp_p}" if resp_h and resp_p else resp_h,
                http_method=(f.get("proto") or "").upper() or None,
                status_code=_CONN_STATE_STATUS.get(conn_state, 200),
                response_size_bytes=_safe_int(f.get("resp_bytes")),
            )

        if path == "dns":
            rcode = f.get("rcode_name", "NOERROR")
            return LogEvent(
                source_format=LogFormat.ZEEK,
                timestamp=ts,
                ip_address=src_ip,
                path=f.get("query"),
                http_method="DNS",
                resource_display_name=f.get("qtype_name"),
                status_code=200 if rcode == "NOERROR" else 400,
            )

        if path == "ssl":
            established = f.get("established", "F")
            return LogEvent(
                source_format=LogFormat.ZEEK,
                timestamp=ts,
                ip_address=src_ip,
                path=f.get("server_name"),
                resource_display_name=f.get("subject"),
                http_method="TLS",
                status_code=200 if established == "T" else 400,
            )

        if path == "files":
            return LogEvent(
                source_format=LogFormat.ZEEK,
                timestamp=ts,
                ip_address=src_ip,
                path=f.get("filename") or f.get("sha256") or f.get("md5"),
                http_method="FILE",
                status_code=200,
                file_hash=f.get("sha256") or f.get("md5"),
            )

        if path in ("weird", "notice", "signature"):
            return LogEvent(
                source_format=LogFormat.ZEEK,
                timestamp=ts,
                ip_address=src_ip,
                path=f.get("name") or f.get("msg") or path,
                http_method=path.upper(),
                status_code=400,
            )

        # Generic fallback for other log types
        return LogEvent(
            source_format=LogFormat.ZEEK,
            timestamp=ts,
            ip_address=src_ip,
            path=path,
            http_method=path.upper(),
            status_code=200,
        )

    except Exception as exc:
        logger.debug("Zeek: skipping row in %s log: %s", path, exc)
        return None


def parse_zeek(raw_text: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    fields: list[str] = []
    separator = "\t"
    path = "unknown"

    for line in raw_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        if line_stripped.startswith("#"):
            # Metadata header lines
            if line_stripped.startswith("#separator"):
                # "#separator \x09" or "#separator \\t"
                sep_raw = line_stripped.split(" ", 1)[1] if " " in line_stripped else "\t"
                separator = sep_raw.encode("utf-8").decode("unicode_escape")
            elif line_stripped.startswith("#fields"):
                fields = line_stripped.split(separator)[1:]  # skip the "#fields" token
            elif line_stripped.startswith("#path"):
                path = line_stripped.split(separator)[1] if separator in line_stripped else line_stripped.split()[1]
            # ignore #types, #open, #close, #set_separator, etc.
            continue

        if not fields:
            continue

        values = line.split(separator)
        if e := _row_to_log(path, fields, values):
            events.append(e)

    logger.info("Zeek parser: %d events (path=%s)", len(events), path)
    return events


class ZeekParser(BaseParser):
    """Plugin-registry entry for Zeek (Bro) unified TSV logs."""

    format_name = "zeek"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename and "zeek" in filename.lower():
            pass  # fall through to content check
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Zeek logs always start with the #separator directive
            return stripped.startswith("#separator")
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_zeek(content)
