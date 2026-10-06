# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
PostgreSQL CSV log parser.

PostgreSQL can write logs in CSV format (log_destination = 'csvlog').
The header (if present) lists 23-24 columns; this parser handles both
with-header and without-header variants.

CSV columns (in order):
  log_time, user_name, database_name, process_id, connection_from,
  session_id, session_line_num, command_tag, session_start_time,
  virtual_transaction_id, transaction_id, error_severity, sql_state_code,
  message, detail, hint, internal_query, internal_query_pos, context, query,
  query_pos, location, application_name[, backend_type]

Severity mapping:
  FATAL / PANIC / ERROR → 403
  WARNING               → 400
  LOG / INFO / NOTICE   → 200

Reference:
  https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-CSVLOG
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_PG_HEADER = [
    "log_time", "user_name", "database_name", "process_id", "connection_from",
    "session_id", "session_line_num", "command_tag", "session_start_time",
    "virtual_transaction_id", "transaction_id", "error_severity", "sql_state_code",
    "message", "detail", "hint", "internal_query", "internal_query_pos",
    "context", "query", "query_pos", "location", "application_name",
]

_FATAL_LEVELS = frozenset({"fatal", "panic", "error"})
_WARN_LEVELS = frozenset({"warning"})

# Detect PostgreSQL CSV by timestamp format and error_severity column values
_SEVERITY_VALUES = frozenset({"LOG", "ERROR", "WARNING", "FATAL", "PANIC", "INFO", "NOTICE", "DEBUG"})


def _parse_ts(raw: str) -> datetime:
    # "2023-01-01 12:00:00.000 UTC" or "2023-01-01 12:00:00 UTC"
    raw = raw.strip().replace(" UTC", "+00:00").replace(" EST", "-05:00")
    try:
        return datetime.fromisoformat(raw.replace(" ", "T", 1))
    except ValueError:
        return datetime.now(timezone.utc)


def _row_to_log(row: dict[str, str]) -> LogEvent | None:
    try:
        severity = row.get("error_severity", "LOG").lower()
        if severity in _FATAL_LEVELS:
            status = 403
        elif severity in _WARN_LEVELS:
            status = 400
        else:
            status = 200

        # connection_from: "192.168.1.1:54321" or "[local]"
        conn = row.get("connection_from", "")
        ip: str | None = None
        if conn and conn not in ("[local]", ""):
            ip = conn.rsplit(":", 1)[0]
            if ip.startswith("["):
                ip = None  # IPv6 [::1]:port — skip for now

        return LogEvent(
            source_format=LogFormat.POSTGRESQL,
            timestamp=_parse_ts(row.get("log_time", "")),
            ip_address=ip,
            path=f"/db/{row.get('database_name', 'postgres')}",
            status_code=status,
            user_principal_name=row.get("user_name") or None,
            resource_display_name=row.get("application_name") or "postgresql",
            failure_reason=row.get("message") if status == 403 else None,
            raw_line=",".join(row.values())[:300],
        )
    except Exception as exc:
        logger.debug("PostgreSQL: skipping row: %s", exc)
        return None


def _is_pg_csv(content: str) -> bool:
    """Detect PostgreSQL CSV by checking first data row structure."""
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row:
            continue
        # 23 or 24 columns
        if len(row) < 23:
            return False
        severity = row[11].strip() if len(row) > 11 else ""
        if severity in _SEVERITY_VALUES:
            # Check timestamp format (col 0)
            ts = row[0].strip()
            return bool(ts and ts[0].isdigit() and len(ts) >= 19)
        # might be header row
        if row[0].lower() == "log_time" and row[11].lower() == "error_severity":
            return True
        return False
    return False


class PostgresqlParser(BaseParser):
    format_name = "postgresql"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        if filename:
            fn = filename.lower()
            if ("postgres" in fn or "pg" in fn) and fn.endswith(".csv"):
                return True
        return _is_pg_csv(content)

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        events: list[LogEvent] = []
        reader = csv.reader(io.StringIO(content))
        header = _PG_HEADER
        for row in reader:
            if not row:
                continue
            # Detect header row
            if row[0].lower() == "log_time":
                header = [c.lower().replace(" ", "_") for c in row]
                continue
            if len(row) < len(header):
                # Pad short rows
                row = row + [""] * (len(header) - len(row))
            record = dict(zip(header, row))
            if ev := _row_to_log(record):
                events.append(ev)
        logger.info("PostgreSQL parser: %d events", len(events))
        return events
