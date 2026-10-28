# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Generic fallback parser for CSV and NDJSON (newline-delimited JSON) log formats.

Fields are resolved through ordered candidate lists (_CANDIDATES): the first
non-empty candidate wins. Keys are matched case-insensitively with spaces and
hyphens normalised ("Client IP", "original-client-ip"), against top-level
keys, dotted paths ("client.ip") and nested leaf names (except under
destination/server-side objects). Forwarded/original client addresses outrank
the immediate peer, an authenticated user outranks a generic user name, and
"@timestamp", ISO 8601, nginx time_local and epoch s/ms timestamps parse.

Input shapes: CSV with or without a header row, comma / semicolon / tab / "|"
separated (see csv_layout: fields the column names do not provide are read from
columns whose values have their shape); JSON arrays; wrapper objects holding the
record list (records/events/logs/data/items/value/results/entries, or an
Elasticsearch hits export); NDJSON; a single JSON record.

Special handling:
  request field "GET /path HTTP/1.1" is split into http_method + path.
  X-Forwarded-For lists resolve to the first (client) address.
  nginx "-" placeholder values are normalised to None.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

# Candidate source fields per canonical field, in priority order — the first
# non-empty one wins. Keys are matched after normalisation (lower-case, runs
# of spaces/hyphens/dots-in-names → "_"), so "original-client-ip", "Client IP"
# and "client_ip" all match. Nested objects are searched too (see
# _flatten): a candidate matches a top-level key, a full dotted path
# ("client.ip"), or — for objects not describing the destination/server side —
# a nested leaf name ("meta.auth_user" matches "auth_user").
#
# Priority matters (found 2026-10-16 on a real JSON access log behind a
# gateway): the immediate peer field ("client_ip") held ~10 internal hop
# addresses while a nested original/forwarded client field held the ~440 real
# clients, and "@timestamp" was not recognised at all, so every event got the
# time of analysis. Forwarded/original client fields therefore outrank peer
# fields, and an authenticated user outranks a generic user name.
_CANDIDATES: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp", "@timestamp", "time", "time_iso8601", "time_local", "datetime", "date",
        "ts", "event_time", "eventtime", "created_at", "logged_at", "timegenerated",
    ),
    "ip_address": (
        "original_client_ip", "true_client_ip", "cf_connecting_ip", "x_real_ip", "real_ip",
        "x_forwarded_for", "http_x_forwarded_for", "forwarded_for",
        "client_ip", "clientip", "client.ip", "client_address", "c_ip",
        "source_ip", "src_ip", "source.ip", "sourceip",
        "remote_addr", "remote_ip", "remoteaddr", "remote_address", "remote_host",
        "ip_address", "ipaddress", "ip",
    ),
    "http_method": ("http_method", "request_method", "method", "verb", "cs_method", "httpmethod", "http.request.method"),
    "path": (
        "path", "request_path", "url_path", "url.path", "request_uri", "uri", "request_url",
        "url", "url.original", "endpoint", "path_info", "cs_uri_stem",
    ),
    "status_code": (
        "status_code", "http_status", "http_status_code", "response_status", "statuscode", "sc_status",
        "status", "response_code", "http.response.status_code", "response", "code",
    ),
    "response_size_bytes": (
        "response_size_bytes", "bytes", "bytes_sent", "body_bytes_sent", "response_size",
        "response_content_size", "bytes_out", "sc_bytes", "size",
    ),
    "user_agent": ("user_agent", "http_user_agent", "useragent", "user_agent.original", "ua", "agent", "cs_user_agent"),
    "referrer": ("referrer", "referer", "http_referer", "cs_referer"),
    "user_principal_name": (
        "user_principal_name", "userprincipalname", "upn", "auth_user", "remote_user", "user_name",
        "username", "user", "user.name", "cs_username", "account_name", "login", "user_email", "email",
        "user_id", "userid",
    ),
}

# Nested objects describing the far side of a connection: their leaves must
# not be mistaken for the client ("destination.ip" is not the source).
_DESTINATION_PARENTS = frozenset({
    "destination", "dst", "dest", "server", "upstream", "target", "backend", "peer", "host", "observer",
})
_KEY_SEP = re.compile(r"[\s\-]+")


def _norm_key(key: str) -> str:
    return _KEY_SEP.sub("_", str(key).strip().lower())


def _flatten(record: dict[str, Any], max_depth: int = 3) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return ({dotted path: value}, {leaf name: value}) for scalar values.

    Top-level keys are their own dotted path. Leaves come from nested objects
    only, first occurrence wins, and skip anything under a destination-side
    parent.
    """
    paths: dict[str, Any] = {}
    leaves: dict[str, Any] = {}

    def walk(obj: dict[str, Any], prefix: tuple[str, ...]) -> None:
        for raw_key, value in obj.items():
            key = _norm_key(raw_key)
            path = prefix + (key,)
            if isinstance(value, dict):
                if len(path) < max_depth:
                    walk(value, path)
                continue
            paths.setdefault(".".join(path), value)
            if prefix and not (set(prefix) & _DESTINATION_PARENTS):
                leaves.setdefault(key, value)

    walk(record, ())
    return paths, leaves


def _first_ip(value: Any) -> Any:
    """X-Forwarded-For style lists ("client, proxy1, proxy2") → the client."""
    if isinstance(value, str) and "," in value:
        return value.split(",", 1)[0].strip()
    return value


# Nginx uses "-" as a placeholder for missing optional fields; strip these.
def _clean(val: Any) -> Any:
    """Return None for nginx '-' placeholders and empty strings."""
    if isinstance(val, str) and val.strip() in ("-", ""):
        return None
    return val or None


def _normalise_keys(record: dict[str, Any]) -> dict[str, Any]:
    paths, leaves = _flatten(record)
    out: dict[str, Any] = {}
    for canonical, candidates in _CANDIDATES.items():
        for name in candidates:
            value = paths.get(name)
            if _clean(value) is None and "." not in name:
                value = leaves.get(name)
            if _clean(value) is not None:
                out[canonical] = _first_ip(value) if canonical == "ip_address" else value
                break

    # Handle nginx-style request line: "GET /path HTTP/1.1" → method + path
    request_line = paths.get("request")
    if isinstance(request_line, str) and request_line.strip():
        parts = request_line.split()
        if len(parts) >= 2 and not out.get("http_method"):
            out["http_method"] = parts[0]
        if len(parts) >= 2 and not out.get("path"):
            out["path"] = parts[1]

    return out


def _try_parse_ts(raw: Any) -> datetime | None:
    """The time in `raw`, or None when it holds no time this reader understands."""
    if raw is None or raw == "":
        return None
    # Epoch seconds or milliseconds (numbers or numeric strings), only within
    # plausible ranges (2001-2286) so a compact date such as 20261015 is not
    # misread as a 1970 timestamp.
    if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.strip().replace(".", "", 1).isdigit()):
        try:
            value = float(raw)
            if 1e12 <= value < 1e13:  # milliseconds
                value /= 1000
            if 1e9 <= value < 1e10:
                return datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass
    s = str(raw).strip()
    try:  # ISO 8601 incl. "Z", fractions (SQL Server's 7 digits too) and offsets
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%b/%Y:%H:%M:%S %z",         # nginx $time_local: "17/May/2015:08:05:32 +0000"
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_ts(raw: Any) -> datetime:
    return _try_parse_ts(raw) or datetime.now(timezone.utc)


def _record_to_event(record: dict[str, Any], source_format: LogFormat = LogFormat.GENERIC_JSON) -> LogEvent | None:
    norm = _normalise_keys(record)

    def _int(key: str) -> int | None:
        raw = norm.get(key)
        if raw is None:
            return None
        try:
            return int(raw)
        except (ValueError, TypeError):
            return None

    return LogEvent(
        source_format=source_format,
        timestamp=_parse_ts(norm.get("timestamp")),
        ip_address=_clean(norm.get("ip_address")),
        user_agent=_clean(norm.get("user_agent")),
        http_method=_clean(norm.get("http_method")),
        path=_clean(norm.get("path")),
        status_code=_int("status_code"),
        response_size_bytes=_int("response_size_bytes"),
        referrer=_clean(norm.get("referrer")),
        user_principal_name=_clean(norm.get("user_principal_name")),
    )


def parse_ndjson(raw_text: str) -> list[LogEvent]:
    """Parse newline-delimited JSON (one JSON object per line)."""
    events: list[LogEvent] = []
    for i, line in enumerate(raw_text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if event := _record_to_event(record):
                events.append(event)
        except (json.JSONDecodeError, Exception) as exc:
            logger.debug("NDJSON line %d skipped: %s", i + 1, exc)
    logger.info("NDJSON parser: %d events", len(events))
    return events


# Wrapper keys that commonly hold the record list in exported JSON documents.
_CONTAINER_KEYS = ("records", "events", "logs", "data", "items", "value", "results", "entries", "hits")


def parse_json(raw_text: str) -> list[LogEvent]:
    """Parse a JSON array, a wrapper object holding a record list, or NDJSON.

    The registry has always advertised "JSON array or NDJSON", but only the
    NDJSON path existed, so a pretty-printed array parsed to nothing.
    """
    stripped = raw_text.strip()
    try:
        doc = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return parse_ndjson(raw_text)  # several objects, one per line
    records: list[Any] = []
    if isinstance(doc, list):
        records = doc
    elif isinstance(doc, dict):
        for key in _CONTAINER_KEYS:
            inner = doc.get(key)
            if isinstance(inner, dict) and isinstance(inner.get("hits"), list):  # Elasticsearch export
                inner = [h.get("_source", h) for h in inner["hits"] if isinstance(h, dict)]
            if isinstance(inner, list) and inner and all(isinstance(r, dict) for r in inner):
                records = inner
                break
        else:
            records = [doc]  # a single record
    events: list[LogEvent] = []
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        try:
            if event := _record_to_event(record):
                events.append(event)
        except Exception as exc:
            logger.debug("JSON record %d skipped: %s", i + 1, exc)
    logger.info("JSON parser: %d events", len(events))
    return events


# ── CSV layout ────────────────────────────────────────────────────────────────
# A CSV can arrive without a header row (a database or script export) or with ";",
# tab or "|" between its fields (Excel in many locales). Until 2026-10-27 this reader
# split on commas only and took the first row as the header, so neither kind mapped a
# single field: a real 109,356-row export without a header "completed" with no time,
# address or user in any event, and was reported as low risk. Now the delimiter is
# sniffed, a first row that holds data is read as data, and any canonical field the
# column names do not provide is taken from a column whose values have its shape
# (addresses, e-mail addresses, times, URLs) — never from a destination-side column.

_SAMPLE_ROWS = 200
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"})
_EMAIL_VALUE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[A-Za-z]{2,}$")
# A user agent starts with product/version ("Mozilla/5.0 (…)", "curl/8.0.1", "sqlmap/1.7.8");
# a version starting with a digit keeps out "text/html" and "api/v1".
_UA_VALUE = re.compile(r"^[A-Za-z][\w.+-]*/\d[\w.+-]*(?:\s|$)")
_HAS_CLOCK = re.compile(r"\d{1,2}:\d{2}")
_DESTINATION_NAME = re.compile(r"(^|_)(dst|dest|destination|server|target|upstream|backend|host|to)(_|$)")
# Shapes that a column name never has: a first row holding one of them is data.
_DATA_SHAPES = frozenset({"ip", "email", "datetime", "date", "path", "user_agent"})
# Which shape fills which canonical field, in order; a date-only column is the time
# only when no column holds a full date and time.
_FIELD_SHAPES: tuple[tuple[str, str], ...] = (
    ("timestamp", "datetime"), ("ip_address", "ip"), ("user_principal_name", "email"), ("path", "path"),
    ("user_agent", "user_agent"), ("http_method", "method"), ("status_code", "status"), ("timestamp", "date"),
)
FIELD_LABELS = {
    "timestamp": "the time", "ip_address": "the client address", "user_principal_name": "the user",
    "path": "the URL or path", "user_agent": "the user agent", "http_method": "the HTTP method",
    "status_code": "the status code",
}


def _count_outside_quotes(line: str, delim: str) -> int:
    count, quoted = 0, False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        elif ch == delim and not quoted:
            count += 1
    return count


def _sniff_delimiter(first_line: str) -> str:
    """The separator used most outside quotes in the first line (comma on a tie)."""
    best, best_count = ",", -1
    for delim in (",", ";", "\t", "|"):
        count = _count_outside_quotes(first_line, delim)
        if count > best_count:
            best, best_count = delim, count
    return best


def _cell_shape(value: str) -> str:
    v = value.strip()
    if not v or v == "-":
        return "empty"
    if v.upper() in _HTTP_METHODS:
        return "method"
    if v.isdigit():
        if len(v) == 3 and 100 <= int(v) <= 599:
            return "status"
        if len(v) in (10, 13) and _try_parse_ts(v) is not None:
            return "datetime"
        return "int"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _EMAIL_VALUE.match(v):
        return "email"
    if v.lower().startswith(("http://", "https://")) or (v.startswith("/") and " " not in v):
        return "path"
    if _UA_VALUE.match(v):
        return "user_agent"
    if _try_parse_ts(v) is not None:
        return "datetime" if _HAS_CLOCK.search(v) else "date"
    return "text"


def _column_shapes(rows: list[list[str]], columns: int) -> list[str]:
    """The shape of each column: the one at least 80% of its non-empty cells have."""
    shapes = []
    for c in range(columns):
        seen = [s for s in (_cell_shape(r[c]) for r in rows if c < len(r)) if s != "empty"]
        top, count = Counter(seen).most_common(1)[0] if seen else ("empty", 0)
        shapes.append(top if seen and count >= 0.8 * len(seen) else "mixed")
    return shapes


@dataclass
class CsvLayout:
    delimiter: str
    has_header: bool
    names: list[str]             # the key of each column in the records built from rows
    by_value: dict[int, str]     # column index -> canonical field read from its values
    columns: int
    shapes: list[str] = field(default_factory=list)   # what each column's values look like (_cell_shape)
    header: list[str] = field(default_factory=list)   # the header row as written, when there is one


def columns_read(layout: CsvLayout) -> dict[int, str]:
    """Column index -> the canonical field the reader takes from it, by its name or by its
    values (columns read by value carry the field's own name, which leads its candidate list).
    The first candidate name present wins, as in _normalise_keys."""
    normalised = [_norm_key(n) for n in layout.names]
    out: dict[int, str] = {}
    for field_name, candidates in _CANDIDATES.items():
        for candidate in candidates:
            if candidate in normalised:
                out[normalised.index(candidate)] = field_name
                break
    return out


def csv_layout(text: str) -> CsvLayout:
    """How to read a CSV: delimiter, whether the first row is a header, and which column
    gives each canonical field. Reads the first rows only."""
    text = text.lstrip("﻿")
    first_line = next((line for line in text.splitlines() if line.strip()), "")
    delimiter = _sniff_delimiter(first_line)
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    sample = [row for _, row in zip(range(_SAMPLE_ROWS + 1), (r for r in reader if any(c.strip() for c in r)))]
    if not sample:
        return CsvLayout(delimiter, True, [], {}, 0)
    first, rest = sample[0], sample[1:]
    columns = max(len(r) for r in sample)
    body_shapes = _column_shapes(rest or [first], columns)
    first_shapes = [_cell_shape(c) for c in first]
    data_cells = [i for i, s in enumerate(first_shapes) if s in _DATA_SHAPES]
    # Compare only columns the rows below say something about: a user column that is empty
    # after row 1 made a data row look like a header (found by the CSV shape tests).
    comparable = [i for i in data_cells if body_shapes[i] not in ("empty", "mixed")]
    has_header = not comparable or not all(body_shapes[i] == first_shapes[i] for i in comparable)

    names = [str(n) for n in first] if has_header else []
    names += [f"column_{i + 1}" for i in range(len(names), columns)]
    normalised = [_norm_key(n) for n in names]
    provided = {f for f, cands in _CANDIDATES.items() if any(n in cands for n in normalised)} if has_header else set()
    shapes = body_shapes if has_header else _column_shapes(sample, columns)
    taken = {i for i, n in enumerate(normalised) if any(n in cands for cands in _CANDIDATES.values())} if has_header else set()
    by_value: dict[int, str] = {}
    for field_name, shape in _FIELD_SHAPES:
        if field_name in provided or field_name in by_value.values():
            continue
        for i, s in enumerate(shapes):
            if s == shape and i not in taken and i not in by_value and not _DESTINATION_NAME.search(normalised[i]):
                by_value[i] = field_name
                break
    for i, field_name in by_value.items():
        names[i] = field_name
    return CsvLayout(delimiter, has_header, names, by_value, columns, shapes=list(shapes),
                     header=[str(n) for n in first] if has_header else [])


def describe_layout(layout: CsvLayout) -> str | None:
    """One sentence for the report when columns were read by their values, else None."""
    if not layout.by_value:
        return None
    read = "; ".join(f"column {i + 1} as {FIELD_LABELS[f]}" for i, f in sorted(layout.by_value.items()))
    if layout.has_header:
        return f"Some column names were not ones LogTriage knows, so it read columns by their values: {read}."
    return f"This CSV has no header row, so LogTriage read its columns by their values: {read}."


def parse_csv(raw_text: str) -> list[LogEvent]:
    """Parse a generic CSV: sniffed delimiter, header row optional (see csv_layout)."""
    text = raw_text.lstrip("﻿")
    layout = csv_layout(text)
    reader = csv.reader(io.StringIO(text), delimiter=layout.delimiter)
    events: list[LogEvent] = []
    header_skipped = not layout.has_header
    for i, row in enumerate(reader):
        if not any(c.strip() for c in row):
            continue
        if not header_skipped:
            header_skipped = True
            continue
        try:
            record = {name: (row[c] if c < len(row) else "") for c, name in enumerate(layout.names)}
            if event := _record_to_event(record, source_format=LogFormat.GENERIC_CSV):
                events.append(event)
        except Exception as exc:
            logger.debug("CSV row %d skipped: %s", i + 1, exc)
    logger.info("CSV parser: %d events (delimiter %r, header %s, by value %s)",
                len(events), layout.delimiter, layout.has_header, layout.by_value or "-")
    return events


# Common/Combined Log Format: client ident user [time] "request", optionally after
# leading fields such as a forwarded-for address or Apache's vhost:port
_CLF_PREFIX = re.compile(r'^(?:\S+ ){0,3}?\S+ \S+ \S+ \[[^\]]+\] "')


class GenericCsvParser(BaseParser):
    """Plugin-registry entry for generic CSV logs."""

    format_name = "generic_csv"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        stripped = content.strip()
        if stripped.startswith(("{", "[")):
            return False
        lines = [line for line in stripped.splitlines()[:20] if line.strip()][:5]
        first = lines[0] if lines else ""
        if not first or _CLF_PREFIX.match(first):
            return False  # an access log saved as .csv (its user agents contain commas)
        delim = _sniff_delimiter(first)
        count = _count_outside_quotes(first, delim)
        if count < 1:
            return False
        if filename.lower().endswith(".csv"):
            return True
        # Content decides, not the name. A comma header row that does not start with a digit
        # (nginx lines start with an address) as before; any other separator, or a first row
        # of data, needs the same count on every sampled line (at least two for data) — one
        # stray tab or ";" in the first line of arbitrary text or binary data is not a table.
        consistent = len(lines) >= 2 and all(_count_outside_quotes(line, delim) == count for line in lines)
        if not first[0].isdigit():
            return delim == "," or consistent
        return count >= 2 and len(lines) >= 3 and consistent

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_csv(content)


class GenericJsonParser(BaseParser):
    """Plugin-registry entry for generic JSON array / NDJSON logs."""

    format_name = "generic_json"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        stripped = content.strip()
        if stripped.startswith(("{", "[")):
            return True
        # NDJSON — first non-empty line is a JSON object
        for line in stripped.splitlines():
            if line.strip():
                try:
                    return isinstance(json.loads(line), dict)
                except (json.JSONDecodeError, ValueError):
                    return False
        return False

    @classmethod
    def parse(cls, content: str, filename: str = "") -> list[LogEvent]:
        return parse_json(content)
