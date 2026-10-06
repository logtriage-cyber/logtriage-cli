"""Read log files and run them through the parser registry.

Nothing in this module touches the network.
"""
from __future__ import annotations

import codecs
import difflib
import gzip
import logging
import re
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from logtriage.formats import CATCH_ALL, display_name
from logtriage.models import LogEvent

logger = logging.getLogger(__name__)

EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNRECOGNISED = 3

EVTX_MAGIC = b"ElfFile\x00"
GZIP_MAGIC = b"\x1f\x8b"


class LogTriageError(Exception):
    """An error with a message meant for the user and a process exit code."""

    exit_code = EXIT_ERROR


class UsageError(LogTriageError):
    exit_code = EXIT_USAGE


class UnrecognisedFormat(LogTriageError):
    exit_code = EXIT_UNRECOGNISED


@dataclass
class ParsedFile:
    path: Path
    format_id: str
    events: list[LogEvent]

    @property
    def format_name(self) -> str:
        return display_name(self.format_id)


# ---------------------------------------------------------------------------
# Parser registry
# ---------------------------------------------------------------------------

_PARSERS: list[Any] | None = None


def parsers() -> list[Any]:
    """Parser classes in detection order: most specific first, catch-alls last."""
    global _PARSERS
    if _PARSERS is None:
        from logtriage.parsers import format_registry

        _PARSERS = list(format_registry._build_registry())
        if sys.version_info < (3, 11):
            _backport_fromisoformat()
    return _PARSERS


def parser_ids() -> list[str]:
    return [cls.format_name for cls in parsers()]


def parser_for(format_id: str) -> Any:
    """The parser class for a format id, e.g. ``"cloudtrail"``."""
    for cls in parsers():
        if cls.format_name == format_id:
            return cls
    close = difflib.get_close_matches(format_id, parser_ids(), n=3)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    raise UsageError(
        f"unknown format {format_id!r}.{hint} Run 'logtriage formats' to list the format ids."
    )


def detect(text: str, filename: str) -> Any | None:
    """The first parser whose ``can_parse`` accepts the content, or None.

    A ``can_parse`` that raises (for example the csv module rejecting NUL
    bytes on Python 3.10) counts as "not this format".
    """
    for cls in parsers():
        try:
            if cls.can_parse(text, filename):
                return cls
        except Exception as exc:
            logger.debug("%s.can_parse failed (%s); trying the next parser", cls.__name__, exc)
    return None


# ---------------------------------------------------------------------------
# Python 3.10 compatibility
# ---------------------------------------------------------------------------

_ISO_FRACTION = re.compile(r"(?<=\d\d:\d\d:\d\d)[.,](\d+)")
_ISO_BASIC_OFFSET = re.compile(r"(?<=\d)([+-]\d\d)(\d\d)$")


def _normalise_iso(value: str) -> str:
    text = value
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _ISO_FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    return _ISO_BASIC_OFFSET.sub(r"\1:\2", text)


class _Py311Datetime(datetime):
    """``datetime`` whose ``fromisoformat`` accepts what Python 3.11+ accepts.

    The parsers run in production on Python 3.11+, where ``fromisoformat``
    understands a trailing ``Z``, fractional seconds of any length (Windows
    writes 7 digits, GCP 9) and ``+HHMM`` offsets. Python 3.10 rejects all
    three, and the parsers then fall back to the current time. On 3.10 only,
    the parser modules' ``datetime`` name is pointed at this subclass.
    """

    @classmethod
    def fromisoformat(cls, date_string: str) -> _Py311Datetime:
        try:
            return super().fromisoformat(date_string)
        except ValueError:
            if not isinstance(date_string, str):
                raise
            fixed = _normalise_iso(date_string)
            if fixed == date_string:
                raise
            return super().fromisoformat(fixed)


def _backport_fromisoformat() -> None:
    for name, module in list(sys.modules.items()):
        if name.startswith("logtriage.parsers.") and getattr(module, "datetime", None) is datetime:
            module.datetime = _Py311Datetime  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Reading files
# ---------------------------------------------------------------------------


def decode(raw: bytes) -> str:
    """Decode log bytes: honour a UTF-8/16/32 byte-order mark, else UTF-8.

    Undecodable bytes become U+FFFD instead of failing, as in the hosted service.
    """
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig", errors="replace")
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return raw.decode("utf-32", errors="replace")
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _peek(path: Path) -> bytes:
    if path.is_dir():
        raise LogTriageError(f"{path}: is a directory")
    try:
        with path.open("rb") as fh:
            return fh.read(8)
    except FileNotFoundError:
        raise LogTriageError(f"{path}: no such file") from None
    except OSError as exc:
        raise LogTriageError(f"{path}: cannot read file: {exc.strerror or exc}") from None


def _read_text(path: Path, gzipped: bool) -> str:
    try:
        if gzipped:
            with gzip.open(path, "rb") as fh:
                raw = fh.read()
        else:
            raw = path.read_bytes()
    except (EOFError, OSError, zlib.error) as exc:
        kind = "gzip file" if gzipped else "file"
        raise LogTriageError(f"{path}: cannot read {kind}: {exc}") from None
    # The bytes are released when this returns, so only the decoded text
    # stays in memory while the file is parsed.
    return decode(raw)


def _export_hint(path: Path) -> str:
    return f'wevtutil qe "{path}" /lf:true /f:xml /e:Events > events.xml'


def _parse_binary_evtx(path: Path) -> list[LogEvent]:
    from logtriage.parsers.parser_evtx import parse_evtx_binary

    try:
        return parse_evtx_binary(str(path))
    except ImportError:
        raise LogTriageError(
            f"{path}: binary .evtx files need the optional python-evtx package "
            "(pip install 'logtriage[evtx]'), or export the log to XML first: "
            f"{_export_hint(path)}"
        ) from None
    except Exception as exc:  # python-evtx raises many exception types
        raise LogTriageError(f"{path}: cannot read the .evtx file: {exc}") from None


def _unrecognised(path: Path, format_id: str | None, text: str, forced: bool) -> UnrecognisedFormat:
    if not text.strip():
        return UnrecognisedFormat(f"{path}: the file is empty")
    if forced and format_id:
        return UnrecognisedFormat(
            f"{path}: no events could be parsed as {display_name(format_id)} ({format_id})"
        )
    if format_id is None or format_id in CATCH_ALL:
        binary = " The file looks binary (it contains NUL bytes)." if "\x00" in text[:8192] else ""
        return UnrecognisedFormat(
            f"{path}: format not recognised; no records matched a supported format.{binary} "
            "Run 'logtriage formats' for the list, and if the file is one of them, "
            "force its parser with --format ID."
        )
    return UnrecognisedFormat(
        f"{path}: looks like {display_name(format_id)} ({format_id}), "
        "but no events could be parsed from it"
    )


def load(path: str | Path, format_id: str | None = None) -> ParsedFile:
    """Read one log file, detect its format (unless forced) and parse it.

    Handles plain text (UTF-8, or UTF-16/32 with a byte-order mark),
    gzip-compressed text and, with the ``evtx`` extra, binary Windows .evtx.
    Raises ``LogTriageError`` (or a subclass) with a user-facing message.
    """
    path = Path(path)
    forced = parser_for(format_id) if format_id else None
    head = _peek(path)

    if head.startswith(EVTX_MAGIC) and (forced is None or forced.format_name == "evtx"):
        events = _parse_binary_evtx(path)
        if not events:
            raise UnrecognisedFormat(
                f"{path}: no supported Windows Security events in this .evtx file. "
                "For other channels (Sysmon, for example), export to XML and parse that: "
                f"{_export_hint(path)}"
            )
        return ParsedFile(path, "evtx", events)

    gzipped = head.startswith(GZIP_MAGIC)
    # Detection hints use the file name, so "auth.log.gz" is judged as "auth.log".
    name = path.name[:-3] if gzipped and path.name.lower().endswith(".gz") else path.name
    text = _read_text(path, gzipped)

    parser = forced or detect(text, name)
    if parser is None:
        raise _unrecognised(path, None, text, forced=False)
    try:
        events = parser.parse(text, name)
    except Exception as exc:  # surface any parser failure as a clean error
        if forced is not None:  # the content is not in the format the user named
            raise UnrecognisedFormat(
                f"{path}: cannot be parsed as {display_name(parser.format_name)} "
                f"({parser.format_name}): {exc}"
            ) from None
        raise LogTriageError(
            f"{path}: looks like {display_name(parser.format_name)} ({parser.format_name}) "
            f"but could not be parsed: {exc}"
        ) from None
    if not events:
        raise _unrecognised(path, parser.format_name, text, forced=forced is not None)
    return ParsedFile(path, parser.format_name, events)
