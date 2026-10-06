# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Entry point for log format detection and parsing.

Delegates to format_registry which iterates registered parsers in priority order.
To add a new format: create a BaseParser subclass in a new parser_*.py file and
add it to the registry list in format_registry.py.
"""
from __future__ import annotations

import logging

from logtriage.parsers.format_registry import detect_and_parse
from logtriage.models import LogEvent

logger = logging.getLogger(__name__)


def normalize_log_file(raw_text: str, filename: str = "") -> list[LogEvent]:
    """
    Detect format and parse raw log text into a list of LogEvent objects.
    Raises ValueError on unrecoverable parse errors or unknown format.
    """
    events, _ = detect_and_parse(raw_text, filename)
    return events


def normalize_log_file_with_format(raw_text: str, filename: str = "") -> tuple[list[LogEvent], str]:
    """
    Like normalize_log_file but also returns the detected format name
    (matching LogFormat enum values, e.g. "nginx", "azure_signin").
    """
    return detect_and_parse(raw_text, filename)
