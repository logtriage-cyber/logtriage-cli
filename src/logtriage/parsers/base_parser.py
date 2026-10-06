# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""Abstract base class for all log format parsers."""
from __future__ import annotations

from abc import ABC, abstractmethod

from logtriage.models import LogEvent


class BaseParser(ABC):
    """All format parsers must inherit from this class and implement both methods."""

    format_name: str  # e.g. "nginx", "cloudtrail"

    @classmethod
    @abstractmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        """Return True if this parser can handle the given content/filename."""
        ...

    @classmethod
    @abstractmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        """Parse content into a list of LogEvent. Never returns None."""
        ...
