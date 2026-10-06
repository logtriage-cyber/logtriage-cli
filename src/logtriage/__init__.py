"""LogTriage CLI: parse and triage security logs locally.

The parsers in ``logtriage.parsers`` are the ones the hosted LogTriage service
runs (https://logtriage.app). Everything except ``logtriage analyze`` works
offline.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _version() -> str:
    try:
        return version("logtriage")
    except PackageNotFoundError:
        # Running from a source checkout without installing (PYTHONPATH=src).
        version_file = Path(__file__).resolve().parents[2] / "VERSION"
        try:
            return version_file.read_text(encoding="utf-8").strip()
        except OSError:
            return "0.0.0"


__version__ = _version()

__all__ = ["__version__"]
