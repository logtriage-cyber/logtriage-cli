from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"

# Fixture file -> (detected format id, event count). All fixtures are benign
# sample logs that use private or documentation (RFC 5737) IP addresses.
FIXTURES: dict[str, tuple[str, int]] = {
    "authlog_normal.log": ("auth_log", 20),
    "cisco_asa_normal.log": ("cisco_asa", 6),
    "cloudtrail_normal_operations.json": ("cloudtrail", 4),
    "generic_normal_api.csv": ("generic_csv", 12),
    "m365_normal_activity.json": ("m365_audit", 6),
    "nginx_api_developer.log": ("nginx", 15),
    "syslog_normal.log": ("syslog", 14),
    "vpc_flow_benign.log": ("vpc_flow", 10),
    "windows_normal_logons.xml": ("evtx", 7),
    "zeek_normal_http.log": ("zeek", 5),
}


@pytest.fixture
def data() -> Path:
    return DATA


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Callable[..., tuple[int, str, str]]:
    """Run the CLI in-process. Returns (exit code, stdout, stderr)."""
    from logtriage.cli import main

    def _run(*args: object) -> tuple[int, str, str]:
        code = main([str(arg) for arg in args])
        out, err = capsys.readouterr()
        return code, out, err

    return _run
