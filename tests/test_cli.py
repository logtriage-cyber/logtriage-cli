from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import logtriage
from logtriage.engine import _normalise_iso, _Py311Datetime

ROOT = Path(__file__).resolve().parents[1]


def test_version(run) -> None:
    code, out, _ = run("--version")
    assert code == 0
    assert out.strip() == f"logtriage {logtriage.__version__}"
    version_file = ROOT / "VERSION"
    if version_file.exists():
        assert logtriage.__version__ == version_file.read_text(encoding="utf-8").strip()


def test_no_command_prints_usage(run) -> None:
    code, _, err = run()
    assert code == 2
    assert "usage: logtriage" in err


def test_help_lists_every_command_and_exit_codes(run) -> None:
    code, out, _ = run("--help")
    assert code == 0
    for command in ("formats", "detect", "parse", "summary", "analyze"):
        assert command in out
    assert "exit codes:" in out


def test_unknown_option_is_a_usage_error(run, data: Path) -> None:
    code, _, err = run("parse", data / "syslog_normal.log", "--output", "xml")
    assert code == 2
    assert "invalid choice" in err


def test_verbose_flag_before_or_after_the_command(run, data: Path) -> None:
    assert run("-v", "detect", data / "syslog_normal.log")[0] == 0
    assert run("detect", "-v", data / "syslog_normal.log")[0] == 0


def test_python_dash_m(data: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "logtriage", "detect", str(data / "zeek_normal_http.log")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "zeek" in result.stdout


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2024-03-20T07:58:01.1234567Z", datetime(2024, 3, 20, 7, 58, 1, 123456, tzinfo=timezone.utc)),
        ("2024-03-20T07:58:01.123456789+00:00", datetime(2024, 3, 20, 7, 58, 1, 123456, tzinfo=timezone.utc)),
        ("2024-03-20T07:58:01.5Z", datetime(2024, 3, 20, 7, 58, 1, 500000, tzinfo=timezone.utc)),
        (
            "2024-03-20T07:58:01+0530",
            datetime(2024, 3, 20, 7, 58, 1, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        ),
        ("2024-03-20T07:58:01", datetime(2024, 3, 20, 7, 58, 1)),
    ],
)
def test_fromisoformat_backport(raw: str, expected: datetime) -> None:
    assert _Py311Datetime.fromisoformat(raw) == expected


def test_fromisoformat_backport_still_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        _Py311Datetime.fromisoformat("not a timestamp")
    assert _normalise_iso("2024-03-20") == "2024-03-20"


# Ranges a fixture may use: private, loopback, link-local, documentation, reserved.
_SAFE = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16", "198.51.100.0/24",
        "203.0.113.0/24", "240.0.0.0/4",
    )
]
_IPV4 = re.compile(r"(?<![\d.])(?<![A-Za-z]/)(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


@pytest.mark.parametrize("path", sorted((Path(__file__).parent / "data").iterdir()), ids=lambda p: p.name)
def test_fixtures_use_only_private_or_documentation_addresses(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in _IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        assert any(ip in net for net in _SAFE), f"{path.name}: routable address {ip}"
