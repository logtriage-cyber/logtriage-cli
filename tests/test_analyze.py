"""``logtriage analyze`` against a fake service: the HTTP layer is replaced, no network."""
from __future__ import annotations

import gzip
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from logtriage import hosted

API = "https://api.logtriage.app"
JOB = "8d0c6a8e-1b6b-4b8f-9a55-3f1f6f3c2f10"
REPORT_URL = f"https://app.logtriage.app/app/report/{JOB}"

COMPLETE = {
    "job_id": JOB,
    "status": "complete",
    "log_format": "auth_log",
    "event_count": 20,
    "has_report": True,
    "report_severity": "LOW",
    "report_confidence": "HIGH",
    "report_model_used": "claude-haiku-4-5-20251001",
    "report_risk_score_overall": 12,
    "report_attack_pattern": "Routine administrative activity",
}
REPORT = {"severity": "LOW", "executive_summary": "Routine SSH and sudo use by known administrators."}


class FakeService:
    """Answers requests from a script of (method, path prefix) -> responses."""

    def __init__(self, routes: dict[tuple[str, str], list[Any]]) -> None:
        self.routes = {key: list(value) for key, value in routes.items()}
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
        data = request.data
        body = b"".join(data) if data is not None and not isinstance(data, bytes) else data
        url = request.full_url
        self.requests.append(
            {
                "method": request.get_method(),
                "url": url,
                "headers": {k.lower(): v for k, v in request.header_items()},
                "body": body,
            }
        )
        path = url[len(API):]
        for (method, prefix), responses in self.routes.items():
            if request.get_method() == method and path.startswith(prefix):
                response = responses.pop(0) if len(responses) > 1 else responses[0]
                if isinstance(response, Exception):
                    raise response
                status, payload = response
                return status, json.dumps(payload).encode()
        raise AssertionError(f"unexpected request {request.get_method()} {url}")


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    monkeypatch.setattr(hosted, "_sleep", sleep)
    monkeypatch.setattr(hosted, "_clock", lambda: clock[0])
    monkeypatch.delenv("LOGTRIAGE_API_KEY", raising=False)
    monkeypatch.delenv("LOGTRIAGE_APP_URL", raising=False)
    return clock


def install(monkeypatch: pytest.MonkeyPatch, routes: dict[tuple[str, str], list[Any]]) -> FakeService:
    service = FakeService(routes)
    monkeypatch.setattr(hosted, "_send", service)
    return service


def happy_routes() -> dict[tuple[str, str], list[Any]]:
    return {
        ("POST", "/analyze"): [(202, {"job_id": JOB, "status": "queued"})],
        ("GET", f"/jobs/{JOB}/report"): [(200, REPORT)],
        ("GET", f"/jobs/{JOB}"): [
            (200, {"job_id": JOB, "status": "queued"}),
            (200, {"job_id": JOB, "status": "analyzing"}),
            (200, COMPLETE),
        ],
    }


def test_analyze_uploads_polls_and_prints_the_verdict(run, data: Path, monkeypatch) -> None:
    service = install(monkeypatch, happy_routes())
    log = data / "authlog_normal.log"

    code, out, err = run("analyze", log, "--api-key", "ltk_test")

    assert code == 0, err
    assert "leaves this machine" in err
    assert "status: analyzing" in err and "status: complete" in err
    assert "Severity        LOW (confidence HIGH, risk score 12/100)" in out
    assert "Attack pattern  Routine administrative activity" in out
    assert "Model           claude-haiku-4-5-20251001" in out
    assert "Events          20 (auth_log)" in out
    assert f"Report          {REPORT_URL}" in out
    assert "Routine SSH and sudo use" in out

    upload = service.requests[0]
    assert (upload["method"], upload["url"]) == ("POST", f"{API}/analyze")
    headers = upload["headers"]
    assert headers["authorization"] == "Bearer ltk_test"
    assert headers["user-agent"].startswith("logtriage-cli/")
    assert headers["content-type"].startswith("multipart/form-data; boundary=")
    assert int(headers["content-length"]) == len(upload["body"])
    assert b'name="file"; filename="authlog_normal.log"' in upload["body"]
    assert log.read_bytes() in upload["body"]
    assert all(r["headers"]["authorization"] == "Bearer ltk_test" for r in service.requests)


def test_api_key_from_the_environment(run, data: Path, monkeypatch) -> None:
    service = install(monkeypatch, happy_routes())
    monkeypatch.setenv("LOGTRIAGE_API_KEY", "ltk_from_env")
    code, _, err = run("analyze", data / "syslog_normal.log")
    assert code == 0, err
    assert service.requests[0]["headers"]["authorization"] == "Bearer ltk_from_env"


def test_json_output(run, data: Path, monkeypatch) -> None:
    install(monkeypatch, happy_routes())
    code, out, _ = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test", "--json")
    assert code == 0
    result = json.loads(out)
    assert result["job_id"] == JOB
    assert result["severity"] == "LOW"
    assert result["report_url"] == REPORT_URL
    assert result["report"] == REPORT


def test_missing_api_key_is_a_usage_error(run, data: Path, monkeypatch) -> None:
    service = install(monkeypatch, happy_routes())
    code, _, err = run("analyze", data / "authlog_normal.log")
    assert code == 2
    assert "LOGTRIAGE_API_KEY" in err
    assert service.requests == []


def test_failed_job(run, data: Path, monkeypatch) -> None:
    routes = happy_routes()
    routes[("GET", f"/jobs/{JOB}")] = [(200, {"status": "failed", "error_message": "Log parsing timed out"})]
    install(monkeypatch, routes)
    code, _, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test")
    assert code == 1
    assert "analysis failed: Log parsing timed out" in err


def test_rejected_api_key(run, data: Path, monkeypatch) -> None:
    install(monkeypatch, {("POST", "/analyze"): [(401, {"detail": "Invalid or revoked API key"})]})
    code, _, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_wrong")
    assert code == 1
    assert "HTTP 401: Invalid or revoked API key" in err
    assert "/app/integrations" in err


def test_out_of_credits(run, data: Path, monkeypatch) -> None:
    install(monkeypatch, {("POST", "/analyze"): [(402, {"detail": "No credits remaining"})]})
    code, _, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test")
    assert code == 1
    assert "/app/billing" in err


def test_service_unreachable(run, data: Path, monkeypatch) -> None:
    install(monkeypatch, {("POST", "/analyze"): [urllib.error.URLError("Name or service not known")]})
    code, _, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test")
    assert code == 1
    assert "could not reach https://api.logtriage.app" in err


def test_transient_poll_errors_are_retried(run, data: Path, monkeypatch) -> None:
    routes = happy_routes()
    routes[("GET", f"/jobs/{JOB}")] = [
        (503, {"detail": "Service Unavailable"}),
        urllib.error.URLError("connection reset"),
        (429, {"detail": "Too Many Requests"}),
        (200, COMPLETE),
    ]
    install(monkeypatch, routes)
    code, out, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test")
    assert code == 0, err
    assert "Severity        LOW" in out


def test_timeout(run, data: Path, monkeypatch) -> None:
    routes = happy_routes()
    routes[("GET", f"/jobs/{JOB}")] = [(200, {"status": "analyzing"})]
    install(monkeypatch, routes)
    code, _, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test", "--timeout", "30")
    assert code == 4
    assert "no result after 30s" in err
    assert REPORT_URL in err


def test_rule_based_verdict_is_labelled(run, data: Path, monkeypatch) -> None:
    routes = happy_routes()
    routes[("GET", f"/jobs/{JOB}")] = [(200, {**COMPLETE, "report_model_used": "rule-based"})]
    install(monkeypatch, routes)
    code, out, _ = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test")
    assert code == 0
    assert "Model           rule-based (no AI call was made)" in out


def test_files_the_service_cannot_take_are_refused_locally(run, data: Path, tmp_path: Path, monkeypatch) -> None:
    service = install(monkeypatch, happy_routes())

    gz = tmp_path / "auth.log.gz"
    gz.write_bytes(gzip.compress((data / "authlog_normal.log").read_bytes()))
    code, _, err = run("analyze", gz, "--api-key", "ltk_test")
    assert code == 2 and "gunzip" in err

    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    code, _, err = run("analyze", empty, "--api-key", "ltk_test")
    assert code == 2 and "empty" in err

    monkeypatch.setattr(hosted, "MAX_UPLOAD_BYTES", 100)
    code, _, err = run("analyze", data / "authlog_normal.log", "--api-key", "ltk_test")
    assert code == 2 and "100 MB limit" in err

    code, _, err = run("analyze", tmp_path / "missing.log", "--api-key", "ltk_test")
    assert code == 1 and "no such file" in err

    assert service.requests == []


def test_multipart_body_streams_the_file(tmp_path: Path) -> None:
    log = tmp_path / "w\u00e9ird name.log"
    log.write_bytes(b"line one\nline two\n")
    chunks, length, content_type = hosted.multipart_body(log)
    body = b"".join(chunks)
    assert len(body) == length
    boundary = content_type.split("boundary=")[1]
    assert body.startswith(f"--{boundary}\r\n".encode())
    assert body.endswith(f"\r\n--{boundary}--\r\n".encode())
    assert b'filename="w_ird name.log"' in body
    assert b"\r\n\r\nline one\nline two\n\r\n" in body
