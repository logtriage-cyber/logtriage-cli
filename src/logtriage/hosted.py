"""Client for the hosted LogTriage service, used only by ``logtriage analyze``.

This is the only module that opens network connections. It uses the public
REST API (https://api.logtriage.app): upload with ``POST /analyze``, poll
``GET /jobs/{id}``, then fetch ``GET /jobs/{id}/report``.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from logtriage import __version__
from logtriage.engine import LogTriageError

DEFAULT_API_URL = "https://api.logtriage.app"
DEFAULT_APP_URL = "https://app.logtriage.app"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # the service's upload limit
# Cloudflare in front of the API rejects urllib's default User-Agent.
USER_AGENT = f"logtriage-cli/{__version__} (+https://logtriage.app)"

EXIT_TIMEOUT = 4
FINAL_STATUSES = frozenset({"complete", "failed"})
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_TRANSIENT_ERRORS = 5

# Indirection points for tests (no network, no real waiting).
_sleep = time.sleep
_clock = time.monotonic


class ApiError(LogTriageError):
    """The service could not be reached or answered with an error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class TimedOut(LogTriageError):
    exit_code = EXIT_TIMEOUT


def _send(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    """Perform one HTTP request and return (status, body). Raises on network errors."""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _detail(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except ValueError:
        return ""
    if isinstance(payload, dict):
        detail = payload.get("detail") or payload.get("message") or ""
        return detail if isinstance(detail, str) else json.dumps(detail)
    return ""


def _safe_filename(name: str) -> str:
    """ASCII-only file name for the multipart header (keeps the extension the
    service uses as a format hint)."""
    cleaned = "".join(ch if 32 <= ord(ch) < 127 and ch not in '"\\' else "_" for ch in name)
    return cleaned or "upload.log"


def multipart_body(path: Path) -> tuple[Iterator[bytes], int, str]:
    """Stream a single-file multipart/form-data body (field ``file``).

    Returns (chunks, content_length, content_type). The file is read in blocks
    while it is sent, never loaded into memory as a whole.
    """
    boundary = f"logtriage-{uuid.uuid4().hex}"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{_safe_filename(path.name)}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("ascii")
    tail = f"\r\n--{boundary}--\r\n".encode("ascii")
    size = path.stat().st_size

    def chunks() -> Iterator[bytes]:
        yield head
        with path.open("rb") as fh:
            while block := fh.read(64 * 1024):
                yield block
        yield tail

    return chunks(), len(head) + size + len(tail), f"multipart/form-data; boundary={boundary}"


class Client:
    def __init__(self, api_key: str, api_url: str = DEFAULT_API_URL, app_url: str = DEFAULT_APP_URL):
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.app_url = app_url.rstrip("/")

    def report_url(self, job_id: str) -> str:
        return f"{self.app_url}/app/report/{urllib.parse.quote(job_id)}"

    def _call(
        self,
        method: str,
        path: str,
        data: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        request = urllib.request.Request(
            self.api_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                **(headers or {}),
            },
        )
        try:
            status, body = _send(request, timeout)
        except (OSError, http.client.HTTPException) as exc:  # URLError is an OSError
            reason = getattr(exc, "reason", None) or exc
            raise ApiError(f"could not reach {self.api_url}: {reason}") from None
        if 200 <= status < 300:
            try:
                return json.loads(body)
            except ValueError:
                raise ApiError(
                    f"unexpected response from {self.api_url} (HTTP {status}, not JSON)", status
                ) from None
        raise ApiError(self._explain(status, _detail(body)), status)

    def _explain(self, status: int, detail: str) -> str:
        hints = {
            401: f"check the API key; create one at {self.app_url}/app/integrations",
            402: f"no analysis credits left; see {self.app_url}/app/billing",
            404: "not found",
            413: "the file is larger than the service accepts (100 MB)",
            429: "rate limited; wait a minute and try again",
        }
        message = f"the service returned HTTP {status}"
        if detail:
            message += f": {detail}"
        hint = hints.get(status)
        if hint is None and status >= 500:
            hint = "service error; try again later"
        return f"{message} ({hint})" if hint else message

    def upload(self, path: Path) -> str:
        """Upload a log file; returns the job id."""
        body, length, content_type = multipart_body(path)
        payload = self._call(
            "POST",
            "/analyze",
            data=body,
            headers={"Content-Type": content_type, "Content-Length": str(length)},
            timeout=300.0,
        )
        job_id = payload.get("job_id") if isinstance(payload, dict) else None
        if not isinstance(job_id, str) or not job_id:
            raise ApiError("the service accepted the upload but returned no job id")
        return job_id

    def job(self, job_id: str) -> dict[str, Any]:
        payload = self._call("GET", f"/jobs/{urllib.parse.quote(job_id)}?page_size=1")
        if not isinstance(payload, dict):
            raise ApiError("unexpected job status response")
        return payload

    def report(self, job_id: str) -> dict[str, Any]:
        payload = self._call("GET", f"/jobs/{urllib.parse.quote(job_id)}/report")
        if not isinstance(payload, dict):
            raise ApiError("unexpected report response")
        return payload

    def wait(
        self,
        job_id: str,
        timeout: float,
        on_status: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Poll until the job is complete or failed. Raises TimedOut."""
        deadline = _clock() + timeout
        delay = 2.0
        transient_errors = 0
        status = None
        while True:
            try:
                job = self.job(job_id)
            except ApiError as exc:
                transient = exc.status is None or exc.status in _TRANSIENT_STATUSES
                transient_errors += 1
                if not transient or transient_errors > _MAX_TRANSIENT_ERRORS:
                    raise
            else:
                transient_errors = 0
                if job.get("status") != status:
                    status = job.get("status")
                    if on_status is not None:
                        on_status(str(status))
                if status in FINAL_STATUSES:
                    return job
            remaining = deadline - _clock()
            if remaining <= 0:
                raise TimedOut(
                    f"no result after {timeout:.0f}s (last status: {status or 'unknown'}). "
                    f"The analysis continues on the server; open {self.report_url(job_id)} later."
                )
            _sleep(min(delay, remaining))
            delay = min(delay * 1.5, 10.0)
