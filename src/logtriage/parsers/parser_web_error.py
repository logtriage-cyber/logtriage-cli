# Synced from the LogTriage service (https://logtriage.app). Edits made here are
# overwritten on the next sync; see 'Contributing' in README.md.
"""
Web server error logs: Apache HTTP Server 2.2 / 2.4 and nginx (2026-11-04).

The first upload of a company that signed up that morning (job 54bd64e2) was an Apache error log —
22,200 lines of PHP warnings, client denials and probes for missing scripts — and no reader took
it: its lines start with "[", so the generic JSON reader claimed the file and read nothing.

Apache (https://httpd.apache.org/docs/2.4/logs.html#errorlog,
https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat). The 2.4 default for threaded
MPMs is "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\\ %a] %M% ,\\ referer\\ %{Referer}i":
  [Thu May 12 08:28:57.652118 2011] [core:error] [pid 8777:tid 4326490112] [client ::1:58619] AH00124: ...
prefork writes "[pid N]" alone, 2.2 has no module and no microseconds ("[%t] [%l] ..."), and the
client is "address:port" (an IPv6 address unbracketed). Messages read, with the status Apache
answers for them, as written in the 2.4.x source (APLOGNO ids):
  AH00128 core              "File does not exist: %s"                                   404
  AH01630 mod_authz_core,
  AH01797 mod_access_compat "client denied by server configuration: %s%s"               403
  AH01276 mod_autoindex     "Cannot serve directory %s: No matching DirectoryIndex ..."  403
  AH01617 mod_auth_basic    "user %s: authentication failure for \"%s\": Password Mismatch"  401
  AH01618 mod_auth_basic    "user %s not found: %s"                                     401
  AH00126 core              "Invalid URI in request '%s' '%s'"  (the request line)      400
  AH00135 core              "Invalid method in request %s"      (the request line)
  AH00565 protocol          "request failed: client's request-line exceeds LimitRequestLine ..."  414
PHP writes "PHP %s:  %s in %s on line %u" (main/main.c; a fatal error is the 500 the client got)
and mod_php "script '%s' not found or unable to stat" (the 404 of a missing .php file).
ModSecurity v2 ends its lines with " [uri \"%s\"]" (apache2/apache2_util.c): that is the path.

nginx (src/core/ngx_log.c, src/http/ngx_http_request.c): "YYYY/MM/DD HH:MM:SS [level] pid#tid:
*connection message", then ", client: %V", ", server: %V", ", request: \"%V\"", ", upstream:
\"%V\"", ", host: \"%V\"", ", referrer: \"%V\"". Messages, from the modules' source:
  ngx_http_static_module   "%s \"%s\" failed" + " (errno: text)"   2/20 → 404, 13 → 403
  ngx_http_access_module   "access forbidden by rule"                                    403
  ngx_http_index_module    "directory index of \"%s\" is forbidden"                     403
  ngx_http_auth_basic      "user \"%V\" was not found in \"%s\"", "user \"%V\": password mismatch"  401
  ngx_http_limit_req       "limiting requests%s, excess: ... by zone \"%V\""  503 (not in dry run)
  ngx_http_core_module     "client intended to send too large body: %O bytes"           413
  ngx_http_upstream        "upstream timed out" 504; connect() failed / no live upstreams 502

Neither format writes a time zone (the server's local time): times are read as UTC. A basic-auth
failure (401 with a user) is a failed login for the brute-force checks (pattern_detector).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime

from logtriage.parsers.base_parser import BaseParser
from logtriage.models import LogEvent, LogFormat

logger = logging.getLogger(__name__)

_LEVELS = r"emerg|alert|crit|error|warn|notice|info|debug|trace[1-8]"
_APACHE_RE = re.compile(
    r"^\[(?P<ts>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} "
    r"\d\d:\d\d:\d\d(?:\.\d{1,6})? \d{4})\] \[(?:(?P<module>[\w.-]+):)?(?P<level>" + _LEVELS + r")\](?P<rest>.*)$"
)
_NGINX_RE = re.compile(
    r"^(?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<level>emerg|alert|crit|error|warn|notice|info|debug)\] "
    r"\d+#\d+: (?:\*\d+ )?(?P<rest>.*)$"
)
_PID_RE = re.compile(r"^ \[pid \d+(?::tid \d+)?\]")
_CLIENT_RE = re.compile(r"\[client ([^\]]+)\]")
_LEADING_RE = re.compile(r"^(?:\s*\[[^\]]*\])*\s*(?:[\w.-]+\.c\(\d+\): )?(?:\(\d+\)[^:\[]*: )?")
_REFERER_RE = re.compile(r", referer: (\S+)\s*\Z")
_AH_RE = re.compile(r"^AH(\d{5}): ")
_NGINX_FIELD_RE = re.compile(r', (client|server|request|subrequest|upstream|host|referrer): ("(?:[^"\\]|\\.)*"|[^,]*)')
_REQUEST_LINE_RE = re.compile(r"^([A-Z][A-Z0-9_-]{0,19}) (\S+)(?: HTTP/[\d.]+)?$")
_STATUS_FROM_CODE = {"00128": 404, "01630": 403, "01797": 403, "01276": 403, "01617": 401, "01618": 401,
                     "00126": 400, "00565": 414}
_MAX_MESSAGE = 500


def _client_ip(value: str) -> str | None:
    """Apache's "%a" is address:port, an IPv6 address unbracketed ("::1:58619"); 2.2 has no port."""
    v = value.strip().strip("[]")
    for candidate in (v, v.rsplit(":", 1)[0].strip("[]")):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _request(line: str) -> tuple[str | None, str | None]:
    m = _REQUEST_LINE_RE.match(line.strip())
    return (m.group(1), m.group(2)) if m else (None, None)


def _share(content: str, regex: re.Pattern[str]) -> float:
    lines = [ln for ln in content.splitlines()[:200] if ln.strip()][:60]
    return sum(1 for ln in lines if regex.match(ln)) / len(lines) if lines else 0.0


def _apache_event(m: re.Match[str], line: str, continuation: str = "") -> LogEvent:
    ts = datetime.strptime(re.sub(" +", " ", m["ts"]), "%a %b %d %H:%M:%S.%f %Y" if "." in m["ts"] else "%a %b %d %H:%M:%S %Y")
    rest = _PID_RE.sub("", m["rest"], count=1)
    client = _CLIENT_RE.search(rest)
    message = rest[client.end():].strip() if client else _LEADING_RE.sub("", rest, count=1).strip()
    message = re.sub(r"^(?:\[client [^\]]+\] ?)+", "", message)  # ModSecurity repeats the client
    if continuation:  # a multi-line message (a PHP stack trace): Apache appends the referer to its end
        message = f"{message}\n{continuation}"
        line = f"{line}\n{continuation}"
    referrer = None
    if ref := _REFERER_RE.search(message):
        referrer, message = ref.group(1), message[:ref.start()]
    code = _AH_RE.match(message)
    body = message[code.end():] if code else message
    status = _STATUS_FROM_CODE.get(code.group(1)) if code else None
    method = path = user = None
    if code and code.group(1) == "00128":
        path = body.split(": ", 1)[-1]
    elif code and code.group(1) in ("01630", "01797"):
        target = body.split("configuration: ", 1)[-1]
        path = target[4:] if target.startswith("uri ") else target
    elif code and code.group(1) == "01276":
        path = body.removeprefix("Cannot serve directory ").split(": No matching", 1)[0]
    elif code and code.group(1) == "01617":
        if am := re.match(r'user (.+?): authentication failure for "(.*?)": ', body):
            user, path = am.group(1), am.group(2)
    elif code and code.group(1) == "01618":
        if am := re.match(r"user (.+?) not found: (\S*)", body):
            user, path = am.group(1), am.group(2)
    elif code and code.group(1) == "00126":
        if am := re.match(r"Invalid URI in request '.*?' '(.*)'$", body):
            method, path = _request(am.group(1))
    elif code and code.group(1) == "00135":
        method, path = _request(body.removeprefix("Invalid method in request "))
    elif sm := re.match(r"script '(.+?)' not found or unable to stat", body):
        status, path = 404, sm.group(1)
    elif body.startswith("PHP Fatal error:"):
        status = 500
    elif body.startswith("ModSecurity: "):
        if um := re.search(r' \[uri "((?:[^"\\]|\\.)*)"\]', body):
            path = um.group(1)
        if cm := re.search(r"with code (\d{3})", body):
            status = int(cm.group(1))
    return LogEvent(
        source_format=LogFormat.APACHE_ERROR, raw_line=line[:2000], timestamp=ts,
        ip_address=_client_ip(client.group(1)) if client else None, http_method=method, path=path,
        status_code=status, referrer=referrer, user_principal_name=user,
        resource_display_name=m["module"] or None, failure_reason=f"[{m['level']}] {message}"[:_MAX_MESSAGE],
    )


def _nginx_event(m: re.Match[str], line: str) -> LogEvent:
    ts = datetime.strptime(m["ts"], "%Y/%m/%d %H:%M:%S")
    rest = m["rest"]
    cut = rest.find(", client: ")
    message, suffix = (rest[:cut], rest[cut:]) if cut >= 0 else (rest, "")
    fields = {k: v[1:-1] if v.startswith('"') else v for k, v in _NGINX_FIELD_RE.findall(suffix)}
    method, path = _request(fields.get("request", ""))
    status = user = None
    if om := re.match(r'(?:open|stat|openat)\(\) "(.*?)" failed \((\d+): ', message):
        status = {"2": 404, "20": 404, "13": 403}.get(om.group(2))
        path = path or om.group(1)
    elif message.startswith("access forbidden by rule") or re.match(r'directory index of ".*" is forbidden', message):
        status = 403
    elif um := re.match(r'user "(.*?)"(?: was not found in "|: password mismatch)', message):
        status, user = 401, um.group(1)
    elif message.startswith("limiting requests,") and ", dry run," not in message:
        status = 503
    elif message.startswith("client intended to send too large body"):
        status = 413
    elif message.startswith("upstream timed out"):
        status = 504
    elif "while connecting to upstream" in message or message.startswith("no live upstreams"):
        status = 502
    return LogEvent(
        source_format=LogFormat.NGINX_ERROR, raw_line=line[:2000], timestamp=ts,
        ip_address=_client_ip(fields["client"]) if fields.get("client") else None,
        http_method=method, path=path, status_code=status, user_principal_name=user,
        referrer=fields.get("referrer") or None, app_display_name=fields.get("host") or fields.get("server") or None,
        failure_reason=f"[{m['level']}] {message}"[:_MAX_MESSAGE],
    )


class ApacheErrorParser(BaseParser):
    """Apache HTTP Server error_log (2.2 and 2.4 formats)."""

    format_name = "apache_error"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        return _share(content, _APACHE_RE) >= 0.6

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        # An entry is its bracketed first line plus any continuation lines (a stack trace).
        entries: list[tuple[re.Match[str], str, list[str]]] = []
        for raw in content.split("\n"):
            line = raw.rstrip("\r")
            m = _APACHE_RE.match(line)
            if m:
                entries.append((m, line, []))
            elif entries and line.strip() and len(entries[-1][2]) < 50:
                entries[-1][2].append(line)
        events: list[LogEvent] = []
        for m, line, more in entries:
            try:
                events.append(_apache_event(m, line, "\n".join(more)))
            except ValueError as exc:
                logger.debug("Apache error line skipped: %s", exc)
        return events


class NginxErrorParser(BaseParser):
    """nginx error_log."""

    format_name = "nginx_error"

    @classmethod
    def can_parse(cls, content: str, filename: str) -> bool:
        return _share(content, _NGINX_RE) >= 0.6

    @classmethod
    def parse(cls, content: str, filename: str) -> list[LogEvent]:
        events: list[LogEvent] = []
        for line in content.split("\n"):
            m = _NGINX_RE.match(line.rstrip("\r"))
            if m:
                try:
                    events.append(_nginx_event(m, line.rstrip("\r")))
                except ValueError as exc:
                    logger.debug("nginx error line skipped: %s", exc)
        return events
