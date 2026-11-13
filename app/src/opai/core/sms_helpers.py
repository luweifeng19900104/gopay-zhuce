"""
SMS activation API helpers for GoPay protocol flows.

The live worker uses SMSBower-style ``handler_api.php`` endpoints.  Older
deployments named the same config ``OPAI_HEROSMS_*``; keep those names as
aliases so existing launch scripts still work while the canonical config is
``OPAI_SMSBOWER_*``.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import logging
import json
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Collection
from pathlib import Path

import tls_client

log = logging.getLogger(__name__)

SMSBOWER_HANDLER_PATH = "/stubs/handler_api.php"
SMS_TIMEOUT = 40
_SMS_ENV_PREFIXES = ("OPAI_SMSBOWER_", "OPAI_HEROSMS_")

# Serialize getNumber purchases: the provider's live pool is small and concurrent
# batch workers otherwise stampede it into NO_NUMBERS.
_GET_NUMBER_LOCK = threading.Lock()


MAX_IMPORTED_SMS_BYTES = 256 * 1024
_FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")
_SMS_DNS_CACHE: dict[str, tuple[float, tuple[str, ...]]] = {}
_SMS_DNS_LOCK = threading.Lock()


def _public_sms_dns(host: str, timeout: float = 5) -> tuple[str, ...]:
    """Resolve Fake-IP hostnames without passing SMS URLs/tokens to DNS."""
    with _SMS_DNS_LOCK:
        cached = _SMS_DNS_CACHE.get(host)
        if cached and cached[0] > time.monotonic():
            return cached[1]
    query = urllib.parse.urlencode({"name": host, "type": "A"})
    req = urllib.request.Request(
        "https://dns.google/resolve?" + query,
        headers={"Accept": "application/dns-json", "User-Agent": "GoPay-SMS-Poller/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = response.read(65537)
        if len(payload) > 65536:
            raise ValueError("DNS response too large")
        data = json.loads(payload)
        addresses = tuple(dict.fromkeys(
            str(row["data"]) for row in data.get("Answer", [])
            if row.get("type") == 1
        ))
        if data.get("Status") != 0 or not addresses:
            raise ValueError("no DNS answer")
        if any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError("non-public DNS answer")
    except Exception:
        raise ValueError("短信域名真实 DNS 解析失败，请检查网络后重试") from None
    with _SMS_DNS_LOCK:
        if len(_SMS_DNS_CACHE) >= 128:
            _SMS_DNS_CACHE.clear()
        _SMS_DNS_CACHE[host] = (time.monotonic() + 30, addresses)
    return addresses


def _resolve_sms_addresses(host: str, port: int, timeout: float = 5) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError("短信链接域名解析失败") from None
    addresses = tuple(dict.fromkeys(info[4][0].split("%", 1)[0] for info in infos))
    parsed = [ipaddress.ip_address(address) for address in addresses]
    if not parsed:
        raise ValueError("短信链接域名解析失败")
    # Only domain-name answers entirely inside the Fake-IP range qualify.
    # Private/loopback IP literals, mixed answers and redirects still fail.
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if not literal and all(ip.version == 4 and ip in _FAKE_IP_NETWORK for ip in parsed):
        addresses = _public_sms_dns(host, timeout=timeout)
        parsed = [ipaddress.ip_address(address) for address in addresses]
    if not parsed or any(not ip.is_global for ip in parsed):
        raise ValueError("短信链接不能指向本机、内网或保留地址")
    return addresses


def validate_imported_sms_url(raw_url: str) -> str:
    """Validate an imported SMS polling URL before any network request."""
    url = str(raw_url or "").strip()
    parsed = urllib.parse.urlsplit(url)
    allow_http = os.environ.get("OPAI_ALLOW_INSECURE_SMS_URL", "").strip().lower() in {"1", "true", "yes"}
    allowed = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed or not parsed.hostname:
        raise ValueError("短信链接必须使用 HTTPS 公网地址")
    if parsed.username or parsed.password:
        raise ValueError("短信链接不能包含 URL 用户名或密码")
    _resolve_sms_addresses(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    return url


def _connect_sms_socket(address, timeout=8, source_address=None):
    """Connect to a checked numeric IP; HTTPS still verifies the original host."""
    host, port = address
    deadline = time.monotonic() + float(timeout)
    addresses = _resolve_sms_addresses(host, port, timeout=min(5, float(timeout)))
    for ip in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            return socket.create_connection((ip, port), timeout=remaining, source_address=source_address)
        except OSError:
            continue
    raise OSError("短信接口连接失败，请检查网络后重试")


class _SmsHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect_sms_socket


class _SmsHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect_sms_socket


class _SmsHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_SmsHTTPSConnection, req, context=self._context)


class _SmsHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_SmsHTTPConnection, req)


class _ValidatedSmsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_imported_sms_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_imported_sms_url(raw_url: str, *, timeout: float = 8, max_bytes: int = MAX_IMPORTED_SMS_BYTES) -> str:
    """Read a bounded public SMS page and revalidate every redirect target."""
    url = validate_imported_sms_url(raw_url)
    request = urllib.request.Request(url, headers={"User-Agent": "GoPay-SMS-Poller/1.0"})
    # Pin the validated public destination instead of sending an unchecked
    # hostname to an environment proxy. TLS hostname verification stays on.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _SmsHTTPSHandler(), _SmsHTTPHandler(),
        _ValidatedSmsRedirect(),
    )
    with opener.open(request, timeout=timeout) as response:
        final_url = response.geturl()
        validate_imported_sms_url(final_url)
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > max_bytes:
            raise ValueError("短信响应超过大小限制")
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("短信响应超过大小限制")
    return payload.decode("utf-8", "ignore")


def extract_imported_sms_codes(body: str) -> list[str]:
    """Read OTP fields, not status codes, phone numbers or expiry-date years."""
    if re.fullmatch(r"\s*\d{4,6}\s*", body):
        return [body.strip()]

    def text_codes(text):
        text = re.sub(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?", "", str(text))
        return list(reversed(re.findall(r"(?<!\d)(\d{4,6})(?!\d)", text)))

    def visit(value, nested=False):
        if isinstance(value, list):
            return [code for row in reversed(value) for code in visit(row, nested=True)]
        if isinstance(value, dict):
            codes = []
            for key in ("otp", "sms_code", "verification_code", "code"):
                if key == "code" and not nested:
                    continue  # Top-level JSON code is normally an API status.
                raw_code = value.get(key)
                code = str(raw_code or "").strip()
                if re.fullmatch(r"\d{4,6}", code):
                    codes.append(code)
                elif nested and isinstance(raw_code, str):
                    # SMS8 puts the complete SMS body in data.code, e.g.
                    # "(GOJEK) Use OTP 1234 to set up your GoTo PIN...".
                    codes.extend(text_codes(raw_code))
            for key in ("data", "records", "messages", "result"):
                if key in value:
                    codes.extend(visit(value[key], nested=True))
            for key in ("text", "content", "sms", "body", "message"):
                text = value.get(key)
                if isinstance(text, str):
                    codes.extend(text_codes(text))
            return codes
        if isinstance(value, str):
            return text_codes(value)
        return []

    try:
        codes = visit(json.loads(body))
    except (ValueError, TypeError):
        codes = text_codes(body)
    return list(dict.fromkeys(codes))


def sms_code_sha256(code: str) -> str:
    """Return a stable hash for an OTP without retaining its plaintext."""
    normalized = str(code or "").strip()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_selected_env_file(prefixes: tuple[str, ...], path: str = "") -> None:
    """Load selected KEY=VALUE entries without requiring python-dotenv."""
    configured = (path or os.environ.get("OPAI_GOPAY_SMS_ENV_FILE", "")).strip()
    candidates = [Path(configured).expanduser()] if configured else [
        Path.cwd() / "config" / "sms.env",
        Path(__file__).resolve().parents[4] / "config" / "sms.env",
    ]
    for env_path in candidates:
        if not env_path.is_file():
            continue
        try:
            with env_path.open(encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key.startswith(prefixes) and not os.environ.get(key):
                        os.environ[key] = value
        except OSError as exc:
            log.debug("Could not load SMS env file %s: %s", env_path, exc)
        if configured:
            break


def _load_env_file(path: str = "") -> None:
    load_selected_env_file(_SMS_ENV_PREFIXES, path)


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return default


def get_sms_api_key(api_key: str = "") -> str:
    _load_env_file()
    if api_key:
        return api_key
    key = _env_first("OPAI_SMSBOWER_API_KEY", "OPAI_HEROSMS_API_KEY")
    if key:
        return key
    key_file = _env_first("OPAI_SMSBOWER_API_KEY_FILE", "OPAI_HEROSMS_API_KEY_FILE")
    if key_file and os.path.exists(key_file):
        try:
            return Path(key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            log.warning("Could not read SMS API key file %s: %s", key_file, exc)
    return ""


def sms_api_base_url() -> str:
    _load_env_file()
    return _env_first(
        "OPAI_SMSBOWER_API_BASE_URL",
        "OPAI_HEROSMS_API_BASE_URL",
        default="https://smsbower.page",
    ).rstrip("/")


def sms_api_url() -> str:
    """Return the configured handler endpoint without duplicating its path."""
    base = sms_api_base_url()
    if base.lower().endswith("handler_api.php"):
        return base
    return f"{base}{SMSBOWER_HANDLER_PATH}"


def _sanitize_sms_error(error: object, *secrets: str) -> str:
    """Remove API credentials from transport errors before they reach logs."""
    text = str(error or "")
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "***")
    text = re.sub(
        r"(?i)((?:api[_-]?key|apikey|key)(?:=|%3[dD]))[^&\s\"']+",
        r"\1***",
        text,
    )
    text = re.sub(
        r"(?i)([\"']?api[_-]?key[\"']?\s*:\s*[\"'])[^\"']+",
        r"\1***",
        text,
    )
    return text[:500]


def _json_response_payload(response: str) -> dict | None:
    try:
        value = json.loads(response)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _json_values(payload: object):
    """Yield scalar values from the provider's occasionally nested JSON body."""
    if isinstance(payload, dict):
        for value in payload.values():
            yield from _json_values(value)
    elif isinstance(payload, (list, tuple)):
        for value in payload:
            yield from _json_values(value)
    elif payload is not None:
        yield str(payload)


def sms_api(api_key: str, action: str, params: dict | None = None, retries: int = 3) -> str:
    api_key = get_sms_api_key(api_key)
    try:
        timeout_sec = max(3.0, min(60.0, float(_env_first("OPAI_SMSBOWER_API_TIMEOUT", "OPAI_HEROSMS_API_TIMEOUT", default="12") or "12")))
    except ValueError:
        timeout_sec = 12.0
    p = {"api_key": api_key, "action": action}
    if params:
        p.update(params)
    last_error: Exception | None = None
    for i in range(1, retries + 1):
        try:
            s = tls_client.Session(client_identifier="chrome_120")
            r = s.get(sms_api_url(), params=p, timeout_seconds=int(timeout_sec))
            body = str(getattr(r, "text", "") or "").strip()
            status_code = int(getattr(r, "status_code", 200) or 200)
            if 200 <= status_code < 300:
                return body
            if status_code not in {408, 425, 429} and status_code < 500:
                raise RuntimeError(f"HTTP {status_code}: {body[:200]}")
            raise RuntimeError(f"HTTP {status_code}: {body[:200]}")
        except Exception as e:
            last_error = e
            log.warning(
                "sms_api %s attempt %d/%d failed: %s",
                action,
                i,
                retries,
                _sanitize_sms_error(e, api_key),
            )
            if i < retries:
                time.sleep(3)
    raise RuntimeError(f"sms_api {action} failed after {retries} retries") from last_error


def sms_get_number(api_key: str) -> tuple[str | None, str | None]:
    _load_env_file()
    service = _env_first("OPAI_SMSBOWER_SERVICE", "OPAI_HEROSMS_SERVICE", default="ni")
    country = _env_first("OPAI_SMSBOWER_COUNTRY", "OPAI_HEROSMS_COUNTRY", default="6")
    retries = max(1, int(_env_first("OPAI_SMSBOWER_GETNUMBER_RETRIES", "OPAI_HEROSMS_GETNUMBER_RETRIES", default="3") or "3"))
    retry_delay = max(0.5, float(_env_first("OPAI_SMSBOWER_GETNUMBER_RETRY_DELAY", "OPAI_HEROSMS_GETNUMBER_RETRY_DELAY", default="1.0") or "1.0"))
    min_price = (_env_first("OPAI_SMSBOWER_MIN_PRICE", "OPAI_HEROSMS_MIN_PRICE", default="") or "").strip()
    max_price = (_env_first("OPAI_SMSBOWER_MAX_PRICE", "OPAI_HEROSMS_MAX_PRICE", default="") or "").strip()
    with _GET_NUMBER_LOCK:
        last_resp = ""
        params: dict[str, str] = {"service": service, "country": country}
        parsed_max_price: float | None = None
        if max_price:
            try:
                if float(max_price) > 0:
                    parsed_max_price = float(max_price)
                    params["maxPrice"] = str(parsed_max_price)
            except ValueError:
                log.warning("getNumber 忽略无效 maxPrice=%r", max_price)
        if min_price:
            try:
                parsed_min_price = float(min_price)
                if parsed_min_price > 0 and parsed_max_price is None:
                    log.warning("getNumber 忽略 minPrice=%r：最低价格必须与最高价格同时设置", min_price)
                elif parsed_min_price > 0 and parsed_min_price > parsed_max_price:
                    log.warning("getNumber 忽略 minPrice=%r：最低价格高于最高价格", min_price)
                elif parsed_min_price > 0:
                    params["minPrice"] = str(parsed_min_price)
            except ValueError:
                log.warning("getNumber 忽略无效 minPrice=%r", min_price)
        for attempt in range(1, retries + 1):
            resp = sms_api(api_key, "getNumber", params, retries=1)
            log.info("getNumber attempt %d/%d: %s", attempt, retries, resp)
            if resp.startswith("ACCESS_NUMBER:"):
                parts = resp.split(":", 2)
                if len(parts) == 3 and parts[1] and parts[2]:
                    number = parts[2].strip()
                    return number if number.startswith("+") else f"+{number}", parts[1].strip()
            payload = _json_response_payload(resp)
            if payload:
                data = payload.get("data", payload)
                values = list(_json_values(data))
                aid = next((v for v in values if re.fullmatch(r"\d+", v)), "")
                number = next((v for v in values if re.search(r"\d{7,}", v) and v != aid), "")
                if aid and number:
                    return number if number.startswith("+") else f"+{number}", aid
            last_resp = resp
            if attempt < retries:
                log.warning("getNumber attempt %d/%d returned %s, retrying in %.1fs", attempt, retries, resp, retry_delay)
                time.sleep(retry_delay)
        log.warning("getNumber failed after %d attempts: %s", retries, last_resp)
    return None, None


def sms_wait_code(
    api_key: str,
    aid: str,
    timeout: int = SMS_TIMEOUT,
    *,
    ignore_code: str = "",
    ignore_codes: Collection[str] | None = None,
    ignore_code_hashes: Collection[str] | None = None,
) -> str | None:
    """Poll one activation while filtering already-consumed OTPs.

    SMSBower/compatible gateways can expose the last received code through
    either ``STATUS_OK`` or ``STATUS_WAIT_RETRY``.  The status name alone is
    therefore not enough to decide whether a code is stale; persisted hashes
    of codes that this application already consumed are the source of truth.
    """
    ignored = {
        str(value or "").strip()
        for value in (ignore_codes or ())
        if str(value or "").strip()
    }
    legacy_ignored = str(ignore_code or "").strip()
    if legacy_ignored:
        ignored.add(legacy_ignored)
    ignored_hashes = {
        str(value or "").strip().lower()
        for value in (ignore_code_hashes or ())
        if re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "").strip())
    }

    def is_ignored(candidate: str) -> bool:
        normalized = str(candidate or "").strip()
        if not normalized:
            return True
        return normalized in ignored or sms_code_sha256(normalized) in ignored_hashes

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = sms_api(api_key, "getStatus", {"id": aid})
        except Exception:
            remaining = deadline - time.time()
            if remaining > 0:
                time.sleep(min(5, remaining))
            continue
        if resp.startswith("STATUS_OK:"):
            code = resp.split(":", 1)[1]
            m = re.search(r"\b(\d{4,6})\b", code)
            candidate = m.group(1) if m else code.strip()
            if candidate and not is_ignored(candidate):
                return candidate
            log.debug("Ignoring stale SMS code for aid=%s", aid)
        if resp.startswith("STATUS_WAIT_RETRY:"):
            value = resp.split(":", 1)[1]
            m = re.search(r"\b(\d{4,8})\b", value)
            candidate = m.group(1) if m else value.strip()
            if candidate and not is_ignored(candidate):
                return candidate
            if candidate:
                log.debug("Ignoring consumed SMS retry code for aid=%s", aid)
        payload = _json_response_payload(resp)
        if payload:
            values = list(_json_values(payload.get("data", payload)))
            code = next((v for v in values if re.fullmatch(r"\d{4,8}", v) and not is_ignored(v)), "")
            if code:
                return code
            state = " ".join(values).upper()
            if "CANCEL" in state or "NO_ACTIVATION" in state:
                return None
        if resp == "STATUS_CANCEL":
            log.warning("SMS activation cancelled")
            return None
        remaining = deadline - time.time()
        if remaining > 0:
            time.sleep(min(5, remaining))
    return None


def sms_request_another(api_key: str, aid: str) -> bool:
    try:
        resp = sms_api(api_key, "setStatus", {"id": aid, "status": "3"})
        log.info("sms_request_another: %s", resp)
        return "ACCESS_RETRY_GET" in resp
    except Exception:
        return False


def sms_cancel(api_key: str, aid: str) -> bool:
    try:
        resp = sms_api(api_key, "setStatus", {"id": aid, "status": "8"})
        log.info("sms_cancel %s: %s", aid, resp)
        upper = str(resp or "").upper()
        return "ACCESS_CANCEL" in upper or "STATUS_CANCEL" in upper
    except Exception:
        return False


def sms_done(api_key: str, aid: str) -> bool:
    try:
        resp = sms_api(api_key, "setStatus", {"id": aid, "status": "6"})
        log.info("sms_done %s: %s", aid, resp)
        upper = str(resp or "").upper()
        return "ACCESS_ACTIVATION" in upper or "ACCESS_READY" in upper
    except Exception:
        return False


# ========== API Error Helpers ==========

def is_waf_block(result: dict) -> bool:
    body = result.get("body", {})
    if isinstance(body, dict) and "raw" in body:
        return "WAF Block Page" in body["raw"]
    return False


def is_rate_limited(result: dict) -> bool:
    errors = result.get("body", {}).get("errors", [])
    if errors:
        code = errors[0].get("code", "")
        return "ratelimit" in code.lower() or "rate_limit" in code.lower()
    return result.get("status") == 429


def get_error_code(result: dict) -> str:
    body = result.get("body", {})
    if not isinstance(body, dict):
        return str(body)
    errors = body.get("errors", [])
    if errors:
        first = errors[0]
        return " ".join(str(first.get(k, "")) for k in ("code", "message") if first.get(k))
    error = body.get("error", {})
    if isinstance(error, dict):
        return " ".join(str(error.get(k, "")) for k in ("code", "description") if error.get(k))
    if "raw" in body:
        return str(body["raw"])
    return ""


def api_call_with_retry(fn, *args, max_retries: int = 2, **kwargs) -> dict:
    """Retry API call on WAF block or transient errors."""
    result = {}
    for attempt in range(max_retries + 1):
        result = fn(*args, **kwargs)
        if result["status"] in (200, 201, 204):
            return result
        if is_waf_block(result):
            if attempt < max_retries:
                wait = 5 * (attempt + 1)
                log.warning("WAF blocked, retrying in %ds... (%d/%d)", wait, attempt + 1, max_retries)
                time.sleep(wait)
                continue
        if is_rate_limited(result):
            if attempt < max_retries:
                wait = 30 * (attempt + 1)
                log.warning("Rate limited, retrying in %ds...", wait)
                time.sleep(wait)
                continue
        return result
    return result
