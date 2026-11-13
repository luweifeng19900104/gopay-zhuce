"""CAPTCHA providers for the Alibaba CAPTCHA used by Midtrans linking."""
from __future__ import annotations

import json
import os
import re
import time
import threading
import multiprocessing
import queue
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .proxy_utils import normalize_proxy_url


# The opai package lives under <app-root>/app/src/opai/core, so the app
# root is four levels up (config/captcha.env lives next to runtime.env).
PROJECT_ROOT = Path(__file__).resolve().parents[4]
PROJECT_ROOT = Path(os.environ.get("OPAI_GOPAY_APP_ROOT") or PROJECT_ROOT).expanduser()
DEFAULT_API_BASE = "https://api.2captcha.com"
DEFAULT_SOLVERIFY_API_BASE = "https://solver.solverify.net"
DEFAULT_SCENE_ID = "1mbz0gpl6"
DEFAULT_PREFIX = "y1rdnbp"
DEFAULT_REGION = "sgp"
DEFAULT_API_GET_LIB = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"
TOKEN_FIELDS = ("sceneId", "certifyId", "deviceToken", "data")
CAPTCHA_BROWSER_LOCK = threading.Lock()
RETRYABLE_PROVIDER_ERRORS = {
    "ERROR_NO_SLOT_AVAILABLE",
    "ERROR_SERVICE_UNAVAILABLE",
}
UNSOLVABLE_PROVIDER_ERRORS = {
    "ERROR_CAPTCHA_UNSOLVABLE",
}


def _parse_form_body(raw: str) -> dict[str, str]:
    """Decode an InitCaptcha form body without losing encoded device data."""
    if not raw:
        return {}
    return {
        str(key): str(value)
        for key, value in urllib.parse.parse_qsl(raw, keep_blank_values=True)
    }


def _browser_proxy_arg(raw: str) -> str | None:
    value = normalize_proxy_url(raw)
    if not value:
        return None
    parsed = urllib.parse.urlparse(value)
    if not parsed.hostname:
        return None
    result = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        result += f":{parsed.port}"
    return result


def _browser_proxy_settings(raw: str, *, scheme: str = "") -> dict[str, str] | None:
    value = normalize_proxy_url(raw)
    if not value:
        return None
    parsed = urllib.parse.urlparse(value)
    if not parsed.hostname:
        return None
    proxy_scheme = str(scheme or parsed.scheme or "http").lower()
    server = f"{proxy_scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    settings = {"server": server}
    if parsed.username is not None:
        settings["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password is not None:
        settings["password"] = urllib.parse.unquote(parsed.password)
    return settings


def _browser_proxy_candidates(raw: str) -> list[tuple[str, dict[str, str] | None]]:
    value = str(raw or "").strip()
    primary = _browser_proxy_settings(value)
    if primary is None:
        return [("direct", None)]
    parsed = urllib.parse.urlparse(normalize_proxy_url(value))
    scheme = str(parsed.scheme or "http").lower()
    candidates: list[tuple[str, dict[str, str] | None]] = [
        (f"{scheme.upper()} proxy", primary)
    ]
    if scheme.startswith("socks"):
        # Chromium does not consistently support authenticated SOCKS5. Some
        # residential providers accept HTTP CONNECT on the same endpoint, so
        # try that before falling back to a direct page-session capture.
        candidates.append(("HTTP proxy fallback", _browser_proxy_settings(value, scheme="http")))
    candidates.append(("direct fallback", None))
    return candidates


def _two_captcha_proxy_fields(value: Any) -> dict[str, str]:
    """Convert a browser proxy into 2Captcha's legacy proxy parameters."""
    if isinstance(value, dict):
        server = str(value.get("server") or "").strip()
        username = str(value.get("username") or "")
        password = str(value.get("password") or "")
    else:
        server = str(value or "").strip()
        username = ""
        password = ""
    if not server:
        return {}
    if "://" not in server:
        server = "http://" + server
    parsed = urllib.parse.urlparse(server)
    if not parsed.hostname or not parsed.port:
        return {}
    username = username or urllib.parse.unquote(parsed.username or "")
    password = password or urllib.parse.unquote(parsed.password or "")
    proxy_type = str(parsed.scheme or "http").upper()
    if proxy_type in {"SOCKS5H", "SOCKS"}:
        proxy_type = "SOCKS5"
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    credentials = ""
    if username:
        credentials = urllib.parse.quote(username, safe="")
        if password:
            credentials += ":" + urllib.parse.quote(password, safe="")
        credentials += "@"
    return {
        "proxy": f"{credentials}{host}:{parsed.port}",
        "proxytype": proxy_type,
    }


def _solverify_proxy_fields(value: Any) -> dict[str, str]:
    """Convert the effective Playwright HTTP route into Solverify fields."""
    if isinstance(value, dict):
        server = str(value.get("server") or "").strip()
        username = str(value.get("username") or "")
        password = str(value.get("password") or "")
    else:
        server = str(value or "").strip()
        username = ""
        password = ""
    if not server:
        raise CaptchaProviderError(
            "Solverify requires the same HTTP proxy that loaded the Midtrans CAPTCHA page"
        )
    if "://" not in server:
        server = "http://" + server
    parsed = urllib.parse.urlparse(server)
    if str(parsed.scheme or "").lower() != "http":
        raise CaptchaProviderError(
            "Solverify only accepts an HTTP proxy; the live CAPTCHA page must use the HTTP proxy route"
        )
    if not parsed.hostname or not parsed.port:
        raise CaptchaProviderError("Solverify HTTP proxy is missing address or port")
    username = username or urllib.parse.unquote(parsed.username or "")
    password = password or urllib.parse.unquote(parsed.password or "")
    fields = {
        "proxyType": "http",
        "proxyAddress": parsed.hostname,
        "proxyPort": str(parsed.port),
    }
    if username:
        fields["proxyLogin"] = username
    if password:
        fields["proxyPassword"] = password
    return fields


def _api_proxy_url(value: Any) -> str:
    """Convert the effective CAPTCHA page route into a plain proxy URL.

    The Solverify/2Captcha API does not need the Indonesian proxy to reach
    Midtrans, but routing our API calls through the same working egress avoids
    the flaky system/Clash path and keeps the whole flow on one exit.
    """
    if isinstance(value, dict):
        server = str(value.get("server") or "").strip()
        username = str(value.get("username") or "").strip()
        password = str(value.get("password") or "").strip()
    else:
        server = str(value or "").strip()
        username = ""
        password = ""
    if not server:
        return ""
    if "://" not in server:
        server = "http://" + server
    parsed = urllib.parse.urlparse(server)
    if not parsed.hostname or not parsed.port:
        return ""
    host = f"{parsed.hostname}:{parsed.port}"
    if username:
        quoted_user = urllib.parse.quote(username, safe="")
        quoted_pass = urllib.parse.quote(password, safe="")
        return f"http://{quoted_user}:{quoted_pass}@{host}"
    return f"http://{host}"


def _captcha_loader_url(value: Any) -> str:
    """Return the AliyunCaptcha.js loader URL expected by 2Captcha."""
    raw = str(value or "").strip()
    if raw.startswith("//"):
        raw = "https:" + raw
    if not raw.startswith(("http://", "https://")):
        return ""
    path = urllib.parse.urlparse(raw).path.lower()
    if not path.endswith("/captcha-frontend/aliyuncaptcha/aliyuncaptcha.js"):
        return ""
    return raw


def capture_live_captcha_session(
    website_url: str,
    *,
    proxy: str = "",
    user_agent: str = "",
    progress: Callable[[str], None] | None = None,
    timeout_sec: float = 25.0,
    require_proxy: bool = False,
) -> dict[str, Any]:
    """Open the current Midtrans redirection page and capture its CAPTCHA session.

    The values returned by an old HAR are not interchangeable with a live
    page.  This collector records the current InitCaptcha request/response,
    the AliyunCaptcha.js loader, rotating dynamicJS URL, effective proxy, and
    browser cookies so the token provider can submit the same page session.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CaptchaProviderError("Playwright is required for live CAPTCHA capture") from exc

    navigation_url = str(website_url or "").strip()
    page_url = navigation_url.split("#", 1)[0]
    if not navigation_url.startswith(("https://", "http://")):
        raise CaptchaProviderError("invalid Midtrans redirection URL for live CAPTCHA capture")
    def report(message: str) -> None:
        if progress:
            progress(message)

    def capture_attempt(
        playwright: Any,
        route_name: str,
        proxy_settings: dict[str, str] | None,
    ) -> dict[str, Any]:
        state: dict[str, Any] = {
            "website_url": page_url,
            "website_url_full": navigation_url,
            "init_request": {},
            "init_response": {},
            "api_get_lib": "",
            "dynamic_js_url": "",
            "user_agent": "",
            "solver_proxy": dict(proxy_settings or {}),
        }
        dynamic_event = False

        def on_request(request: Any) -> None:
            nonlocal dynamic_event
            url = str(getattr(request, "url", "") or "")
            lower_url = url.lower()
            if "/captcha-frontend/aliyuncaptcha/aliyuncaptcha.js" in lower_url:
                state["api_get_lib"] = url
                return
            if "/captcha-frontend/dynamicjs/" in lower_url and urllib.parse.urlparse(url).path.lower().endswith(".js"):
                state["dynamic_js_url"] = url
                dynamic_event = True
                return
            if "captcha-open-" not in url or str(getattr(request, "method", "")) != "POST":
                return
            try:
                fields = _parse_form_body(str(request.post_data or ""))
            except Exception:
                fields = {}
            if str(fields.get("Action") or fields.get("action") or "").lower() != "initcaptcha":
                return
            state["init_request"] = fields
            state["init_endpoint"] = url
            state["prefix"] = urllib.parse.urlparse(url).netloc.split(".captcha-open-", 1)[0]
            state["region"] = "sgp" if "southeast" in url else ""
            state["user_agent"] = str(request.headers.get("user-agent") or "")
            report("CAPTCHA InitCaptcha request captured")

        def on_response(response: Any) -> None:
            nonlocal dynamic_event
            url = str(getattr(response, "url", "") or "")
            lower_url = url.lower()
            if "/captcha-frontend/aliyuncaptcha/aliyuncaptcha.js" in lower_url:
                state["api_get_lib"] = url
                report("CAPTCHA AliyunCaptcha.js loader captured")
                return
            if "/captcha-frontend/dynamicjs/" in lower_url and urllib.parse.urlparse(url).path.lower().endswith(".js"):
                state["dynamic_js_url"] = url
                dynamic_event = True
                report("CAPTCHA dynamicJS loaded: " + url.rsplit("/", 1)[-1])
                return
            if "captcha-open-" not in url:
                return
            request = getattr(response, "request", None)
            if request is None:
                return
            try:
                fields = _parse_form_body(str(request.post_data or ""))
            except Exception:
                fields = {}
            if str(fields.get("Action") or fields.get("action") or "").lower() != "initcaptcha":
                return
            try:
                payload = response.json()
            except Exception:
                payload = {}
            if isinstance(payload, dict):
                state["init_response"] = payload
                state["certify_id"] = str(payload.get("CertifyId") or payload.get("certifyId") or "")
                state["static_path"] = str(payload.get("StaticPath") or payload.get("staticPath") or "")
                state["captcha_type"] = str(payload.get("CaptchaType") or payload.get("captchaType") or "")
                if not state.get("dynamic_js_url"):
                    state["dynamic_js_url"] = _dynamic_js_url(state["static_path"])
                report("CAPTCHA InitCaptcha response captured")

        launch_kwargs: dict[str, Any] = {
            "headless": True,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        executable = str(os.environ.get("OPAI_CAPTCHA_BROWSER_EXECUTABLE") or "").strip()
        if executable:
            launch_kwargs["executable_path"] = executable
        if proxy_settings:
            launch_kwargs["proxy"] = proxy_settings
        report(f"CAPTCHA browser route: {route_name}")
        browser = playwright.chromium.launch(**launch_kwargs)
        try:
            context_kwargs: dict[str, Any] = {
                "locale": "en-US",
                "timezone_id": "Asia/Jakarta",
            }
            if str(user_agent or "").strip():
                context_kwargs["user_agent"] = str(user_agent).strip()
            context = browser.new_context(**context_kwargs)
            page = context.new_page()
            page.on("request", on_request)
            page.on("response", on_response)
            try:
                state["user_agent"] = state.get("user_agent") or str(
                    page.evaluate("() => navigator.userAgent") or ""
                )
            except Exception:
                state["user_agent"] = state.get("user_agent") or ""
            try:
                goto_timeout = max(float(timeout_sec), 60.0 if proxy_settings else float(timeout_sec))
                page.goto(navigation_url, wait_until="domcontentloaded", timeout=int(goto_timeout * 1000))
            except Exception as exc:
                report(f"CAPTCHA page navigation warning: {exc}")
                proxy_error_markers = (
                    "ERR_SOCKS_CONNECTION_FAILED",
                    "ERR_PROXY_CONNECTION_FAILED",
                    "ERR_TUNNEL_CONNECTION_FAILED",
                    "does not support socks5 proxy authentication",
                )
                if proxy_settings and not state.get("init_request") and any(
                    marker.lower() in str(exc).lower() for marker in proxy_error_markers
                ):
                    raise CaptchaProviderError(f"{route_name} navigation failed") from exc
            deadline = time.monotonic() + max(5.0, float(timeout_sec))
            while time.monotonic() < deadline:
                if (
                    state.get("init_request")
                    and state.get("init_response")
                    and state.get("api_get_lib")
                    and dynamic_event
                ):
                    break
                page.wait_for_timeout(250)
            cookies = context.cookies()
            state["cookies"] = cookies
            if not state.get("init_request"):
                raise CaptchaProviderError("live Midtrans page did not issue InitCaptcha")
            if not state.get("init_response"):
                raise CaptchaProviderError("live InitCaptcha response was not captured")
            if not state.get("api_get_lib"):
                raise CaptchaProviderError("live Midtrans page did not load AliyunCaptcha.js")
            if not state.get("dynamic_js_url"):
                raise CaptchaProviderError("live InitCaptcha response did not load dynamicJS")
            return state
        finally:
            browser.close()

    state: dict[str, Any] | None = None
    errors: list[str] = []
    candidates = _browser_proxy_candidates(proxy)
    if require_proxy:
        # Solverify must submit the exact HTTP proxy that loaded the CAPTCHA
        # page, so a direct fallback can never produce a usable token.
        candidates = [c for c in candidates if c[1] is not None]
        if not candidates:
            raise CaptchaProviderError(
                "Solverify 需要与 CAPTCHA 页面相同的 HTTP 代理，"
                "但当前没有可用的支付代理（OPAI_GOPAY_DEFAULT_PROXY 或任务代理为空）"
            )
    with CAPTCHA_BROWSER_LOCK:
        manager = sync_playwright()
        playwright = None
        try:
            playwright = manager.start()
            for index, (route_name, proxy_settings) in enumerate(candidates, start=1):
                try:
                    state = capture_attempt(playwright, route_name, proxy_settings)
                    if index > 1:
                        report(f"CAPTCHA browser fallback succeeded: {route_name}")
                    break
                except Exception as exc:
                    errors.append(f"{route_name}: {exc}")
                    if index >= len(candidates):
                        raise CaptchaProviderError("; ".join(errors)) from exc
                    report(f"CAPTCHA browser route failed: {route_name}; trying next route")
        finally:
            if playwright is not None:
                playwright.stop()

    if state is None:  # pragma: no cover - guarded by the loop above
        raise CaptchaProviderError("live CAPTCHA browser capture failed")

    request = state.get("init_request") or {}
    response = state.get("init_response") or {}
    scene_id = str(request.get("SceneId") or request.get("sceneId") or "")
    state["scene_id"] = scene_id
    state["device_token"] = str(request.get("DeviceToken") or "")
    state["device_data"] = str(request.get("DeviceData") or "")
    state["user_id"] = str(
        request.get("UserId") or request.get("userId") or request.get("user_id") or ""
    )
    state["user_user_id"] = str(
        request.get("UserUserId") or request.get("userUserId") or request.get("user_user_id") or ""
    )
    state["verify_type"] = str(
        request.get("VerifyType") or request.get("verifyType") or request.get("verify_type") or ""
    )
    # ``data`` is optional in some InitCaptcha sessions; DeviceConfig is the
    # closest current-session equivalent when Alibaba returns it.
    state["data"] = str(response.get("DeviceConfig") or response.get("Data") or "")
    state["certify_id"] = str(response.get("CertifyId") or response.get("certifyId") or state.get("certify_id") or "")
    state["prefix"] = str(state.get("prefix") or "")
    state["region"] = str(state.get("region") or "sgp")
    state["provider"] = "alibaba_traceless_live"
    return state


class CaptchaProviderError(RuntimeError):
    pass


def _env_path() -> Path:
    configured = str(os.environ.get("OPAI_MIDTRANS_CAPTCHA_ENV_FILE") or "").strip()
    return Path(configured).expanduser() if configured else PROJECT_ROOT / "config" / "captcha.env"


def _read_env_pairs(path: Path) -> dict[str, str]:
    pairs: dict[str, str] = {}
    if not path.is_file():
        return pairs
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        pairs[key.strip()] = value.strip().strip('"').strip("'")
    return pairs


def load_captcha_config() -> dict[str, str]:
    pairs = _read_env_pairs(_env_path())
    for key, value in pairs.items():
        if key.startswith(("OPAI_2CAPTCHA_", "OPAI_SOLVERIFY_", "OPAI_MIDTRANS_CAPTCHA_")):
            os.environ.setdefault(key, value)
    return {
        "api_key": str(os.environ.get("OPAI_2CAPTCHA_API_KEY") or pairs.get("OPAI_2CAPTCHA_API_KEY") or "").strip(),
        "api_base_url": str(os.environ.get("OPAI_2CAPTCHA_API_BASE_URL") or pairs.get("OPAI_2CAPTCHA_API_BASE_URL") or DEFAULT_API_BASE).strip().rstrip("/"),
        "solverify_api_key": str(os.environ.get("OPAI_SOLVERIFY_API_KEY") or pairs.get("OPAI_SOLVERIFY_API_KEY") or "").strip(),
        "solverify_api_base_url": str(os.environ.get("OPAI_SOLVERIFY_API_BASE_URL") or pairs.get("OPAI_SOLVERIFY_API_BASE_URL") or DEFAULT_SOLVERIFY_API_BASE).strip().rstrip("/"),
        "solverify_poll_sec": str(os.environ.get("OPAI_SOLVERIFY_POLL_SEC") or pairs.get("OPAI_SOLVERIFY_POLL_SEC") or "3").strip(),
        "solverify_timeout_sec": str(os.environ.get("OPAI_SOLVERIFY_TIMEOUT_SEC") or pairs.get("OPAI_SOLVERIFY_TIMEOUT_SEC") or "130").strip(),
        "scene_id": str(os.environ.get("OPAI_MIDTRANS_CAPTCHA_SCENE_ID") or pairs.get("OPAI_MIDTRANS_CAPTCHA_SCENE_ID") or DEFAULT_SCENE_ID).strip(),
        "prefix": str(os.environ.get("OPAI_MIDTRANS_CAPTCHA_PREFIX") or pairs.get("OPAI_MIDTRANS_CAPTCHA_PREFIX") or DEFAULT_PREFIX).strip(),
        "region": str(os.environ.get("OPAI_MIDTRANS_CAPTCHA_REGION") or pairs.get("OPAI_MIDTRANS_CAPTCHA_REGION") or DEFAULT_REGION).strip(),
        "api_get_lib": str(os.environ.get("OPAI_MIDTRANS_CAPTCHA_API_GET_LIB") or pairs.get("OPAI_MIDTRANS_CAPTCHA_API_GET_LIB") or DEFAULT_API_GET_LIB).strip(),
        "poll_sec": str(os.environ.get("OPAI_2CAPTCHA_POLL_SEC") or pairs.get("OPAI_2CAPTCHA_POLL_SEC") or "5").strip(),
        "timeout_sec": str(os.environ.get("OPAI_2CAPTCHA_TIMEOUT_SEC") or pairs.get("OPAI_2CAPTCHA_TIMEOUT_SEC") or "180").strip(),
        "max_attempts": str(os.environ.get("OPAI_2CAPTCHA_MAX_ATTEMPTS") or pairs.get("OPAI_2CAPTCHA_MAX_ATTEMPTS") or "3").strip(),
    }


def _mask_secret(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    return value[:4] + "..." + value[-4:] if len(value) > 8 else value[:2] + "***"


def captcha_config_status() -> dict[str, Any]:
    cfg = load_captcha_config()
    solverify_configured = bool(cfg["solverify_api_key"])
    return {
        "provider": "Solverify Aliyun Solver" if solverify_configured else "2Captcha Alibaba",
        "api_key_configured": solverify_configured or bool(cfg["api_key"]),
        "api_key": _mask_secret(cfg["api_key"]),
        "api_base_url": cfg["api_base_url"],
        "solverify_api_key_configured": solverify_configured,
        "solverify_api_key": _mask_secret(cfg["solverify_api_key"]),
        "solverify_api_base_url": cfg["solverify_api_base_url"],
        "solverify_poll_sec": cfg["solverify_poll_sec"],
        "solverify_timeout_sec": cfg["solverify_timeout_sec"],
        "scene_id": cfg["scene_id"],
        "prefix": cfg["prefix"],
        "region": cfg["region"],
        "api_get_lib": cfg["api_get_lib"],
        "poll_sec": cfg["poll_sec"],
        "timeout_sec": cfg["timeout_sec"],
        "max_attempts": cfg["max_attempts"],
        "env_file": str(_env_path()),
    }


def write_captcha_config(data: dict[str, Any]) -> dict[str, Any]:
    path = _env_path()
    pairs = _read_env_pairs(path)
    current_key = str(pairs.get("OPAI_2CAPTCHA_API_KEY") or os.environ.get("OPAI_2CAPTCHA_API_KEY") or "").strip()
    new_key = str(data.get("api_key") or "").strip()
    pairs["OPAI_2CAPTCHA_API_KEY"] = new_key or current_key
    pairs["OPAI_2CAPTCHA_API_BASE_URL"] = str(data.get("api_base_url") or pairs.get("OPAI_2CAPTCHA_API_BASE_URL") or DEFAULT_API_BASE).strip().rstrip("/")
    current_solverify_key = str(pairs.get("OPAI_SOLVERIFY_API_KEY") or os.environ.get("OPAI_SOLVERIFY_API_KEY") or "").strip()
    new_solverify_key = str(data.get("solverify_api_key") or "").strip()
    pairs["OPAI_SOLVERIFY_API_KEY"] = new_solverify_key or current_solverify_key
    pairs["OPAI_SOLVERIFY_API_BASE_URL"] = str(data.get("solverify_api_base_url") or pairs.get("OPAI_SOLVERIFY_API_BASE_URL") or DEFAULT_SOLVERIFY_API_BASE).strip().rstrip("/")
    pairs["OPAI_MIDTRANS_CAPTCHA_SCENE_ID"] = str(data.get("scene_id") or pairs.get("OPAI_MIDTRANS_CAPTCHA_SCENE_ID") or DEFAULT_SCENE_ID).strip()
    pairs["OPAI_MIDTRANS_CAPTCHA_PREFIX"] = str(data.get("prefix") or pairs.get("OPAI_MIDTRANS_CAPTCHA_PREFIX") or DEFAULT_PREFIX).strip()
    pairs["OPAI_MIDTRANS_CAPTCHA_REGION"] = str(data.get("region") or pairs.get("OPAI_MIDTRANS_CAPTCHA_REGION") or DEFAULT_REGION).strip()
    pairs["OPAI_MIDTRANS_CAPTCHA_API_GET_LIB"] = str(data.get("api_get_lib") or pairs.get("OPAI_MIDTRANS_CAPTCHA_API_GET_LIB") or DEFAULT_API_GET_LIB).strip()
    for field, key, default in (
        ("poll_sec", "OPAI_2CAPTCHA_POLL_SEC", "5"),
        ("timeout_sec", "OPAI_2CAPTCHA_TIMEOUT_SEC", "180"),
        ("solverify_poll_sec", "OPAI_SOLVERIFY_POLL_SEC", "3"),
        ("solverify_timeout_sec", "OPAI_SOLVERIFY_TIMEOUT_SEC", "130"),
    ):
        raw = str(data.get(field) or pairs.get(key) or default).strip()
        try:
            value = float(raw)
        except ValueError:
            raise ValueError(f"{field} must be numeric") from None
        if value <= 0:
            raise ValueError(f"{field} must be greater than zero")
        pairs[key] = str(int(value)) if value.is_integer() else str(value)

    raw_attempts = str(data.get("max_attempts") or pairs.get("OPAI_2CAPTCHA_MAX_ATTEMPTS") or "3").strip()
    try:
        max_attempts = int(raw_attempts)
    except ValueError:
        raise ValueError("max_attempts must be an integer") from None
    if not 1 <= max_attempts <= 5:
        raise ValueError("max_attempts must be between 1 and 5")
    pairs["OPAI_2CAPTCHA_MAX_ATTEMPTS"] = str(max_attempts)

    ordered = (
        "OPAI_SOLVERIFY_API_KEY",
        "OPAI_SOLVERIFY_API_BASE_URL",
        "OPAI_SOLVERIFY_POLL_SEC",
        "OPAI_SOLVERIFY_TIMEOUT_SEC",
        "OPAI_2CAPTCHA_API_KEY",
        "OPAI_2CAPTCHA_API_BASE_URL",
        "OPAI_MIDTRANS_CAPTCHA_SCENE_ID",
        "OPAI_MIDTRANS_CAPTCHA_PREFIX",
        "OPAI_MIDTRANS_CAPTCHA_REGION",
        "OPAI_MIDTRANS_CAPTCHA_API_GET_LIB",
        "OPAI_2CAPTCHA_POLL_SEC",
        "OPAI_2CAPTCHA_TIMEOUT_SEC",
        "OPAI_2CAPTCHA_MAX_ATTEMPTS",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    extras = tuple(sorted(key for key in pairs if key not in ordered))
    path.write_text(
        "# Midtrans Alibaba CAPTCHA provider configuration\n"
        + "\n".join(f"{key}={pairs.get(key, '')}" for key in ordered + extras)
        + "\n",
        encoding="utf-8",
    )
    os.environ["OPAI_MIDTRANS_CAPTCHA_ENV_FILE"] = str(path)
    for key in ordered + extras:
        os.environ[key] = pairs.get(key, "")
    return captcha_config_status()


def _post_json(
    url: str,
    payload: dict[str, Any],
    timeout: float = 30.0,
    proxy: str = "",
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener()
    raw = ""
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            with opener.open(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", "replace")
            break
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            raise CaptchaProviderError(f"Captcha provider HTTP {exc.code}: {raw[:300]}") from None
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            reason = getattr(exc, "reason", None) or exc
            if attempt < 3:
                time.sleep(float(attempt))
                continue
            raise CaptchaProviderError(f"Captcha provider network error: {reason}") from None
    try:
        result = json.loads(raw)
    except ValueError:
        raise CaptchaProviderError(f"Captcha provider returned non-JSON data: {raw[:300]}") from None
    if not isinstance(result, dict):
        raise CaptchaProviderError("Captcha provider returned an invalid response object")
    return result


def _legacy_request(
    url: str,
    params: dict[str, Any],
    *,
    method: str = "POST",
    timeout: float = 30.0,
    proxy: str = "",
) -> dict[str, Any]:
    encoded = urllib.parse.urlencode(params).encode("utf-8")
    if method == "GET":
        request = urllib.request.Request(
            f"{url}?{encoded.decode('ascii')}",
            headers={"Accept": "application/json"},
            method="GET",
        )
    else:
        request = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
    retryable_http = {500, 502, 503, 504, 520, 521, 522, 523, 524}
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener()
    raw = ""
    for network_attempt in range(1, 4):
        try:
            with opener.open(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", "replace")
            break
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            if exc.code in retryable_http and network_attempt < 3:
                time.sleep(float(network_attempt))
                continue
            raise CaptchaProviderError(f"Captcha provider HTTP {exc.code}: {raw[:300]}") from None
        except urllib.error.URLError as exc:
            if network_attempt < 3:
                time.sleep(float(network_attempt))
                continue
            raise CaptchaProviderError(f"Captcha provider network error: {exc.reason}") from None
    try:
        result = json.loads(raw)
    except ValueError:
        raise CaptchaProviderError(f"2Captcha returned non-JSON data: {raw[:300]}") from None
    if not isinstance(result, dict):
        raise CaptchaProviderError("2Captcha returned an invalid response object")
    return result


def _legacy_error(response: dict[str, Any], stage: str) -> CaptchaProviderError:
    code = str(response.get("request") or "unknown")
    if code.strip().upper() in UNSOLVABLE_PROVIDER_ERRORS:
        return CaptchaProviderError(
            "2Captcha "
            f"{stage} failed [{code}]: workers could not solve the current "
            "Alibaba challenge; discard this challenge and use a fresh "
            "current-page CAPTCHA token/session"
        )
    return CaptchaProviderError(f"2Captcha {stage} failed [{code}]")


def _legacy_error_code(response: dict[str, Any]) -> str:
    return str(response.get("request") or "").strip().upper()


def _legacy_base_url(configured: str) -> str:
    return str(configured or DEFAULT_API_BASE).strip().rstrip("/")


def _dynamic_js_url(value: Any) -> str:
    """Return a current Alibaba dynamicJS URL, or an empty string.

    The provider must not submit the initial AliyunCaptcha.js loader or a
    stale FeiLin bundle as ``api_get_lib``.  Midtrans' InitCaptcha response
    supplies a rotating StaticPath which the payment layer normalizes before
    reaching this function.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("//"):
        raw = "https:" + raw
    if raw.startswith(("http://", "https://")):
        if "/captcha-frontend/dynamicJS/" not in raw:
            return ""
        return raw if raw.lower().endswith(".js") else raw + ".js"
    raw = raw.lstrip("/")
    if raw.startswith("captcha-frontend/dynamicJS/"):
        return f"https://g.alicdn.com/{raw if raw.lower().endswith('.js') else raw + '.js'}"
    if raw.lower().endswith(".js"):
        raw = raw[:-3].rstrip(".")
    if "/" not in raw:
        return ""
    return f"https://g.alicdn.com/captcha-frontend/dynamicJS/{raw}.js"


def _provider_error(response: dict[str, Any], stage: str) -> CaptchaProviderError:
    code = str(response.get("errorCode") or response.get("errorId") or "unknown")
    description = str(response.get("errorDescription") or response.get("errorMessage") or "provider error")
    return CaptchaProviderError(f"2Captcha {stage} failed [{code}]: {description}")


def _provider_error_code(response: dict[str, Any]) -> str:
    return str(response.get("errorCode") or "").strip().upper()


def _header_value(headers: Any, name: str) -> str:
    needle = name.lower()
    if isinstance(headers, list):
        for item in headers:
            if not isinstance(item, dict):
                continue
            if str(item.get("name") or "").lower() == needle:
                return str(item.get("value") or "")
    return ""


def _har_request_params(request: dict[str, Any]) -> dict[str, str]:
    params: dict[str, str] = {}
    url = str(request.get("url") or "")
    parsed = urllib.parse.urlparse(url)
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        params[key] = value
    post = request.get("postData") or {}
    text = str(post.get("text") or "")
    mime = str(post.get("mimeType") or "").lower()
    if text and ("form" in mime or "=" in text):
        for key, value in urllib.parse.parse_qsl(text, keep_blank_values=True):
            params[key] = value
    if isinstance(post.get("params"), list):
        for item in post["params"]:
            if isinstance(item, dict) and item.get("name"):
                params[str(item["name"])] = str(item.get("value") or "")
    return params


def _har_response_json(entry: dict[str, Any]) -> dict[str, Any]:
    text = str(((entry.get("response") or {}).get("content") or {}).get("text") or "")
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def extract_har_captcha_challenges(har_path: str | Path, limit: int = 20) -> dict[str, Any]:
    """Extract Alibaba CAPTCHA InitCaptcha fields from a browser HAR.

    HAR values are session evidence.  They are useful for comparing field names
    and proving whether a live capture contains dynamic params, but old values
    should not be reused as a fresh Midtrans payment proof.
    """
    path = Path(har_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"HAR file not found: {path}")
    if path.suffix.lower() != ".har":
        raise ValueError("captcha HAR inspector only accepts .har files")
    data = json.loads(path.read_text(encoding="utf-8-sig", errors="ignore"))
    entries = ((data.get("log") or {}).get("entries") or []) if isinstance(data, dict) else []
    rows: list[dict[str, Any]] = []
    last_page_url = ""
    last_api_get_lib = ""
    last_dynamic_js = ""
    linking_accounts: list[str] = []
    for index, entry in enumerate(entries):
        request = entry.get("request") or {}
        url = str(request.get("url") or "")
        if "app.midtrans.com/snap/v" in url and "/redirection/" in url:
            last_page_url = url.split("#", 1)[0]
        account_match = None
        if "/snap/v3/accounts/" in url and "/linking" in url:
            account_match = url.split("/snap/v3/accounts/", 1)[-1].split("/", 1)[0]
            if account_match and account_match not in linking_accounts:
                linking_accounts.append(account_match)
        lower_url = url.lower()
        if "/captcha-frontend/aliyuncaptcha/aliyuncaptcha.js" in lower_url:
            last_api_get_lib = url
        if "/captcha-frontend/dynamicjs/" in lower_url and urllib.parse.urlparse(url).path.lower().endswith(".js"):
            last_dynamic_js = url
            for row in reversed(rows):
                if not row.get("dynamic_js_url"):
                    row["dynamic_js_url"] = url
                    break
        params = _har_request_params(request)
        action = str(params.get("Action") or params.get("action") or "")
        if action.lower() != "initcaptcha":
            continue
        host = urllib.parse.urlparse(url).netloc
        prefix = host.split(".captcha-open-", 1)[0] if ".captcha-open-" in host else host.split(".", 1)[0]
        body = _har_response_json(entry)
        static_path = str(body.get("StaticPath") or body.get("staticPath") or "")
        dynamic_url = _dynamic_js_url(static_path) or last_dynamic_js
        row = {
            "index": index,
            "website_url": last_page_url,
            "account_id": linking_accounts[-1] if linking_accounts else "",
            "prefix": prefix,
            "scene_id": str(params.get("SceneId") or params.get("sceneId") or ""),
            "region": "sgp" if "southeast" in host else "",
            "api_get_lib": last_api_get_lib,
            "dynamic_js_url": dynamic_url,
            "static_path": static_path,
            "captcha_type": str(body.get("CaptchaType") or ""),
            "certify_id": str(body.get("CertifyId") or ""),
            "device_token_present": bool(params.get("DeviceToken")),
            "device_data_present": bool(params.get("DeviceData")),
            "user_agent": _header_value(request.get("headers"), "User-Agent"),
        }
        rows.append(row)
    return {
        "har": str(path),
        "entries": len(entries),
        "count": len(rows),
        "challenges": rows[-max(1, min(100, int(limit))):],
    }


def solve_alibaba_captcha(
    challenge: dict[str, Any],
    progress: Callable[[str], None] | None = None,
    *,
    max_attempts: int | None = None,
) -> dict[str, str]:
    cfg = load_captcha_config()
    if not cfg["api_key"]:
        raise CaptchaProviderError("2Captcha API key is not configured")

    # 2Captcha expects the document URL, not the client-side SPA route fragment.
    website_url = str(challenge.get("website_url") or "").strip().split("#", 1)[0]
    scene_id = str(challenge.get("scene_id") or cfg.get("scene_id") or "").strip()
    prefix = str(challenge.get("prefix") or cfg.get("prefix") or "").strip()
    region = str(challenge.get("region") or cfg.get("region") or DEFAULT_REGION).strip()
    # 2Captcha's api_get_lib is the AliyunCaptcha.js loader, not the rotating
    # dynamicJS bundle returned by InitCaptcha.
    api_get_lib = _captcha_loader_url(challenge.get("api_get_lib"))
    user_agent = str(challenge.get("user_agent") or "").strip()
    if not all((website_url, scene_id, prefix)):
        missing = [
            name
            for name, value in (
                ("websiteUrl", website_url),
                ("sceneId", scene_id),
                ("prefix", prefix),
            )
            if not value
        ]
        raise CaptchaProviderError(
            "current Alibaba CAPTCHA dynamic params missing: "
            + ", ".join(missing)
            + "; capture them from the live Midtrans page InitCaptcha/dynamicJS session"
        )

    poll_sec = max(1.0, float(cfg["poll_sec"]))
    timeout_sec = max(10.0, float(cfg["timeout_sec"]))
    configured_attempts = int(cfg.get("max_attempts") or 3)
    max_attempts = max(1, min(5, int(max_attempts or configured_attempts)))
    last_error: CaptchaProviderError | None = None
    api_base = _legacy_base_url(cfg["api_base_url"])

    for attempt in range(1, max_attempts + 1):
        create_params: dict[str, Any] = {
            "key": cfg["api_key"],
            "method": "alibaba",
            "pageurl": website_url,
            "scene_id": scene_id,
            "prefix": prefix,
            "region": region,
            "json": 1,
        }
        for source, target in (
            ("user_id", "user_id"),
            ("user_user_id", "user_user_id"),
            ("verify_type", "verify_type"),
            ("trace_id", "user_certify_id"),
            ("user_certify_id", "user_certify_id"),
        ):
            value = str(challenge.get(source) or "").strip()
            if value:
                create_params[target] = value
        api_proxy = _api_proxy_url(challenge.get("solver_proxy") or challenge.get("proxy"))
        proxy_fields = _two_captcha_proxy_fields(
            challenge.get("solver_proxy") or challenge.get("proxy")
        )
        create_params.update(proxy_fields)
        task_mode = "legacy-core"
        if api_get_lib:
            create_params["api_get_lib"] = api_get_lib
            task_mode += "+loader"
        if user_agent:
            create_params["useragent"] = user_agent
            task_mode += "+ua"
        if proxy_fields:
            task_mode += "+proxy"
        create = _legacy_request(
            f"{api_base}/in.php",
            create_params,
            proxy=api_proxy,
        )
        if int(create.get("status") or 0) != 1 or not create.get("request"):
            error = _legacy_error(create, "submit")
            if _legacy_error_code(create) in RETRYABLE_PROVIDER_ERRORS and attempt < max_attempts:
                last_error = error
                if progress:
                    progress(f"Step 1: 2Captcha temporary failure, retrying task ({attempt}/{max_attempts})")
                time.sleep(poll_sec)
                continue
            raise error

        task_id = str(create["request"])
        if progress:
            progress(
                f"Step 1: 2Captcha Alibaba task {task_id} submitted "
                f"({attempt}/{max_attempts}, legacy API, mode={task_mode})"
            )

        deadline = time.monotonic() + timeout_sec
        retry_task = False
        while time.monotonic() < deadline:
            time.sleep(poll_sec)
            result = _legacy_request(
                f"{api_base}/res.php",
                {
                    "key": cfg["api_key"],
                    "action": "get",
                    "id": task_id,
                    "json": 1,
                },
                method="GET",
                proxy=api_proxy,
            )
            if int(result.get("status") or 0) != 1:
                code = _legacy_error_code(result)
                if code == "CAPCHA_NOT_READY":
                    continue
                error = _legacy_error(result, "result")
                if code in UNSOLVABLE_PROVIDER_ERRORS and attempt < max_attempts:
                    last_error = error
                    retry_task = True
                    if progress:
                        progress(
                            f"Step 1: 2Captcha task {task_id} is unsolvable for "
                            f"this Alibaba challenge; creating a fresh task ({attempt + 1}/{max_attempts})"
                        )
                    break
                if code in UNSOLVABLE_PROVIDER_ERRORS:
                    raise error
                if code in RETRYABLE_PROVIDER_ERRORS and attempt < max_attempts:
                    last_error = error
                    retry_task = True
                    if progress:
                        progress(
                            f"Step 1: 2Captcha could not solve task {task_id}; "
                            f"creating a fresh task ({attempt + 1}/{max_attempts})"
                        )
                    break
                raise error
            tokens: Any = result.get("request")
            if isinstance(tokens, str):
                try:
                    tokens = json.loads(tokens)
                except ValueError:
                    raise CaptchaProviderError("2Captcha tokens field is not valid JSON") from None
            if not isinstance(tokens, dict):
                raise CaptchaProviderError("2Captcha response is missing solution.data.tokens")
            missing = [key for key in TOKEN_FIELDS if tokens.get(key) in (None, "")]
            if missing:
                raise CaptchaProviderError(f"2Captcha token is missing fields: {', '.join(missing)}")
            if progress:
                progress("Step 1: 2Captcha token ready")
            return {key: str(tokens[key]) for key in TOKEN_FIELDS}

        if retry_task:
            continue
        raise CaptchaProviderError(f"2Captcha task {task_id} timed out after {cfg['timeout_sec']} seconds")

    raise last_error or CaptchaProviderError("2Captcha failed after all task attempts")


def _normalize_solution_tokens(value: Any) -> dict[str, str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    if isinstance(value, dict):
        nested = value.get("tokens")
        if nested is not None:
            value = nested
    if not isinstance(value, dict):
        return {}
    aliases = {
        "sceneid": "sceneId",
        "certifyid": "certifyId",
        "devicetoken": "deviceToken",
    }
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        canonical = aliases.get(re.sub(r"[^a-z0-9]", "", str(key).lower()), str(key))
        normalized[canonical] = item
    required = ("sceneId", "certifyId", "deviceToken", "data")
    if any(normalized.get(key) in (None, "") for key in required):
        return {}
    return {key: str(normalized[key]) for key in required}


def solve_alibaba_captcha_solverify(
    challenge: dict[str, Any],
    progress: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """Solve one live Alibaba session with Solverify using its exact HTTP route."""
    cfg = load_captcha_config()
    api_key = str(cfg.get("solverify_api_key") or "").strip()
    if not api_key:
        raise CaptchaProviderError("Solverify API key is not configured")

    website_url = str(
        challenge.get("website_url_full") or challenge.get("website_url") or ""
    ).strip()
    scene_id = str(challenge.get("scene_id") or cfg.get("scene_id") or "").strip()
    prefix = str(challenge.get("prefix") or cfg.get("prefix") or "").strip()
    region = str(challenge.get("region") or cfg.get("region") or DEFAULT_REGION).strip()
    if not all((website_url, scene_id, prefix)):
        missing = [
            name
            for name, value in (
                ("websiteURL", website_url),
                ("websiteKey", scene_id),
                ("prefix", prefix),
            )
            if not value
        ]
        raise CaptchaProviderError(
            "current Alibaba CAPTCHA fields missing for Solverify: " + ", ".join(missing)
        )

    task: dict[str, Any] = {
        "type": "aliyun",
        "websiteURL": website_url,
        "websiteKey": scene_id,
        "prefix": prefix,
        "region": region or DEFAULT_REGION,
    }
    user_agent = str(challenge.get("user_agent") or "").strip()
    if user_agent:
        task["useragent"] = user_agent
    task.update(_solverify_proxy_fields(challenge.get("solver_proxy")))

    api_base = str(cfg.get("solverify_api_base_url") or DEFAULT_SOLVERIFY_API_BASE).rstrip("/")
    api_proxy = _api_proxy_url(challenge.get("solver_proxy"))
    create = _post_json(
        f"{api_base}/createTask",
        {"clientKey": api_key, "task": task},
        proxy=api_proxy,
    )
    if int(create.get("errorId") or 0) != 0 or not create.get("taskId"):
        code = str(create.get("errorCode") or "ERROR_CREATE_TASK")
        detail = str(create.get("errorDescription") or create.get("message") or "")
        raise CaptchaProviderError(f"Solverify createTask failed [{code}]: {detail}".rstrip())

    task_id = str(create["taskId"])
    if progress:
        progress(f"Step 1: Solverify Aliyun task {task_id} submitted with matching HTTP proxy")
    poll_sec = max(1.0, float(cfg.get("solverify_poll_sec") or 3))
    timeout_sec = max(10.0, float(cfg.get("solverify_timeout_sec") or 130))
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        time.sleep(poll_sec)
        result = _post_json(
            f"{api_base}/getTaskResult",
            {"clientKey": api_key, "taskId": task_id},
            proxy=api_proxy,
        )
        status = str(result.get("status") or "").lower()
        if int(result.get("errorId") or 0) != 0:
            code = str(result.get("errorCode") or "ERROR_TASK_FAILED")
            detail = str(result.get("errorDescription") or result.get("message") or "")
            raise CaptchaProviderError(f"Solverify task failed [{code}]: {detail}".rstrip())
        if status in {"processing", "queued", "pending"}:
            continue
        if status not in {"completed", "ready"}:
            raise CaptchaProviderError(f"Solverify returned unexpected task status: {status or 'empty'}")
        solution = result.get("solution") or {}
        value = solution.get("value") if isinstance(solution, dict) else solution
        tokens = _normalize_solution_tokens(value)
        if not tokens:
            raise CaptchaProviderError("Solverify response is missing sceneId/certifyId/deviceToken/data")
        if progress:
            progress("Step 1: Solverify Alibaba token ready")
        return tokens
    raise CaptchaProviderError(f"Solverify task {task_id} timed out after {timeout_sec:g} seconds")


def solve_alibaba_captcha_official(
    challenge: dict[str, Any],
    progress: Callable[[str], None] | None = None,
) -> dict[str, str]:
    """Submit current dynamic Alibaba fields through 2Captcha's JSON API."""
    cfg = load_captcha_config()
    if not cfg["api_key"]:
        raise CaptchaProviderError("2Captcha API key is not configured")
    website_url = str(challenge.get("website_url") or "").strip().split("#", 1)[0]
    scene_id = str(challenge.get("scene_id") or "").strip()
    prefix = str(challenge.get("prefix") or "").strip()
    api_get_lib = _dynamic_js_url(challenge.get("api_get_lib") or challenge.get("static_path"))
    if not all((website_url, scene_id, prefix, api_get_lib)):
        raise CaptchaProviderError("live Alibaba CAPTCHA fields incomplete before 2Captcha submission")
    task: dict[str, Any] = {
        "type": "AlibabaTaskProxyless",
        "websiteUrl": website_url,
        "sceneId": scene_id,
        "prefix": prefix,
        "apiGetLib": api_get_lib,
        "userAgent": str(challenge.get("user_agent") or "").strip(),
    }
    for source, target in (
        ("region", "region"),
        ("user_id", "userId"),
        ("user_user_id", "userUserId"),
        ("verify_type", "verifyType"),
        ("certify_id", "userCertifyId"),
    ):
        value = str(challenge.get(source) or "").strip()
        if value:
            task[target] = value
    create = _post_json(
        f"{cfg['api_base_url'].rstrip('/')}/createTask",
        {"clientKey": cfg["api_key"], "task": task},
    )
    if int(create.get("errorId") or 0) != 0 or not create.get("taskId"):
        raise CaptchaProviderError(f"2Captcha official createTask failed: {create}")
    task_id = str(create["taskId"])
    if progress:
        progress(f"CAPTCHA official task {task_id} submitted with current dynamicJS")
    deadline = time.monotonic() + max(10.0, float(cfg.get("timeout_sec") or 180))
    while time.monotonic() < deadline:
        time.sleep(max(1.0, float(cfg.get("poll_sec") or 5)))
        result = _post_json(
            f"{cfg['api_base_url'].rstrip('/')}/getTaskResult",
            {"clientKey": cfg["api_key"], "taskId": task_id},
        )
        if str(result.get("status") or "") == "processing":
            continue
        if str(result.get("status") or "") != "ready":
            if str(result.get("errorCode") or "").upper() == "ERROR_CAPTCHA_UNSOLVABLE":
                raise CaptchaProviderError("2Captcha official task returned ERROR_CAPTCHA_UNSOLVABLE")
            raise CaptchaProviderError(f"2Captcha official result failed: {result}")
        solution = result.get("solution") or {}
        tokens = _normalize_solution_tokens(solution.get("data") if isinstance(solution, dict) else solution)
        if not tokens:
            raise CaptchaProviderError("2Captcha official response is missing solution.data.tokens fields")
        if progress:
            progress("CAPTCHA official token ready")
        return tokens
    raise CaptchaProviderError(f"2Captcha official task {task_id} timed out")


def solve_live_alibaba_captcha(
    website_url: str,
    *,
    proxy: str = "",
    user_agent: str = "",
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    cfg = load_captcha_config()
    attempts = max(1, min(5, int(cfg.get("max_attempts") or 3)))
    use_solverify = bool(str(cfg.get("solverify_api_key") or "").strip())
    if use_solverify and not str(proxy or "").strip():
        raise CaptchaProviderError(
            "Solverify 需要与 CAPTCHA 页面相同的 HTTP 代理，"
            "但当前支付代理为空；请在配置里设置 OPAI_GOPAY_DEFAULT_PROXY 或为任务指定代理"
        )
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        challenge = capture_live_captcha_session(
            website_url,
            proxy=proxy,
            user_agent=user_agent,
            progress=progress,
            require_proxy=use_solverify,
        )
        try:
            if use_solverify:
                tokens = solve_alibaba_captcha_solverify(challenge, progress=progress)
            else:
                tokens = solve_alibaba_captcha(
                    challenge,
                    progress=progress,
                    max_attempts=1,
                )
            return {"token": tokens, "cookies": challenge.get("cookies") or [], "challenge": challenge}
        except CaptchaProviderError as exc:
            last_error = exc
            retryable = any(
                marker in str(exc).upper()
                for marker in (
                    "UNSOLVABLE",
                    "ERROR_NO_CAPACITY",
                    "ERROR_TASK_FAILED",
                    "ERROR_TIMEOUT",
                    "TIMED OUT",
                )
            )
            if not retryable or attempt >= attempts:
                raise
            if progress:
                progress(
                    f"CAPTCHA {('Solverify' if use_solverify else '2Captcha')} task failed; "
                    "discarding the page session "
                    f"and recapturing ({attempt + 1}/{attempts})"
                )
    raise CaptchaProviderError(str(last_error or "live CAPTCHA failed"))


def _isolated_solver_worker(
    website_url: str,
    proxy: str,
    user_agent: str,
    output: Any,
) -> None:
    """Run one browser and solver session in an isolated process."""
    try:
        result = solve_live_alibaba_captcha(
            website_url,
            proxy=proxy,
            user_agent=user_agent,
            progress=lambda message: output.put(("progress", str(message))),
        )
        output.put(("result", result))
    except BaseException as exc:
        output.put(("error", {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }))


def solve_live_alibaba_captcha_isolated(
    website_url: str,
    *,
    proxy: str = "",
    user_agent: str = "",
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Solve CAPTCHA in a child process so payment threads can run concurrently."""
    cfg = load_captcha_config()
    attempts = max(1, min(5, int(cfg.get("max_attempts") or 3)))
    per_attempt = max(40.0, float(cfg.get("solverify_timeout_sec") or 130) + 40.0)
    deadline = time.monotonic() + per_attempt * attempts
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(
        target=_isolated_solver_worker,
        args=(str(website_url), str(proxy), str(user_agent), output),
        daemon=True,
    )
    process.start()
    try:
        while time.monotonic() < deadline:
            try:
                kind, payload = output.get(timeout=0.5)
            except queue.Empty:
                if not process.is_alive():
                    break
                continue
            if kind == "progress":
                if progress:
                    progress(str(payload))
                continue
            if kind == "result":
                return payload
            if kind == "error":
                raise CaptchaProviderError(
                    f"CAPTCHA subprocess failed [{payload.get('type')}]: {payload.get('message')}"
                )
        if process.is_alive():
            process.terminate()
        raise CaptchaProviderError(
            f"CAPTCHA subprocess timed out after {int(per_attempt * attempts)} seconds"
        )
    finally:
        process.join(timeout=5)
        output.close()


def build_captcha_token_provider(
    progress: Callable[[str], None] | None = None,
) -> Callable[[dict[str, Any]], dict[str, str]] | None:
    cfg = load_captcha_config()
    # The standalone payment application intentionally uses Solverify only.
    # Do not silently switch providers when its key is missing.
    if not cfg.get("solverify_api_key"):
        return None
    def provider(challenge: dict[str, Any]) -> dict[str, Any]:
        # The current page session is the source of truth.  Set
        # OPAI_MIDTRANS_CAPTCHA_LIVE=0 only for offline HAR/provider tests.
        live = str(os.environ.get("OPAI_MIDTRANS_CAPTCHA_LIVE", "1")).strip().lower()
        if live not in {"0", "false", "no", "off"}:
            return solve_live_alibaba_captcha_isolated(
                str(challenge.get("website_url") or ""),
                proxy=str(challenge.get("proxy") or ""),
                user_agent=str(challenge.get("user_agent") or ""),
                progress=progress,
            )
        return {"token": solve_alibaba_captcha(challenge, progress=progress)}
    return provider
