"""Visible, persistent-browser GoPay payment flow.

This mode uses the installed Chrome browser instead of replaying Midtrans HTTP
requests.  Each GoPay account receives a stable user-data directory so cookies,
storage, the real browser TLS stack and the browser's native fingerprint remain
consistent across payments.  CAPTCHA/PIN/OTP challenges stay in the official
page for the operator to complete.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import unquote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .payment_fingerprint import normalize_payment_fingerprint
from .proxy_utils import normalize_proxy_url


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_PROFILE_ROOT = PROJECT_ROOT / "config" / "payment_browser_profiles"


def browser_payment_enabled() -> bool:
    """Use the real-browser flow by default; set mode=protocol/emulator to roll back."""
    mode = os.environ.get("OPAI_GOPAY_PAYMENT_MODE", "browser").strip().lower()
    return mode in {"", "browser"}


def _require_indonesia_exit() -> bool:
    return os.environ.get("OPAI_GOPAY_BROWSER_REQUIRE_ID", "1").strip().lower() not in {"0", "false", "no"}


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(os.environ.get(name, default)).strip())
    except (TypeError, ValueError):
        value = default
    return min(maximum, max(minimum, value))


def _safe_profile_id(payment_fingerprint: Optional[dict] = None) -> str:
    fp = normalize_payment_fingerprint(payment_fingerprint)
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(fp.get("profile_id") or "default"))


def _profile_directory(payment_fingerprint: Optional[dict] = None, profile_root: Optional[Path] = None) -> Path:
    directory = (profile_root or DEFAULT_PROFILE_ROOT) / _safe_profile_id(payment_fingerprint)
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def _chrome_path() -> Path:
    configured = str(os.environ.get("OPAI_CHROME_PATH") or "").strip()
    candidates = [
        Path(configured) if configured else None,
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("未找到 Google Chrome，请设置 OPAI_CHROME_PATH")


def _proxy_settings(raw_proxy: str) -> Optional[dict[str, str]]:
    value = normalize_proxy_url(raw_proxy)
    if not value:
        return None
    parsed = urlsplit(value)
    if not parsed.hostname or not parsed.port:
        raise ValueError("支付代理地址无效")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError(f"浏览器不支持代理协议: {scheme}")
    if scheme == "socks5h":
        scheme = "socks5"
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    result = {"server": f"{scheme}://{host}:{parsed.port}"}
    if parsed.username:
        result["username"] = unquote(parsed.username)
    if parsed.password:
        result["password"] = unquote(parsed.password)
    return result


class _AuthenticatedSocksBridge:
    """Expose SOCKS5 as local HTTP so preflight, Chrome and polling share one route."""

    def __init__(self, raw_proxy: str):
        self.raw_proxy = str(raw_proxy or "").strip()
        self.process = None

    def start(self) -> str:
        if not self.raw_proxy:
            return ""
        value = normalize_proxy_url(self.raw_proxy)
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError(f"不支持的代理协议: {scheme}")
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        has_auth = bool(username or password)
        host = f"[{parsed.hostname}]" if parsed.hostname and ":" in parsed.hostname else parsed.hostname
        port = parsed.port
        # 无认证的 HTTP(S) 代理可以直接交给原生 Chrome
        if not has_auth and scheme in {"http", "https"}:
            return value
        if scheme == "socks5h":
            scheme = "socks5"
        upstream = f"{scheme}://{host}:{port}"
        if has_auth:
            upstream += f"#{username}:{password}"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            local_port = listener.getsockname()[1]
        command = [
            sys.executable,
            "-m",
            "pproxy",
            "-l",
            f"http://127.0.0.1:{local_port}",
            "-r",
            upstream,
        ]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("本地代理桥启动失败")
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.2):
                    return f"http://127.0.0.1:{local_port}"
            except OSError:
                time.sleep(0.1)
        self.close()
        raise TimeoutError("本地代理桥启动超时")
    def close(self) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)


class _ProfileLock:
    """Prevent two payment jobs from opening the same persistent Chrome profile."""

    def __init__(self, profile_directory: Path):
        self.path = Path(profile_directory) / ".opai-payment.lock"
        self.handle = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"0")
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError) as exc:
            self.close()
            raise RuntimeError("该账号的 Chrome 支付会话已在运行") from exc

    def close(self) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        except (OSError, IOError):
            pass
        self.handle.close()
        self.handle = None


def _stop_process_tree(process) -> None:
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def build_browser_launch_options(
    *,
    payment_fingerprint: Optional[dict] = None,
    proxy: str = "",
    profile_root: Optional[Path] = None,
) -> dict:
    """Return deterministic Playwright options without spoofing Chrome's UA."""
    fp = normalize_payment_fingerprint(payment_fingerprint)
    viewport = fp.get("viewport") or {}
    width = max(960, int(viewport.get("width") or 1366))
    height = max(720, int(viewport.get("height") or 768))
    locale = str(fp.get("locale") or "id-ID")
    timezone = str(fp.get("timezone") or "Asia/Jakarta")
    user_data_dir = _profile_directory(fp, profile_root)

    options = {
        "user_data_dir": str(user_data_dir.resolve()),
        "executable_path": str(_chrome_path()),
        "headless": False,
        "locale": locale,
        "timezone_id": timezone,
        "viewport": {"width": width, "height": height},
        "args": [
            f"--lang={locale}",
            f"--window-size={width},{height}",
            "--disable-features=TranslateUI",
            "--no-first-run",
            "--no-default-browser-check",
        ],
    }
    proxy_settings = _proxy_settings(proxy)
    if proxy_settings:
        options["proxy"] = proxy_settings
    return options


def build_native_chrome_launch(
    *,
    midtrans_url: str,
    payment_fingerprint: Optional[dict] = None,
    proxy: str = "",
    profile_root: Optional[Path] = None,
) -> tuple[list[str], dict[str, str]]:
    """Build a normal Chrome command line, without Playwright automation flags."""
    options = build_browser_launch_options(
        payment_fingerprint=payment_fingerprint,
        proxy="",
        profile_root=profile_root,
    )
    locale = str(options["locale"])
    timezone = str(options["timezone_id"])
    viewport = options["viewport"]
    command = [
        str(options["executable_path"]),
        f"--user-data-dir={options['user_data_dir']}",
        f"--lang={locale}",
        f"--window-size={viewport['width']},{viewport['height']}",
        "--disable-features=TranslateUI",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    proxy_settings = _proxy_settings(proxy)
    if proxy_settings:
        if proxy_settings.get("username") or proxy_settings.get("password"):
            raise ValueError("原生 Chrome 仅接受无认证代理；请先使用本地代理桥")
        command.extend(
            [
                f"--proxy-server={proxy_settings['server']}",
                "--proxy-bypass-list=<-loopback>",
            ]
        )
    command.extend(["--new-window", midtrans_url])
    child_env = dict(os.environ)
    child_env["LANG"] = locale.replace("-", "_") + ".UTF-8"
    child_env["TZ"] = timezone
    return command, child_env


def _proxy_exit_details(proxy: str) -> dict:
    handlers = [ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = build_opener(*handlers)
    request = Request("https://ipwho.is/", headers={"Accept": "application/json", "User-Agent": "GoPay-Proxy-Check/1.0"})
    with opener.open(request, timeout=25) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        raise ValueError("代理出口服务返回格式无效")
    return payload


def _snap_token(midtrans_url: str) -> str:
    match = re.search(r"/redirection/([0-9a-f-]{36})", str(midtrans_url), re.I)
    return match.group(1) if match else ""


class GoPayBrowserPayment:
    """Open the official flow in ordinary Chrome and only poll its public status."""

    def __init__(self, proxy: str = "", payment_fingerprint: Optional[dict] = None):
        self.proxy = str(proxy or "").strip()
        self.payment_fingerprint = normalize_payment_fingerprint(payment_fingerprint)

    @property
    def profile_id(self) -> str:
        return str(self.payment_fingerprint.get("profile_id") or "")

    def pay(
        self,
        midtrans_url: str,
        phone: str,
        country_code: str,
        pin: str,
        wait_otp: Callable[[str, int], Optional[str]] = None,
        progress: Callable[[str], None] | None = None,
        midtrans_client_key: str = "",
    ) -> dict:
        del pin, wait_otp, midtrans_client_key

        def note(message: str) -> None:
            if progress:
                try:
                    progress(message)
                except Exception:
                    pass

        if not re.search(r"^https://app\.midtrans\.com/snap/v[34]/redirection/[0-9a-f-]{36}", midtrans_url):
            return {"success": False, "detail": "invalid midtrans URL"}

        timeout_seconds = _bounded_env_int("OPAI_GOPAY_BROWSER_TIMEOUT", 900, 60, 3600)
        poll_seconds = _bounded_env_int("OPAI_GOPAY_STATUS_POLL_SECONDS", 3, 2, 30)
        proxy_bridge = _AuthenticatedSocksBridge(self.proxy)
        chrome = None
        profile_lock = None
        try:
            profile_lock = _ProfileLock(_profile_directory(self.payment_fingerprint))
            profile_lock.acquire()
            effective_proxy = proxy_bridge.start()
            command, child_env = build_native_chrome_launch(
                midtrans_url=midtrans_url,
                payment_fingerprint=self.payment_fingerprint,
                proxy=effective_proxy,
            )
            if _require_indonesia_exit():
                geo = _proxy_exit_details(effective_proxy)
                if not geo.get("success") or str(geo.get("country_code") or "").upper() != "ID":
                    return {
                        "success": False,
                        "detail": f"浏览器代理出口不是印度尼西亚: {geo.get('country_code') or 'unknown'}",
                    }
                proxy_timezone = str((geo.get("timezone") or {}).get("id") or "Asia/Jakarta")
                child_env["TZ"] = proxy_timezone
                note(
                    "代理出口验证通过: "
                    f"country=ID city={geo.get('city') or '-'} timezone={proxy_timezone}"
                )

            note(f"原生 Chrome 指纹支付 profile_id={self.profile_id}")
            note("已移除 Playwright 控制；官方页面将自行生成 X-Captcha-Token")
            note(f"请在打开的 Chrome 输入 +{country_code}{phone}，点击 Link and pay，并完成页面要求的验证；完成后可直接关闭浏览器窗口，程序会继续后台确认到账")
            chrome = subprocess.Popen(command, env=child_env)

            snap = _snap_token(midtrans_url)
            from .gopay_payment_protocol import GoPayPayment

            # 约束：协议只负责状态查询，绝不调用 Snap 前端私有 POST /charge。
            # 没有商户侧官方服务端 Charge API 凭据时，计费必须在 Chrome 里完成，
            # 否则 Charge 阶段又会触发人机验证导致失败。
            status_client = GoPayPayment(proxy=effective_proxy, payment_fingerprint=self.payment_fingerprint)
            deadline = time.monotonic() + timeout_seconds
            last_status = ""
            status_errors = 0
            browser_closed = False
            while time.monotonic() < deadline:
                try:
                    status_response = status_client._midtrans_get(f"/snap/v1/transactions/{snap}/status")
                    body = status_response.get("body") if isinstance(status_response, dict) else {}
                    transaction_status = str((body or {}).get("transaction_status") or "").lower()
                    if transaction_status and transaction_status != last_status:
                        last_status = transaction_status
                        note(f"Midtrans 交易状态: {transaction_status}")
                    if status_errors:
                        note("Midtrans 状态查询已恢复")
                        status_errors = 0
                    if transaction_status in {"settlement", "capture"}:
                        note("Midtrans 已确认支付成功")
                        return {
                            "success": True,
                            "detail": "payment completed in native Chrome",
                            "transaction_status": transaction_status,
                        }
                    if transaction_status in {"deny", "cancel", "expire", "failure"}:
                        return {
                            "success": False,
                            "detail": f"transaction_status={transaction_status}",
                            "transaction_status": transaction_status,
                        }
                except Exception as exc:
                    status_errors += 1
                    if status_errors in {1, 5}:
                        note(f"Midtrans 状态查询暂时失败（第 {status_errors} 次）: {str(exc)[:120]}")
                if chrome.poll() is not None:
                    if not browser_closed:
                        browser_closed = True
                        close_grace = max(30.0, float(os.environ.get("OPAI_GOPAY_BROWSER_CLOSE_GRACE_SEC", "120") or "120"))
                        deadline = min(deadline, time.monotonic() + close_grace)
                        note("浏览器窗口已关闭，转入后台继续查询交易状态…")
                time.sleep(poll_seconds)

            return {
                "success": False,
                "detail": f"原生 Chrome 支付等待超时（{timeout_seconds} 秒）",
                "failure_code": "browser_timeout",
                "transaction_status": last_status or "unknown",
            }
        except Exception as exc:
            return {"success": False, "detail": f"browser payment failed: {str(exc)[:260]}"}
        finally:
            _stop_process_tree(chrome)
            proxy_bridge.close()
            if profile_lock is not None:
                profile_lock.close()
