# -*- coding: utf-8 -*-
"""
模拟器支付模式 (OPAI_GOPAY_PAYMENT_MODE=emulator)

在 BlueStacks 模拟器里用 Chrome 打开 Midtrans Snap 链接：
  1. Snap 页面自动拉起 GoPay App（gojek:// 深链）
   2. 程序尽力自动：登录页填手机号 / 点系统"用 GoPay 打开" / 点确认按钮 / 输 PIN / 读 SMSBower 验证码并填入
  3. 无法自动的部分（Snap 页面按钮、应用内滑块等）由用户在模拟器窗口手动完成
  4. 后台轮询 /snap/v1/transactions/{snap}/status 直到 settlement / 终态

环境变量：
  OPAI_GOPAY_ADB                   adb 路径（默认 BlueStacks HD-Adb.exe）
  OPAI_GOPAY_EMULATOR_SERIAL       模拟器序列号（默认 emulator-5554）
  OPAI_GOPAY_EMULATOR_PROXY        模拟器全局代理（默认 10.0.2.2:7897 = 宿主 Clash）
  OPAI_GOPAY_EMULATOR_TIMEOUT      支付总超时秒（默认 900）
  OPAI_GOPAY_EMULATOR_AUTO_UI      是否自动点按钮/填 PIN/填 OTP（默认 1）
"""

from __future__ import annotations

import os
import re
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .gopay_payment_protocol import GoPayPayment

ADB_DEFAULT = r"C:\Program Files\BlueStacks_nxt\HD-Adb.exe"
SERIAL_DEFAULT = "emulator-5554"
GUEST_CLASH_PROXY = "10.0.2.2:7897"

_SNAP_URL_RE = re.compile(r"^https://app\.midtrans\.com/snap/v[34]/redirection/[0-9a-f-]{36}", re.I)


def emulator_payment_enabled() -> bool:
    mode = str(os.environ.get("OPAI_GOPAY_PAYMENT_MODE") or "").strip().lower()
    return mode == "emulator"


def emulator_auth_enabled() -> bool:
    """Use the Android app for registration/login when emulator payment is selected."""
    mode = str(os.environ.get("OPAI_GOPAY_AUTH_MODE") or "").strip().lower()
    return mode == "emulator" or (not mode and emulator_payment_enabled())


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(os.environ.get(name, default))
        return max(lo, min(hi, value))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.environ.get(name, "1" if default else "0")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _norm_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def _has_any(text: str, words: tuple) -> Optional[str]:
    for word in words:
        if word in text:
            return word
    return None


# 强确认词：单独出现也安全
_STRONG_CONFIRM = (
    "bayar", "konfirmasi", "setuju", "setujui", "izinkan", "aktifkan",
    "authorize", "allow", "agree", "confirm", "approve", "lanjutkan",
)
# 弱确认词：需要支付上下文或已处于确认流程才点
_WEAK_CONFIRM = ("lanjut", "continue", "ya", "selesai", "ok")
# 危险/取消词：绝不点
_CANCEL_WORDS = (
    "batal", "tolak", "tutup", "kembali", "back", "cancel", "decline",
    "deny", "skip", "lewati", "nanti", "close", "tidak",
)
# OTP 界面提示
_OTP_WORDS = (
    "otp", "kode verifikasi", "kode verif", "verification code", "verifikasi",
    "6 digit", "4 digit", "masukkan kode", "enter the code", "kode sandi",
)
# PIN 界面提示
_PIN_WORDS = ("pin",)
# 登录页提示（自动点击保护）
_LOGIN_WORDS = (
    "selamat datang", "masuk atau daftar", "welcome", "phone number",
    "nomor hp", "masuk ke gopay", "sign in",
)
# 登录页内允许提交手机号的按钮。该集合只在已识别 GoPay 登录页且手机号已输入时使用。
_LOGIN_SUBMIT_WORDS = (
    "lanjut", "continue", "next", "masuk", "sign in", "kirim kode", "send code",
)

_NODE_RE = re.compile(r"<node\b([^>]*)>")
_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def _parse_ui(xml: str) -> list[dict[str, str]]:
    nodes: list[dict[str, str]] = []
    for match in _NODE_RE.finditer(xml or ""):
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', match.group(1)))
        nodes.append(attrs)
    return nodes


def _node_text(node: dict[str, str]) -> str:
    return _norm_text(f'{node.get("text", "")} {node.get("content-desc", "")}')


def _is_clickable(node: dict[str, str]) -> bool:
    return node.get("clickable") == "true" or node.get("class") == "android.widget.Button"


def _is_editable(node: dict[str, str]) -> bool:
    return node.get("editable") == "true" or "edittext" in _norm_text(node.get("class", ""))


def _login_phone_number(phone: str, country_code: str) -> str:
    """Return the national number expected by the GoPay login form.

    The Indonesian country picker supplies +62, while task records may contain
    either 812... or 62812....  Keep a leading 0 intact because some app builds
    explicitly request that local form.
    """
    digits = re.sub(r"\D", "", str(phone or ""))
    code = re.sub(r"\D", "", str(country_code or ""))
    if code and digits.startswith(code) and len(digits) > len(code):
        digits = digits[len(code):]
    return digits


def emulator_selftest(serial: str = "") -> dict[str, Any]:
    """控制台环境体检用：返回模拟器就绪状态。"""
    adb = os.environ.get("OPAI_GOPAY_ADB") or ADB_DEFAULT
    serial = serial or os.environ.get("OPAI_GOPAY_EMULATOR_SERIAL") or SERIAL_DEFAULT
    try:
        p = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=15, errors="replace")
        lines = (p.stdout or "").splitlines()
    except Exception as exc:
        return {"ok": False, "detail": f"adb 不可用: {str(exc)[:80]}"}
    state = ""
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == serial:
            state = parts[1]
            break
    if not state:
        return {"ok": False, "detail": f"{serial} 不在线，请启动 BlueStacks"}
    if state != "device":
        return {"ok": False, "detail": f"{serial} 状态异常: {state}"}
    detail = f"{serial} 在线"
    boot = ""
    try:
        p = subprocess.run([adb, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                           capture_output=True, text=True, timeout=15, errors="replace")
        boot = (p.stdout or "").strip()
    except Exception:
        pass
    if boot != "1":
        return {"ok": False, "detail": f"{serial} 未完成启动"}
    detail += " · 已启动"
    try:
        p = subprocess.run([adb, "-s", serial, "shell", "pm", "list", "packages"],
                           capture_output=True, text=True, timeout=20, errors="replace")
        if "com.gojek.gopay" in (p.stdout or ""):
            detail += " · GoPay 已安装"
        else:
            return {"ok": False, "detail": detail + " · GoPay 未安装"}
    except Exception:
        pass
    try:
        p = subprocess.run([adb, "-s", serial, "shell", "settings", "get", "global", "http_proxy"],
                           capture_output=True, text=True, timeout=15, errors="replace")
        proxy = (p.stdout or "").strip()
        detail += f" · 代理 {proxy or '未设置'}"
    except Exception:
        pass
    return {"ok": True, "detail": detail}


class GoPayEmulatorPayment:
    """在模拟器里打开 Midtrans 链接，由 GoPay App 原生完成支付，后台轮询到账。"""

    def __init__(self, proxy: str = "", payment_fingerprint: Optional[dict] = None):
        self.proxy = str(proxy or "").strip()
        self.payment_fingerprint = payment_fingerprint or {}
        self._adb = os.environ.get("OPAI_GOPAY_ADB") or ADB_DEFAULT
        self._serial = os.environ.get("OPAI_GOPAY_EMULATOR_SERIAL") or SERIAL_DEFAULT
        self._guest_proxy = os.environ.get("OPAI_GOPAY_EMULATOR_PROXY") or GUEST_CLASH_PROXY
        self._timeout = _env_int("OPAI_GOPAY_EMULATOR_TIMEOUT", 900, 120, 3600)
        self._poll = _env_int("OPAI_GOPAY_STATUS_POLL_SECONDS", 3, 2, 30)
        self._auto_ui = _env_bool("OPAI_GOPAY_EMULATOR_AUTO_UI", True)

    # ---- adb helpers ----
    def _run(self, *args: str, timeout: int = 30) -> Optional[subprocess.CompletedProcess]:
        try:
            return subprocess.run(
                [self._adb, "-s", self._serial, *args],
                capture_output=True, text=True, timeout=timeout, errors="replace",
            )
        except Exception:
            return None

    def _shell(self, command: str, timeout: int = 30) -> str:
        p = self._run("shell", command, timeout=timeout)
        return (p.stdout or "") if p and p.returncode == 0 else ""

    @staticmethod
    def _note(progress: Optional[Callable[[str], None]], message: str) -> None:
        if progress:
            try:
                progress(message)
            except Exception:
                pass

    # ---- 环境 ----
    def _emulator_ready(self) -> tuple[bool, str]:
        try:
            p = subprocess.run([self._adb, "devices"], capture_output=True, text=True, timeout=15, errors="replace")
        except Exception as exc:
            return False, f"adb 不可用: {str(exc)[:80]}"
        found = False
        for line in (p.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == self._serial:
                if parts[1] == "device":
                    found = True
                else:
                    return False, f"模拟器 {self._serial} 状态异常: {parts[1]}"
        if not found:
            return False, f"模拟器 {self._serial} 不在线，请先启动 BlueStacks（work\\bs_emulator.py start）"
        boot = self._shell("getprop sys.boot_completed").strip()
        if boot != "1":
            return False, f"模拟器 {self._serial} 未完成启动"
        return True, f"模拟器 {self._serial} 在线"

    def _ensure_guest_proxy(self, progress: Optional[Callable[[str], None]]) -> None:
        if not self._guest_proxy:
            return
        current = self._shell("settings get global http_proxy").strip()
        if current != self._guest_proxy:
            self._shell(f"settings put global http_proxy {self._guest_proxy}")
            self._note(progress, f"模拟器全局代理已设为 {self._guest_proxy}（宿主 Clash），请确保 Clash 出口为印尼")
        else:
            self._note(progress, f"模拟器全局代理已是 {self._guest_proxy}（宿主 Clash）")

    def _open_url(self, url: str, progress: Optional[Callable[[str], None]]) -> None:
        self._run("shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", url, timeout=30)
        self._note(progress, "已在模拟器用 Chrome 打开 Midtrans 链接，Snap 页面将拉起 GoPay App")
        time.sleep(6)

    @staticmethod
    def _session_file() -> Path:
        configured = str(os.environ.get("OPAI_GOPAY_EMULATOR_SESSION_FILE") or "").strip()
        if configured:
            return Path(configured).expanduser()
        return Path(__file__).resolve().parents[4] / "config" / "gopay_emulator_session.json"

    def _record_session(self, phone: str, country_code: str) -> None:
        """Persist app-session metadata; the authenticated session itself remains in BlueStacks."""
        path = self._session_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "phone": _login_phone_number(phone, country_code),
            "country_code": str(country_code or "62").lstrip("+"),
            "serial": self._serial,
            "updated_at": int(time.time()),
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _open_gopay_app(self, progress: Optional[Callable[[str], None]]) -> None:
        self._run("shell", "monkey", "-p", "com.gojek.gopay", "1", timeout=30)
        self._note(progress, "已在模拟器打开 GoPay App，开始登录/注册并保留应用会话")
        time.sleep(3)

    def _foreground_package(self) -> str:
        out = self._shell("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp' | head -1")
        m = re.search(r"(\S+)/[.\w]+", out)
        return m.group(1) if m else ""

    def _dump_ui(self) -> str:
        self._run("shell", "uiautomator dump --compressed /sdcard/_opai_ui.xml", timeout=30)
        p = self._run("shell", "cat /sdcard/_opai_ui.xml", timeout=30)
        return (p.stdout or "") if p and p.returncode == 0 else ""

    def _tap_center(self, node: dict[str, str]) -> bool:
        m = _BOUNDS_RE.search(node.get("bounds") or "")
        if not m:
            return False
        x = (int(m.group(1)) + int(m.group(3))) // 2
        y = (int(m.group(2)) + int(m.group(4))) // 2
        self._run("shell", "input", "tap", str(x), str(y), timeout=15)
        return True

    def _tap_node_once(self, node: dict[str, str], state: dict[str, Any], cooldown: float = 4.0) -> bool:
        key = (node.get("bounds"), node.get("text"), node.get("content-desc"))
        last = state.get("tapped", {}).get(key, 0.0)
        if time.monotonic() - last < cooldown:
            return False
        if not self._tap_center(node):
            return False
        state.setdefault("tapped", {})[key] = time.monotonic()
        return True

    # ---- 自动化 ----
    def _automate_chooser(self, progress: Optional[Callable[[str], None]], state: dict[str, Any]) -> str:
        """系统"打开方式"弹窗：选 GoPay/Gojek。"""
        nodes = _parse_ui(self._dump_ui())
        for node in nodes:
            text = _node_text(node)
            if _has_any(text, ("gopay", "gojek")) and _is_clickable(node):
                if self._tap_node_once(node, state):
                    self._note(progress, f"已选择用 GoPay 打开: {text[:40]}")
                    return "chooser"
        return "none"

    def _automate_chrome(self, progress: Optional[Callable[[str], None]], state: dict[str, Any]) -> str:
        """Snap 页面按钮（Link and pay / Lanjut dengan GoPay 等）。"""
        nodes = _parse_ui(self._dump_ui())
        for node in nodes:
            pkg = node.get("package", "")
            if pkg and "chrome" not in pkg:
                continue
            text = _node_text(node)
            if not _is_clickable(node):
                continue
            if _has_any(text, _CANCEL_WORDS):
                continue
            if _has_any(text, ("gopay", "link and pay", "tautkan", "lanjutkan", "bayar")):
                if self._tap_node_once(node, state):
                    self._note(progress, f"已点击 Snap 页面按钮: {text[:40]}")
                    return "chrome"
        return "none"

    def _tap_confirm(self, nodes: list[dict[str, str]], progress: Optional[Callable[[str], None]],
                     state: dict[str, Any], weak_ok: bool) -> bool:
        candidates: list[tuple[bool, str, dict[str, str]]] = []
        for node in nodes:
            if not _is_clickable(node):
                continue
            text = _node_text(node)
            if not text:
                continue
            if _has_any(text, _CANCEL_WORDS):
                continue
            strong = _has_any(text, _STRONG_CONFIRM)
            weak = _has_any(text, _WEAK_CONFIRM)
            if strong or (weak_ok and weak):
                if weak and _has_any(text, _LOGIN_WORDS):
                    continue
                candidates.append((bool(strong), text, node))
        if not candidates:
            return False
        candidates.sort(key=lambda item: (not item[0], len(item[1])))
        strong, text, node = candidates[0]
        if self._tap_node_once(node, state):
            self._note(progress, f"已自动点击确认按钮: {text[:40]}")
            return True
        return False

    def _input_pin_digits(self, pin: str, nodes: list[dict[str, str]]) -> bool:
        digits = re.sub(r"\D", "", str(pin or ""))
        if len(digits) < 4:
            return False
        digit_nodes: dict[str, dict[str, str]] = {}
        for node in nodes:
            desc = _norm_text(node.get("content-desc", "") or node.get("text", ""))
            if re.fullmatch(r"[0-9]", desc) and _is_clickable(node):
                digit_nodes.setdefault(desc, node)
        if len(digit_nodes) < 10:
            return False
        for ch in digits:
            node = digit_nodes.get(ch)
            if not node:
                return False
            self._tap_center(node)
            time.sleep(0.25)
        return True

    def _input_login_phone(self, phone: str, country_code: str, nodes: list[dict[str, str]]) -> bool:
        """Focus the GoPay phone field, clear stale content, and enter the task number."""
        number = _login_phone_number(phone, country_code)
        if len(number) < 7:
            return False
        fields = [node for node in nodes if _is_editable(node) and node.get("enabled", "true") != "false"]
        if not fields or not self._tap_center(fields[0]):
            return False
        # Android's `input text` appends.  Clear a pre-filled/partially typed
        # number first so a retry cannot produce an invalid combined number.
        self._run("shell", "input", "keyevent", "123", timeout=15)  # MOVE_END
        for _ in range(20):
            self._run("shell", "input", "keyevent", "67", timeout=15)  # DEL
        result = self._run("shell", "input", "text", number, timeout=15)
        return bool(result and result.returncode == 0)

    def _automate_login(self, phone: str, country_code: str, nodes: list[dict[str, str]],
                        progress: Optional[Callable[[str], None]], state: dict[str, Any]) -> str:
        """Complete the app's phone-number step and leave OTP/PIN to their handlers."""
        state["login_active"] = True
        if not state.get("login_phone_entered"):
            if self._input_login_phone(phone, country_code, nodes):
                state["login_phone_entered"] = True
                self._note(progress, "已在 GoPay 登录页填入手机号，正在提交验证码请求")
                return "login_phone"
            self._note(progress, "GoPay 登录页未识别到手机号输入框，请在模拟器手动输入手机号")
            return "login_wait"

        for node in nodes:
            text = _node_text(node)
            if not _is_clickable(node) or _has_any(text, _CANCEL_WORDS):
                continue
            # "Masuk atau daftar" is page chrome, not a submit action.
            if "masuk atau daftar" in text:
                continue
            if _has_any(text, _LOGIN_SUBMIT_WORDS) and self._tap_node_once(node, state):
                self._note(progress, f"已提交 GoPay 登录手机号: {text[:40]}")
                return "login_submit"
        self._note(progress, "GoPay 登录页等待下一步按钮；可在模拟器手动点击继续")
        return "login_wait"

    def _automate_gopay(self, phone: str, country_code: str, pin: str, get_otp: Optional[Callable[[], Optional[str]]],
                        progress: Optional[Callable[[str], None]], state: dict[str, Any]) -> str:
        xml = self._dump_ui()
        nodes = _parse_ui(xml)
        if not nodes:
            return "none"
        joined = " ".join(_node_text(n) for n in nodes)

        # OTP：读 SMSBower 验证码自动填入
        # OTP 优先于登录页标题判断：部分 GoPay 版本在 OTP 页面仍显示“Masuk”。
        if _has_any(joined, _OTP_WORDS):
            last = state.get("otp_last", 0.0)
            if get_otp and time.monotonic() - last > 30:
                state["otp_last"] = time.monotonic()
                self._note(progress, "检测到验证码输入界面，正在读取短信验证码…")
                code = get_otp()
                if code:
                    self._run("shell", "input", "text", str(code), timeout=15)
                    self._note(progress, f"已自动填入验证码 {code}")
                    time.sleep(2)
                    return "otp"
            self._note(progress, "验证码界面：等待短信验证码（可在模拟器手动输入，或稍候自动填入）")
            return "otp_wait"

        # 登录页：填手机号并提交，随后继续复用 OTP/PIN 自动化。
        if _has_any(joined, _LOGIN_WORDS):
            return self._automate_login(phone, country_code, nodes, progress, state)

        # PIN 键盘
        if _has_any(joined, _PIN_WORDS):
            if self._input_pin_digits(pin, nodes):
                self._note(progress, "已自动输入 GoPay PIN")
                time.sleep(2)
                return "pin"
            if pin and re.fullmatch(r"\d{4,6}", str(pin)):
                self._note(progress, "PIN 键盘无法自动识别，请手动输入 PIN")

        # 登录完成后重新打开原 Snap 链接，使已登录的 App 会话回到支付深链。
        if state.get("login_active") and not state.get("login_resumed"):
            state["login_resumed"] = True
            self._note(progress, "GoPay 登录已离开登录页，正在重新打开 Midtrans 链接继续支付")
            return "login_complete"

        # 确认按钮
        if self._tap_confirm(nodes, progress, state, weak_ok=False):
            return "tapped"
        return "none"

    def _ui_automate_round(self, phone: str, country_code: str, pin: str,
                           get_otp: Optional[Callable[[], Optional[str]]],
                           progress: Optional[Callable[[str], None]], state: dict[str, Any]) -> str:
        if not self._auto_ui:
            return "disabled"
        try:
            fg = self._foreground_package()
        except Exception:
            return "none"
        if not fg:
            return "none"
        if fg == "android":
            return self._automate_chooser(progress, state)
        if "chrome" in fg:
            return self._automate_chrome(progress, state)
        if fg == "com.gojek.gopay":
            return self._automate_gopay(phone, country_code, pin, get_otp, progress, state)
        return "none"

    def authenticate(
        self,
        phone: str,
        country_code: str,
        pin: str,
        wait_otp: Optional[Callable[[str, int], Optional[str]]] = None,
        progress: Optional[Callable[[str], None]] = None,
        register_if_needed: bool = True,
    ) -> dict[str, Any]:
        """Drive the installed GoPay app through its login/register entrance.

        GoPay keeps the resulting authenticated state in the emulator application
        data, so later Midtrans payments reuse that same native session rather
        than recreating a protocol login.
        """
        ok, detail = self._emulator_ready()
        if not ok:
            return {"success": False, "detail": detail, "failure_code": "emulator_unavailable"}
        self._note(progress, detail)
        self._ensure_guest_proxy(progress)
        self._open_gopay_app(progress)
        deadline = time.monotonic() + self._timeout
        state: dict[str, Any] = {"tapped": {}, "login_active": False, "login_resumed": False}
        ready_since = 0.0

        def get_otp_code() -> Optional[str]:
            if wait_otp is None:
                return None
            try:
                return wait_otp(phone, 45)
            except Exception as exc:
                self._note(progress, f"自动读取登录验证码失败: {str(exc)[:100]}")
                return None

        while time.monotonic() < deadline:
            fg = self._foreground_package()
            if fg == "com.gojek.gopay":
                xml = self._dump_ui()
                joined = " ".join(_node_text(node) for node in _parse_ui(xml))
                auth_prompt = _has_any(joined, _LOGIN_WORDS + _OTP_WORDS + _PIN_WORDS)
                action = (
                    self._automate_gopay(phone, country_code, pin, get_otp_code, progress, state)
                    if auth_prompt or state.get("login_active")
                    else "none"
                )
                if action == "login_complete":
                    self._record_session(phone, country_code)
                    return {"success": True, "detail": "emulator GoPay session ready", "registered": bool(register_if_needed)}
                # A home screen on an already logged-in emulator has neither
                # authentication prompt nor PIN/OTP prompt. Require a brief
                # stable observation before accepting that persisted session.
                if not auth_prompt:
                    if not ready_since:
                        ready_since = time.monotonic()
                    elif time.monotonic() - ready_since >= 3:
                        self._record_session(phone, country_code)
                        self._note(progress, "检测到已保持的 GoPay 模拟器登录会话")
                        return {"success": True, "detail": "emulator GoPay session ready", "registered": False}
                else:
                    ready_since = 0.0
                if action not in {"none", "disabled", "login_wait", "otp_wait"}:
                    time.sleep(1)
            else:
                ready_since = 0.0
                if fg == "android":
                    self._automate_chooser(progress, state)
            time.sleep(self._poll)
        return {"success": False, "detail": f"模拟器登录/注册等待超时（{self._timeout} 秒）", "failure_code": "emulator_auth_timeout"}

    # ---- 主流程 ----
    def pay(
        self,
        midtrans_url: str,
        phone: str,
        country_code: str,
        pin: str,
        wait_otp: Optional[Callable[[str, int], Optional[str]]] = None,
        progress: Optional[Callable[[str], None]] = None,
        midtrans_client_key: str = "",
    ) -> dict[str, Any]:
        del midtrans_client_key

        def note(message: str) -> None:
            self._note(progress, message)

        if not _SNAP_URL_RE.search(midtrans_url):
            return {"success": False, "detail": "invalid midtrans URL"}

        ok, detail = self._emulator_ready()
        if not ok:
            return {"success": False, "detail": detail}
        note(detail)

        self._ensure_guest_proxy(progress)
        note("请在模拟器窗口完成剩余操作：Snap 页面点 Link and pay → GoPay App 确认 → 返回浏览器即可")
        note("程序会尝试自动点确认 / 输 PIN / 填验证码，并后台轮询到账")

        self._open_url(midtrans_url, progress)

        snap_match = re.search(r"/redirection/([0-9a-f-]{36})", midtrans_url, re.I)
        snap = snap_match.group(1) if snap_match else ""

        def get_otp_code() -> Optional[str]:
            if wait_otp is None:
                return None
            try:
                return wait_otp(phone, 45)
            except Exception as exc:
                note(f"自动读取验证码失败: {str(exc)[:100]}")
                return None

        status_client: Optional[GoPayPayment] = None
        try:
            status_client = GoPayPayment(proxy=self.proxy or None, payment_fingerprint=self.payment_fingerprint)
        except Exception as exc:
            note(f"状态查询客户端初始化失败: {str(exc)[:120]}")

        state: dict[str, Any] = {"tapped": {}, "login_active": False, "login_resumed": False}
        deadline = time.monotonic() + self._timeout
        last_status = ""
        status_errors = 0
        terminal = {"deny", "cancel", "expire", "failure"}
        success = {"settlement", "capture"}

        while time.monotonic() < deadline:
            # 1) 轮询 Midtrans 状态
            if status_client is not None:
                try:
                    status_response = status_client._midtrans_get(f"/snap/v1/transactions/{snap}/status")
                    body = status_response.get("body") if isinstance(status_response, dict) else {}
                    if isinstance(body, dict):
                        transaction_status = str(body.get("transaction_status") or "").lower()
                    else:
                        transaction_status = ""
                    if transaction_status and transaction_status != last_status:
                        last_status = transaction_status
                        note(f"Midtrans 交易状态: {transaction_status}")
                    if status_errors:
                        note("Midtrans 状态查询已恢复")
                        status_errors = 0
                    if transaction_status in success:
                        note("Midtrans 已确认支付成功")
                        return {
                            "success": True,
                            "detail": "payment completed in emulator GoPay app",
                            "transaction_status": transaction_status,
                        }
                    if transaction_status in terminal:
                        return {
                            "success": False,
                            "detail": f"transaction_status={transaction_status}",
                            "transaction_status": transaction_status,
                        }
                except Exception as exc:
                    status_errors += 1
                    if status_errors in {1, 5}:
                        note(f"Midtrans 状态查询暂时失败（第 {status_errors} 次）: {str(exc)[:120]}")

            # 2) 尽力自动操作模拟器 UI
            action = self._ui_automate_round(phone, country_code, pin, get_otp_code, progress, state)
            if action == "login_complete":
                state["tapped"] = {}
                self._open_url(midtrans_url, progress)
            if action not in {"none", "disabled"}:
                time.sleep(1.0)

            time.sleep(self._poll)

        return {
            "success": False,
            "detail": f"模拟器支付等待超时（{self._timeout} 秒），请在模拟器确认是否已完成，交易状态 {last_status or 'unknown'}",
            "failure_code": "emulator_timeout",
            "transaction_status": last_status or "unknown",
        }
