import json
import os
import platform
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "app" / "src"))


def _load_runtime_environment() -> dict[str, str]:
    """Load runtime.env before importing modules that read settings at import time."""
    path = ROOT / "config" / "runtime.env"
    pairs: dict[str, str] = {}
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                continue
            pairs[key] = value.strip().strip('"').strip("'")
        for key, value in pairs.items():
            os.environ.setdefault(key, value)
    return pairs


RUNTIME_ENV = _load_runtime_environment()


def _force_protocol_runtime():
    """Keep both account authentication and payment on the protocol path."""
    os.environ["OPAI_GOPAY_PAYMENT_MODE"] = "protocol"
    os.environ["OPAI_GOPAY_AUTH_MODE"] = "protocol"


_force_protocol_runtime()

from opai.core.payment_inbox import (  # noqa: E402
    InboxStore,
    ProxyPreflightError,
    _cancel_sms_activation_with_retry,
    _claim_gopay_reward,
    _ManualRegisterManager,
    _PinManager,
    _WebPaymentManager,
    _find_gopay_account,
    _default_gopay_proxy,
    _gopay_client_from_account,
    _load_gopay_accounts,
    _load_gopay_accounts_raw,
    _list_payment_eligible_accounts,
    _normalize_proxy_url,
    _preflight_gopay_proxy,
    _proxy_preflight_error,
    _release_gopay_sms,
    _refresh_gopay_balance,
    _refresh_gopay_pin_status,
    _release_gopay_midtrans_binding,
    _sms_api_status,
    _save_gopay_account_tokens_and_pin,
    _write_sms_config,
    _write_gopay_accounts_raw,
)
from opai.core.captcha_provider import (  # noqa: E402
    captcha_config_status,
    write_captcha_config,
)

from opai.core.file_utils import atomic_write_json, atomic_write_text  # noqa: E402
from opai.core.proxy_provider import (  # noqa: E402
    delete_provider as delete_proxy_provider,
    public_state as proxy_provider_state,
    resolve_proxy as resolve_provider_proxy,
    save_bindings as save_proxy_bindings,
    save_provider as save_proxy_provider,
)
from opai.core.sms_helpers import read_imported_sms_url, validate_imported_sms_url, extract_imported_sms_codes  # noqa: E402
from opai.core.gojek_client import (  # noqa: E402
    GOPAY_APP_BUILD,
    GOPAY_APP_VERSION,
    probe_proxy_risk,
    proxy_fraud_denied,
)

POOL = ROOT / "config" / "gopay_phone_pool.json"
PHONE_CHANGE_TASKS_FILE = ROOT / "config" / "phone_change_tasks.json"
AUTH_ENVIRONMENT_FILE = Path(
    os.environ.get("OPAI_GOPAY_AUTH_ENVIRONMENT_FILE", str(ROOT / "config" / "gopay_auth_environment.jsonl"))
).expanduser()
if not AUTH_ENVIRONMENT_FILE.is_absolute():
    AUTH_ENVIRONMENT_FILE = ROOT / AUTH_ENVIRONMENT_FILE
_phone_change_tasks_lock = threading.RLock()
_phone_change_codes: dict[str, str] = {}
_phone_change_workers_lock = threading.RLock()
_phone_change_workers: set[str] = set()
PHONE_CHANGE_MAX_ATTEMPTS = 10
PHONE_CHANGE_OTP_TIMEOUT_SEC = 60
PHONE_CHANGE_APP_VERSION = os.environ.get("OPAI_GOPAY_PHONE_CHANGE_APP_VERSION", "2.16.1").strip() or "2.16.1"
PHONE_CHANGE_APP_BUILD = os.environ.get("OPAI_GOPAY_PHONE_CHANGE_APP_BUILD", "2161").strip() or "2161"
PHONE_CHANGE_LOGIN_APP_VERSION = os.environ.get(
    "OPAI_GOPAY_PHONE_CHANGE_LOGIN_APP_VERSION", "2.22.1"
).strip() or "2.22.1"
PHONE_CHANGE_LOGIN_APP_BUILD = os.environ.get(
    "OPAI_GOPAY_PHONE_CHANGE_LOGIN_APP_BUILD", "2221"
).strip() or "2221"
PHONE_CHANGE_LOGIN_PREFER_SMS = os.environ.get(
    "OPAI_GOPAY_PHONE_CHANGE_LOGIN_PREFER_SMS", "1"
).strip().lower() not in {"0", "false", "no", "off"}


def _sanitize_public_error(value):
    text = str(value or "")
    text = re.sub(r"://[^/@\s]+@", "://***@", text)
    text = re.sub(
        r"(?i)((?:api[_-]?key|apikey|key)(?:=|%3[dD]))[^&\s\"']+",
        r"\1***",
        text,
    )
    return text[:500]


def _public_auth_environment(item):
    """Return only display-safe fields from an authentication audit record."""
    network = item.get("network") if isinstance(item.get("network"), dict) else {}
    device = item.get("device") if isinstance(item.get("device"), dict) else {}
    return {
        "event_id": str(item.get("event_id") or ""),
        "recorded_at": str(item.get("recorded_at") or ""),
        "flow": str(item.get("flow") or "auth"),
        "phone": str(item.get("phone") or ""),
        "country_code": str(item.get("country_code") or ""),
        "network": {
            "mode": str(network.get("mode") or ""),
            "proxy": _sanitize_public_error(network.get("proxy") or "direct"),
            "egress_ip": str(network.get("egress_ip") or ""),
            "probe_ok": bool(network.get("probe_ok")),
            "probe_status": int(network.get("probe_status") or 0),
            "probe_error": _sanitize_public_error(network.get("probe_error") or ""),
        },
        "device": {
            "platform": str(device.get("platform") or "Android"),
            "model": str(device.get("model") or ""),
            "manufacturer": str(device.get("manufacturer") or ""),
            "os": str(device.get("os") or ""),
            "app_id": str(device.get("app_id") or ""),
            "app_version": str(device.get("app_version") or ""),
            "unique_id": str(device.get("unique_id") or ""),
            "session_id": str(device.get("session_id") or ""),
            "user_agent": str(device.get("user_agent") or ""),
            "tls_profile": str(device.get("tls_profile") or ""),
            "xm1": str(device.get("xm1") or ""),
            "xm1_sha256": str(device.get("xm1_sha256") or ""),
        },
    }


def _load_auth_environments(limit=200):
    limit = max(1, min(1000, int(limit or 200)))
    rows = deque(maxlen=limit)
    total = 0
    if AUTH_ENVIRONMENT_FILE.is_file():
        try:
            with AUTH_ENVIRONMENT_FILE.open("r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(item, dict):
                        continue
                    total += 1
                    rows.append(_public_auth_environment(item))
        except OSError:
            rows.clear()
            total = 0
    stat = AUTH_ENVIRONMENT_FILE.stat() if AUTH_ENVIRONMENT_FILE.is_file() else None
    return {
        "records": list(reversed(rows)),
        "total": total,
        "returned": len(rows),
        "path": str(AUTH_ENVIRONMENT_FILE),
        "file_size": int(stat.st_size) if stat else 0,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)) if stat else "",
    }


def _parse_proxy_list(value):
    raw_items = value if isinstance(value, list) else str(value or "").splitlines()
    proxies = []
    seen = set()
    for line_number, raw in enumerate(raw_items, 1):
        text = str(raw or "").strip()
        if not text:
            continue
        proxy = _normalize_proxy_url(text)
        try:
            parsed = urlsplit(proxy)
            port = parsed.port
        except ValueError:
            parsed = None
            port = None
        if (
            parsed is None
            or parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"}
            or not parsed.hostname
            or port is None
        ):
            raise ValueError(f"第 {line_number} 条代理格式无效，请使用 http://、https:// 或 socks5:// 地址")
        if proxy not in seen:
            seen.add(proxy)
            proxies.append(proxy)
        if len(proxies) > 100:
            raise ValueError("代理最多填写 100 条")
    return proxies


def _check_proxy_pool(proxies):
    def check(item):
        index, proxy = item
        try:
            result = _preflight_gopay_proxy(proxy)
        except Exception as exc:
            result = {"ok": False, "status": 0, "error": str(exc)}
        error = "" if result.get("ok") else _proxy_preflight_error(proxy, result)
        error = _sanitize_public_error(error)[:300]
        risk = {}
        if result.get("ok"):
            try:
                risk = probe_proxy_risk(proxy, timeout_sec=10)
            except Exception:
                risk = {}
        return {
            "index": index,
            "proxy": proxy,
            "ok": bool(result.get("ok")),
            "ip": str(result.get("ip") or ""),
            "error": error,
            "risk": risk,
        }

    if not proxies:
        return {"total": 0, "available": 0, "unavailable": 0, "healthy": [], "results": []}
    with ThreadPoolExecutor(max_workers=min(10, len(proxies))) as executor:
        results = list(executor.map(check, enumerate(proxies)))
    healthy = [row["proxy"] for row in results if row["ok"]]
    public_results = [
        {
            "line": row["index"] + 1,
            "ok": row["ok"],
            "ip": row["ip"],
            "error": row["error"],
            "risk_level": (row.get("risk") or {}).get("risk_level") or "",
            "country": (row.get("risk") or {}).get("country") or "",
            "org": (row.get("risk") or {}).get("org") or "",
            "verdict": (row.get("risk") or {}).get("verdict") or "",
        }
        for row in results
    ]
    return {
        "total": len(proxies),
        "available": len(healthy),
        "unavailable": len(proxies) - len(healthy),
        "healthy": healthy,
        "results": public_results,
    }


def _runtime_env_path() -> Path:
    return ROOT / "config" / "runtime.env"


def _read_runtime_env() -> dict[str, str]:
    pairs: dict[str, str] = {}
    path = _runtime_env_path()
    if not path.exists():
        return pairs
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        pairs[key.strip()] = value.strip().strip('"').strip("'")
    return pairs


def _upsert_runtime_env(key: str, value: str) -> None:
    path = _runtime_env_path()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    index = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        if stripped.split("=", 1)[0].strip() == key:
            index = i
            break
    if index is None:
        if value:
            if lines and lines[-1].strip():
                lines.append("")
            lines.append(f"{key}={value}")
    elif value:
        lines[index] = f"{key}={value}"
    else:
        lines[index] = f"# {key}="
    atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))
    if value:
        os.environ[key] = value
    else:
        os.environ.pop(key, None)


DEFAULT_CLASH_ADDRESS = os.environ.get("OPAI_GOPAY_CLASH_ADDRESS") or "http://127.0.0.1:7890"


def proxy_config_status() -> dict:
    pairs = _read_runtime_env()
    default_proxy = str(
        os.environ.get("OPAI_GOPAY_DEFAULT_PROXY") or pairs.get("OPAI_GOPAY_DEFAULT_PROXY") or ""
    ).strip()
    clash_address = str(
        os.environ.get("OPAI_GOPAY_CLASH_ADDRESS") or pairs.get("OPAI_GOPAY_CLASH_ADDRESS") or DEFAULT_CLASH_ADDRESS
    ).strip()
    return {
        "default_proxy": default_proxy,
        "clash_enabled": bool(default_proxy),
        "clash_address": clash_address,
        "env_file": str(_runtime_env_path()),
    }


def write_proxy_config(data: dict) -> dict:
    clash_address = str(data.get("clash_address") or "").strip() or DEFAULT_CLASH_ADDRESS
    if "clash_address" in data:
        _upsert_runtime_env("OPAI_GOPAY_CLASH_ADDRESS", clash_address)
    if "default_proxy" in data:
        raw = str(data.get("default_proxy") or "").strip()
        _upsert_runtime_env("OPAI_GOPAY_DEFAULT_PROXY", _normalize_proxy_url(raw) if raw else "")
    elif data.get("use_clash"):
        _upsert_runtime_env("OPAI_GOPAY_DEFAULT_PROXY", _normalize_proxy_url(clash_address))
    return proxy_config_status()


ENV_CHECK_CACHE: dict = {"at": 0.0, "data": None}
ENV_CHECK_LOCK = threading.Lock()


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> None:
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.close()


def _http_get(url: str, timeout: float = 10, proxy: str = "") -> str:
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener()
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 GoPayEnvCheck/1.0"}
    )
    with opener.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _http_probe(url: str, proxy: str) -> tuple[bool, str]:
    """True when the server answered any HTTP status (route works)."""
    try:
        _http_get(url, timeout=12, proxy=proxy)
        return True, "HTTP 可达"
    except urllib.error.HTTPError as exc:
        return True, "HTTP %d (服务可达)" % exc.code
    except Exception as exc:
        return False, str(exc)[:140]


def env_check_status(force: bool = False) -> dict:
    runtime_env = _read_runtime_env()
    now = time.time()
    with ENV_CHECK_LOCK:
        cached = ENV_CHECK_CACHE.get("data")
        if not force and cached and now - ENV_CHECK_CACHE.get("at", 0.0) < 20:
            return cached
        items: list[dict] = []

        def log(name: str, ok: bool, detail: str = "") -> None:
            items.append({"name": name, "ok": bool(ok), "detail": str(detail or "")})

        log("Python 版本", platform.python_version_tuple()[:2] >= ("3", "10"),
            platform.python_version() + " (" + os.path.realpath(sys.executable) + ")")
        for mod in ("tls_client", "playwright"):
            try:
                __import__(mod)
                log("依赖 " + mod, True)
            except Exception as exc:
                log("依赖 " + mod, False, str(exc)[:150])
        for rel in ("config/runtime.env", "config/sms.env", "config/captcha.env", "config/payment_tasks.json"):
            path = ROOT / rel
            log("配置 " + rel, path.is_file(), "" if path.is_file() else "文件缺失: " + str(path))

        clash_address = proxy_config_status().get("clash_address") or "http://127.0.0.1:7897"
        try:
            host, _, port = clash_address.replace("http://", "").replace("https://", "").rpartition(":")
            _tcp_reachable(host or "127.0.0.1", int(port or 7897))
            log("Clash 代理 " + clash_address, True, "端口可达 " + (host or "127.0.0.1") + ":" + str(port or 7897))
            try:
                body = _http_get("https://api.ipify.org?format=json", timeout=12, proxy=clash_address)
                ip = json.loads(body).get("ip", body.strip())
                log("Clash 出口 IP", True, str(ip))
            except Exception as exc:
                log("Clash 出口 IP", False, str(exc)[:150])
            try:
                risk = probe_proxy_risk(clash_address, timeout_sec=10)
                level = str(risk.get("risk_level") or "unknown")
                risk_detail = "IP={ip} 国家={country} 机构={org} -> {verdict}".format(
                    ip=risk.get("ip") or "-",
                    country=risk.get("country") or "-",
                    org=risk.get("org") or "-",
                    verdict=risk.get("verdict") or "",
                )
                log("出口 IP 风控画像", level not in {"high", "unknown"}, risk_detail)
            except Exception as exc:
                log("出口 IP 风控画像", False, str(exc)[:140])
        except Exception as exc:
            log("Clash 代理 " + clash_address, False, str(exc)[:150])

        for domain in ("app.midtrans.com", "api.midtrans.com", "smsbower.page"):
            try:
                ip = socket.gethostbyname(domain)
                log("DNS " + domain, True, ip)
            except Exception as exc:
                log("DNS " + domain, False, str(exc)[:150])

        sms = _sms_api_status(None, include_balance=True)
        bal = sms.get("balance")
        detail = ("余额 $" + str(bal)) if bal is not None else (sms.get("balance_error") or "未配置")
        if bal is not None:
            try:
                if float(bal) < 1.0:
                    detail += "  (偏低, 建议充值, 否则容易出现 NO_NUMBERS)"
            except ValueError:
                pass
        log("SMSBower 余额", bool(sms.get("ok")) and bal is not None, detail)

        # ---- 支付链路 ----
        mode = str(os.environ.get("OPAI_GOPAY_PAYMENT_MODE") or runtime_env.get("OPAI_GOPAY_PAYMENT_MODE") or "").strip()
        log("支付模式", mode == "protocol", mode or "未设置 (OPAI_GOPAY_PAYMENT_MODE)")
        device_sim = str(os.environ.get("OPAI_GOPAY_DEVICE_SIM") or runtime_env.get("OPAI_GOPAY_DEVICE_SIM") or "desktop").strip().lower()
        log("协议设备指纹", device_sim in {"mobile", "android", "phone"}, device_sim if device_sim in {"mobile", "android", "phone"} else "desktop")
        px_status = proxy_config_status()
        default_pay_proxy = str(px_status.get("default_proxy") or "").strip()
        log("支付默认代理", bool(default_pay_proxy), default_pay_proxy or "未设置, 支付时需手动填代理")
        for label, url in (
            ("Midtrans SNAP 经代理", "https://app.midtrans.com/"),
            ("GoPay GWA 经代理", "https://gwa.gopayapi.com/"),
            ("GoPay Customer 经代理", "https://customer.gopayapi.com/"),
        ):
            probe_ok, probe_detail = _http_probe(url, clash_address)
            log(label, probe_ok, probe_detail)
        cap = captcha_config_status()
        solverify_ok = bool(cap.get("solverify_api_key_configured"))
        scene_ok = bool(cap.get("scene_id") and cap.get("prefix") and cap.get("region"))
        detail_parts = []
        if solverify_ok:
            detail_parts.append("Solverify 已配置")
        else:
            detail_parts.append("Solverify 未配置")
        if scene_ok:
            detail_parts.append("scene/prefix/region 完整")
        else:
            detail_parts.append("scene/prefix/region 缺失")
        log("人机验证配置", solverify_ok and scene_ok, " · ".join(detail_parts))
        solver_ok, solver_detail = _http_probe("https://solver.solverify.net/", clash_address)
        log("Solverify API 经代理", solver_ok, solver_detail)
        try:
            payable_count = _count_payable_accounts()
            log("GoPay 可支付账号", payable_count > 0,
                "%d 个 (需余额>=1 且 PIN 已配置)" % payable_count)
        except Exception as exc:
            log("GoPay 可支付账号", False, str(exc)[:120])
        log("支付执行路径", mode == "protocol", "纯协议支付；不启动模拟器")

        result = {
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ok": all(item["ok"] for item in items),
            "items": items,
        }
        ENV_CHECK_CACHE.update({"at": now, "data": result})
        return result


POOL_ACCOUNT_STATES = {"unregistered", "login_required", "registered"}


def _phone_key(value):
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def _local_account_phone_keys():
    keys = set()
    try:
        accounts = _load_gopay_accounts_raw()
    except Exception:
        accounts = []
    for account in accounts:
        for field in ("phone", "local"):
            key = _phone_key((account or {}).get(field))
            if key:
                keys.add(key)
                if key.startswith("62"):
                    keys.add(key[2:])
    return keys


def _read_gopay_phone_pool_raw():
    try:
        data = json.loads(POOL.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _load_gopay_phone_pool():
    account_keys = _local_account_phone_keys()
    rows = []
    for raw in _read_gopay_phone_pool_raw():
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        key = _phone_key(row.get("phone"))
        local_key = key[2:] if key.startswith("62") else key
        state = str(row.get("account_state") or "").strip().lower()
        if key in account_keys or local_key in account_keys:
            state = "registered"
        elif state not in POOL_ACCOUNT_STATES:
            state = "login_required" if str(row.get("status") or "") == "registered" else "unregistered"
        status = str(row.get("status") or "available").strip().lower()
        if status == "registered":
            status = "available"
        row["status"] = status or "available"
        row["account_state"] = state
        row["account_state_label"] = {
            "unregistered": "未注册",
            "login_required": "待登录",
            "registered": "已入账号库",
        }[state]
        rows.append(row)
    return rows


def _set_pool_account_state(phones, account_state, *, force=False):
    state = str(account_state or "").strip().lower()
    if state not in POOL_ACCOUNT_STATES:
        raise ValueError("号码分类必须为 unregistered、login_required 或 registered")
    values = phones if isinstance(phones, list) else [phones]
    targets = {_phone_key(value) for value in values if _phone_key(value)}
    if not targets:
        raise ValueError("请至少选择一个号码")
    account_keys = _local_account_phone_keys()
    with _pool_claim_lock:
        rows = _load_gopay_phone_pool()
        changed = []
        for row in rows:
            key = _phone_key(row.get("phone"))
            if key not in targets:
                continue
            local_key = key[2:] if key.startswith("62") else key
            if not force and state != "registered" and (key in account_keys or local_key in account_keys):
                raise ValueError(f"{row.get('phone')} 已在本机账号库，不能标记为未注册或待登录")
            row["account_state"] = state
            row["status"] = "available"
            row["account_state_updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            changed.append(str(row.get("phone") or ""))
        missing = targets - {_phone_key(phone) for phone in changed}
        if missing:
            raise ValueError("号码池中不存在所选号码: " + ", ".join(sorted(missing)))
        _save_gopay_phone_pool(rows)
    return {"ok": True, "account_state": state, "phones": changed, "updated": len(changed)}


def _pool_row_eligible(row, login_existing):
    if str((row or {}).get("status") or "available") == "used":
        return False
    state = str((row or {}).get("account_state") or "unregistered")
    return state in ({"login_required", "registered"} if login_existing else {"unregistered"})


def _select_pool_rows(requested_phones, login_existing, count):
    rows = _load_gopay_phone_pool()
    if requested_phones:
        requested = []
        seen = set()
        for value in requested_phones:
            key = _phone_key(value)
            if key and key not in seen:
                seen.add(key)
                requested.append(key)
        by_phone = {_phone_key(row.get("phone")): row for row in rows}
        selected = []
        for key in requested:
            row = by_phone.get(key)
            if row is None:
                raise ValueError(f"号码池中不存在所选号码: {key}")
            if not _pool_row_eligible(row, login_existing):
                mode = "登录" if login_existing else "注册"
                raise ValueError(f"{row.get('phone')} 当前分类为“{row.get('account_state_label')}”，不能执行{mode}")
            selected.append(row)
        if not selected:
            raise ValueError("请至少选择一个号码")
        return selected
    return [row for row in rows if _pool_row_eligible(row, login_existing)][:count]


def _poll_imported_sms_code(phone, _seen=None):
    target = "".join(ch for ch in str(phone or "") if ch.isdigit())
    row = next((x for x in _load_gopay_phone_pool() if "".join(ch for ch in str(x.get("phone") or "") if ch.isdigit()) == target), None)
    url = str((row or {}).get("sms_url") or "").strip()
    if not url:
        return ""
    try:
        body = read_imported_sms_url(url, timeout=8)
        seen = {str(code) for code in (_seen or set())}
        return next((code for code in extract_imported_sms_codes(body) if code not in seen), "")
    except Exception:
        return ""


def _import_gopay_phone_pool(raw, default_state="unregistered"):
    requested_state = str(default_state or "unregistered").strip().lower()
    if requested_state not in {"unregistered", "login_required"}:
        raise ValueError("导入分类必须为 unregistered 或 login_required")
    rows = _load_gopay_phone_pool()
    account_keys = _local_account_phone_keys()
    inserted = 0
    updated = 0
    for line in raw.splitlines():
        if "----" not in line:
            continue
        phone, url = [x.strip() for x in line.split("----", 1)]
        if not phone:
            continue
        url = validate_imported_sms_url(url)
        target = "".join(ch for ch in phone if ch.isdigit())
        existing = next(
            (
                row for row in rows
                if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit()) == target
            ),
            None,
        )
        if existing is not None:
            existing["phone"] = phone
            existing["sms_url"] = url
            existing.setdefault("status", "available")
            local_target = target[2:] if target.startswith("62") else target
            if target in account_keys or local_target in account_keys:
                existing["account_state"] = "registered"
            else:
                existing["account_state"] = requested_state
            updated += 1
        else:
            local_target = target[2:] if target.startswith("62") else target
            state = "registered" if target in account_keys or local_target in account_keys else requested_state
            rows.append({"phone": phone, "sms_url": url, "status": "available", "account_state": state})
            inserted += 1
    POOL.parent.mkdir(exist_ok=True)
    atomic_write_json(POOL, rows)
    return {"inserted": inserted, "updated": updated, "total": len(rows)}


def _delete_gopay_phone(phone):
    target = "".join(ch for ch in str(phone or "") if ch.isdigit())
    rows = _load_gopay_phone_pool()
    kept = [row for row in rows if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit()) != target]
    removed = len(rows) - len(kept)
    if removed:
        POOL.parent.mkdir(exist_ok=True)
        atomic_write_json(POOL, kept)
    return removed


def _clear_gopay_phone_pool():
    removed = len(_load_gopay_phone_pool())
    POOL.parent.mkdir(exist_ok=True)
    atomic_write_text(POOL, "[]\n")
    return removed


register = _ManualRegisterManager()
payment = _WebPaymentManager(InboxStore())
pin_manager = _PinManager()
batch_jobs = {}
batch_jobs_lock = threading.RLock()
payment_batches = {}
payment_batches_lock = threading.RLock()
pin_batches = {}
pin_batches_lock = threading.RLock()
_payment_account_locks: dict[str, threading.Lock] = {}
_payment_account_locks_guard = threading.Lock()
_proxy_rr_lock = threading.Lock()
_proxy_rr_index = 0

# 坏代理短期禁用 + 筛号超时配置
PROXY_BAN_SEC = int(os.environ.get("OPAI_PROXY_BAN_SEC", "90"))
SCREEN_LOGIN_OTP_TIMEOUT = int(os.environ.get("OPAI_SCREEN_LOGIN_OTP_TIMEOUT", "20"))
SCREEN_JOB_TIMEOUT_SEC = int(os.environ.get("OPAI_SCREEN_JOB_TIMEOUT_SEC", "90"))
_proxy_ban_until: dict[str, float] = {}
_proxy_ban_lock = threading.Lock()
SMSBOWER_POOL_BATCH = int(os.environ.get("OPAI_SMSBOWER_POOL_BATCH", "10"))
SMSBOWER_POOL_CONCURRENCY = int(os.environ.get("OPAI_SMSBOWER_POOL_CONCURRENCY", "4"))
SMSBOWER_POOL_WAIT_SEC = int(os.environ.get("OPAI_SMSBOWER_POOL_WAIT_SEC", "180"))
_pool_lock = threading.RLock()
_pool_state = {"target_pin": "", "wake": threading.Event(), "rate_limit_until": 0.0}
_pool_inflight = 0
_pool_log = []
_pool_log_lock = threading.RLock()


def _auto_feed_relogin_otp(job_id, phone, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = next((x for x in register.list() if str(x.get("id")) == str(job_id)), None)
        if not job or str(job.get("status")) in {"success", "failed", "already_registered"}:
            return
        # The manager owns SMS polling; this helper only awaits relogin completion.
        time.sleep(3)


def _delete_gopay_account(phone):
    target = "".join(ch for ch in str(phone or "") if ch.isdigit())
    rows = _load_gopay_accounts_raw()
    kept = [row for row in rows if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit()) != target]
    removed = len(rows) - len(kept)
    if removed:
        _write_gopay_accounts_raw(kept)
        _mark_existing_pool_account_state(phone, "login_required")
    return removed


def _delete_all_gopay_accounts():
    rows = _load_gopay_accounts_raw()
    _write_gopay_accounts_raw([])
    for row in rows:
        _mark_existing_pool_account_state(row.get("phone"), "login_required")
    return len(rows)


def _set_account_phone_type(phone, phone_type):
    """Persist the operator-managed lifecycle classification for one account."""
    kind = str(phone_type or "").strip().lower()
    if kind not in {"long_term", "short_term"}:
        raise ValueError("号码类型必须为 long_term 或 short_term")
    account, index = _find_gopay_account(phone)
    if account is None or index < 0:
        raise ValueError(f"账号不存在: {phone}")
    rows = _load_gopay_accounts_raw()
    rows[index]["phone_type"] = kind
    rows[index]["phone_type_updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _write_gopay_accounts_raw(rows)
    return rows[index]


def _sync_phone_change(
    old_phone,
    new_phone,
    phone_type="long_term",
    test_only=False,
    *,
    sms_activation_id="",
    sms_consumed_code_hashes=None,
):
    """Update only the local account record after the owner completes an in-app change.

    The GoPay application remains the source of truth for phone verification;
    this keeps the console account index, local number and lifecycle grouping in
    sync with the already-completed app change.
    """
    old_digits = "".join(ch for ch in str(old_phone or "") if ch.isdigit())
    new_digits = "".join(ch for ch in str(new_phone or "") if ch.isdigit())
    if len(new_digits) < 9:
        raise ValueError("新手机号格式不正确")
    account, index = _find_gopay_account(old_digits)
    if account is None or index < 0:
        raise ValueError(f"账号不存在: {old_phone}")
    duplicate, duplicate_index = _find_gopay_account(new_digits)
    if duplicate is not None and duplicate_index != index:
        raise ValueError("新手机号已存在于本机账号库")
    rows = _load_gopay_accounts_raw()
    row = dict(rows[index])
    row["phone"] = new_digits
    row["local"] = new_digits[2:] if new_digits.startswith("62") else new_digits
    row["phone_type"] = str(phone_type or "long_term").strip().lower()
    if row["phone_type"] not in {"long_term", "short_term"}:
        raise ValueError("号码类型必须为 long_term 或 short_term")
    row["previous_phone"] = old_digits
    row["phone_changed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    if test_only:
        row["phone_change_test"] = True
        row["phone_change_test_at"] = row["phone_changed_at"]
    else:
        row.pop("phone_change_test", None)
        row.pop("phone_change_test_at", None)
    activation_id = str(sms_activation_id or "").strip()
    if activation_id:
        if not re.fullmatch(r"\d+", activation_id):
            raise ValueError("SMSBower 激活 ID 格式不正确")
        hashes = []
        for value in sms_consumed_code_hashes or ():
            digest = str(value or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest) and digest not in hashes:
                hashes.append(digest)
        row["activation_id"] = activation_id
        row.pop("aid", None)
        row["sms_provider"] = "smsbower"
        row["sms_activation_status"] = "active"
        row["sms_activation_updated_at"] = row["phone_changed_at"]
        row["sms_consumed_code_activation_id"] = activation_id
        row["sms_consumed_code_hashes"] = hashes[-20:]
        row["sms_consumed_code_hashes_updated_at"] = row["phone_changed_at"]
        row["phone_change_source"] = "smsbower"
    # GoPay invalidates prior sessions after a verified number change.  Remove
    # cached tokens so the next explicit re-login creates a fresh local session.
    row.pop("access_token", None)
    row.pop("refresh_token", None)
    rows[index] = row
    _write_gopay_accounts_raw(rows)
    _mark_existing_pool_account_state(old_digits, "unregistered")
    _mark_existing_pool_account_state(new_digits, "registered")
    return row


def _test_short_phone_change(old_phone, new_phone):
    """Local-only short-number migration fixture for UI and account-index tests."""
    account, _index = _find_gopay_account(old_phone)
    if account is None:
        raise ValueError(f"账号不存在: {old_phone}")
    if str(account.get("phone_type") or "").strip().lower() != "short_term":
        raise ValueError("仅短效手机号账号可运行短效换绑测试")
    return _sync_phone_change(old_phone, new_phone, "short_term", test_only=True)


def _load_phone_change_tasks():
    try:
        data = json.loads(PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, dict):
        data = data.get("tasks", [])
    return [dict(item) for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def _write_phone_change_tasks(tasks):
    PHONE_CHANGE_TASKS_FILE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(PHONE_CHANGE_TASKS_FILE, {"tasks": tasks})


def _phone_change_now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _append_phone_change_log(task, message):
    now = _phone_change_now()
    logs = task.setdefault("logs", [])
    logs.append({"at": now, "message": str(message or "")[:500]})
    task["logs"] = logs[-100:]
    task["message"] = str(message or "")[:500]
    task["updated_at"] = now
    return now


def _public_phone_change_task(task):
    hidden = {"activation_id", "previous_activation_id", "activation_release_requested", "code_hash"}
    return {key: value for key, value in dict(task or {}).items() if key not in hidden}


def _phone_change_task_by_id(tasks, job_id):
    return next((item for item in tasks if str(item.get("id") or "") == str(job_id or "")), None)


def _phone_change_type(account, requested=""):
    requested = str(requested or "").strip().lower()
    if requested:
        if requested not in {"long_term", "short_term"}:
            raise ValueError("换绑号码类型必须为 long_term 或 short_term")
        return requested
    current = str((account or {}).get("phone_type") or "").strip().lower()
    if current in {"long_term", "short_term"}:
        return current
    activation_id = str((account or {}).get("activation_id") or (account or {}).get("aid") or "").strip()
    return "short_term" if activation_id else "long_term"


def _resolve_phone_change_proxy(task, account):
    provider_id = int((task or {}).get("proxy_provider_id") or 0)
    session_id = str((task or {}).get("proxy_session_id") or (task or {}).get("id") or "")
    country = str((task or {}).get("proxy_country") or "ID")
    if provider_id:
        resolved = resolve_provider_proxy(
            "phone_change",
            country,
            provider_id=provider_id,
            session_id=session_id,
        )
        if resolved.get("url"):
            return str(resolved["url"]), resolved
    proxy = _normalize_proxy_url((account or {}).get("proxy", "")) or _default_gopay_proxy()
    return proxy, {}


def _start_smsbower_phone_change(old_phone, phone_type=""):
    old_digits = "".join(ch for ch in str(old_phone or "") if ch.isdigit())
    account, _index = _find_gopay_account(old_digits)
    if account is None:
        raise ValueError(f"账号不存在: {old_phone}")
    if not re.fullmatch(r"\d{6}", str(account.get("pin") or "")):
        raise ValueError("该账号没有本机保存的 6 位 PIN，无法自动执行手机号换绑")
    target_phone_type = _phone_change_type(account, phone_type)
    active_to_cancel = None
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        active = next(
            (
                item
                for item in reversed(tasks)
                if str(item.get("old_phone") or "") == old_digits
                and str(item.get("status") or "")
                in {
                    "number_acquired",
                    "refreshing_token",
                    "submitting_phone",
                    "waiting_otp",
                    "rotating",
                    "code_received",
                    "verifying_otp",
                    "completing",
                }
            ),
            None,
        )
        if active:
            if str(active.get("phone_type") or "") != target_phone_type:
                raise ValueError("该账号已有不同号码类型的未完成换绑任务，请先完成或取消原任务")
            if str(active.get("automation_mode") or "") == "protocol":
                result = _public_phone_change_task(active)
                result["reused"] = True
                _launch_smsbower_phone_change_worker(str(active.get("id") or ""))
                return result
            active_to_cancel = (str(active.get("id") or ""), str(active.get("activation_id") or ""))
            active["status"] = "cancelled"
            active["finished_at"] = _phone_change_now()
            _append_phone_change_log(active, "旧版手动换绑任务已被新的全自动协议任务替换，当前号码已提交释放")
            _write_phone_change_tasks(tasks)

    from opai.core.sms_helpers import get_sms_api_key, sms_get_number
    from opai.core.gojek_client import mask_proxy_url, probe_proxy_egress

    api_key = get_sms_api_key("")
    if not api_key:
        raise ValueError("请先在设置页保存 SMSBower API Key")
    if active_to_cancel and active_to_cancel[1]:
        _cancel_sms_activation_with_retry(api_key, active_to_cancel[1])
        _phone_change_codes.pop(active_to_cancel[0], None)

    job_id = uuid.uuid4().hex[:12]
    provider_route = resolve_provider_proxy("phone_change", "ID", session_id=job_id)
    proxy_url = str(provider_route.get("url") or "") or _normalize_proxy_url(account.get("proxy", "")) or _default_gopay_proxy()
    if proxy_url:
        probe = probe_proxy_egress(proxy_url, timeout_sec=12)
        if not probe.get("ok"):
            detail = probe.get("error") or probe.get("raw") or f"HTTP {probe.get('status')}"
            raise RuntimeError(f"换绑代理不可用：{mask_proxy_url(proxy_url)} {detail}")
    else:
        probe = {"ok": True, "ip": "direct"}

    new_phone, activation_id = sms_get_number(api_key)
    if not new_phone or not activation_id:
        raise RuntimeError("SMSBower 暂无可用号码，或取号接口未返回激活 ID")
    new_digits = "".join(ch for ch in str(new_phone) if ch.isdigit())
    if len(new_digits) < 9:
        _cancel_sms_activation_with_retry(api_key, str(activation_id))
        raise RuntimeError("SMSBower 返回的手机号格式不正确")
    duplicate, _duplicate_index = _find_gopay_account(new_digits)
    if duplicate is not None:
        _cancel_sms_activation_with_retry(api_key, str(activation_id))
        raise ValueError("SMSBower 返回的号码已存在于本机账号库，已安排释放该号码")
    now = _phone_change_now()
    task = {
        "id": job_id,
        "old_phone": old_digits,
        "new_phone": new_digits,
        "phone_type": target_phone_type,
        "provider": "smsbower",
        "automation_mode": "protocol",
        "activation_id": str(activation_id),
        "activation_release_requested": False,
        "previous_activation_id": str(account.get("activation_id") or account.get("aid") or ""),
        "attempt_count": 1,
        "max_attempts": PHONE_CHANGE_MAX_ATTEMPTS,
        "proxy_provider_id": int(provider_route.get("provider_id") or 0),
        "proxy_provider_name": str(provider_route.get("provider_name") or ("账号代理" if proxy_url else "服务器直连")),
        "proxy_country": str(provider_route.get("country") or "ID"),
        "proxy_session_id": str(provider_route.get("session_id") or job_id),
        "proxy_preview": str(provider_route.get("preview") or mask_proxy_url(proxy_url)),
        "proxy_exit_ip": str(probe.get("ip") or ""),
        "status": "number_acquired",
        "created_at": now,
        "updated_at": now,
        "logs": [],
    }
    _append_phone_change_log(
        task,
        f"第 1/{PHONE_CHANGE_MAX_ATTEMPTS} 个换绑号码已购买：{new_digits}；后台将自动提交 GoPay 并发送 OTP",
    )
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        tasks.append(task)
        _write_phone_change_tasks(tasks[-200:])
    _launch_smsbower_phone_change_worker(task["id"])
    return _public_phone_change_task(task)


def _fail_phone_change_task(job_id, message, *, exhausted=False):
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        activation_id = str(task.get("activation_id") or "")
        should_release = bool(activation_id and not task.get("activation_release_requested"))
        if should_release:
            task["activation_release_requested"] = True
        task["status"] = "failed"
        task["finished_at"] = _phone_change_now()
        _append_phone_change_log(task, message)
        _write_phone_change_tasks(tasks)
        result = _public_phone_change_task(task)
    if should_release:
        try:
            from opai.core.sms_helpers import get_sms_api_key

            api_key = get_sms_api_key("")
            if api_key:
                _cancel_sms_activation_with_retry(api_key, activation_id)
        except Exception:
            pass
    _phone_change_codes.pop(str(job_id), None)
    result.update({"code": "", "rotated": False, "exhausted": bool(exhausted)})
    return result


def _phone_change_task_snapshot(job_id):
    with _phone_change_tasks_lock:
        task = _phone_change_task_by_id(_load_phone_change_tasks(), job_id)
        return dict(task) if task is not None else None


def _update_phone_change_progress(job_id, status, message):
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        if str(task.get("status") or "") == "cancelled":
            return _public_phone_change_task(task)
        task["status"] = status
        _append_phone_change_log(task, message)
        _write_phone_change_tasks(tasks)
        return _public_phone_change_task(task)


def _phone_change_error_summary(result):
    status = int((result or {}).get("status") or 0)
    body = (result or {}).get("body")
    data = body.get("data", body) if isinstance(body, dict) else {}
    parts = []
    if isinstance(data, dict):
        for key in ("code", "message", "error", "errors"):
            value = data.get(key)
            if value:
                parts.append(str(value))
    return _sanitize_public_error(f"HTTP {status}: {' | '.join(parts) or 'unknown response'}")


def _phone_change_number_rejected(result):
    status = int((result or {}).get("status") or 0)
    text = json.dumps((result or {}).get("body", {}), ensure_ascii=False).lower()
    if status in (409, 422):
        return True
    return status == 400 and any(word in text for word in (
        "phone already",
        "phone number already",
        "already registered",
        "invalid phone",
        "invalid number",
        "nomor sudah",
        "nomor tidak valid",
    ))


def _phone_change_otp_rejected(result):
    status = int((result or {}).get("status") or 0)
    text = json.dumps((result or {}).get("body", {}), ensure_ascii=False).lower()
    return status in (400, 409, 422) and any(word in text for word in (
        "otp",
        "verification code",
        "invalid code",
        "kode verifikasi",
    ))


def _log_phone_change_network(job_id, client, label="换绑网络"):
    from opai.core.gojek_client import mask_proxy_url, probe_proxy_egress

    proxy = str(getattr(client, "proxy", "") or "")
    if proxy:
        result = probe_proxy_egress(proxy, timeout_sec=12)
        ip = str(result.get("ip") or "未探测到")
        state = "已确认" if result.get("ok") else "探测失败"
        _update_phone_change_progress(
            job_id,
            "number_acquired",
            f"{label}：代理 {mask_proxy_url(proxy)} / 出口 IP {ip} / {state}",
        )
        return
    try:
        payload = json.loads(_http_get("https://api.ipify.org?format=json", timeout=10))
        ip = str(payload.get("ip") or "未探测到") if isinstance(payload, dict) else "未探测到"
    except Exception:
        ip = "未探测到"
    _update_phone_change_progress(job_id, "number_acquired", f"{label}：服务器直连 / 出口 IP {ip}")


def _auto_relogin_for_phone_change(job_id, account, timeout_sec=240, proxy_override=""):
    phone = str(account.get("phone") or "")
    pin = str(account.get("pin") or "").strip()
    target = "".join(ch for ch in phone if ch.isdigit())
    pool_row = next(
        (
            row
            for row in _load_gopay_phone_pool()
            if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit()) == target
        ),
        {},
    )
    sms_url = str(pool_row.get("sms_url") or "").strip()
    if not sms_url:
        raise RuntimeError("账号登录会话已失效，号码池中没有该账号的短信接口，无法自动重新登录")
    _update_phone_change_progress(
        job_id,
        "relogin",
        f"GoPay 登录会话已失效，正在以登录协议身份 GoPay {PHONE_CHANGE_LOGIN_APP_VERSION} 通过号码池自动重新登录",
    )
    try:
        seen_codes = set(extract_imported_sms_codes(read_imported_sms_url(sms_url, timeout=8)))
    except Exception:
        seen_codes = set()

    def wait_code(_purpose, timeout):
        deadline = time.monotonic() + max(1, int(timeout or 60))
        while time.monotonic() < deadline:
            code = _poll_imported_sms_code(phone, seen_codes)
            if code:
                seen_codes.add(code)
                return code
            time.sleep(1)
        return None

    from opai.core.gopay_protocol_worker import _login_one_manual_existing

    result = _login_one_manual_existing(
        phone=phone,
        pin=pin,
        proxy=str(proxy_override or account.get("proxy") or ""),
        wait_code=wait_code,
        aid="phone-change-relogin",
        country_code="+62",
        status_cb=lambda message: _update_phone_change_progress(job_id, "relogin", f"自动重登：{message}"),
        return_failure=True,
        login_otp_timeout=min(180, max(60, int(timeout_sec))),
        app_version=PHONE_CHANGE_LOGIN_APP_VERSION,
        app_build=PHONE_CHANGE_LOGIN_APP_BUILD,
        prefer_otp_sms=PHONE_CHANGE_LOGIN_PREFER_SMS,
    )
    if not result or result.get("failed"):
        raise RuntimeError(f"自动重新登录失败：{(result or {}).get('error') or 'unknown'}")
    updated, updated_index = _find_gopay_account(phone)
    if updated is None:
        raise RuntimeError("自动重新登录成功，但本地账号记录未找到")
    _update_phone_change_progress(job_id, "number_acquired", "自动重新登录成功，已恢复新的 GoPay token")
    return updated, updated_index


def _run_smsbower_phone_change(job_id):
    from opai.core.sms_helpers import get_sms_api_key

    try:
        snapshot = _phone_change_task_snapshot(job_id)
        if snapshot is None or str(snapshot.get("status") or "") in {"completed", "cancelled", "failed"}:
            return
        old_phone = str(snapshot.get("old_phone") or "")
        account, account_index = _find_gopay_account(old_phone)
        if account is None:
            _fail_phone_change_task(job_id, f"自动换绑失败：账号不存在 {old_phone}")
            return
        pin = str(account.get("pin") or "").strip()
        if not re.fullmatch(r"\d{6}", pin):
            _fail_phone_change_task(job_id, "自动换绑失败：账号没有本机保存的 6 位 PIN")
            return
        api_key = get_sms_api_key("")
        if not api_key:
            _fail_phone_change_task(job_id, "自动换绑失败：SMSBower API Key 未配置")
            return

        change_proxy, _proxy_route = _resolve_phone_change_proxy(snapshot, account)

        def build_client(current_account):
            account_with_proxy = dict(current_account)
            if change_proxy:
                account_with_proxy["proxy"] = change_proxy
            current = _gopay_client_from_account(account_with_proxy, old_phone)
            current.version = PHONE_CHANGE_APP_VERSION
            current.app_build = PHONE_CHANGE_APP_BUILD
            return current

        client = build_client(account)
        relogin_attempted = False
        _log_phone_change_network(job_id, client)
        _update_phone_change_progress(job_id, "refreshing_token", "正在刷新 GoPay 登录 token，准备全自动换绑")
        refreshed = {"status": 0, "body": {"error": "not_started"}}
        try:
            refreshed = client.refresh_token()
        except Exception:
            refreshed = {"status": 0, "body": {"error": "refresh_exception"}}
        if refreshed.get("status") in (200, 201):
            _save_gopay_account_tokens_and_pin(account_index, client)
            _update_phone_change_progress(job_id, "number_acquired", "GoPay token 刷新成功")
        else:
            try:
                account, account_index = _auto_relogin_for_phone_change(job_id, account, proxy_override=change_proxy)
                client = build_client(account)
                relogin_attempted = True
                _log_phone_change_network(job_id, client, "自动重登后的换绑网络")
                _update_phone_change_progress(job_id, "number_acquired", "GoPay token 刷新失败，已自动重新登录并恢复新 token")
            except Exception as login_exc:
                _fail_phone_change_task(job_id, f"自动换绑失败：{_sanitize_public_error(login_exc)}")
                return

        while True:
            snapshot = _phone_change_task_snapshot(job_id)
            if snapshot is None or str(snapshot.get("status") or "") in {"completed", "cancelled", "failed"}:
                return
            attempt = max(1, int(snapshot.get("attempt_count") or 1))
            max_attempts = max(1, int(snapshot.get("max_attempts") or PHONE_CHANGE_MAX_ATTEMPTS))
            new_phone = str(snapshot.get("new_phone") or "")
            activation_id = str(snapshot.get("activation_id") or "")
            _update_phone_change_progress(
                job_id,
                "submitting_phone",
                f"正在把第 {attempt}/{max_attempts} 个号码 {new_phone} 提交给 GoPay，并自动发送 SMS OTP",
            )
            requested = client.phone_change_request_otp(new_phone, pin)
            if requested.get("status") == 401 and not relogin_attempted:
                _update_phone_change_progress(job_id, "relogin", "GoPay 返回 Session is revoked，自动重新登录后重试当前号码")
                try:
                    account, account_index = _auto_relogin_for_phone_change(job_id, account, proxy_override=change_proxy)
                    client = build_client(account)
                    relogin_attempted = True
                    _log_phone_change_network(job_id, client, "自动重登后的换绑网络")
                    requested = client.phone_change_request_otp(new_phone, pin)
                except Exception as login_exc:
                    _fail_phone_change_task(job_id, f"自动换绑失败：{_sanitize_public_error(login_exc)}")
                    return
            if requested.get("status") not in (200, 201):
                summary = _phone_change_error_summary(requested)
                if _phone_change_number_rejected(requested):
                    rotated = _rotate_smsbower_phone_change_number(
                        job_id,
                        api_key,
                        activation_id,
                        0,
                        reason=f"第 {attempt}/{max_attempts} 个号码被 GoPay 拒绝（{summary}）；已提交取消并自动换号",
                    )
                    if rotated.get("status") == "failed":
                        return
                    continue
                _fail_phone_change_task(job_id, f"自动提交新手机号失败：{summary}")
                return

            _update_phone_change_progress(
                job_id,
                "waiting_otp",
                f"GoPay 已向第 {attempt}/{max_attempts} 个号码发送 SMS OTP，自动等待 {PHONE_CHANGE_OTP_TIMEOUT_SEC} 秒",
            )
            otp_result = _poll_smsbower_phone_change_code(
                job_id,
                PHONE_CHANGE_OTP_TIMEOUT_SEC,
                automated=True,
            )
            if otp_result.get("status") == "failed" or otp_result.get("exhausted"):
                return
            if otp_result.get("rotated"):
                continue
            code = str(otp_result.get("code") or "")
            if not code:
                _fail_phone_change_task(job_id, "自动换绑失败：SMSBower 未返回 OTP，也未成功换号")
                return

            _update_phone_change_progress(job_id, "verifying_otp", "已收到换绑 OTP，正在自动提交 GoPay 验证")
            verified = client.phone_change_verify_otp(code)
            if verified.get("status") not in (200, 201):
                summary = _phone_change_error_summary(verified)
                if _phone_change_otp_rejected(verified):
                    rotated = _rotate_smsbower_phone_change_number(
                        job_id,
                        api_key,
                        activation_id,
                        0,
                        reason=f"第 {attempt}/{max_attempts} 个号码的 OTP 验证失败（{summary}）；已提交取消并自动换号",
                    )
                    if rotated.get("status") == "failed":
                        return
                    continue
                _fail_phone_change_task(job_id, f"自动验证换绑 OTP 失败：{summary}")
                return

            _complete_smsbower_phone_change(job_id, verified_by="protocol")
            return
    except Exception as exc:
        try:
            snapshot = _phone_change_task_snapshot(job_id)
            if snapshot is not None and str(snapshot.get("status") or "") not in {"completed", "cancelled", "failed"}:
                _fail_phone_change_task(job_id, f"自动换绑异常：{type(exc).__name__}: {_sanitize_public_error(exc)}")
        except Exception:
            pass


def _launch_smsbower_phone_change_worker(job_id):
    job_id = str(job_id or "")
    if not job_id:
        return False
    with _phone_change_workers_lock:
        if job_id in _phone_change_workers:
            return False
        _phone_change_workers.add(job_id)

    def runner():
        try:
            _run_smsbower_phone_change(job_id)
        finally:
            with _phone_change_workers_lock:
                _phone_change_workers.discard(job_id)

    threading.Thread(target=runner, daemon=True, name=f"phone-change-{job_id}").start()
    return True


def _resume_smsbower_phone_change_workers():
    with _phone_change_tasks_lock:
        active_ids = [
            str(task.get("id") or "")
            for task in _load_phone_change_tasks()
            if str(task.get("automation_mode") or "") == "protocol"
            and str(task.get("status") or "")
            not in {"completed", "cancelled", "failed"}
        ]
    for job_id in active_ids:
        _launch_smsbower_phone_change_worker(job_id)


def _rotate_smsbower_phone_change_number(job_id, api_key, old_activation_id, timeout_sec, *, reason=""):
    from opai.core.sms_helpers import sms_get_number

    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        if str(task.get("activation_id") or "") != str(old_activation_id or ""):
            result = _public_phone_change_task(task)
            result.update({"code": "", "rotated": task.get("status") == "number_acquired", "exhausted": False})
            return result
        current_attempt = max(1, int(task.get("attempt_count") or 1))
        max_attempts = max(1, int(task.get("max_attempts") or PHONE_CHANGE_MAX_ATTEMPTS))
        automated = str(task.get("automation_mode") or "") == "protocol"
        old_phone = str(task.get("new_phone") or "")
        task["status"] = "rotating"
        task["activation_release_requested"] = True
        _append_phone_change_log(
            task,
            reason or f"第 {current_attempt}/{max_attempts} 个号码 {old_phone} 等待 {timeout_sec} 秒未收到 OTP；已提交取消并准备自动换号",
        )
        _write_phone_change_tasks(tasks)

    _cancel_sms_activation_with_retry(api_key, str(old_activation_id or ""))
    _phone_change_codes.pop(str(job_id), None)
    if current_attempt >= max_attempts:
        return _fail_phone_change_task(
            job_id,
            f"已尝试 {max_attempts} 个换绑号码，均未在等待时间内收到 OTP；任务结束",
            exhausted=True,
        )

    while current_attempt < max_attempts:
        new_phone, activation_id = sms_get_number(api_key)
        if not new_phone or not activation_id:
            return _fail_phone_change_task(job_id, "自动换号失败：SMSBower 暂无可用号码或未返回激活 ID")
        current_attempt += 1
        new_digits = "".join(ch for ch in str(new_phone) if ch.isdigit())
        duplicate, _duplicate_index = _find_gopay_account(new_digits)
        invalid_reason = ""
        if len(new_digits) < 9:
            invalid_reason = "手机号格式不正确"
        elif duplicate is not None:
            invalid_reason = "号码已存在于本机账号库"

        if invalid_reason:
            _cancel_sms_activation_with_retry(api_key, str(activation_id))
            with _phone_change_tasks_lock:
                tasks = _load_phone_change_tasks()
                task = _phone_change_task_by_id(tasks, job_id)
                if task is None:
                    raise ValueError(f"换绑任务不存在: {job_id}")
                task["attempt_count"] = current_attempt
                _append_phone_change_log(
                    task,
                    f"第 {current_attempt}/{max_attempts} 个候选号码 {new_digits or '-'} 无效（{invalid_reason}），已提交取消",
                )
                _write_phone_change_tasks(tasks)
            if current_attempt >= max_attempts:
                return _fail_phone_change_task(
                    job_id,
                    f"已购买并检查 {max_attempts} 个号码，未获得可继续换绑的号码；任务结束",
                    exhausted=True,
                )
            continue

        with _phone_change_tasks_lock:
            tasks = _load_phone_change_tasks()
            task = _phone_change_task_by_id(tasks, job_id)
            if task is None:
                _cancel_sms_activation_with_retry(api_key, str(activation_id))
                raise ValueError(f"换绑任务不存在: {job_id}")
            if str(task.get("status") or "") == "cancelled":
                _cancel_sms_activation_with_retry(api_key, str(activation_id))
                result = _public_phone_change_task(task)
                result.update({"code": "", "rotated": False, "exhausted": False})
                return result
            task["new_phone"] = new_digits
            task["activation_id"] = str(activation_id)
            task["activation_release_requested"] = False
            task["attempt_count"] = current_attempt
            task["max_attempts"] = max_attempts
            task["status"] = "number_acquired"
            task.pop("code_hash", None)
            task.pop("code_received_at", None)
            _append_phone_change_log(
                task,
                (
                    f"第 {current_attempt}/{max_attempts} 个换绑号码已购买：{new_digits}；后台将自动提交 GoPay 并重新发送 OTP"
                    if automated
                    else f"第 {current_attempt}/{max_attempts} 个换绑号码已购买：{new_digits}；请在 GoPay App 改填该号码并重新发送 OTP"
                ),
            )
            _write_phone_change_tasks(tasks)
            result = _public_phone_change_task(task)
        result.update({"code": "", "rotated": True, "exhausted": False, "requires_action": not automated})
        return result

    return _fail_phone_change_task(job_id, "自动换号次数已用尽；任务结束", exhausted=True)


def _poll_smsbower_phone_change_code(job_id, timeout_sec=60, *, automated=False):
    timeout_sec = max(1, min(90, int(timeout_sec or 60)))
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        status = str(task.get("status") or "")
        if status in {"completed", "cancelled", "failed"}:
            raise ValueError("换绑任务已结束")
        if status == "rotating":
            raise ValueError("换绑任务正在自动更换号码，请稍后重试")
        if str(task.get("automation_mode") or "") == "protocol" and not automated:
            result = _public_phone_change_task(task)
            result.update({"code": "", "rotated": False, "exhausted": False, "background": True})
            return result
        attempt = max(1, int(task.get("attempt_count") or 1))
        max_attempts = max(1, int(task.get("max_attempts") or PHONE_CHANGE_MAX_ATTEMPTS))
        task["status"] = "waiting_otp"
        _append_phone_change_log(task, f"正在等待第 {attempt}/{max_attempts} 个号码的换绑 OTP，最长 {timeout_sec} 秒")
        _write_phone_change_tasks(tasks)
        activation_id = str(task.get("activation_id") or "")
    from opai.core.sms_helpers import get_sms_api_key, sms_code_sha256, sms_wait_code

    api_key = get_sms_api_key("")
    if not api_key:
        raise ValueError("SMSBower API Key 未配置")
    code = _phone_change_codes.get(str(job_id)) or sms_wait_code(
        api_key,
        activation_id,
        timeout=timeout_sec,
    )
    if not code:
        return _rotate_smsbower_phone_change_number(job_id, api_key, activation_id, timeout_sec)

    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        _phone_change_codes[str(job_id)] = str(code)
        task["status"] = "code_received"
        task["code_hash"] = sms_code_sha256(str(code))
        task["code_received_at"] = _phone_change_now()
        attempt = max(1, int(task.get("attempt_count") or 1))
        max_attempts = max(1, int(task.get("max_attempts") or PHONE_CHANGE_MAX_ATTEMPTS))
        _append_phone_change_log(
            task,
            (
                f"第 {attempt}/{max_attempts} 个号码已收到换绑 OTP；后台正在自动验证并完成换绑"
                if str(task.get("automation_mode") or "") == "protocol"
                else f"第 {attempt}/{max_attempts} 个号码已收到换绑 OTP；请在 GoPay App 完成验证"
            ),
        )
        _write_phone_change_tasks(tasks)
        result = _public_phone_change_task(task)
        result.update({"code": str(code), "rotated": False, "exhausted": False})
        return result


def _complete_smsbower_phone_change(job_id, *, verified_by="app"):
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        if str(task.get("status") or "") == "completed":
            account, _index = _find_gopay_account(str(task.get("new_phone") or ""))
            return {"ok": True, "task": _public_phone_change_task(task), "account": account or {}}
        allowed_statuses = {"code_received", "verifying_otp"} if verified_by == "protocol" else {"code_received"}
        if str(task.get("status") or "") not in allowed_statuses:
            raise ValueError("请先成功读取 SMSBower 换绑 OTP")
        task["status"] = "completing"
        _append_phone_change_log(
            task,
            (
                "GoPay 已确认手机号换绑成功，正在同步本地账号和 SMSBower 激活信息"
                if verified_by == "protocol"
                else "GoPay App 已确认换绑成功，正在同步本地账号和 SMSBower 激活信息"
            ),
        )
        _write_phone_change_tasks(tasks)
        snapshot = dict(task)
    try:
        row = _sync_phone_change(
            snapshot.get("old_phone"),
            snapshot.get("new_phone"),
            snapshot.get("phone_type") or "short_term",
            sms_activation_id=snapshot.get("activation_id"),
            sms_consumed_code_hashes=[snapshot.get("code_hash")],
        )
        from opai.core.sms_helpers import get_sms_api_key, sms_done, sms_request_another, sms_wait_code

        api_key = get_sms_api_key("")
        retry_ready = bool(api_key and sms_request_another(api_key, str(snapshot.get("activation_id") or "")))
        post_change_login_ok = False
        post_change_login_error = ""
        if verified_by == "protocol" and api_key:
            try:
                from opai.core.gopay_protocol_worker import _login_one_manual_existing

                change_proxy, _route = _resolve_phone_change_proxy(snapshot, row)
                _update_phone_change_progress(job_id, "relogin", "手机号换绑成功，正在使用新号码自动登录并保存最终 token")
                consumed_hashes = {str(snapshot.get("code_hash") or "").strip().lower()}
                login_result = _login_one_manual_existing(
                    phone=str(snapshot.get("new_phone") or ""),
                    pin=str(row.get("pin") or ""),
                    proxy=change_proxy,
                    aid=str(snapshot.get("activation_id") or ""),
                    country_code="+62",
                    wait_code=lambda _purpose, timeout: sms_wait_code(
                        api_key,
                        str(snapshot.get("activation_id") or ""),
                        timeout=timeout,
                        ignore_code_hashes=consumed_hashes,
                    ),
                    status_cb=lambda message: _update_phone_change_progress(job_id, "relogin", f"新号登录：{message}"),
                    return_failure=True,
                    request_another_code=lambda: sms_request_another(api_key, str(snapshot.get("activation_id") or "")),
                    login_otp_timeout=180,
                )
                post_change_login_ok = bool(login_result and not login_result.get("failed"))
                if not post_change_login_ok:
                    post_change_login_error = _sanitize_public_error((login_result or {}).get("error") or "新号码自动登录未完成")
                retry_ready = bool(sms_request_another(api_key, str(snapshot.get("activation_id") or "")))
            except Exception as login_exc:
                post_change_login_error = _sanitize_public_error(login_exc)
        previous_activation_id = str(snapshot.get("previous_activation_id") or "")
        if api_key and re.fullmatch(r"\d+", previous_activation_id) and previous_activation_id != str(snapshot.get("activation_id") or ""):
            sms_done(api_key, previous_activation_id)
    except Exception:
        with _phone_change_tasks_lock:
            tasks = _load_phone_change_tasks()
            task = _phone_change_task_by_id(tasks, job_id)
            if task is not None and str(task.get("status") or "") == "completing":
                task["status"] = "code_received"
                _append_phone_change_log(task, "本地换绑保存失败，可修正后重试")
                _write_phone_change_tasks(tasks)
        raise
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        task["status"] = "completed"
        task["completed_at"] = _phone_change_now()
        _append_phone_change_log(
            task,
            (
                "全自动换绑完成；新号码已自动登录并保存最终 token，SMSBower 可继续接收下一条验证码"
                if verified_by == "protocol" and post_change_login_ok and retry_ready
                else f"全自动换绑已成功，但新号码自动登录未完成：{post_change_login_error or '请稍后重新登录'}"
                if verified_by == "protocol" and not post_change_login_ok
                else "全自动换绑完成；新号码 token 已保存，SMSBower 下一条接码准备未确认"
                if verified_by == "protocol"
                else "换绑已同步；SMSBower 可继续接收下一条验证码"
                if retry_ready
                else "换绑已同步；SMSBower 下一条接码准备未确认"
            ),
        )
        _write_phone_change_tasks(tasks)
        _phone_change_codes.pop(str(job_id), None)
        account_after, _index_after = _find_gopay_account(str(snapshot.get("new_phone") or ""))
        return {
            "ok": True,
            "task": _public_phone_change_task(task),
            "account": account_after or row,
            "retry_ready": retry_ready,
            "post_change_login_ok": post_change_login_ok,
        }


def _retry_smsbower_phone_change(job_id):
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        if str(task.get("status") or "") in {"completed", "cancelled", "failed", "rotating", "completing"}:
            raise ValueError("当前换绑任务不能重发 OTP")
        activation_id = str(task.get("activation_id") or "")
    from opai.core.sms_helpers import get_sms_api_key, sms_request_another

    api_key = get_sms_api_key("")
    if not api_key:
        raise ValueError("SMSBower API Key 未配置")
    if not sms_request_another(api_key, activation_id):
        raise RuntimeError("SMSBower 未确认接收下一条验证码，请稍后重试")
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        task["status"] = "number_acquired"
        _append_phone_change_log(task, "SMSBower 已准备接收重发 OTP；请在 GoPay App 点击重发")
        task.pop("code_hash", None)
        task.pop("code_received_at", None)
        _write_phone_change_tasks(tasks)
        _phone_change_codes.pop(str(job_id), None)
        return {"ok": True, "task": _public_phone_change_task(task)}


def _cancel_smsbower_phone_change(job_id):
    with _phone_change_tasks_lock:
        tasks = _load_phone_change_tasks()
        task = _phone_change_task_by_id(tasks, job_id)
        if task is None:
            raise ValueError(f"换绑任务不存在: {job_id}")
        if str(task.get("status") or "") == "completed":
            raise ValueError("换绑任务已完成，不能取消新号码")
        activation_id = str(task.get("activation_id") or "")
        task["status"] = "cancelled"
        task["activation_release_requested"] = True
        task["finished_at"] = _phone_change_now()
        _append_phone_change_log(task, "换绑任务已取消，当前 SMSBower 号码已提交释放")
        _write_phone_change_tasks(tasks)
        result = _public_phone_change_task(task)
    from opai.core.sms_helpers import get_sms_api_key

    api_key = get_sms_api_key("")
    if api_key and activation_id:
        _cancel_sms_activation_with_retry(api_key, activation_id)
    _phone_change_codes.pop(str(job_id), None)
    return {"ok": True, "task": result}


def _page():
    return (ROOT / "gopay" / "index.html").read_text(encoding="utf-8")


def _safe_register_jobs():
    rows = []
    for item in register.list():
        clean = dict(item)
        clean.pop("pin", None)
        if isinstance(clean.get("result"), dict):
            clean["result"] = {key: value for key, value in clean["result"].items() if key != "pin"}
        rows.append(clean)
    return rows


def _apply_pool_auth_result(phone, status, message, login_existing):
    if not phone:
        return
    terminal = str(status or "").strip().lower()
    text = str(message or "")
    if terminal == "success":
        _mark_pool_phone(phone, "available", "registered")
    elif login_existing:
        _mark_pool_phone(phone, "login_failed", "login_required")
    elif terminal == "already_registered" or "已注册" in text or "already" in text.lower():
        _mark_pool_phone(phone, "available", "login_required")
    else:
        _mark_pool_phone(phone, "available", "unregistered")


def _track_pool_register_job(job_id, phone, login_existing):
    while True:
        current = register.get(job_id) or {}
        status = str(current.get("status") or "")
        if status not in {"running", "waiting_otp"}:
            _apply_pool_auth_result(
                str(current.get("phone") or phone or ""),
                status,
                current.get("message") or current.get("error") or "",
                login_existing,
            )
            return
        time.sleep(1)


def _parse_midtrans_links(value):
    items = value if isinstance(value, list) else str(value or "").splitlines()
    links = []
    for line_number, raw in enumerate(items, 1):
        text = str(raw or "").strip()
        if not text:
            continue
        if "midtrans.com" not in text:
            raise ValueError(f"第 {line_number} 条不是有效的 Midtrans 链接")
        links.append(text)
    if not links:
        raise ValueError("请至少填写一条 Midtrans 链接")
    return links


def _proxy_ban_key(proxy: str) -> str:
    try:
        parsed = urlsplit(_normalize_proxy_url(proxy))
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return f"{parsed.scheme}://{host}:{port}"
    except Exception:
        return str(proxy or "")


def _ban_proxy(proxy: str, seconds: int = 0):
    key = _proxy_ban_key(proxy)
    if not key:
        return
    with _proxy_ban_lock:
        _proxy_ban_until[key] = time.time() + int(seconds or PROXY_BAN_SEC)


def _proxy_banned(proxy: str) -> bool:
    key = _proxy_ban_key(proxy)
    if not key:
        return False
    with _proxy_ban_lock:
        until = _proxy_ban_until.get(key) or 0.0
        if until and time.time() >= until:
            _proxy_ban_until.pop(key, None)
            return False
        return time.time() < until


def _proxy_failure_needle(text: str) -> bool:
    lower = str(text or "").lower()
    return (
        "代理预检失败" in str(text or "")
        or "failed to do request" in lower
        or "proxyconnect" in lower
        or "eof" in lower
        or "server gave http response to https client" in lower
    )


def _pick_proxy(proxies):
    global _proxy_rr_index
    if not proxies:
        return ""
    with _proxy_rr_lock:
        total = len(proxies)
        for _ in range(total):
            proxy = proxies[_proxy_rr_index % total]
            _proxy_rr_index += 1
            if not _proxy_banned(proxy) and not proxy_fraud_denied(proxy):
                return proxy
        return proxies[(_proxy_rr_index - 1) % total]


def _claim_payment_account(pin_override=""):
    for account in _list_payment_eligible_accounts(pin_override):
        phone = str(account.get("phone") or "").strip()
        binding_status = str(account.get("midtrans_binding_status") or "").strip()
        if binding_status in {"success", "failed"}:
            try:
                _release_gopay_midtrans_binding(phone, message="历史记录已清除，账号重新可用")
            except Exception:
                pass
        return account
    return None


def _account_worker_lock(phone):
    with _payment_account_locks_guard:
        lock = _payment_account_locks.get(phone)
        if lock is None:
            lock = threading.Lock()
            _payment_account_locks[phone] = lock
        return lock


def _wait_pin_job_terminal(job, timeout_sec=200, log_sink=None):
    job_id = str((job or {}).get("id") or "")
    if not job_id:
        return {"ok": False, "error": "PIN 任务未创建"}
    log_cursor = 0
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        current = pin_manager.get(job_id) or {}
        log_cursor = _sync_job_logs(current, log_cursor, log_sink)
        status = str(current.get("status") or "")
        if status == "success":
            return {"ok": True, "message": str(current.get("message") or "PIN 处理成功")}
        if status in {"failed", "cancelled"}:
            return {"ok": False, "error": str(current.get("message") or current.get("error") or "PIN 处理失败")}
        if status == "waiting_otp":
            return {"ok": False, "error": "需要手动输入短信验证码，自动流程已跳过该账号"}
        time.sleep(1)
    return {"ok": False, "error": f"PIN 处理超时（{timeout_sec}s）"}


def _uniform_pin(primary=""):
    if re.fullmatch(r"\d{6}", str(primary or "")):
        return str(primary).strip()
    with _pool_lock:
        target = str(_pool_state.get("target_pin") or "")
    if re.fullmatch(r"\d{6}", target):
        return target
    return os.environ.get("OPAI_GOPAY_PIN") or "147258"


def _ensure_account_pin(account, target_pin, log_sink=None):
    phone = str(account.get("phone") or "").strip()
    saved = str(account.get("pin") or "").strip()
    setup_status = str(account.get("pin_setup_status") or "").strip()
    if re.fullmatch(r"\d{6}", saved) and setup_status == "configured":
        return {"ok": True, "pin": saved, "note": "使用本地已保存 PIN"}
    if setup_status != "configured":
        last_err = ""
        for candidate in _pin_candidates(target_pin):
            try:
                job = pin_manager.start(phone=phone, old_pin="", new_pin=candidate, mode="setup")
                result = _wait_pin_job_terminal(job, log_sink=log_sink)
                if result["ok"]:
                    note = "已为新账号设置 PIN"
                    if candidate != target_pin:
                        note += f"（目标 PIN {target_pin} 被 GoPay 拒绝，已改用 {candidate}）"
                    return {"ok": True, "pin": candidate, "note": note}
                last_err = result["error"] or last_err
                if not _is_pin_policy_rejection(result):
                    break
            except Exception as exc:
                last_err = _sanitize_public_error(exc)
                break
        return {"ok": False, "error": last_err or "PIN 设置失败"}
    last_err = ""
    for candidate in _pin_candidates(target_pin):
        try:
            job = pin_manager.start(phone=phone, old_pin="", new_pin=candidate, mode="forgot")
            result = _wait_pin_job_terminal(job, log_sink=log_sink)
            if result["ok"]:
                note = "忘记 PIN 已重置"
                if candidate != target_pin:
                    note += f"（目标 PIN {target_pin} 被 GoPay 拒绝，已改用 {candidate}）"
                return {"ok": True, "pin": candidate, "note": note}
            last_err = result["error"] or last_err
            if not _is_pin_policy_rejection(result):
                break
        except Exception as exc:
            last_err = _sanitize_public_error(exc)
            break
    return {"ok": False, "error": last_err or "忘记 PIN 重置失败"}


def _pick_relaxed_payment_account(skip_phones=None):
    raw = _load_gopay_accounts_raw()
    skip = set(skip_phones or ())
    for account in raw:
        phone = str(account.get("phone") or "").strip()
        if not phone or phone in skip:
            continue
        if str(account.get("midtrans_binding_status") or "").strip() in {"reserved", "running", "linking", "waiting_otp"}:
            continue
        try:
            balance = int(account.get("balance", 0) or 0)
        except Exception:
            balance = 0
        if balance < 1:
            continue
        return account
    return None


_pool_claim_lock = threading.Lock()


def _save_gopay_phone_pool(rows):
    POOL.parent.mkdir(exist_ok=True)
    atomic_write_json(POOL, rows)


def _mark_existing_pool_account_state(phone, account_state):
    key = _phone_key(phone)
    if not key:
        return False
    with _pool_claim_lock:
        rows = _load_gopay_phone_pool()
        changed = False
        for row in rows:
            if _phone_key(row.get("phone")) != key:
                continue
            row["account_state"] = account_state
            row["status"] = "available"
            row["account_state_updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            changed = True
        if changed:
            _save_gopay_phone_pool(rows)
        return changed


def _claim_pool_phone():
    with _pool_claim_lock:
        rows = _load_gopay_phone_pool()
        for row in rows:
            phone = str(row.get("phone") or "").strip()
            status = str(row.get("status") or "available").strip()
            state = str(row.get("account_state") or "unregistered").strip()
            if not phone or status == "used" or state != "login_required":
                continue
            row["status"] = "used"
            _save_gopay_phone_pool(rows)
            return phone, row
    return "", None


def _mark_pool_phone(phone, status, account_state=None):
    if not phone:
        return
    with _pool_claim_lock:
        rows = _load_gopay_phone_pool()
        changed = False
        for row in rows:
            if _phone_key(row.get("phone")) == _phone_key(phone):
                row["status"] = status
                if account_state in POOL_ACCOUNT_STATES:
                    row["account_state"] = account_state
                    row["account_state_updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                changed = True
        if changed:
            _save_gopay_phone_pool(rows)


def _sync_job_logs(job, cursor, log_sink):
    logs = job.get("logs") if isinstance(job, dict) else None
    if not isinstance(logs, list):
        return cursor
    new_cursor = cursor
    for index in range(cursor, len(logs)):
        entry = logs[index]
        if isinstance(entry, dict):
            message = str(entry.get("message") or "")
            if message and log_sink:
                log_sink(message)
        new_cursor = index + 1
    return new_cursor


def _wait_register_job_terminal(job, phone="", timeout_sec=360, log_sink=None):
    job_id = str((job or {}).get("id") or "")
    if not job_id:
        return {"ok": False, "error": "登录任务未创建"}
    last_phone = phone
    log_cursor = 0
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        current = register.get(job_id) or {}
        log_cursor = _sync_job_logs(current, log_cursor, log_sink)
        if current.get("phone"):
            last_phone = str(current.get("phone") or "")
        status = str(current.get("status") or "")
        if status not in {"running", "waiting_otp"}:
            _sync_job_logs(register.get(job_id) or {}, log_cursor, log_sink)
            if status == "success":
                return {"ok": True, "phone": last_phone, "message": str(current.get("message") or "登录成功")}
            return {"ok": False, "phone": last_phone, "error": str(current.get("message") or current.get("error") or f"登录流程失败: {status}")}
        # The registration manager handles automatic OTP input, including
        # registration/PIN/login phases and history-code exclusion.
        time.sleep(1)
    _sync_job_logs(register.get(job_id) or {}, log_cursor, log_sink)
    return {"ok": False, "phone": last_phone, "error": f"登录流程超时（{timeout_sec}s）"}


def _login_pool_gopay_account(target_pin, proxy, job_timeout_sec=0, log_sink=None, claimed=None):
    if claimed is None:
        phone, row = _claim_pool_phone()
    else:
        phone, row = claimed
    if not phone:
        return {"ok": False, "error": "号码池没有“待登录”号码"}
    try:
        job = register.start(
            source="pool",
            phone=phone,
            sms_url=str((row or {}).get("sms_url") or ""),
            pin=target_pin,
            proxy=proxy,
            login_existing=True,
            change_pin_after_login=False,
            new_pin="",
        )
    except Exception as exc:
        _mark_pool_phone(phone, "login_failed", "login_required")
        return {"ok": False, "error": f"{phone} 登录启动失败: {_sanitize_public_error(exc)}"}
    result = _wait_register_job_terminal(job, phone=phone, timeout_sec=int(job_timeout_sec or 360), log_sink=log_sink)
    if not result["ok"]:
        _mark_pool_phone(phone, "login_failed", "login_required")
        result["error"] = f"{phone} {result['error']}"
        return result
    account, _idx = _find_gopay_account(phone)
    if account is None:
        _mark_pool_phone(phone, "login_failed", "login_required")
        return {"ok": False, "error": f"{phone} 登录成功但本地账号记录未找到"}
    pin_prep = _ensure_account_pin(account, target_pin, log_sink=log_sink)
    if not pin_prep["ok"]:
        _mark_pool_phone(phone, "login_failed", "login_required")
        return {"ok": False, "error": f"{phone} PIN 处理失败: {pin_prep['error']}"}
    try:
        if int(account.get("balance", 0) or 0) < 1:
            reward = _claim_gopay_reward(phone)
            if int(reward.get("balance", 0) or 0) >= 1:
                refreshed, _idx = _find_gopay_account(phone)
                if refreshed is not None:
                    account = refreshed
    except Exception as exc:
        print("pool account reward warmup failed:", exc, file=sys.stderr, flush=True)
    _mark_pool_phone(phone, "available", "registered")
    return {"ok": True, "account": account, "pin": pin_prep["pin"], "message": f"{phone} 登录成功"}

def _acquire_batch_login_account(target_pin, proxy, log_sink):
    """批量支付取号：本地号码池优先，无可用本地号码时回退 SMSBower。"""
    local_phone, local_row = _claim_pool_phone()
    if local_phone:
        if log_sink:
            log_sink(f"使用本地号码池 {local_phone} 登录已有账号")
        result = _login_pool_gopay_account(
            target_pin,
            proxy,
            job_timeout_sec=SCREEN_JOB_TIMEOUT_SEC,
            log_sink=log_sink,
            claimed=(local_phone, local_row),
        )
        if result.get("ok"):
            return result
        if log_sink:
            log_sink(f"本地号码 {local_phone} 登录失败，回退 SMSBower：{str(result.get('error') or '')[:120]}")
    return _login_smsbower_gopay_account(
        target_pin,
        proxy,
        login_otp_timeout=SCREEN_LOGIN_OTP_TIMEOUT,
        job_timeout_sec=SCREEN_JOB_TIMEOUT_SEC,
        log_sink=log_sink,
    )


def _login_smsbower_gopay_account(target_pin, proxy, login_otp_timeout=0, job_timeout_sec=0, log_sink=None):
    try:
        job = register.start(
            source="smsbower",
            phone="",
            pin=target_pin,
            proxy=proxy,
            login_existing=True,
            change_pin_after_login=False,
            new_pin="",
            login_otp_timeout=login_otp_timeout or None,
        )
    except Exception as exc:
        return {"ok": False, "error": "SMSBower 取号/登录启动失败: " + _sanitize_public_error(exc)}
    phone = str((job or {}).get("phone") or "")
    result = _wait_register_job_terminal(job, phone=phone, timeout_sec=int(job_timeout_sec or 360), log_sink=log_sink)
    if not result["ok"]:
        return {"ok": False, "error": "SMSBower " + (result.get("error") or "登录失败")}
    phone = str(result.get("phone") or phone or "")
    if not phone:
        return {"ok": False, "error": "SMSBower 登录成功但未获取到号码"}
    account, _idx = _find_gopay_account(phone)
    if account is None:
        return {"ok": False, "error": "SMSBower 已有账号登录成功但本地账号记录未找到: " + phone}
    pin_prep = _ensure_account_pin(account, target_pin, log_sink=log_sink)
    if not pin_prep["ok"]:
        return {"ok": False, "error": phone + " PIN 处理失败: " + pin_prep["error"]}
    try:
        if int(account.get("balance", 0) or 0) < 1:
            reward = _claim_gopay_reward(phone)
            if int(reward.get("balance", 0) or 0) >= 1:
                refreshed, _idx = _find_gopay_account(phone)
                if refreshed is not None:
                    account = refreshed
    except Exception as exc:
        print("smsbower account reward warmup failed:", exc, file=sys.stderr, flush=True)
    return {"ok": True, "account": account, "pin": pin_prep["pin"], "message": "SMSBower 已有账号 " + phone + " 登录完成"}



def _count_payable_accounts():
    count = 0
    for account in _load_gopay_accounts_raw():
        phone = str(account.get("phone") or "").strip()
        if not phone:
            continue
        if str(account.get("midtrans_binding_status") or "").strip() in {"reserved", "running", "linking", "waiting_otp"}:
            continue
        try:
            if int(account.get("balance", 0) or 0) < 1:
                continue
        except Exception:
            continue
        count += 1
    return count


FALLBACK_PINS = ["847152", "629483", "573916", "264837", "918475"]


def _pin_candidates(target_pin):
    seen = []
    if re.fullmatch(r"\d{6}", str(target_pin or "")):
        seen.append(str(target_pin))
    for p in FALLBACK_PINS:
        if p not in seen:
            seen.append(p)
    return seen


def _is_pin_policy_rejection(result):
    text = str((result or {}).get("error") or "")
    return "GoPay-113" in text or "mudah ditebak" in text or "Format Pin Tidak Valid" in text


def _pool_log_append(text):
    with _pool_log_lock:
        _pool_log.append({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "text": str(text)})
        if len(_pool_log) > 200:
            del _pool_log[:-200]


def _smsbower_batch_login(count, target_pin, proxy):
    from concurrent.futures import ThreadPoolExecutor

    def one(_idx):
        try:
            return _login_smsbower_gopay_account(target_pin, proxy)
        except Exception as exc:
            return {"ok": False, "error": _sanitize_public_error(exc)}

    with ThreadPoolExecutor(max_workers=max(1, min(SMSBOWER_POOL_CONCURRENCY, count))) as executor:
        results = list(executor.map(one, range(count)))
    ok_rows = [r for r in results if r.get("ok")]
    failed_rows = [r for r in results if not r.get("ok")]
    return {
        "ok": bool(ok_rows),
        "requested": count,
        "logged": len(ok_rows),
        "failed": len(failed_rows),
        "errors": [str(r.get("error") or "未知原因") for r in failed_rows][:5],
    }


def _smsbower_pool_needed():
    with payment_batches_lock:
        has_running = any(str(b.get("status") or "") == "running" for b in payment_batches.values())
        direct_login = any(
            str(b.get("status") or "") == "running" and bool(b.get("auto_login"))
            for b in payment_batches.values()
        )
    if not has_running or direct_login:
        # 批量支付直接登录新号时，暂停池子补号，避免和任务抢 SMSBower 号源
        return 0
    available = _count_payable_accounts()
    return max(0, SMSBOWER_POOL_BATCH - available)


def _smsbower_pool_screen_worker(need_fn, label="pool", log_fn=None, proxy_fn=None, index=0):
    """常驻并发筛号 worker：一个验证完立刻取下一个号，始终保持并发登录。

    只有当 need_fn() 返回的缺口大于当前在途数量时才取新号，避免超量取号；
    任务侧通过 _pool_inflight > 0 判断池是否仍在筛号。限频时进入共享冷却，
    避免多个 worker 同时反复打接口导致永远恢复不了。
    """
    global _pool_inflight
    last_ui_log = 0.0
    while True:
        try:
            with _pool_lock:
                cooldown_until = _pool_state.get("rate_limit_until") or 0.0
            if time.time() < cooldown_until:
                _pool_state["wake"].wait(min(5.0, max(0.1, cooldown_until - time.time())))
                _pool_state["wake"].clear()
                # 限频解除后错峰放行，避免多个 worker 同一秒同时打接口再次触发限频
                if index:
                    time.sleep(float(index) * 1.5)
                continue
            need = need_fn()
            with _pool_lock:
                in_flight = _pool_inflight
            if need <= in_flight:
                _pool_state["wake"].wait(5)
                _pool_state["wake"].clear()
                continue
            target_pin = str(_pool_state.get("target_pin") or "")
            if not re.fullmatch(r"\d{6}", target_pin):
                _pool_state["wake"].wait(5)
                _pool_state["wake"].clear()
                continue
            with _pool_lock:
                _pool_inflight += 1
            try:
                proxy = str(proxy_fn() if proxy_fn else "") or ""
                result = _login_smsbower_gopay_account(
                    target_pin,
                    proxy,
                    login_otp_timeout=SCREEN_LOGIN_OTP_TIMEOUT,
                    job_timeout_sec=SCREEN_JOB_TIMEOUT_SEC,
                )
                if result.get("ok"):
                    msg = str(result.get("message") or "SMSBower 登录成功")
                    print(label + " screen ok: " + msg[:140], flush=True)
                    if log_fn:
                        log_fn("筛号成功：" + msg[:140])
                        last_ui_log = time.time()
                else:
                    err = str(result.get("error") or "未知原因")
                    print(label + " screen fail: " + err[:180], flush=True)
                    if "限频" in err or "rate limit" in err.lower():
                        with _pool_lock:
                            _pool_state["rate_limit_until"] = time.time() + 30
                        if log_fn:
                            log_fn("GoTo 登录被限频，暂停 30 秒冷却后继续筛号")
                            last_ui_log = time.time()
                        time.sleep(3)
                    else:
                        if proxy and _proxy_failure_needle(err):
                            _ban_proxy(proxy)
                            if log_fn:
                                log_fn("代理预检异常，已临时禁用 " + _sanitize_public_error(proxy) + " " + str(PROXY_BAN_SEC) + " 秒")
                                last_ui_log = time.time()
                        if log_fn and time.time() - last_ui_log >= 2.0:
                            log_fn("筛号失败：" + err[:160])
                            last_ui_log = time.time()
                        time.sleep(1)
            finally:
                with _pool_lock:
                    _pool_inflight = max(0, _pool_inflight - 1)
        except Exception as exc:
            print(label + " screen error:", exc, file=sys.stderr, flush=True)
            time.sleep(2)


def _short_failure_label(message: str) -> str:
    text = str(message or "")
    low = text.lower()
    if "x-captcha-token" in low or "captcha" in low or "人机验证" in text:
        return "需要人机验证"
    if "余额不足" in text or ("balance" in low and "insufficient" in low):
        return "余额不足"
    if "410" in text or "gone" in low:
        return "链接失效(410)"
    if "过期" in text or "expire" in low:
        return "链接过期"
    if "已绑定" in text or "重复使用" in text or "已支付" in text or "正常使用" in text or "binding" in low:
        return "链接已用/绑定冲突"
    if "otp" in low or "验证码" in text:
        return "验证码超时/失败"
    if "代理" in text or "proxy" in low or "eof" in low or "network" in low or "timeout" in low or "connection" in low or "refused" in low:
        return "代理/网络"
    if "blocked" in low or "deny" in low or "fraud" in low or "风控" in text or "拦截" in text or "未开放" in text:
        return "风控/拦截"
    if "没有可用" in text or "未找到" in text or "不存在" in text:
        return "账号缺失"
    return text[:40] or "未知原因"


# 0 = 不限次数：账号级失败一直换号重试，直到支付成功或链接级问题才停
PAYMENT_BATCH_MAX_ACCOUNT_ATTEMPTS = int(os.environ.get("OPAI_PAYMENT_BATCH_MAX_ACCOUNT_ATTEMPTS", "0"))


def _payment_batch_log(bid, text):
    with payment_batches_lock:
        batch = payment_batches.get(bid)
        if not batch:
            return
        batch.setdefault("logs", []).append({"at": time.strftime("%H:%M:%S"), "text": str(text)})
        batch["last_log"] = str(text)
        batch["updated_at"] = time.strftime("%H:%M:%S")
        if len(batch["logs"]) > 1000:
            del batch["logs"][:-1000]


def _batch_register_log(bid, text):
    with batch_jobs_lock:
        batch = batch_jobs.get(bid)
        if not batch:
            return
        batch.setdefault("logs", []).append({"at": time.strftime("%H:%M:%S"), "text": str(text)})
        if len(batch["logs"]) > 400:
            del batch["logs"][:-400]


def _payment_batch_should_stop(bid):
    with payment_batches_lock:
        batch = payment_batches.get(bid)
        return bool(batch and batch.get("cancelled"))


def _is_link_terminal_failure(text):
    """True = 链接本身的问题（已支付/过期/410/污染/风控拒绝等），应停止该链接；
    False = 账号/网络级问题，应换号继续重试。"""
    low = str(text or "").lower()
    needles = [
        "x-captcha-token", "captcha", "人机验证",
        "410 gone", "http 410", "status 410", "410 not found", "410 error",
        "链接已过期", "midtrans 链接已过期", "expired",
        "已跑过", "不能重复支付",
        "绑定状态已污染", "不能重复绑定", "重新生成新链接", "请重新生成",
        "这条链接不要重试", "读取不到 order_id",
        "非 1 idr 授权链", "订单类型不是", "链接状态不可支付", "已经绑定过 gopay",
        "fraud denied", "fraud_status", 'transaction_status": "deny', "风控拒绝",
    ]
    return any(k in low for k in needles)


def _sleep_account_retry(err):
    text = str(err or "")
    low = text.lower()
    if "限频" in text or "429" in text or "rate limit" in low:
        time.sleep(30)
    elif "代理" in text or "proxy" in low or "eof" in low or "network" in low or "timeout" in low or "connection" in low or "refused" in low:
        time.sleep(3)
    else:
        time.sleep(2)


def _run_payment_batch(bid, links, workers, proxies, release_after_use, pin_override, auto_pin=False, target_pin="", auto_login=False):
    count = len(links)
    task_queue = list(links)
    lock = threading.Lock()

    def one():
        while True:
            with lock:
                if not task_queue:
                    return
                url = task_queue.pop(0)
            with payment_batches_lock:
                payment_batches[bid]["started"] += 1
            short_url = url if len(url) <= 56 else url[-56:]

            def sink(text):
                _payment_batch_log(bid, f"[{short_url}] {text}")

            last_error = ""
            job = None
            current = {}
            phone_used = ""
            terminal_reason = ""
            attempt = 0

            def pay_once(phone, pin, use_proxy):
                """单次支付：成功返回 ok；链接级问题返回 link；账号级失败返回 retry；取消返回 cancelled。"""
                nonlocal last_error, job, current
                try:
                    job = payment.start(phone=phone, pin=pin, midtrans_url=url, proxy=use_proxy)
                except ProxyPreflightError as exc:
                    last_error = _sanitize_public_error(exc)
                    return {"retry": last_error}
                except Exception as exc:
                    msg = _sanitize_public_error(exc)
                    last_error = msg
                    if _is_link_terminal_failure(msg):
                        return {"link": msg}
                    if any(k in msg for k in ("已绑定", "链接被重复使用", "存在失败记录")):
                        try:
                            payment.reset_snap_for_retry(url)
                        except Exception:
                            pass
                        return {"retry": msg}
                    return {"retry": msg}
                job_id = str((job or {}).get("id") or "")
                wait_deadline = time.time() + 600
                pay_log_cursor = 0
                current = {}
                while job_id and time.time() < wait_deadline:
                    if _payment_batch_should_stop(bid):
                        try:
                            payment.release_snap_link(url, reason="任务已取消，已释放链接占用，可重新提交")
                        except Exception:
                            pass
                        return {"cancelled": True}
                    current = payment.get(job_id) or {}
                    pay_log_cursor = _sync_job_logs(current, pay_log_cursor, sink)
                    if str(current.get("status") or "") not in {"running", "waiting_otp", "linking"}:
                        break
                    time.sleep(1)
                if job_id:
                    _sync_job_logs(payment.get(job_id) or {}, pay_log_cursor, sink)
                status = str(current.get("status") or "")
                if status == "success":
                    return {"ok": True}
                if status in {"running", "waiting_otp", "linking"}:
                    last_error = "支付等待超时（可能仍在等待 OTP）"
                    try:
                        payment.release_snap_link(url, reason="支付等待超时，已释放链接占用，可重新提交")
                    except Exception:
                        pass
                    return {"retry": last_error}
                reason = str(current.get("message") or current.get("error") or last_error or "")
                last_error = reason
                if _is_link_terminal_failure(reason):
                    return {"link": reason}
                return {"retry": reason}

            try:
                # 批量支付：直接从本地 GoPay 账号选号绑定，每条链接分配一个账号，失败换号重试
                skipped_phones = set()
                while True:
                    if _payment_batch_should_stop(bid):
                        terminal_reason = "任务已取消"
                        break
                    attempt += 1
                    if PAYMENT_BATCH_MAX_ACCOUNT_ATTEMPTS > 0 and attempt > PAYMENT_BATCH_MAX_ACCOUNT_ATTEMPTS:
                        last_error = last_error or f"连续 {attempt - 1} 次绑定失败"
                        break
                    account = _pick_relaxed_payment_account(skip_phones=skipped_phones)
                    if account is None:
                        last_error = last_error or "没有可用的 GoPay 账号（本地账号为空、余额不足或已被占用）"
                        _payment_batch_log(bid, f"[{short_url}] {last_error}")
                        break
                    phone_used = str(account.get("phone") or "").strip()
                    if not phone_used:
                        continue
                    skipped_phones.add(phone_used)
                    acc_lock = _account_worker_lock(phone_used)
                    if not acc_lock.acquire(blocking=False):
                        continue
                    try:
                        account, _idx = _find_gopay_account(phone_used)
                        if account is None:
                            continue
                        if str(account.get("midtrans_binding_status") or "").strip() in {"reserved", "running", "linking", "waiting_otp"}:
                            continue
                        pin = str(pin_override or "").strip()
                        if not re.fullmatch(r"\d{6}", pin):
                            pin = str(account.get("pin") or "").strip()
                        if not re.fullmatch(r"\d{6}", pin):
                            pin_prep = _ensure_account_pin(account, target_pin, log_sink=sink)
                            if not pin_prep["ok"]:
                                last_error = f"{phone_used} PIN 处理失败: {pin_prep['error']}"
                                _payment_batch_log(bid, f"[{short_url}] {last_error}，换号重试")
                                time.sleep(1)
                                continue
                            pin = pin_prep["pin"]
                        try:
                            if int(account.get("balance", 0) or 0) < 1:
                                last_error = f"{phone_used} 余额为 0，跳过该账号"
                                _payment_batch_log(bid, f"[{short_url}] {last_error}")
                                try:
                                    _release_gopay_midtrans_binding(phone_used, message="批量支付余额为 0，账号已释放")
                                except Exception:
                                    pass
                                time.sleep(1)
                                continue
                        except Exception:
                            pass
                        use_proxy = _pick_proxy(proxies) or str(account.get("proxy") or "").strip()
                        outcome = pay_once(phone_used, pin, use_proxy)
                        if outcome.get("ok"):
                            break
                        if outcome.get("cancelled"):
                            terminal_reason = "任务已取消"
                            break
                        if outcome.get("link"):
                            terminal_reason = outcome["link"]
                            _payment_batch_log(bid, f"[{short_url}] 链接问题，停止该链接：{terminal_reason[:160]}")
                            break
                        reason = str(outcome.get("retry") or "未知失败")
                        _payment_batch_log(bid, f"[{short_url}] {reason[:160]}，换号重试")
                        try:
                            _release_gopay_midtrans_binding(phone_used, message="批量支付失败，账号已释放")
                        except Exception:
                            pass
                        _sleep_account_retry(reason)
                    finally:
                        acc_lock.release()
                if phone_used and job:
                    _payment_batch_log(bid, f"[{short_url}] 账号 {phone_used} 支付结束：{current.get('status') or job.get('status') or ''} {str(current.get('message') or '')[:120]}")
                if release_after_use and phone_used:
                    try:
                        _release_gopay_midtrans_binding(phone_used)
                        with payment_batches_lock:
                            payment_batches[bid].setdefault("released", 0)
                            payment_batches[bid]["released"] += 1
                    except Exception:
                        pass
                with payment_batches_lock:
                    batch = payment_batches[bid]
                    batch["finished"] += 1
                    terminal = str(current.get("status") or (job.get("status") if job else "") or "")
                    if terminal == "success":
                        batch["succeeded"] += 1
                        _payment_batch_log(bid, f"[{short_url}] 支付成功 ✓")
                    else:
                        batch["failed"] += 1
                        if terminal_reason == "任务已取消":
                            reason = "任务已取消"
                        else:
                            reason = str(current.get("message") or current.get("error") or last_error or "")
                            if terminal_reason:
                                reason = reason or terminal_reason
                        label = _short_failure_label(reason)
                        batch.setdefault("failures", {}).setdefault(label, 0)
                        batch["failures"][label] += 1
                        if reason:
                            batch["last_error"] = reason[:500]
                        _payment_batch_log(bid, f"[{short_url}] 失败：{reason[:160]}")
                    batch["message"] = (
                        f"完成 {batch['finished']}/{count}，成功 {batch['succeeded']}，失败 {batch['failed']}"
                    )
            except Exception as exc:
                with payment_batches_lock:
                    batch = payment_batches[bid]
                    batch["finished"] += 1
                    batch["failed"] += 1
                    reason = _sanitize_public_error(exc)
                    batch["last_error"] = reason
                    label = _short_failure_label(reason)
                    batch.setdefault("failures", {}).setdefault(label, 0)
                    batch["failures"][label] += 1
                    batch["message"] = (
                        f"完成 {batch['finished']}/{count}，成功 {batch['succeeded']}，失败 {batch['failed']}"
                    )
                    _payment_batch_log(bid, f"[{short_url}] 异常：{reason[:160]}")

    thread_count = min(workers, count)
    threads = [threading.Thread(target=one, daemon=True) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with payment_batches_lock:
        batch = payment_batches[bid]
        if batch.get("cancelled"):
            batch["status"] = "cancelled"
        else:
            batch["status"] = "failed" if batch["succeeded"] == 0 and batch["failed"] else "done"

def _run_pin_batch(bid, phones, workers, new_pin, skip_configured, mode="setup"):
    count = len(phones)
    task_queue = list(phones)
    lock = threading.Lock()

    def one():
        while True:
            with lock:
                if not task_queue:
                    return
                phone = task_queue.pop(0)
            with pin_batches_lock:
                pin_batches[bid]["started"] += 1
            last_error = ""
            outcome = "failed"
            try:
                account, _idx = _find_gopay_account(phone)
                if account is None:
                    raise ValueError(f"账号不存在: {phone}")
                if mode == "reset":
                    saved_pin = str(account.get("pin") or "").strip()
                    if not re.fullmatch(r"\d{6}", saved_pin):
                        outcome = "skipped"
                    else:
                        job = pin_manager.start(phone=phone, old_pin=saved_pin, new_pin=new_pin, mode="known")
                else:
                    if skip_configured and str(account.get("pin_setup_status") or "").strip() == "configured":
                        outcome = "skipped"
                    else:
                        job = pin_manager.start(phone=phone, old_pin="", new_pin=new_pin, mode="setup")
                    job_id = str((job or {}).get("id") or "")
                    wait_deadline = time.time() + 700
                    while job_id and time.time() < wait_deadline:
                        current = pin_manager.get(job_id) or {}
                        if str(current.get("status") or "") in {"success", "failed", "cancelled"}:
                            break
                        time.sleep(1)
                    current = pin_manager.get(job_id) or {}
                    status = str(current.get("status") or "")
                    if status == "success":
                        outcome = "success"
                    else:
                        last_error = str(current.get("message") or current.get("error") or "") or ("PIN 重置失败或超时" if mode == "reset" else "PIN 设置失败或超时")
            except Exception as exc:
                last_error = _sanitize_public_error(exc)
            with pin_batches_lock:
                batch = pin_batches[bid]
                batch["finished"] += 1
                if outcome == "success":
                    batch["succeeded"] += 1
                elif outcome == "skipped":
                    batch["skipped"] += 1
                else:
                    batch["failed"] += 1
                    if last_error:
                        batch["last_error"] = last_error
                batch["message"] = (
                    f"完成 {batch['finished']}/{count}，成功 {batch['succeeded']}，失败 {batch['failed']}，跳过 {batch['skipped']}"
                )

    thread_count = min(workers, count)
    threads = [threading.Thread(target=one, daemon=True) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with pin_batches_lock:
        batch = pin_batches[bid]
        batch["status"] = "failed" if batch["succeeded"] == 0 and batch["failed"] else "done"


MAX_JSON_BODY_BYTES = int(os.environ.get("OPAI_GOPAY_MAX_JSON_BODY_BYTES", str(1024 * 1024)))
_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def _is_loopback_authority(value: str) -> bool:
    try:
        host = urlsplit("//" + value if "://" not in value else value).hostname
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1"}


class Handler(BaseHTTPRequestHandler):
    def _security_headers(self):
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)

    def _trusted_request(self):
        host = str(self.headers.get("Host") or "")
        origin = str(self.headers.get("Origin") or "").strip()
        return _is_loopback_authority(host) and (not origin or _is_loopback_authority(origin))

    def send(self, code, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not self._trusted_request():
            self.send(403, {"error": "untrusted_origin"})
            return
        path = self.path.split("?", 1)[0]
        if path == "/":
            raw = _page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if path == "/api/accounts":
            self.send(200, {"accounts": _load_gopay_accounts()})
            return
        if path == "/api/auth-environments":
            query = parse_qs(urlsplit(self.path).query)
            try:
                limit = int((query.get("limit") or ["200"])[0])
            except (TypeError, ValueError):
                limit = 200
            self.send(200, _load_auth_environments(limit))
            return
        if path == "/api/phone-pool":
            rows = _load_gopay_phone_pool()
            summary = {
                state: sum(1 for row in rows if row.get("account_state") == state)
                for state in sorted(POOL_ACCOUNT_STATES)
            }
            self.send(200, {"phones": rows, "summary": summary})
            return
        if path == "/api/sms-status":
            self.send(200, _sms_api_status(include_balance=False))
            return
        if path == "/api/phone-change-tasks":
            with _phone_change_tasks_lock:
                rows = [_public_phone_change_task(item) for item in reversed(_load_phone_change_tasks())]
            self.send(200, {"tasks": rows[:100]})
            return
        if path == "/api/captcha-status":
            self.send(200, captcha_config_status())
            return
        if path == "/api/proxy-config":
            self.send(200, proxy_config_status())
            return
        if path == "/api/proxy/providers":
            self.send(200, proxy_provider_state())
            return
        if path == "/api/env-check":
            self.send(200, env_check_status(force=True))
            return
        if path == "/api/pool-log":
            with _pool_log_lock:
                rows = list(_pool_log[-150:])
            self.send(200, {"logs": rows})
            return
        if path.startswith("/api/accounts/") and path.endswith("/sms-code"):
            phone = unquote(path[len("/api/accounts/"):-len("/sms-code")].strip("/"))
            self.send(200, {"phone": phone, "code": _poll_imported_sms_code(phone)})
            return
        if path == "/api/register-jobs":
            rows = _safe_register_jobs()
            with batch_jobs_lock:
                batches = [dict(batch) for batch in batch_jobs.values()]
            for batch in batches:
                rows.insert(0, {
                    "id": batch["id"],
                    "phone": f"批量 {batch.get('started', 0)}/{batch.get('count', 0)}",
                    "source": batch.get("source"),
                    "login_existing": bool(batch.get("login_existing")),
                    "status": batch.get("status"),
                    "message": batch.get("message") or batch.get("error") or f"完成 {batch.get('finished', 0)}/{batch.get('count', 0)}",
                })
            self.send(200, {"jobs": rows, "batches": batches})
            return
        if path == "/api/payment-jobs":
            with payment_batches_lock:
                pay_batches = [dict(batch) for batch in payment_batches.values()]
            self.send(200, {"jobs": payment.list(), "batches": pay_batches})
            return
        if path == "/api/pin-tasks":
            with pin_batches_lock:
                pin_batch_rows = [dict(b) for b in pin_batches.values()]
            self.send(200, {"jobs": pin_manager.list(), "batches": pin_batch_rows})
            return
        if path.startswith("/api/pin-tasks/"):
            job_id = unquote(path[len("/api/pin-tasks/"):].strip("/"))
            job = pin_manager.get(job_id)
            if job:
                self.send(200, job)
            else:
                self.send(404, {"error": "pin_task_not_found"})
            return
        self.send(404, {"error": "not_found"})

    def do_POST(self):
        if not self._trusted_request():
            self.send(403, {"error": "untrusted_origin"})
            return
        path = self.path.split("?", 1)[0]
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > MAX_JSON_BODY_BYTES:
                self.send(413, {"error": "request_too_large", "max_bytes": MAX_JSON_BODY_BYTES})
                return
            data = json.loads(self.rfile.read(size) or b"{}") if size else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            self.send(400, {"error": "invalid_json"})
            return
        try:
            if path == "/api/proxy/providers":
                self.send(201, save_proxy_provider(data)); return
            if path == "/api/proxy/bindings":
                self.send(200, {"ok": True, "bindings": save_proxy_bindings(data.get("bindings"))}); return
            provider_match = re.fullmatch(r"/api/proxy/providers/(\d+)(?:/(test|delete))?", path)
            if provider_match:
                provider_id = int(provider_match.group(1))
                action = str(provider_match.group(2) or "")
                if action == "delete":
                    self.send(200, {"ok": delete_proxy_provider(provider_id)}); return
                if action == "test":
                    from opai.core.gojek_client import probe_proxy_egress

                    resolved = resolve_provider_proxy(
                        "",
                        str(data.get("country") or "ID"),
                        provider_id=provider_id,
                        session_id=uuid.uuid4().hex[:12],
                    )
                    if not resolved.get("url"):
                        raise ValueError("代理服务商不存在或已停用")
                    started = time.monotonic()
                    probe = probe_proxy_egress(str(resolved["url"]), timeout_sec=12)
                    self.send(200, {
                        "ok": bool(probe.get("ok")),
                        "provider": resolved.get("provider_name"),
                        "proxy": resolved.get("preview"),
                        "ip": probe.get("ip") or "",
                        "ms": int((time.monotonic() - started) * 1000),
                        "error": probe.get("error") or probe.get("raw") or "",
                    }); return
                self.send(200, save_proxy_provider(data, provider_id)); return
            if path == "/api/tasks/clear-finished":
                scope = str(data.get("scope") or "").strip().lower()
                if scope not in {"all", "register", "payment", "pin"}:
                    raise ValueError("清理范围无效")
                removed = {"register": 0, "batches": 0, "payment": 0, "pin": 0, "pin_batches": 0}
                if scope in {"all", "register"}:
                    removed["register"] = register.clear_finished()
                    with batch_jobs_lock:
                        finished_batches = [
                            job_id
                            for job_id, job in batch_jobs.items()
                            if str(job.get("status") or "").strip().lower() in {"done", "failed", "cancelled", "canceled", "error"}
                        ]
                        for job_id in finished_batches:
                            batch_jobs.pop(job_id, None)
                    removed["batches"] = len(finished_batches)
                if scope in {"all", "payment"}:
                    removed["payment"] = payment.clear_finished()
                    with payment_batches_lock:
                        finished_pay_batches = [
                            job_id
                            for job_id, job in payment_batches.items()
                            if str(job.get("status") or "").strip().lower() in {"done", "failed", "cancelled", "canceled", "error"}
                        ]
                        for job_id in finished_pay_batches:
                            payment_batches.pop(job_id, None)
                    removed["pay_batches"] = len(finished_pay_batches)
                if scope in {"all", "pin"}:
                    removed["pin"] = pin_manager.clear_finished()
                    with pin_batches_lock:
                        finished_pin_batches = [
                            job_id
                            for job_id, job in pin_batches.items()
                            if str(job.get("status") or "").strip().lower() in {"done", "failed", "cancelled", "canceled", "error"}
                        ]
                        for job_id in finished_pin_batches:
                            pin_batches.pop(job_id, None)
                    removed["pin_batches"] = len(finished_pin_batches)
                self.send(200, {
                    "ok": True,
                    "scope": scope,
                    "removed": removed,
                    "total": sum(removed.values()),
                })
                return
            if path == "/api/phone-pool/import":
                self.send(201, _import_gopay_phone_pool(str(data.get("text") or ""), data.get("account_state") or "unregistered"))
                return
            if path == "/api/phone-pool/clear":
                self.send(200, {"ok": True, "removed": _clear_gopay_phone_pool()})
                return
            if path == "/api/phone-pool/delete":
                phone = str(data.get("phone") or "").strip()
                removed = _delete_gopay_phone(phone)
                if not removed: raise ValueError(f"号码不存在: {phone}")
                self.send(200, {"ok": True, "phone": phone, "removed": removed})
                return
            if path == "/api/phone-pool/state":
                phones = data.get("phones") if isinstance(data.get("phones"), list) else [data.get("phone")]
                self.send(200, _set_pool_account_state(phones, data.get("account_state")))
                return
            if path == "/api/sms-config":
                self.send(200, _write_sms_config(data))
                return
            if path == "/api/captcha-config":
                self.send(200, write_captcha_config(data))
                return
            if path == "/api/proxy-config":
                self.send(200, write_proxy_config(data))
                return
            if path == "/api/proxies/check":
                proxies = _parse_proxy_list(data.get("proxies"))
                if not proxies:
                    raise ValueError("请先输入至少一条代理")
                checked = _check_proxy_pool(proxies)
                checked.pop("healthy", None)
                self.send(200, checked)
                return
            if path == "/api/register":
                job = register.start(
                    source=str(data.get("source") or "pool"),
                    phone=str(data.get("phone") or ""),
                    sms_url=str(data.get("sms_url") or ""),
                    pin=str(data.get("pin") or "").strip(),
                    login_existing=bool(data.get("login_existing")),
                    change_pin_after_login=bool(data.get("change_pin_after_login") or data.get("change_existing_pin")),
                    new_pin=str(data.get("new_pin") or "").strip(),
                    proxy=str(data.get("proxy") or ""),
                )
                if str(data.get("source") or "pool") == "pool" and str(job.get("id") or ""):
                    threading.Thread(
                        target=_track_pool_register_job,
                        args=(str(job.get("id") or ""), str(job.get("phone") or data.get("phone") or ""), bool(data.get("login_existing"))),
                        daemon=True,
                    ).start()
                self.send(201, job)
                return
            if path == "/api/batch-register":
                source = str(data.get("source") or "pool")
                if source not in {"pool", "smsbower"}:
                    raise ValueError("号码来源无效")
                count = min(500, max(1, int(data.get("count") or 1)))
                workers = min(50, max(1, int(data.get("workers") or 1)))
                login_existing = bool(data.get("login_existing"))
                pin = str(data.get("pin") or "").strip()
                change_pin_after_login = bool(data.get("change_pin_after_login") or data.get("change_existing_pin"))
                if (not login_existing or change_pin_after_login or pin) and not re.fullmatch(r"\d{6}", pin):
                    label = "原 PIN" if login_existing else "PIN"
                    raise ValueError(f"{label}必须是 6 位数字")
                new_pin = str(data.get("new_pin") or "").strip()
                if change_pin_after_login and not login_existing:
                    raise ValueError("只有“登录已有号”模式可以在登录后修改 PIN")
                if change_pin_after_login:
                    if not re.fullmatch(r"\d{6}", new_pin):
                        raise ValueError("新 PIN 必须是 6 位数字")
                    if new_pin == pin:
                        raise ValueError("新 PIN 不能和原 PIN 相同")
                proxy_value = data.get("proxies") if "proxies" in data else data.get("proxy")
                proxies = _parse_proxy_list(proxy_value)
                requested_phones = data.get("phones") if isinstance(data.get("phones"), list) else []
                pool_rows = _select_pool_rows(requested_phones, login_existing, count) if source == "pool" else []
                if source == "pool" and requested_phones:
                    count = len(pool_rows)
                phones = [x.get("phone") for x in pool_rows]
                if source == "pool" and len(phones) < count:
                    mode_label = "登录" if login_existing else "注册"
                    raise ValueError(f"号码池可用号码不足：{mode_label} {count} 个账号需要 {count} 个号码，当前只有 {len(phones)} 个。请先导入号码，或改用 SMSBower。")
                bid = uuid.uuid4().hex[:12]
                with batch_jobs_lock:
                    batch_jobs[bid] = {
                        "id": bid,
                        "source": source,
                        "count": count,
                        "workers": workers,
                        "login_existing": login_existing,
                        "selected_phones": phones,
                        "change_pin_after_login": change_pin_after_login,
                        "status": "running",
                        "started": 0,
                        "finished": 0,
                        "succeeded": 0,
                        "failed": 0,
                        "proxy_total": len(proxies),
                        "failures": {},
                        "logs": [],
                        "proxy_checked": 0,
                        "proxy_available": 0,
                        "proxy_unavailable": 0,
                        "message": f"正在检测 {len(proxies)} 条代理" if proxies else "任务运行中",
                    }
                def run_batch():
                    healthy_proxies = [""]
                    if proxies:
                        healthy_proxies = list(proxies)
                        with batch_jobs_lock:
                            batch = batch_jobs[bid]
                            batch["proxy_checked"] = len(proxies)
                            batch["proxy_available"] = len(proxies)
                            batch["proxy_unavailable"] = 0
                            batch["message"] = f"使用全部 {len(proxies)} 条代理，准备执行任务"
                    task_queue = list(pool_rows) if source == "pool" else [""] * count
                    lock = threading.Lock()
                    proxy_condition = threading.Condition()
                    available_proxies = list(healthy_proxies) if proxies else []
                    disabled_proxies = set()

                    def acquire_proxy():
                        if not proxies:
                            return ""
                        with proxy_condition:
                            while not available_proxies and len(disabled_proxies) < len(healthy_proxies):
                                proxy_condition.wait()
                            if not available_proxies:
                                return None
                            return available_proxies.pop(0)

                    def release_proxy(candidate, usable=True):
                        if not proxies or candidate is None:
                            return
                        with proxy_condition:
                            if usable:
                                available_proxies.append(candidate)
                            else:
                                disabled_proxies.add(candidate)
                            proxy_condition.notify_all()
                        if not usable:
                            with batch_jobs_lock:
                                batch = batch_jobs[bid]
                                batch["proxy_available"] = max(0, checked["available"] - len(disabled_proxies))
                                batch["proxy_unavailable"] = checked["unavailable"] + len(disabled_proxies)

                    def one():
                        while True:
                            with lock:
                                if not task_queue: return
                                task = task_queue.pop(0)
                            if isinstance(task, dict):
                                phone = str(task.get("phone") or "").strip()
                                sms_url = str(task.get("sms_url") or "").strip()
                            else:
                                phone = str(task or "").strip()
                                sms_url = ""
                            with batch_jobs_lock:
                                batch_jobs[bid]["started"] += 1
                            job = None
                            current = {}
                            last_error = ""
                            candidate = acquire_proxy()
                            while candidate is not None:
                                try:
                                    job = register.start(
                                        source=source,
                                        phone=phone,
                                        sms_url=sms_url,
                                        pin=pin,
                                        proxy=candidate,
                                        login_existing=login_existing,
                                        change_pin_after_login=change_pin_after_login,
                                        new_pin=new_pin,
                                    )
                                except ProxyPreflightError as exc:
                                    last_error = _sanitize_public_error(exc)
                                    release_proxy(candidate, usable=False)
                                    candidate = acquire_proxy()
                                    continue
                                except Exception as exc:
                                    last_error = _sanitize_public_error(exc)
                                    release_proxy(candidate, usable=True)
                                    break

                                # register.start() only creates the worker thread;
                                # keep the proxy leased until this account is terminal.
                                job_id = str((job or {}).get("id") or "")
                                while job_id:
                                    current = register.get(job_id) or {}
                                    if current.get("status") not in {"running", "waiting_otp"}:
                                        break
                                    time.sleep(1)
                                release_proxy(candidate, usable=True)
                                break
                            if candidate is None and not last_error:
                                last_error = "可用代理已全部失效，未购买 SMSBower 号码"
                            terminal_status = str(current.get("status") or (job.get("status") if job else ""))
                            pin_ready = True
                            logged_phone = str((job or {}).get("phone") or current.get("phone") or "").strip()
                            if source == "pool":
                                _apply_pool_auth_result(
                                    logged_phone or phone,
                                    terminal_status,
                                    current.get("message") or current.get("error") or last_error,
                                    login_existing,
                                )
                            if terminal_status == "success" and login_existing and not change_pin_after_login:
                                try:
                                    account, _idx = _find_gopay_account(logged_phone)
                                    target_uniform = _uniform_pin()
                                    _batch_register_log(bid, f"[{logged_phone}] 登录成功，确认本地 PIN（缺失时自动设置）")
                                    prep = _ensure_account_pin(account, target_uniform) if account is not None else {"ok": False, "error": "账号记录未找到"}
                                    if prep.get("ok"):
                                        _batch_register_log(bid, f"[{logged_phone}] PIN 处理完成: {prep.get('note') or 'ok'}")
                                    else:
                                        pin_ready = False
                                        last_error = f"{logged_phone} 登录后 PIN 处理失败: {prep.get('error') or ''}"
                                        _batch_register_log(bid, f"[{logged_phone}] {last_error}")
                                except Exception as exc:
                                    pin_ready = False
                                    last_error = f"{logged_phone} 登录后 PIN 处理异常: {_sanitize_public_error(exc)}"
                                    _batch_register_log(bid, f"[{logged_phone}] {last_error}")
                            with batch_jobs_lock:
                                batch = batch_jobs[bid]
                                batch["finished"] += 1
                                if terminal_status == "success" and pin_ready:
                                    batch["succeeded"] += 1
                                    batch.setdefault("pin_ready", 0)
                                    batch["pin_ready"] += 1
                                else:
                                    batch["failed"] += 1
                                    if last_error:
                                        batch["last_error"] = last_error
                                proxy_text = ""
                                if batch.get("proxy_total"):
                                    proxy_text = f"；代理可用 {batch.get('proxy_available', 0)}/{batch.get('proxy_total', 0)}"
                                batch["message"] = (
                                    f"完成 {batch['finished']}/{count}，成功 {batch['succeeded']}，失败 {batch['failed']}{proxy_text}"
                                )
                    thread_count = min(workers, count, len(healthy_proxies)) if proxies else min(workers, count)
                    threads = [threading.Thread(target=one, daemon=True) for _ in range(thread_count)]
                    for thread in threads: thread.start()
                    for thread in threads: thread.join()
                    with batch_jobs_lock:
                        batch = batch_jobs[bid]
                        batch["status"] = "failed" if batch["succeeded"] == 0 and batch["failed"] else "done"
                        if batch["status"] == "done" and batch["failed"]:
                            batch["message"] = f"部分完成：成功 {batch['succeeded']}，失败 {batch['failed']}"
                threading.Thread(target=run_batch, daemon=True).start()
                with batch_jobs_lock:
                    response = dict(batch_jobs[bid])
                self.send(201, response); return
            if path == "/api/payment/links/reset":
                midtrans_url = str(data.get("midtrans_url") or "").strip()
                if not midtrans_url:
                    raise ValueError("请提供 Midtrans 链接")
                payment.release_snap_link(midtrans_url, reason="手动解除链接占用，可重新尝试")
                self.send(200, {"ok": True, "midtrans_url": midtrans_url}); return
            if path == "/api/payment":
                job = payment.start(phone=str(data.get("phone") or ""), pin=str(data.get("pin") or "").strip(), midtrans_url=str(data.get("midtrans_url") or ""), proxy=str(data.get("proxy") or ""))
                self.send(201, job); return
            if path == "/api/batch-payment":
                links = _parse_midtrans_links(data.get("midtrans_links"))
                workers = min(20, max(1, int(data.get("workers") or 1)))
                release_after_use = bool(data.get("release_after_use", True))
                pin_override = str(data.get("pin") or "").strip()
                auto_pin = bool(data.get("auto_pin", False))
                auto_login = bool(data.get("auto_login", False))
                target_pin = str(data.get("target_pin") or "").strip()
                if auto_login and not auto_pin:
                    raise ValueError("自动登录账号需要同时开启自动处理 PIN")
                if auto_pin and not re.fullmatch(r"\d{6}", target_pin):
                    raise ValueError("自动处理 PIN 时必须提供 6 位统一新 PIN")
                if auto_pin and pin_override:
                    raise ValueError("自动处理 PIN 与指定付款 PIN 不能同时使用")
                proxy_value = data.get("proxies") if "proxies" in data else data.get("proxy")
                proxies = _parse_proxy_list(proxy_value)
                bid = uuid.uuid4().hex[:12]
                with payment_batches_lock:
                    payment_batches[bid] = {
                        "id": bid,
                        "count": len(links),
                        "workers": workers,
                        "release_after_use": release_after_use,
                        "auto_pin": auto_pin,
                        "auto_login": auto_login,
                        "status": "running",
                        "started": 0,
                        "finished": 0,
                        "succeeded": 0,
                        "failed": 0,
                        "released": 0,
                        "proxy_total": len(proxies),
                        "message": "批量支付任务运行中（直接选用本地 GoPay 账号绑定，失败自动换号）",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                if auto_login:
                    with _pool_lock:
                        _pool_state["target_pin"] = target_pin
                    _pool_state["wake"].set()
                threading.Thread(
                    target=_run_payment_batch,
                    args=(bid, links, workers, proxies, release_after_use, pin_override, auto_pin, target_pin, auto_login),
                    daemon=True,
                ).start()
                with payment_batches_lock:
                    response = dict(payment_batches[bid])
                self.send(201, response); return
            if path == "/api/payment-batches/cancel":
                bid = str(data.get("bid") or "")
                with payment_batches_lock:
                    batch = payment_batches.get(bid)
                    if batch is None:
                        self.send(404, {"error": "batch_not_found"}); return
                    batch["cancelled"] = True
                    batch["message"] = "已发送取消指令，正在停止剩余链接"
                self.send(200, {"ok": True, "bid": bid}); return
            # ========== 修改点：支持 forgot 模式 ==========
            if path == "/api/pin-tasks/batch":
                phones_raw = data.get("phones")
                if isinstance(phones_raw, str):
                    phones = [line.strip() for line in phones_raw.splitlines() if line.strip()]
                elif isinstance(phones_raw, list):
                    phones = [str(p).strip() for p in phones_raw if str(p).strip()]
                else:
                    phones = []
                if not phones:
                    raise ValueError("请至少填写一个手机号")
                phones = list(dict.fromkeys(phones))
                new_pin = str(data.get("new_pin") or "").strip()
                if not re.fullmatch(r"\d{6}", new_pin):
                    raise ValueError("新 PIN 必须是 6 位数字")
                workers = min(10, max(1, int(data.get("workers") or 2)))
                skip_configured = bool(data.get("skip_configured", True))
                mode = str(data.get("mode") or "setup").strip()
                if mode not in {"setup", "reset"}:
                    raise ValueError("mode 必须是 setup 或 reset")
                bid = uuid.uuid4().hex[:12]
                with pin_batches_lock:
                    pin_batches[bid] = {
                        "id": bid,
                        "count": len(phones),
                        "workers": workers,
                        "skip_configured": skip_configured,
                        "mode": mode,
                        "status": "running",
                        "started": 0,
                        "finished": 0,
                        "succeeded": 0,
                        "failed": 0,
                        "skipped": 0,
                        "message": "批量重置 PIN 任务运行中" if mode == "reset" else "批量设置 PIN 任务运行中",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                threading.Thread(
                    target=_run_pin_batch,
                    args=(bid, phones, workers, new_pin, skip_configured, mode),
                    daemon=True,
                ).start()
                with pin_batches_lock:
                    response = dict(pin_batches[bid])
                self.send(201, response); return
            if path == "/api/pin-tasks":
                mode = str(data.get("mode") or "known").strip()
                if mode not in {"known", "forgot", "setup"}:
                    raise ValueError("mode 必须是 known、forgot 或 setup")
                if mode == "known" and not str(data.get("old_pin") or "").strip():
                    raise ValueError("known 模式必须提供 old_pin")
                job = pin_manager.start(
                    phone=str(data.get("phone") or "").strip(),
                    old_pin=str(data.get("old_pin") or "").strip() if mode == "known" else "",
                    new_pin=str(data.get("new_pin") or "").strip(),
                    mode=mode,
                )
                self.send(201, job); return
            # ========== 新增：PIN 任务 OTP 提交 ==========
            if path.startswith("/api/pin-tasks/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/pin-tasks/"):-len("/otp")].strip("/"))
                code = str(data.get("code") or "").strip()
                if not re.fullmatch(r"\d{4,6}", code):
                    raise ValueError("OTP 必须是 4 到 6 位数字")
                job = pin_manager.submit_otp(job_id, code)
                if not job:
                    raise ValueError(f"PIN 任务不存在或不能接收 OTP: {job_id}")
                self.send(200, job); return
            if path.startswith("/api/payment-jobs/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/payment-jobs/"):-len("/otp")].strip("/"))
                code = str(data.get("code") or "").strip()
                if not re.fullmatch(r"\d{4,6}", code):
                    raise ValueError("OTP 必须是 4 到 6 位数字")
                job = payment.submit_otp(job_id, code)
                if not job:
                    raise ValueError(f"该支付任务当前不在等待 OTP，可能已经失败、完成或超时: {job_id}")
                self.send(200, job); return
            if path.startswith("/api/register-jobs/") and path.endswith("/otp"):
                job_id = unquote(path[len("/api/register-jobs/"):-len("/otp")].strip("/"))
                code = str(data.get("code") or "").strip()
                if not re.fullmatch(r"\d{4,6}", code):
                    raise ValueError("验证码必须是 4 到 6 位数字")
                job = register.submit_otp(job_id, code)
                if not job:
                    raise ValueError(f"注册任务不存在或不能接收验证码: {job_id}")
                clean = dict(job)
                clean.pop("pin", None)
                self.send(200, clean); return
            if path == "/api/accounts/delete-all":
                self.send(200, {"ok": True, "removed": _delete_all_gopay_accounts()}); return
            if path.startswith("/api/accounts/") and path.endswith("/phone-type"):
                phone = unquote(path[len("/api/accounts/"):-len("/phone-type")].strip("/"))
                row = _set_account_phone_type(phone, str(data.get("phone_type") or ""))
                self.send(200, {"ok": True, "phone": row.get("phone"), "phone_type": row.get("phone_type")}); return
            if path.startswith("/api/accounts/") and path.endswith("/smsbower-phone-change/start"):
                phone = unquote(path[len("/api/accounts/"):-len("/smsbower-phone-change/start")].strip("/"))
                self.send(201, _start_smsbower_phone_change(phone, str(data.get("phone_type") or ""))); return
            if path.startswith("/api/phone-change-tasks/") and path.endswith("/code"):
                job_id = unquote(path[len("/api/phone-change-tasks/"):-len("/code")].strip("/"))
                self.send(200, _poll_smsbower_phone_change_code(job_id, data.get("timeout_sec") or 60)); return
            if path.startswith("/api/phone-change-tasks/") and path.endswith("/complete"):
                job_id = unquote(path[len("/api/phone-change-tasks/"):-len("/complete")].strip("/"))
                self.send(200, _complete_smsbower_phone_change(job_id)); return
            if path.startswith("/api/phone-change-tasks/") and path.endswith("/retry"):
                job_id = unquote(path[len("/api/phone-change-tasks/"):-len("/retry")].strip("/"))
                self.send(200, _retry_smsbower_phone_change(job_id)); return
            if path.startswith("/api/phone-change-tasks/") and path.endswith("/cancel"):
                job_id = unquote(path[len("/api/phone-change-tasks/"):-len("/cancel")].strip("/"))
                self.send(200, _cancel_smsbower_phone_change(job_id)); return
            if path.startswith("/api/accounts/") and path.endswith("/test-short-phone-change"):
                phone = unquote(path[len("/api/accounts/"):-len("/test-short-phone-change")].strip("/"))
                row = _test_short_phone_change(phone, str(data.get("new_phone") or ""))
                self.send(200, {"ok": True, "phone": row.get("phone"), "phone_type": "short_term", "test_only": True, "relogin_required": True}); return
            if path.startswith("/api/accounts/") and path.endswith("/sync-phone-change"):
                phone = unquote(path[len("/api/accounts/"):-len("/sync-phone-change")].strip("/"))
                row = _sync_phone_change(phone, str(data.get("new_phone") or ""), str(data.get("phone_type") or "long_term"))
                self.send(200, {"ok": True, "phone": row.get("phone"), "phone_type": row.get("phone_type"), "relogin_required": True}); return
            if path.startswith("/api/accounts/") and path.endswith("/delete"):
                phone = unquote(path[len("/api/accounts/"):-len("/delete")].strip("/"))
                removed = _delete_gopay_account(phone)
                if not removed: raise ValueError(f"账号不存在: {phone}")
                self.send(200, {"ok": True, "phone": phone, "removed": removed}); return
            if path.startswith("/api/accounts/") and path.endswith("/balance"):
                phone = unquote(path[len("/api/accounts/"):-len("/balance")].strip("/"))
                self.send(200, _refresh_gopay_balance(phone)); return
            if path.startswith("/api/accounts/") and path.endswith("/pin-status"):
                phone = unquote(path[len("/api/accounts/"):-len("/pin-status")].strip("/"))
                self.send(200, _refresh_gopay_pin_status(phone)); return
            if path.startswith("/api/accounts/") and path.endswith("/release-sms"):
                phone = unquote(path[len("/api/accounts/"):-len("/release-sms")].strip("/"))
                self.send(200, _release_gopay_sms(phone)); return
            if path.startswith("/api/accounts/") and path.endswith("/release-binding"):
                phone = unquote(path[len("/api/accounts/"):-len("/release-binding")].strip("/"))
                self.send(200, {"ok": _release_gopay_midtrans_binding(phone, message="手动释放 Midtrans 绑定，账号可重新使用"), "phone": phone}); return
            if path.startswith("/api/accounts/") and path.endswith("/relogin"):
                phone = unquote(path[len("/api/accounts/"):-len("/relogin")].strip("/"))
                account, _ = _find_gopay_account(phone)
                if not account: raise ValueError(f"账号不存在: {phone}")
                pool_row = next(
                    (
                        row for row in _load_gopay_phone_pool()
                        if "".join(ch for ch in str(row.get("phone") or "") if ch.isdigit())
                        == "".join(ch for ch in phone if ch.isdigit())
                    ),
                    {},
                )
                job = register.start(
                    source="pool",
                    phone=phone,
                    sms_url=str(pool_row.get("sms_url") or ""),
                    pin=str(data.get("pin") or account.get("pin") or "").strip(),
                    login_existing=True,
                    proxy=str(account.get("proxy") or ""),
                )
                def _relogin_then_ensure_pin():
                    _auto_feed_relogin_otp(job.get("id"), phone)
                    try:
                        acc, _idx = _find_gopay_account(phone)
                        if acc is not None:
                            _ensure_account_pin(acc, _uniform_pin())
                    except Exception:
                        pass
                threading.Thread(target=_relogin_then_ensure_pin, daemon=True).start()
                self.send(201, job); return
            self.send(404, {"error": "not_found"})
        except Exception as exc:
            self.send(400, {"error": _sanitize_public_error(exc)})

    def log_message(self, *_args):
        pass


def main():
    _resume_smsbower_phone_change_workers()
    for _idx in range(max(1, SMSBOWER_POOL_CONCURRENCY)):
        threading.Thread(
            target=_smsbower_pool_screen_worker,
            args=(_smsbower_pool_needed, "pool"),
            kwargs={"log_fn": _pool_log_append, "index": _idx},
            daemon=True,
            name="smsbower-screen-" + str(_idx),
        ).start()
    ThreadingHTTPServer(("127.0.0.1",  19081), Handler).serve_forever()


if __name__ == "__main__":
    main()
