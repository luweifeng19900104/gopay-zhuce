"""Persistent proxy-provider configuration shared by GoPay workflows."""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from .file_utils import atomic_write_json
from .proxy_utils import normalize_proxy_url


PROJECT_ROOT = Path(__file__).resolve().parents[4]
_LOCK = threading.RLock()
PURPOSES = ("registration", "phone_change", "payment")
KINDS = {"custom", "iproyal", "cliproxy", "711proxy", "cakeip"}
SCHEMES = {"http", "https", "socks5"}


def _path() -> Path:
    raw = str(os.environ.get("OPAI_GOPAY_PROXY_PROVIDERS_FILE") or "").strip()
    return Path(raw).expanduser() if raw else PROJECT_ROOT / "config" / "proxy_providers.json"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _default_state() -> dict[str, Any]:
    return {
        "version": 1,
        "next_id": 1,
        "providers": [],
        "bindings": {
            purpose: {"enabled": False, "provider_id": 0, "country": "ID"}
            for purpose in PURPOSES
        },
    }


def _read() -> dict[str, Any]:
    path = _path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        data = _default_state()
    if not isinstance(data, dict):
        data = _default_state()
    providers = data.get("providers")
    data["providers"] = [dict(row) for row in providers if isinstance(row, dict)] if isinstance(providers, list) else []
    bindings = data.get("bindings") if isinstance(data.get("bindings"), dict) else {}
    data["bindings"] = {
        purpose: {
            "enabled": bool((bindings.get(purpose) or {}).get("enabled")),
            "provider_id": int((bindings.get(purpose) or {}).get("provider_id") or 0),
            "country": _country((bindings.get(purpose) or {}).get("country") or "ID"),
        }
        for purpose in PURPOSES
    }
    largest = max((int(row.get("id") or 0) for row in data["providers"]), default=0)
    data["next_id"] = max(largest + 1, int(data.get("next_id") or 1))
    data["version"] = 1
    return data


def _write(data: dict[str, Any]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, data)


def _country(value: Any) -> str:
    text = re.sub(r"[^A-Za-z]", "", str(value or "")).upper()
    return text[:2] if len(text) >= 2 else "ID"


def _mask_url(raw: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(raw or ""))
        if parsed.username or parsed.password:
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            return urllib.parse.urlunsplit((parsed.scheme, f"***:***@{host}{port}", parsed.path, parsed.query, parsed.fragment))
    except Exception:
        pass
    return str(raw or "")


def _public_provider(provider: dict[str, Any]) -> dict[str, Any]:
    clean = {key: value for key, value in provider.items() if key != "password"}
    clean["password_configured"] = bool(str(provider.get("password") or ""))
    try:
        clean["preview"] = _mask_url(build_proxy_url(provider, "ID", "preview", 0))
    except Exception:
        clean["preview"] = ""
    return clean


def public_state() -> dict[str, Any]:
    with _LOCK:
        data = _read()
        return {
            "providers": [_public_provider(row) for row in data["providers"]],
            "bindings": data["bindings"],
            "path": str(_path()),
        }


def _normalize_provider(data: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, Any]:
    current = current or {}
    name = str(data.get("name") or current.get("name") or "").strip()
    if not name:
        raise ValueError("代理服务商名称不能为空")
    kind = str(data.get("kind") or current.get("kind") or "custom").strip().lower()
    if kind not in KINDS:
        kind = "custom"
    scheme = str(data.get("scheme") or current.get("scheme") or "http").strip().lower()
    if scheme not in SCHEMES:
        raise ValueError("代理协议只支持 HTTP、HTTPS 或 SOCKS5")
    host = str(data.get("host") if "host" in data else current.get("host") or "").strip()
    try:
        port = int(data.get("port") if "port" in data else current.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    url_templates = str(data.get("url_templates") if "url_templates" in data else current.get("url_templates") or "").strip()
    if not url_templates and (not host or not 1 <= port <= 65535):
        raise ValueError("请填写代理主机和端口，或填写代理 URL 模板")
    clear_password = bool(data.get("clear_password"))
    incoming_password = str(data.get("password") or "")
    password = "" if clear_password else incoming_password or str(current.get("password") or "")
    ttl = int(data.get("ttl_minutes") or current.get("ttl_minutes") or 30)
    return {
        "id": int(current.get("id") or 0),
        "name": name,
        "kind": kind,
        "enabled": bool(data.get("enabled", current.get("enabled", True))),
        "scheme": scheme,
        "host": host,
        "port": port,
        "username": str(data.get("username") if "username" in data else current.get("username") or "").strip(),
        "username_template": str(data.get("username_template") if "username_template" in data else current.get("username_template") or "").strip(),
        "password": password,
        "password_template": str(data.get("password_template") if "password_template" in data else current.get("password_template") or "").strip(),
        "url_templates": url_templates,
        "ttl_minutes": max(1, min(1440, ttl)),
        "created_at": str(current.get("created_at") or _now()),
        "updated_at": _now(),
    }


def save_provider(payload: dict[str, Any], provider_id: int = 0) -> dict[str, Any]:
    with _LOCK:
        data = _read()
        current = next((row for row in data["providers"] if int(row.get("id") or 0) == int(provider_id or 0)), None)
        if provider_id and current is None:
            raise ValueError("代理服务商不存在")
        provider = _normalize_provider(payload, current)
        duplicate = next(
            (row for row in data["providers"] if str(row.get("name") or "").lower() == provider["name"].lower() and int(row.get("id") or 0) != int(provider_id or 0)),
            None,
        )
        if duplicate:
            raise ValueError("代理服务商名称已存在")
        if current is None:
            provider["id"] = int(data["next_id"])
            data["next_id"] = provider["id"] + 1
            data["providers"].append(provider)
        else:
            data["providers"] = [provider if int(row.get("id") or 0) == provider["id"] else row for row in data["providers"]]
        _write(data)
        return _public_provider(provider)


def delete_provider(provider_id: int) -> bool:
    with _LOCK:
        data = _read()
        provider_id = int(provider_id or 0)
        if any(binding.get("enabled") and int(binding.get("provider_id") or 0) == provider_id for binding in data["bindings"].values()):
            raise ValueError("该代理服务商仍被业务绑定使用")
        before = len(data["providers"])
        data["providers"] = [row for row in data["providers"] if int(row.get("id") or 0) != provider_id]
        if len(data["providers"]) == before:
            raise ValueError("代理服务商不存在")
        _write(data)
        return True


def save_bindings(payload: Any) -> dict[str, Any]:
    rows = payload if isinstance(payload, list) else []
    with _LOCK:
        data = _read()
        providers = {int(row.get("id") or 0): row for row in data["providers"]}
        for row in rows:
            if not isinstance(row, dict):
                continue
            purpose = str(row.get("purpose") or "").strip().lower()
            if purpose not in PURPOSES:
                raise ValueError(f"未知代理用途: {purpose}")
            enabled = bool(row.get("enabled"))
            provider_id = int(row.get("provider_id") or 0)
            if enabled and (provider_id not in providers or not providers[provider_id].get("enabled")):
                raise ValueError(f"{purpose} 未选择已启用的代理服务商")
            data["bindings"][purpose] = {
                "enabled": enabled,
                "provider_id": provider_id,
                "country": _country(row.get("country") or "ID"),
            }
        _write(data)
        return data["bindings"]


def new_session_id() -> str:
    return uuid.uuid4().hex[:12]


def _replace(template: str, provider: dict[str, Any], country: str, session_id: str) -> str:
    ttl = str(int(provider.get("ttl_minutes") or 30))
    values = {
        "{username}": str(provider.get("username") or ""),
        "{password}": str(provider.get("password") or ""),
        "{country}": country,
        "{COUNTRY}": country,
        "{country_lower}": country.lower(),
        "{session}": session_id,
        "{ttl}": ttl,
    }
    result = str(template or "")
    for token, value in values.items():
        result = result.replace(token, value)
    return result


def build_proxy_url(provider: dict[str, Any], country: str, session_id: str, index: int = 0) -> str:
    country = _country(country)
    session_id = re.sub(r"[^A-Za-z0-9_-]", "", str(session_id or "")) or new_session_id()
    templates = [line.strip() for line in str(provider.get("url_templates") or "").splitlines() if line.strip()]
    if templates:
        return normalize_proxy_url(_replace(templates[abs(int(index or 0)) % len(templates)], provider, country, session_id))
    username_template = str(provider.get("username_template") or "")
    password_template = str(provider.get("password_template") or "")
    username = _replace(username_template, provider, country, session_id) if username_template else str(provider.get("username") or "")
    password = _replace(password_template, provider, country, session_id) if password_template else str(provider.get("password") or "")
    scheme = str(provider.get("scheme") or "http").lower()
    host = str(provider.get("host") or "").strip()
    port = int(provider.get("port") or 0)
    auth = ""
    if username:
        auth = urllib.parse.quote(username, safe="-._~")
        if password:
            auth += ":" + urllib.parse.quote(password, safe="-._~")
        auth += "@"
    return f"{scheme}://{auth}{host}:{port}"


def resolve_proxy(
    purpose: str,
    country: str = "ID",
    *,
    session_id: str = "",
    index: int = 0,
    provider_id: int = 0,
) -> dict[str, Any]:
    purpose = str(purpose or "").strip().lower()
    with _LOCK:
        data = _read()
        binding = data["bindings"].get(purpose) or {}
        if not provider_id:
            if not binding.get("enabled"):
                return {}
            provider_id = int(binding.get("provider_id") or 0)
            country = str(binding.get("country") or country)
        provider = next((row for row in data["providers"] if int(row.get("id") or 0) == int(provider_id)), None)
        if provider is None or not provider.get("enabled"):
            return {}
        session_id = session_id or new_session_id()
        url = build_proxy_url(provider, country, session_id, index)
        return {
            "url": url,
            "provider_id": int(provider["id"]),
            "provider_name": str(provider.get("name") or ""),
            "country": _country(country),
            "session_id": session_id,
            "preview": _mask_url(url),
        }
