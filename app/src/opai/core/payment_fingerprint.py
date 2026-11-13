"""Stable browser-style payment fingerprints for GoPay web payment flows."""
from __future__ import annotations

import hashlib
import os
import random
from copy import deepcopy
from typing import Any


_DEFAULT_LOCALE = "id-ID"
_DEFAULT_TIMEZONE = "Asia/Jakarta"

_DESKTOP_VIEWPORTS = [
    {"width": 1366, "height": 768, "device_scale_factor": 1},
    {"width": 1440, "height": 900, "device_scale_factor": 1},
    {"width": 1536, "height": 864, "device_scale_factor": 1},
    {"width": 1600, "height": 900, "device_scale_factor": 1},
    {"width": 1920, "height": 1080, "device_scale_factor": 1},
]

_WINDOWS_PLATFORMS = [
    ("Windows NT 10.0; Win64; x64", '"Windows"'),
    ("Windows NT 10.0; WOW64", '"Windows"'),
]

# 印尼市场常见安卓机的移动指纹（供 OPAI_GOPAY_DEVICE_SIM=mobile 使用）
_MOBILE_VIEWPORTS = [
    {"width": 360, "height": 800, "device_scale_factor": 3},
    {"width": 393, "height": 873, "device_scale_factor": 2.75},
    {"width": 412, "height": 915, "device_scale_factor": 2.625},
    {"width": 360, "height": 780, "device_scale_factor": 3},
    {"width": 412, "height": 914, "device_scale_factor": 3},
]

_ANDROID_PLATFORMS = [
    # (android_ua_token, sec_ch_ua_platform, build)
    ("Linux; Android 12; SM-A536E Build/SP1A.210812.016", '"Android"'),
    ("Linux; Android 13; SM-A346E Build/TP1A.220624.014", '"Android"'),
    ("Linux; Android 13; 2201117TY Build/TKQ1.220829.002", '"Android"'),
    ("Linux; Android 13; CPH2565 Build/TP1A.220624.014", '"Android"'),
    ("Linux; Android 14; 23053RN02A Build/UP1A.231005.007", '"Android"'),
]


def _desired_device() -> str:
    """模拟设备形态：OPAI_GOPAY_DEVICE_SIM=mobile -> 手机，否则桌面。"""
    value = str(os.environ.get("OPAI_GOPAY_DEVICE_SIM") or "").strip().lower()
    return "mobile" if value in {"mobile", "android", "phone"} else "desktop"


def _seed_from_parts(*parts: str) -> str:
    material = "|".join(str(part or "") for part in parts if str(part or ""))
    return material or "gopay-payment-profile"


def _profile_id(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def build_payment_fingerprint(*, seed: str = "", phone: str = "", local: str = "", account_id: str = "", device: str = "") -> dict[str, Any]:
    """Build one deterministic payment fingerprint from stable account data.

    device 可选 "mobile" / "desktop"；缺省读取 OPAI_GOPAY_DEVICE_SIM 环境变量。
    mobile = Android 手机 Chrome（供 OPAI_GOPAY_DEVICE_SIM=mobile 使用）。
    """
    device_mode = device.strip().lower() if str(device or "").strip() else _desired_device()
    if device_mode not in {"mobile", "desktop"}:
        device_mode = "desktop"
    seed_value = _seed_from_parts(device_mode, seed, account_id, phone, local)
    rng = random.Random(seed_value)
    chrome_major = rng.choice([120, 121, 122, 123, 124])
    sec_ch_ua = f'"Not_A Brand";v="8", "Chromium";v="{chrome_major}", "Google Chrome";v="{chrome_major}"'

    if device_mode == "mobile":
        platform_token, sec_ch_platform = rng.choice(_ANDROID_PLATFORMS)
        viewport = deepcopy(rng.choice(_MOBILE_VIEWPORTS))
        user_agent = (
            f"Mozilla/5.0 ({platform_token}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Mobile Safari/537.36"
        )
        sec_ch_ua_mobile = "?1"
    else:
        platform_token, sec_ch_platform = rng.choice(_WINDOWS_PLATFORMS)
        viewport = deepcopy(rng.choice(_DESKTOP_VIEWPORTS))
        user_agent = (
            f"Mozilla/5.0 ({platform_token}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chrome_major}.0.0.0 Safari/537.36"
        )
        sec_ch_ua_mobile = "?0"

    return {
        "version": 2,
        "device": device_mode,
        "profile_id": _profile_id(seed_value),
        "user_agent": user_agent,
        "locale": _DEFAULT_LOCALE,
        "timezone": _DEFAULT_TIMEZONE,
        "viewport": viewport,
        "sec_ch_ua": sec_ch_ua,
        "sec_ch_ua_mobile": sec_ch_ua_mobile,
        "sec_ch_ua_platform": sec_ch_platform,
    }


def normalize_payment_fingerprint(profile: dict[str, Any] | None, **seed_parts: str) -> dict[str, Any]:
    """Return a complete profile, preserving valid saved values when present.

    当 OPAI_GOPAY_DEVICE_SIM 期望的设备形态与已保存指纹不一致时，重建指纹
    （新的 profile_id），避免"桌面指纹 + 移动头"这类自相矛盾被风控识别。
    """
    fallback = build_payment_fingerprint(**seed_parts)
    desired_device = str(fallback.get("device") or "desktop")
    if not isinstance(profile, dict) or str(profile.get("device") or "") != desired_device:
        return fallback

    normalized = deepcopy(fallback)
    for key in (
        "version",
        "device",
        "profile_id",
        "user_agent",
        "locale",
        "timezone",
        "sec_ch_ua",
        "sec_ch_ua_mobile",
        "sec_ch_ua_platform",
    ):
        value = profile.get(key)
        if value not in (None, ""):
            normalized[key] = value

    viewport = profile.get("viewport")
    if isinstance(viewport, dict):
        merged_viewport = deepcopy(fallback["viewport"])
        for key in ("width", "height", "device_scale_factor"):
            value = viewport.get(key)
            if value not in (None, ""):
                try:
                    merged_viewport[key] = int(value)
                except (TypeError, ValueError):
                    try:
                        merged_viewport[key] = float(value)
                    except (TypeError, ValueError):
                        pass
        normalized["viewport"] = merged_viewport

    return normalized


def ensure_account_payment_fingerprint(account: dict[str, Any]) -> dict[str, Any]:
    """Ensure an account dict carries exactly one reusable payment fingerprint."""
    profile = normalize_payment_fingerprint(
        account.get("payment_fingerprint"),
        phone=str(account.get("phone", "")),
        local=str(account.get("local", "")),
        account_id=str(account.get("account_id") or account.get("customer_id") or ""),
    )
    account["payment_fingerprint"] = profile
    return profile


def payment_fingerprint_headers(profile: dict[str, Any] | None) -> dict[str, str]:
    """Map a payment fingerprint to reusable browser request headers."""
    fp = normalize_payment_fingerprint(profile)
    viewport = fp.get("viewport") or {}
    width = str(viewport.get("width") or "")
    dpr = str(viewport.get("device_scale_factor") or "")
    locale = str(fp.get("locale") or _DEFAULT_LOCALE)
    timezone = str(fp.get("timezone") or _DEFAULT_TIMEZONE)

    headers = {
        "User-Agent": str(fp.get("user_agent") or ""),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Accept-Language": f"{locale},{locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7",
        "Sec-CH-UA": str(fp.get("sec_ch_ua") or ""),
        "Sec-CH-UA-Mobile": str(fp.get("sec_ch_ua_mobile") or "?0"),
        "Sec-CH-UA-Platform": str(fp.get("sec_ch_ua_platform") or '"Windows"'),
        "X-Timezone": timezone,
        "X-User-Locale": locale.replace("-", "_"),
    }
    if width:
        headers["Viewport-Width"] = width
        headers["Sec-CH-Viewport-Width"] = width
    if dpr:
        headers["DPR"] = dpr
        headers["Sec-CH-DPR"] = dpr
    return headers
