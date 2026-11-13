"""
GoPay 2.8.0 / GoTo-Gojek enhanced signing helper.

Verified against the latest Burp capture:
  - /goto-auth/login/methods X-E1 first segment: MATCH

Canonical form:
  {x-apptype};{x-phonemodel}:{bearer};{x-uniqueid}:;{md5(body)}:{host+path};
  {method}:{ts};{x-deviceos}:{x-appversion};{x-m1}:{x-appid};
  {nonce}:{x-phonemake};{x-platform}

Usage:
    from opai.core.gopay_signer_v2 import sign_v2

    result = sign_v2(
        token="Bearer eyJ...",
        timestamp_ms="1778088988941",
        url="customer.gopayapi.com/v1/linkedapps",
        method="GET",
    )
    # result["X-E1"], result["X-E2"]
"""
import hashlib
import hmac as hmac_mod
import json
import os
from pathlib import Path
import subprocess
import sys
import time

_DEFAULT_KEY = b"4&G6DbV&j8QZs~{)(Ila_w_|v@aqJq]E-;*(J9PanZ8sm01kTi{X<iG``]d7P&L"

# GoPay 2.8.0 / GoTo enhanced signing static signature id for
# accounts.goto-products.com and api.gojekapi.com captures.
_V2_ID = "ED9A2B38749FBDE9ACA61D6A685B7"


def _native_env_suffix(version: str) -> str:
    return "".join(char for char in str(version or "") if char.isdigit())


def _native_setting(name: str, version: str) -> str:
    suffix = _native_env_suffix(version)
    if suffix:
        value = str(os.environ.get(f"{name}_{suffix}") or "").strip()
        if value:
            return value
    native_version = (
        os.environ.get("OPAI_GOPAY_NATIVE_VERSION", "2.16.1").strip() or "2.16.1"
    )
    if str(version or "").strip() == native_version:
        return str(os.environ.get(name) or "").strip()
    return ""


def _native_signer_enabled(version: str) -> bool:
    enabled = os.environ.get("OPAI_GOPAY_NATIVE_SIGNER", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return enabled and bool(_native_setting("OPAI_GOPAY_NATIVE_LIBRARY", version))


def _native_sign(payload: dict) -> dict:
    version = str(payload.get("version") or "").strip()
    library = _native_setting("OPAI_GOPAY_NATIVE_LIBRARY", version)
    if not library:
        raise RuntimeError(f"native signer library is required for GoPay {version or 'unknown'}")
    helper = Path(__file__).with_name("gopay_native_signer.py")
    env = os.environ.copy()
    library_dir = _native_setting("OPAI_GOPAY_NATIVE_LIBDIR", version)
    if library_dir:
        current = str(env.get("LD_LIBRARY_PATH") or "").strip()
        env["LD_LIBRARY_PATH"] = library_dir if not current else f"{library_dir}{os.pathsep}{current}"
    shim = _native_setting("OPAI_GOPAY_NATIVE_SHIM", version)
    if shim:
        current = str(env.get("LD_PRELOAD") or "").strip()
        env["LD_PRELOAD"] = shim if not current else f"{shim} {current}"

    timeout = max(1.0, float(env.get("OPAI_GOPAY_NATIVE_TIMEOUT", "15") or "15"))
    completed = subprocess.run(
        [sys.executable, str(helper), "--library", library],
        input=json.dumps(payload, separators=(",", ":")),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "native signer failed").strip()
        raise RuntimeError(f"native signer process failed ({completed.returncode}): {detail[:300]}")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("native signer process returned no output")
    try:
        result = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise RuntimeError("native signer process returned invalid JSON") from exc
    if not result.get("X-E1") or not result.get("X-E2"):
        raise RuntimeError("native signer process returned incomplete headers")
    return result


def sign_v2(
    token: str = "",
    timestamp_ms: str = None,
    url: str = "",
    method: str = "GET",
    body: str = "",
    d1: str = "",
    model: str = "Xiaomi, MI 9",
    xm1: str = "",
    os_info: str = "Android,13",
    appid: str = "com.gojek.gopay",
    version: str = "2.8.0",
    adjts: str = "D",
    uniqueid: str = "",
    hmac_key: bytes = None,
    nonce_hex: str = None,
    phone_make: str = "Google",
    os_name: str = "Android",
) -> dict:
    """Sign a GoPay API request using the V2 algorithm.

    Returns dict with X-E1, X-E2, and debug fields (_hmac, _message).
    """
    if timestamp_ms is None:
        timestamp_ms = str(int(time.time() * 1000))

    if _native_signer_enabled(version):
        return _native_sign(
            {
                "token": token,
                "timestamp_ms": timestamp_ms,
                "url": url,
                "method": method,
                "body": body,
                "d1": d1,
                "model": model,
                "xm1": xm1,
                "os_info": os_info,
                "appid": appid,
                "version": version,
                "adjts": adjts,
                "uniqueid": uniqueid,
                "phone_make": phone_make,
                "os_name": os_name,
            }
        )

    if token.startswith("Bearer "):
        token = token[7:]

    # The upstream signing protocol mandates MD5; this digest is not used for password security.
    body_hash = hashlib.md5(body.encode("utf-8"), usedforsecurity=False).hexdigest()

    if nonce_hex is None:
        nonce_hex = os.urandom(80).hex()

    if hmac_key is None:
        hmac_key = _DEFAULT_KEY

    message = (
        f"GOPAY;"
        f"{model}:{token};"
        f"{uniqueid}:;"
        f"{body_hash}:{url};"
        f"{method.upper()}:{timestamp_ms};"
        f"{os_info}:{version};"
        f"{xm1}:{appid};"
        f"{nonce_hex}:{phone_make};"
        f"{os_name}"
    )

    hmac_hex = hmac_mod.new(
        hmac_key, message.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    x_e1 = f"{hmac_hex}:{nonce_hex}:{adjts}:{timestamp_ms}"

    return {
        "X-E1": x_e1,
        "X-E2": _V2_ID,
        "_hmac": hmac_hex,
        "_message": message,
        "_body_hash": body_hash,
    }
