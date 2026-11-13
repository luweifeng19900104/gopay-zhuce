"""Isolated GoPay 2.16.1 native enhanced signer."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path


DYNAMIC_ENCODE_SELECTOR = 0x9D2C3F9511A63B5D
DEFAULT_DYNAMIC_STATE_VALUES = (
    b"4&G6DbV&j8QZs~{)(Ila_w_|v@aqJq]E-;*(J9PanZ8sm01kTi{X<iG``]d7P&L",
    b"ED9A2B38749FBDE9ACA61D6A685B7",
    b"ZQyB45aUcFG6hYTHfqdtSw==",
)


@dataclass(frozen=True)
class CodecProfile:
    xor_value: int
    rotation: int
    key: str


@dataclass(frozen=True)
class NativeLibraryProfile:
    sha256: str
    device_state_pointer_offset: int
    device_state_ready_offset: int
    dynamic_state_pointer_offset: int
    dynamic_state_values: tuple[bytes, bytes, bytes] = DEFAULT_DYNAMIC_STATE_VALUES


NATIVE_LIBRARY_PROFILES = {
    "2.16.1": NativeLibraryProfile(
        sha256="11deb88cdb1c2bd8708a8f4b09806d3ea01d60cd5735171de689d914b0b5a9d9",
        device_state_pointer_offset=0xA1148,
        device_state_ready_offset=0xA1150,
        dynamic_state_pointer_offset=0xA1338,
    ),
    "2.22.1": NativeLibraryProfile(
        sha256="36827105eb05a09dd79f41215224f91fc3bdc1aaf783e977756c4f1cfac255d5",
        device_state_pointer_offset=0xA8508,
        device_state_ready_offset=0xA8510,
        dynamic_state_pointer_offset=0xA86F8,
    ),
}


STATIC_PROFILE = CodecProfile(0x5A, 3, "H=Gq4[Ofjy39~y{")
DYNAMIC_PROFILE = CodecProfile(0xA5, 7, "9~uv=sQ0Bl){vw/")


def _stream_cipher(value: bytes, key: str) -> bytes:
    state = sum(ord(char) for char in key) % 0xFFFFFFFF
    output = bytearray()
    for byte in value:
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        output.append(byte ^ ((state >> 16) & 0xFF))
    return bytes(output)


def encode_envelope(payload: str, profile: CodecProfile, salt_bytes: bytes | None = None) -> str:
    raw = payload.encode("utf-8")
    scrambled = "".join(chr(byte ^ profile.xor_value) for byte in raw)
    offset = profile.rotation % len(scrambled) if scrambled else 0
    rotated = scrambled[offset:] + scrambled[:offset]
    inner = base64.b64encode(rotated.encode("utf-8")).decode("ascii")
    salt = base64.b64encode(salt_bytes or os.urandom(8)).decode("ascii")
    encrypted = base64.b64encode(
        _stream_cipher(inner.encode("ascii"), salt + profile.key)
    ).decode("ascii")
    checksum = sum(encrypted.encode("ascii")) & 0xFF
    return base64.b64encode(f"{salt}:{encrypted}:{checksum:02x}".encode("ascii")).decode("ascii")


def encode_response_envelope(
    payload: str, profile: CodecProfile, salt_bytes: bytes | None = None
) -> str:
    """Build the native-to-Dart response envelope used by decoder tests."""
    salt = base64.b64encode(salt_bytes or os.urandom(8)).decode("ascii")
    encrypted = base64.b64encode(
        _stream_cipher(payload.encode("utf-8"), salt + profile.key)
    ).decode("ascii")
    checksum = sum(encrypted.encode("ascii")) & 0xFF
    frame = f"{salt}:{encrypted}:{checksum:02x}".encode("utf-8")
    scrambled = "".join(chr(byte ^ profile.xor_value) for byte in frame)
    offset = profile.rotation % len(scrambled) if scrambled else 0
    rotated = scrambled[offset:] + scrambled[:offset]
    return base64.b64encode(bytes(ord(char) for char in rotated)).decode("ascii")


def decode_envelope(value: str, profile: CodecProfile) -> str:
    decoded = base64.b64decode(value)
    scrambled = "".join(chr(byte) for byte in decoded)
    offset = profile.rotation % len(scrambled) if scrambled else 0
    rotated = scrambled[-offset:] + scrambled[:-offset] if offset else scrambled
    frame = bytes(ord(char) ^ profile.xor_value for char in rotated).decode("utf-8")
    parts = frame.split(":")
    if len(parts) < 3:
        raise ValueError(f"invalid native response frame: {len(parts)} parts")
    salt = parts[0]
    encrypted = ":".join(parts[1:-1])
    expected = int(parts[-1], 16)
    actual = sum(encrypted.encode("ascii")) & 0xFF
    if actual != expected:
        raise ValueError(f"native response checksum mismatch: {actual:02x} != {expected:02x}")
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", encrypted)
    cleaned += "=" * (-len(cleaned) % 4)
    return _stream_cipher(base64.b64decode(cleaned), salt + profile.key).decode("utf-8")


def _escaped(value: str) -> str:
    return json.dumps(str(value or ""), ensure_ascii=False)[1:-1]


def build_support_payload(data: dict) -> str:
    token = str(data.get("token") or "")
    if token and not token.startswith("Bearer "):
        token = f"Bearer {token}"
    values = (
        ("supportPulsa", token),
        ("supportDataPackage", str(data.get("timestamp_ms") or "")),
        ("supportPlnToken", str(data.get("url") or "")),
        ("supportEMoney", str(data.get("method") or "GET").upper()),
        ("supportPln", str(data.get("body") or "")),
        ("supportPdam", str(data.get("d1") or "")),
        ("supportBpjs", str(data.get("model") or "")),
        ("supportInternetCable", str(data.get("xm1") or "")),
        ("supportPhonePostPaid", str(data.get("os_info") or "")),
        ("supportMultifinance", str(data.get("appid") or "")),
        ("supportEInvoicing", str(data.get("version") or "")),
        ("supportEducation", str(data.get("adjts") or "D")),
        ("supportInsurance", str(data.get("uniqueid") or "")),
    )
    parts = []
    for index, (name, value) in enumerate(values):
        separator = "" if index == 0 else ("," if index >= 11 else ", ")
        parts.append(f'{separator}"{name}": "{_escaped(value)}"')
    return "{" + "".join(parts) + "}"


def _library_base(library_path: Path) -> int:
    resolved = str(library_path.resolve())
    with open("/proc/self/maps", encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) < 6 or parts[2] != "00000000":
                continue
            mapped = parts[-1].removesuffix(" (deleted)")
            if mapped == resolved or os.path.basename(mapped) == library_path.name:
                return int(parts[0].split("-", 1)[0], 16)
    raise RuntimeError("native signer library base not found")


def _verify_library(library_path: Path, expected_sha256: str) -> None:
    if os.environ.get("OPAI_GOPAY_NATIVE_ALLOW_UNVERIFIED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }:
        return
    digest = hashlib.sha256(library_path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise RuntimeError(f"unsupported native signer library sha256: {digest}")


def _write_cpp_string(target, offset: int, value: bytes, keepalive: list) -> None:
    if len(value) <= 22:
        target[offset] = len(value) << 1
        for index, byte in enumerate(value):
            target[offset + 1 + index] = byte
        return
    buffer = ctypes.create_string_buffer(value + b"\0")
    keepalive.append(buffer)
    ctypes.c_uint64.from_buffer(target, offset).value = ((len(value) + 15) // 16 * 16) | 1
    ctypes.c_uint64.from_buffer(target, offset + 8).value = len(value)
    ctypes.c_uint64.from_buffer(target, offset + 16).value = ctypes.addressof(buffer)


def _install_device_state(base: int, data: dict, profile: NativeLibraryProfile):
    model = str(data.get("model") or "Unknown")
    phone_make = str(data.get("phone_make") or "").strip()
    if not phone_make:
        phone_make = model.split(",", 1)[0].strip() or "Unknown"
    values = (
        model,
        str(data.get("os_info") or "Unknown"),
        str(data.get("uniqueid") or "Unknown"),
        "GOPAY",
        str(data.get("version") or "Unknown"),
        str(data.get("appid") or "Unknown"),
        phone_make,
        str(data.get("os_name") or "Android"),
    )
    encoded = [value.encode("utf-8") for value in values]
    buffers = [ctypes.create_string_buffer(value + b"\0") for value in encoded]
    state = (ctypes.c_ubyte * 0xB0)()
    for index, (value, buffer) in enumerate(zip(encoded, buffers)):
        offset = index * 0x10
        ctypes.c_void_p.from_buffer(state, offset).value = ctypes.addressof(buffer)
        ctypes.c_uint64.from_buffer(state, offset + 8).value = len(value)
    state[0x80] = 1
    ctypes.c_void_p.from_address(
        base + profile.device_state_pointer_offset
    ).value = ctypes.addressof(state)
    ctypes.c_ubyte.from_address(base + profile.device_state_ready_offset).value = 1
    return state, buffers


def _install_dynamic_state(base: int, profile: NativeLibraryProfile):
    state = (ctypes.c_ubyte * 0x48)()
    keepalive = []
    for index, value in enumerate(profile.dynamic_state_values):
        _write_cpp_string(state, index * 0x18, value, keepalive)
    ctypes.c_void_p.from_address(
        base + profile.dynamic_state_pointer_offset
    ).value = ctypes.addressof(state)
    return state, keepalive


def native_sign(data: dict, library_path: Path) -> dict:
    version = str(data.get("version") or "")
    allow_mismatch = os.environ.get(
        "OPAI_GOPAY_NATIVE_ALLOW_VERSION_MISMATCH", ""
    ).strip().lower() in {"1", "true", "yes"}
    profile = NATIVE_LIBRARY_PROFILES.get(version)
    if profile is None:
        if not allow_mismatch:
            supported = ", ".join(sorted(NATIVE_LIBRARY_PROFILES))
            raise RuntimeError(
                f"native signer requires GoPay {supported}, got {version or 'empty'}"
            )
        profile = NATIVE_LIBRARY_PROFILES["2.16.1"]

    _verify_library(library_path, profile.sha256)
    shim = str(os.environ.get("OPAI_GOPAY_NATIVE_SHIM") or "").strip()
    if shim:
        ctypes.CDLL(shim, mode=ctypes.RTLD_GLOBAL)
    library = ctypes.CDLL(str(library_path), mode=ctypes.RTLD_GLOBAL)
    base = _library_base(library_path)
    device_state = _install_device_state(base, data, profile)
    dynamic_state = _install_dynamic_state(base, profile)

    payload = build_support_payload(data)
    encoded = encode_envelope(payload, STATIC_PROFILE)
    function = library.JNI_android_DrawableStateChange
    function.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    function.restype = ctypes.c_void_p
    pointer = function(DYNAMIC_ENCODE_SELECTOR, encoded.encode("ascii"))
    if not pointer:
        raise RuntimeError("native signer returned nullptr")
    raw = ctypes.string_at(pointer).decode("utf-8", errors="strict")
    if raw.startswith("error:"):
        raise RuntimeError(f"native signer failed: {raw[:120]}")

    decoded = json.loads(decode_envelope(raw, DYNAMIC_PROFILE))
    x_e1 = decoded.get("ext")
    x_e2 = decoded.get("resolution")
    if not isinstance(x_e1, str) or not x_e1:
        raise RuntimeError("native signer response is missing ext")
    if not isinstance(x_e2, str) or not x_e2:
        raise RuntimeError("native signer response is missing resolution")
    _ = (device_state, dynamic_state)
    return {
        "X-E1": x_e1,
        "X-E2": x_e2,
        "_resolution_code": int(decoded.get("resolution_code") or 0),
        "_native": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True)
    args = parser.parse_args()
    data = json.load(os.fdopen(os.dup(0), "r", encoding="utf-8"))
    if not data.get("timestamp_ms"):
        data["timestamp_ms"] = str(int(time.time() * 1000))
    result = native_sign(data, Path(args.library))
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
