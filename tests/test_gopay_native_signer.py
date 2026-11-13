import json
import subprocess

from opai.core import gopay_native_signer as native
from opai.core import gopay_signer_v2 as signer


def test_dynamic_envelope_round_trip():
    payload = '{"ext":"signed","resolution":"cipher:iv","resolution_code":0}'
    encoded = native.encode_response_envelope(
        payload,
        native.DYNAMIC_PROFILE,
        salt_bytes=bytes.fromhex("0001020304050607"),
    )
    assert native.decode_envelope(encoded, native.DYNAMIC_PROFILE) == payload


def test_native_library_profiles_cover_phone_change_versions():
    profile_2161 = native.NATIVE_LIBRARY_PROFILES["2.16.1"]
    profile_2221 = native.NATIVE_LIBRARY_PROFILES["2.22.1"]

    assert profile_2161.device_state_pointer_offset == 0xA1148
    assert profile_2161.dynamic_state_pointer_offset == 0xA1338
    assert profile_2221.device_state_pointer_offset == 0xA8508
    assert profile_2221.dynamic_state_pointer_offset == 0xA86F8
    assert profile_2161.dynamic_state_values == profile_2221.dynamic_state_values


def test_support_payload_matches_native_field_order_and_spacing():
    payload = native.build_support_payload(
        {
            "token": "access-token",
            "timestamp_ms": "1787570183196",
            "url": "api.gojekapi.com/v6/customers",
            "method": "patch",
            "body": '{"phone":"+628123"}',
            "d1": "CERT",
            "model": "Xiaomi, Redmi 8",
            "xm1": "line\nvalue",
            "os_info": "Android, 9",
            "appid": "com.gojek.gopay",
            "version": "2.16.1",
            "adjts": "D",
            "uniqueid": "abc123",
        }
    )
    assert payload.startswith('{"supportPulsa": "Bearer access-token", "supportDataPackage": "1787570183196"')
    assert '"supportPln": "{\\"phone\\":\\"+628123\\"}"' in payload
    assert '"supportInternetCable": "line\\nvalue"' in payload
    assert payload.endswith(',"supportEducation": "D","supportInsurance": "abc123"}')


def test_sign_v2_dispatches_to_isolated_native_helper(monkeypatch, tmp_path):
    library = tmp_path / "libbatteryOpt.so"
    library.write_bytes(b"placeholder")
    shim = tmp_path / "android_shim.so"
    shim.write_bytes(b"placeholder")
    libdir = tmp_path / "android-libs"
    libdir.mkdir()
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_SIGNER", "1")
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_LIBRARY", str(library))
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_SHIM", str(shim))
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_LIBDIR", str(libdir))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='{"X-E1":"native-e1","X-E2":"native-e2","_native":true}\n',
            stderr="",
        )

    monkeypatch.setattr(signer.subprocess, "run", fake_run)
    result = signer.sign_v2(
        token="access-token",
        timestamp_ms="1787570183196",
        url="api.gojekapi.com/v6/customers",
        method="PATCH",
        body='{"phone":"+628123"}',
        version="2.16.1",
    )
    assert result["X-E1"] == "native-e1"
    assert result["X-E2"] == "native-e2"
    request = json.loads(captured["input"])
    assert request["token"] == "access-token"
    assert request["url"] == "api.gojekapi.com/v6/customers"
    assert captured["env"]["LD_PRELOAD"].startswith(str(shim))
    assert captured["env"]["LD_LIBRARY_PATH"].startswith(str(libdir))


def test_legacy_signer_remains_available_when_native_is_disabled(monkeypatch):
    monkeypatch.delenv("OPAI_GOPAY_NATIVE_SIGNER", raising=False)
    result = signer.sign_v2(
        token="access-token",
        timestamp_ms="1787570183196",
        url="api.gojekapi.com/v6/customers",
        method="PATCH",
        body='{"phone":"+628123"}',
        nonce_hex="00" * 80,
    )
    assert result["X-E2"] == "ED9A2B38749FBDE9ACA61D6A685B7"
    assert result["X-E1"].endswith(":D:1787570183196")


def test_native_signer_only_handles_configured_app_version(monkeypatch):
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_SIGNER", "1")
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_LIBRARY", "/unused/libbatteryOpt.so")

    def unexpected_run(*_args, **_kwargs):
        raise AssertionError("2.10.0 must keep using the legacy signer")

    monkeypatch.setattr(signer.subprocess, "run", unexpected_run)
    result = signer.sign_v2(
        token="access-token",
        timestamp_ms="1787570183196",
        url="api.gojekapi.com/v6/customers",
        method="PATCH",
        body='{"phone":"+628123"}',
        version="2.10.0",
        nonce_hex="00" * 80,
    )

    assert result["X-E2"] == "ED9A2B38749FBDE9ACA61D6A685B7"


def test_version_specific_native_library_enables_second_app_version(monkeypatch, tmp_path):
    library = tmp_path / "libbatteryOpt-2221.so"
    library.write_bytes(b"placeholder")
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_SIGNER", "1")
    monkeypatch.setenv("OPAI_GOPAY_NATIVE_LIBRARY_2221", str(library))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='{"X-E1":"native-e1","X-E2":"native-e2","_native":true}\n',
            stderr="",
        )

    monkeypatch.setattr(signer.subprocess, "run", fake_run)
    result = signer.sign_v2(version="2.22.1")

    assert result["_native"] is True
    assert captured["command"][-1] == str(library)
    assert json.loads(captured["input"])["version"] == "2.22.1"
