from pathlib import Path

import pytest

from opai.core import gopay_browser_payment


def test_browser_mode_is_default_and_protocol_is_opt_in(monkeypatch):
    monkeypatch.delenv("OPAI_GOPAY_PAYMENT_MODE", raising=False)
    assert gopay_browser_payment.browser_payment_enabled() is True
    monkeypatch.setenv("OPAI_GOPAY_PAYMENT_MODE", "protocol")
    assert gopay_browser_payment.browser_payment_enabled() is False


def test_indonesia_exit_is_required_by_default(monkeypatch):
    monkeypatch.delenv("OPAI_GOPAY_BROWSER_REQUIRE_ID", raising=False)
    assert gopay_browser_payment._require_indonesia_exit() is True
    monkeypatch.setenv("OPAI_GOPAY_BROWSER_REQUIRE_ID", "0")
    assert gopay_browser_payment._require_indonesia_exit() is False


def test_launch_options_use_persistent_profile_and_real_chrome(monkeypatch, tmp_path):
    chrome = tmp_path / "chrome.exe"
    chrome.write_bytes(b"fixture")
    monkeypatch.setenv("OPAI_CHROME_PATH", str(chrome))
    monkeypatch.setenv("OPAI_GOPAY_DEVICE_SIM", "desktop")

    options = gopay_browser_payment.build_browser_launch_options(
        payment_fingerprint={
            "profile_id": "acct-123",
            "device": "desktop",
            "locale": "id-ID",
            "timezone": "Asia/Jakarta",
            "viewport": {"width": 1440, "height": 900, "device_scale_factor": 1},
        },
        proxy="socks5://user:pass@127.0.0.1:3000",
        profile_root=tmp_path / "profiles",
    )

    assert Path(options["user_data_dir"]).name == "acct-123"
    assert Path(options["user_data_dir"]).is_dir()
    assert options["executable_path"] == str(chrome.resolve())
    assert options["locale"] == "id-ID"
    assert options["timezone_id"] == "Asia/Jakarta"
    assert options["viewport"] == {"width": 1440, "height": 900}
    assert options["proxy"] == {
        "server": "socks5://127.0.0.1:3000",
        "username": "user",
        "password": "pass",
    }
    assert "user_agent" not in options


def test_unauthenticated_http_proxy_does_not_start_a_bridge():
    direct = gopay_browser_payment._AuthenticatedSocksBridge("http://proxy.test:8080")
    assert direct.start() == "http://proxy.test:8080"
    direct.close()


def test_native_chrome_command_has_stable_profile_proxy_and_no_automation(monkeypatch, tmp_path):
    chrome = tmp_path / "chrome.exe"
    chrome.write_bytes(b"fixture")
    monkeypatch.setenv("OPAI_CHROME_PATH", str(chrome))
    monkeypatch.setenv("OPAI_GOPAY_DEVICE_SIM", "desktop")
    url = "https://app.midtrans.com/snap/v4/redirection/3ef4017a-ad63-4b91-b086-30ad91837822"

    command, child_env = gopay_browser_payment.build_native_chrome_launch(
        midtrans_url=url,
        payment_fingerprint={
            "profile_id": "acct-native",
            "device": "desktop",
            "locale": "id-ID",
            "timezone": "Asia/Jakarta",
            "viewport": {"width": 1366, "height": 768},
        },
        proxy="http://127.0.0.1:19081",
        profile_root=tmp_path / "profiles",
    )

    joined = " ".join(command)
    assert command[0] == str(chrome.resolve())
    assert "--user-data-dir=" in joined
    assert "acct-native" in joined
    assert "--proxy-server=http://127.0.0.1:19081" in command
    assert "--enable-automation" not in joined
    assert "--remote-debugging-port" not in joined
    assert "playwright" not in joined.lower()
    assert command[-1] == url
    assert child_env["TZ"] == "Asia/Jakarta"
    assert child_env["LANG"] == "id_ID.UTF-8"


def test_snap_token_is_extracted_from_redirection_url():
    assert gopay_browser_payment._snap_token(
        "https://app.midtrans.com/snap/v4/redirection/3ef4017a-ad63-4b91-b086-30ad91837822#/gopay-tokenization/linking"
    ) == "3ef4017a-ad63-4b91-b086-30ad91837822"


def test_invalid_browser_timing_env_uses_bounded_default(monkeypatch):
    monkeypatch.setenv("OPAI_TEST_SECONDS", "not-an-int")
    assert gopay_browser_payment._bounded_env_int("OPAI_TEST_SECONDS", 9, 2, 30) == 9
    monkeypatch.setenv("OPAI_TEST_SECONDS", "1")
    assert gopay_browser_payment._bounded_env_int("OPAI_TEST_SECONDS", 9, 2, 30) == 2
    monkeypatch.setenv("OPAI_TEST_SECONDS", "99")
    assert gopay_browser_payment._bounded_env_int("OPAI_TEST_SECONDS", 9, 2, 30) == 30


def test_profile_directory_is_sanitized_and_locked(tmp_path, monkeypatch):
    monkeypatch.setenv("OPAI_GOPAY_DEVICE_SIM", "desktop")
    profile = gopay_browser_payment._profile_directory(
        {"profile_id": "account/../../shared", "device": "desktop"},
        tmp_path,
    )
    assert profile.parent == tmp_path.resolve()
    assert profile.name == "account_______shared"

    first = gopay_browser_payment._ProfileLock(profile)
    second = gopay_browser_payment._ProfileLock(profile)
    first.acquire()
    try:
        with pytest.raises(RuntimeError, match="Chrome 支付会话已在运行"):
            second.acquire()
    finally:
        first.close()
    second.acquire()
    second.close()


def test_ipv6_proxy_server_is_bracketed():
    assert gopay_browser_payment._proxy_settings("socks5://[::1]:1080") == {
        "server": "socks5://[::1]:1080"
    }


def test_bridge_and_profile_lock_are_released_when_chrome_setup_fails(monkeypatch, tmp_path):
    state = {"bridge_closed": False}

    class FakeBridge:
        def __init__(self, raw_proxy):
            assert raw_proxy == "socks5://proxy.test:1080"

        def start(self):
            return "http://127.0.0.1:19081"

        def close(self):
            state["bridge_closed"] = True

    monkeypatch.setattr(gopay_browser_payment, "_AuthenticatedSocksBridge", FakeBridge)
    monkeypatch.setattr(
        gopay_browser_payment,
        "_profile_directory",
        lambda payment_fingerprint=None, profile_root=None: tmp_path / "profile",
    )
    monkeypatch.setattr(
        gopay_browser_payment,
        "build_native_chrome_launch",
        lambda **kwargs: (_ for _ in ()).throw(FileNotFoundError("chrome missing")),
    )

    result = gopay_browser_payment.GoPayBrowserPayment(
        proxy="socks5://proxy.test:1080",
        payment_fingerprint={"profile_id": "cleanup"},
    ).pay(
        "https://app.midtrans.com/snap/v4/redirection/3ef4017a-ad63-4b91-b086-30ad91837822",
        "85861555872",
        "62",
        "123456",
    )

    assert result["success"] is False
    assert "chrome missing" in result["detail"]
    assert state["bridge_closed"] is True
    lock = gopay_browser_payment._ProfileLock(tmp_path / "profile")
    lock.acquire()
    lock.close()
