from pathlib import Path

import gopay.server as server
from opai.core.gopay_browser_payment import browser_payment_enabled
from opai.core.gopay_emulator_payment import (
    emulator_auth_enabled,
    emulator_payment_enabled,
)


ROOT = Path(__file__).resolve().parents[1]


def test_server_forces_protocol_over_inherited_modes(monkeypatch):
    monkeypatch.setenv("OPAI_GOPAY_PAYMENT_MODE", "emulator")
    monkeypatch.setenv("OPAI_GOPAY_AUTH_MODE", "emulator")

    server._force_protocol_runtime()

    assert server.os.environ["OPAI_GOPAY_PAYMENT_MODE"] == "protocol"
    assert server.os.environ["OPAI_GOPAY_AUTH_MODE"] == "protocol"


def test_protocol_disables_emulator_and_browser_selectors():
    server._force_protocol_runtime()

    assert emulator_payment_enabled() is False
    assert emulator_auth_enabled() is False
    assert browser_payment_enabled() is False


def test_both_launchers_force_payment_and_auth_protocol():
    for name in ("start.bat", "启动.bat"):
        text = (ROOT / name).read_text(encoding="utf-8-sig")
        assert 'set "OPAI_GOPAY_PAYMENT_MODE=protocol"' in text
        assert 'set "OPAI_GOPAY_AUTH_MODE=protocol"' in text


def test_runtime_files_are_protocol_only():
    for name in ("runtime.env.example", "runtime.env"):
        text = (ROOT / "config" / name).read_text(encoding="utf-8-sig")
        assert "OPAI_GOPAY_PAYMENT_MODE=protocol" in text
        assert "OPAI_GOPAY_AUTH_MODE=protocol" in text
        assert "OPAI_GOPAY_ADB=" not in text
        assert "OPAI_GOPAY_EMULATOR_" not in text
