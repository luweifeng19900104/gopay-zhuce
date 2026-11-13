from opai.core import gopay_emulator_payment as emulator


def test_emulator_payment_mode_uses_emulator_auth_by_default(monkeypatch):
    monkeypatch.setenv("OPAI_GOPAY_PAYMENT_MODE", "emulator")
    monkeypatch.delenv("OPAI_GOPAY_AUTH_MODE", raising=False)
    assert emulator.emulator_auth_enabled() is True


def test_emulator_auth_reuses_a_stable_existing_app_session(monkeypatch):
    payment = object.__new__(emulator.GoPayEmulatorPayment)
    payment._timeout = 30
    payment._poll = 1
    payment._emulator_ready = lambda: (True, "emulator online")
    payment._ensure_guest_proxy = lambda progress: None
    payment._open_gopay_app = lambda progress: None
    payment._foreground_package = lambda: "com.gojek.gopay"
    payment._dump_ui = lambda: '<hierarchy><node text="Beranda" content-desc="" class="android.widget.TextView" clickable="false" /></hierarchy>'
    saved = []
    payment._record_session = lambda phone, country: saved.append((phone, country))
    ticks = iter([0.0, 0.0, 1.0, 2.0, 5.0])
    monkeypatch.setattr(emulator.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(emulator.time, "sleep", lambda seconds: None)

    result = payment.authenticate("628123456789", "62", "123456")

    assert result == {"success": True, "detail": "emulator GoPay session ready", "registered": False}
    assert saved == [("628123456789", "62")]
