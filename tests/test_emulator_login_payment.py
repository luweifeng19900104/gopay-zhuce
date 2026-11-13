from types import SimpleNamespace

from opai.core import gopay_emulator_payment as emulator


LOGIN_XML = '''<?xml version="1.0"?><hierarchy>
<node text="Masuk atau daftar" content-desc="" class="android.widget.TextView" clickable="false" enabled="true" bounds="[0,0][100,30]" />
<node text="" content-desc="Nomor HP" class="android.widget.EditText" editable="true" clickable="true" enabled="true" bounds="[10,50][300,100]" />
<node text="Lanjut" content-desc="" class="android.widget.Button" clickable="true" enabled="true" bounds="[10,110][300,160]" />
</hierarchy>'''


def _payment_with_ui(xml):
    payment = object.__new__(emulator.GoPayEmulatorPayment)
    commands = []
    taps = []

    payment._dump_ui = lambda: xml
    payment._run = lambda *args, **kwargs: (commands.append(args) or SimpleNamespace(returncode=0))
    payment._tap_center = lambda node: (taps.append(node) or True)
    return payment, commands, taps


def test_login_phone_is_entered_then_submitted():
    payment, commands, taps = _payment_with_ui(LOGIN_XML)
    state = {"tapped": {}}
    messages = []

    first = payment._automate_gopay("628123456789", "62", "123456", None, messages.append, state)
    second = payment._automate_gopay("628123456789", "62", "123456", None, messages.append, state)

    assert first == "login_phone"
    assert second == "login_submit"
    assert ("shell", "input", "text", "8123456789") in commands
    assert len(taps) >= 2
    assert state["login_active"] is True


def test_otp_is_handled_before_persistent_login_heading():
    xml = '''<hierarchy>
    <node text="Masuk" content-desc="" class="android.widget.TextView" clickable="false" bounds="[0,0][10,10]" />
    <node text="Masukkan kode OTP" content-desc="" class="android.widget.TextView" clickable="false" bounds="[0,10][10,20]" />
    </hierarchy>'''
    payment, commands, _ = _payment_with_ui(xml)

    action = payment._automate_gopay(
        "8123456789", "62", "123456", lambda: "654321", None, {"tapped": {}, "login_active": True}
    )

    assert action == "otp"
    assert ("shell", "input", "text", "654321") in commands


def test_completed_login_requests_snap_resume_once():
    payment, _, _ = _payment_with_ui(
        '<hierarchy><node text="Beranda" content-desc="" class="android.widget.TextView" clickable="false" bounds="[0,0][10,10]" /></hierarchy>'
    )
    state = {"tapped": {}, "login_active": True, "login_resumed": False}

    assert payment._automate_gopay("8123456789", "62", "123456", None, None, state) == "login_complete"
    assert state["login_resumed"] is True
    assert payment._automate_gopay("8123456789", "62", "123456", None, None, state) == "none"


def test_login_phone_normalizes_country_prefix_only_once():
    assert emulator._login_phone_number("+62 812-345-6789", "+62") == "8123456789"
    assert emulator._login_phone_number("08123456789", "+62") == "08123456789"


def test_payment_reopens_snap_once_after_login_completion(monkeypatch):
    payment = object.__new__(emulator.GoPayEmulatorPayment)
    payment.proxy = ""
    payment.payment_fingerprint = {}
    payment._timeout = 120
    payment._poll = 2
    payment._emulator_ready = lambda: (True, "emulator online")
    payment._ensure_guest_proxy = lambda progress: None
    opened = []
    payment._open_url = lambda url, progress: opened.append(url)
    actions = iter(["login_complete"])
    payment._ui_automate_round = lambda *args: next(actions, "none")

    class StatusClient:
        def __init__(self, **kwargs):
            self.statuses = iter(["pending", "settlement"])

        def _midtrans_get(self, path):
            return {"body": {"transaction_status": next(self.statuses)}}

    monkeypatch.setattr(emulator, "GoPayPayment", StatusClient)
    monkeypatch.setattr(emulator.time, "sleep", lambda seconds: None)
    url = "https://app.midtrans.com/snap/v4/redirection/3ef4017a-ad63-4b91-b086-30ad91837822"

    result = payment.pay(url, "8123456789", "62", "123456")

    assert result["success"] is True
    assert opened == [url, url]
