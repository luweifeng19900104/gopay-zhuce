import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import gopay.server as gopay_server
from opai.core import payment_inbox


def test_reward_helper_is_imported_by_main_server():
    assert callable(gopay_server._claim_gopay_reward)


def test_inbox_sms_code_requires_auth():
    server = payment_inbox._InboxServer(("127.0.0.1", 0), payment_inbox._InboxHandler)
    server.require_token = "test-secret"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/accounts/628123/sms-code"
        try:
            urllib.request.urlopen(url, timeout=3)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
            assert json.loads(exc.read()) == {"error": "unauthorized"}
        else:
            raise AssertionError("短信验证码接口未执行鉴权")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_poll_imported_sms_code_returns_latest_unseen(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    sms_url = "https://sms.example.test/messages/628123"
    (config / "gopay_phone_pool.json").write_text(
        json.dumps([{"phone": "+62 8123", "sms_url": sms_url}]),
        encoding="utf-8",
    )
    monkeypatch.setattr(payment_inbox, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(payment_inbox, "read_imported_sms_url", lambda url, timeout=8: "旧验证码 1234，新验证码 567890")
    assert payment_inbox._poll_imported_sms_code("628123", {"567890"}) == "1234"
