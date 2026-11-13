from pathlib import Path

import gopay.server as gopay_server
from opai.core import payment_inbox
from opai.core.gopay_payment_protocol import GoPayPayment


CAPTCHA_BODY = {"error_messages": ["Missing X-Captcha-Token header"]}
CAPTCHA_DETAIL = "Midtrans 要求人机验证，请在浏览器打开原 Midtrans 链接，完成人机验证后按页面继续支付"
MIDTRANS_URL = "https://app.midtrans.com/snap/v4/redirection/11111111-2222-3333-4444-555555555555"


def test_payment_protocol_classifies_captcha_requirement():
    payment = GoPayPayment()
    payment._midtrans_post = lambda *args, **kwargs: {"status": 401, "body": CAPTCHA_BODY}
    result = payment.pay(MIDTRANS_URL, "8123456789", "62", "123456", midtrans_client_key="fixture-client-key")
    assert result["success"] is False
    assert result["detail"] == "linking requires a current-session CAPTCHA token"
    assert result["captcha_required"] is True
    assert result["captcha_challenge"]["website_url"] == MIDTRANS_URL


def test_captcha_failure_gets_actionable_label():
    raw = "linking failed: 401 { error_messages: [Missing X-Captcha-Token header]}"
    assert payment_inbox._payment_failure_label(raw) == CAPTCHA_DETAIL


def test_batch_treats_captcha_as_link_terminal():
    assert gopay_server._is_link_terminal_failure("Missing X-Captcha-Token header") is True
    assert gopay_server._short_failure_label("Missing X-Captcha-Token header") == "需要人机验证"


def test_payment_ui_offers_official_verification_link():
    html = Path("gopay/index.html").read_text(encoding="utf-8")
    assert "打开官方验证页" in html
    assert "needsCaptcha" in html
