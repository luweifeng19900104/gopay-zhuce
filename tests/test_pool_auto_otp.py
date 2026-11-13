import http.client
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request

import pytest

from opai.core import payment_inbox as inbox
from opai.core import sms_helpers as sms


def sms8(code=""):
    return json.dumps({
        "code": 0, "msg": "ok",
        "data": {"code": code, "code_time": "", "expired_date": "2026-11-25 00:00:00"},
    })


def manager(monkeypatch, tmp_path, reader=None):
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "gopay_phone_pool.json").write_text(json.dumps([
        {"phone": "+62123456789", "sms_url": "https://sms.example.test/api/record?token=private-fixture"}
    ]), encoding="utf-8")
    monkeypatch.setattr(inbox, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(inbox, "IMPORTED_SMS_POLL_SECONDS", 0.01)
    monkeypatch.setattr(inbox, "read_imported_sms_url", reader or (lambda *a, **kw: sms8()))
    mgr = inbox._ManualRegisterManager()
    job = {
        "id": "fixture", "phone": "+62123456789", "source": "pool",
        "status": "running", "prompt": None, "logs": [], "_otp": [],
        "_otp_hashes_consumed": set(), "_otp_hashes_pending": set(),
    }
    mgr._jobs["fixture"] = job
    mgr._conds["fixture"] = threading.Condition(mgr._lock)
    return mgr, job


def test_sms8_empty_does_not_parse_expiry_year():
    assert sms.extract_imported_sms_codes(sms8()) == []


def test_sms8_reads_data_code_not_api_code_or_expiry():
    assert sms.extract_imported_sms_codes(sms8("314159")) == ["314159"]
    assert sms.extract_imported_sms_codes('{"code":1000,"msg":"no messages"}') == []


def test_sms8_reads_otp_from_message_stored_in_data_code():
    body = json.dumps({
        "code": 1,
        "msg": "ok",
        "data": {
            "code": "(GOJEK) Use OTP 4827 to set up your GoTo PIN. DO NOT SHARE IT.",
            "code_time": "2026-11-06 11:21:08",
            "expired_date": "2026-12-31 00:00:00",
        },
    })
    assert sms.extract_imported_sms_codes(body) == ["4827"]


def test_text_and_json_message_formats():
    assert sms.extract_imported_sms_codes("旧验证码 1234，新验证码 567890") == ["567890", "1234"]
    assert sms.extract_imported_sms_codes("Your OTP is 246810. Valid until 2026-10-06") == ["246810"]
    assert sms.extract_imported_sms_codes('{"data":[{"text":"OTP 123456"},{"text":"OTP 654321"}]}') == ["654321", "123456"]


@pytest.mark.parametrize("purpose", ["signup", "login", "pin"])
def test_pool_otp_auto_submits_all_phases(monkeypatch, tmp_path, purpose):
    mgr, job = manager(monkeypatch, tmp_path)
    mgr._prepare_pool_otp("fixture", job["phone"])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: sms8("314159"))
    assert mgr._wait_otp("fixture", purpose, job["phone"], 2) == "314159"
    assert job["status"] == "running"
    assert job["prompt"] is None
    assert any("自动提交" in row["message"] for row in job["logs"])
    assert "314159" not in json.dumps(mgr.get("fixture"), ensure_ascii=False)
    assert "private-fixture" not in json.dumps(mgr.get("fixture"), ensure_ascii=False)


def test_explicit_pool_sms_url_is_bound_to_the_task(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path)
    selected = "https://sms.example.test/api/record?token=selected-fixture"
    observed = []

    def reader(url, **_kwargs):
        observed.append(url)
        return sms8()

    monkeypatch.setattr(inbox, "read_imported_sms_url", reader)
    mgr._prepare_pool_otp("fixture", job["phone"], sms_url=selected)
    assert observed == [selected]
    public_job = mgr.get("fixture") or {}
    assert public_job.get("message", "").startswith("号码池自动接码已启用")
    logs = json.dumps(job["logs"], ensure_ascii=False)
    assert "sms.example.test/api/record" in logs
    assert "selected-fixture" not in logs


def test_history_and_previous_phase_otp_are_skipped(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path, lambda *a, **kw: sms8("111111"))
    mgr._prepare_pool_otp("fixture", job["phone"])
    replies = iter([sms8("111111"), sms8("222222")])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: next(replies))
    assert mgr._wait_otp("fixture", "signup", job["phone"], 2) == "222222"
    replies = iter([sms8("222222"), sms8("111111"), sms8("333333")])
    assert mgr._wait_otp("fixture", "pin", job["phone"], 2) == "333333"


def test_manual_input_during_slow_poll_and_no_late_submission(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path)
    mgr._prepare_pool_otp("fixture", job["phone"])
    entered, release = threading.Event(), threading.Event()

    def slow_read(*a, **kw):
        entered.set()
        release.wait(3)
        return sms8("999999")

    monkeypatch.setattr(inbox, "read_imported_sms_url", slow_read)
    result = []
    thread = threading.Thread(target=lambda: result.append(mgr._wait_otp("fixture", "signup", job["phone"], 2)))
    thread.start()
    try:
        assert entered.wait(1)
        begin = time.monotonic()
        assert mgr.submit_otp("fixture", "123456") is not None
        thread.join(0.5)
        assert result == ["123456"]
        assert time.monotonic() - begin < 0.5
        release.set()
        time.sleep(0.05)
        assert job["_otp"] == []
        assert sms.sms_code_sha256("999999") not in job["_otp_hashes_consumed"]
    finally:
        release.set()
        thread.join(3)


def test_network_failure_visible_without_url_token_then_recovers(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path)
    mgr._prepare_pool_otp("fixture", job["phone"])
    replies = iter([urllib.error.URLError("https://x/?token=secret-token"), sms8("135790")])

    def reader(*a, **kw):
        response = next(replies)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(inbox, "read_imported_sms_url", reader)
    assert mgr._wait_otp("fixture", "signup", job["phone"], 2) == "135790"
    logs = json.dumps(job["logs"], ensure_ascii=False)
    assert "读取失败" in logs and "已恢复" in logs
    assert "secret-token" not in logs


def test_missing_history_baseline_skips_first_reply(monkeypatch, tmp_path):
    def offline(*a, **kw):
        raise OSError("offline")
    mgr, job = manager(monkeypatch, tmp_path, offline)
    mgr._prepare_pool_otp("fixture", job["phone"])
    replies = iter([sms8("123456"), sms8("654321")])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: next(replies))
    assert mgr._wait_otp("fixture", "signup", job["phone"], 2) == "654321"


def test_pin_manager_uses_imported_phone_pool_url(monkeypatch):
    monkeypatch.setattr(inbox, "IMPORTED_SMS_POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        inbox,
        "_imported_sms_url_for_phone",
        lambda _phone: "https://sms.example.test/api/record?token=private-fixture",
    )
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: sms8("111111"))
    mgr = inbox._PinManager()
    mgr._jobs["pin-fixture"] = {"id": "pin-fixture", "status": "running", "logs": []}

    url, ignored, baseline_ready = mgr._prepare_imported_pin_otp("pin-fixture", "+62123456789")
    replies = iter([sms8("111111"), sms8("222222")])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: next(replies))
    code = mgr._auto_wait_forgot_otp(
        {"activation_id": "manual-login", "sms_activation_status": "unavailable"},
        "pin-fixture",
        "+62123456789",
        timeout_sec=1,
        imported_url=url,
        imported_ignored_hashes=ignored,
        imported_baseline_ready=baseline_ready,
    )

    assert code == "222222"
    logs = json.dumps(mgr._jobs["pin-fixture"]["logs"], ensure_ascii=False)
    assert "号码池短信接口自动获取验证码" in logs
    assert "private-fixture" not in logs


def test_pin_manager_recovers_when_imported_baseline_was_unavailable(monkeypatch):
    monkeypatch.setattr(inbox, "IMPORTED_SMS_POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        inbox,
        "_imported_sms_url_for_phone",
        lambda _phone: "https://sms.example.test/api/record?token=private-fixture",
    )
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: (_ for _ in ()).throw(OSError("offline")))
    mgr = inbox._PinManager()
    mgr._jobs["pin-fixture"] = {"id": "pin-fixture", "status": "running", "logs": []}

    url, ignored, baseline_ready = mgr._prepare_imported_pin_otp("pin-fixture", "+62123456789")
    replies = iter([sms8("333333"), sms8("444444")])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: next(replies))
    code = mgr._auto_wait_forgot_otp(
        {},
        "pin-fixture",
        "+62123456789",
        timeout_sec=1,
        imported_url=url,
        imported_ignored_hashes=ignored,
        imported_baseline_ready=baseline_ready,
    )

    assert code == "444444"
    logs = json.dumps(mgr._jobs["pin-fixture"]["logs"], ensure_ascii=False)
    assert "历史基线已补齐" in logs


def test_empty_response_times_out_without_submitting_date(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path)
    mgr._prepare_pool_otp("fixture", job["phone"])
    assert mgr._wait_otp("fixture", "signup", job["phone"], 1) is None
    assert job["status"] == "failed"
    assert not job["_otp_hashes_consumed"]


def test_cancelled_wait_does_not_submit(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path)
    mgr._prepare_pool_otp("fixture", job["phone"])
    result = []
    thread = threading.Thread(target=lambda: result.append(mgr._wait_otp("fixture", "signup", job["phone"], 2)))
    thread.start()
    try:
        deadline = time.monotonic() + 1
        while job["status"] != "waiting_otp" and time.monotonic() < deadline:
            time.sleep(0.005)
        with mgr._lock:
            job["status"] = "cancelled"
            mgr._conds["fixture"].notify_all()
        thread.join(1)
        assert result == [None]
        assert not job["_otp"]
    finally:
        thread.join(3)


def test_no_pool_url_still_allows_manual_otp(monkeypatch, tmp_path):
    mgr, job = manager(monkeypatch, tmp_path)
    monkeypatch.setattr(inbox, "_imported_sms_url_for_phone", lambda phone: "")
    mgr._prepare_pool_otp("fixture", job["phone"])
    result = []
    thread = threading.Thread(target=lambda: result.append(mgr._wait_otp("fixture", "login", job["phone"], 2)))
    thread.start()
    try:
        deadline = time.monotonic() + 1
        while job["status"] != "waiting_otp" and time.monotonic() < deadline:
            time.sleep(0.005)
        assert mgr.submit_otp("fixture", "654321") is not None
        thread.join(1)
        assert result == ["654321"]
    finally:
        thread.join(3)


def dns_answers(*addresses):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses]


def test_fake_ip_resolves_to_public_ip_without_disabling_validation(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: dns_answers("198.18.0.38"))
    calls = []
    monkeypatch.setattr(sms, "_public_sms_dns", lambda host, **kw: calls.append(host) or ("104.20.21.113",))
    assert sms.validate_imported_sms_url("https://api.sms8.net/api/record?token=private-fixture").startswith("https:")
    assert calls == ["api.sms8.net"]


@pytest.mark.parametrize("addresses", [
    ("127.0.0.1",), ("10.0.0.1",), ("169.254.169.254",),
    ("198.18.0.38", "127.0.0.1"), ("8.8.8.8", "10.1.1.1"),
])
def test_private_and_mixed_dns_still_rejected(monkeypatch, addresses):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: dns_answers(*addresses))
    monkeypatch.setattr(sms, "_public_sms_dns", lambda *a, **kw: pytest.fail("DoH not allowed"))
    with pytest.raises(ValueError, match="本机"):
        sms.validate_imported_sms_url("https://sms.example.test/")


def test_literal_fake_ip_is_not_treated_as_a_hostname(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: dns_answers("198.18.0.38"))
    monkeypatch.setattr(sms, "_public_sms_dns", lambda *a, **kw: pytest.fail("DoH not allowed"))
    with pytest.raises(ValueError, match="本机"):
        sms.validate_imported_sms_url("https://198.18.0.38/")


def test_fake_ip_doh_private_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: dns_answers("198.18.0.38"))
    monkeypatch.setattr(sms, "_public_sms_dns", lambda *a, **kw: ("127.0.0.1",))
    with pytest.raises(ValueError, match="本机"):
        sms.validate_imported_sms_url("https://sms.example.test/")


def test_pinned_socket_uses_verified_numeric_address(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(sms, "_resolve_sms_addresses", lambda *a, **kw: ("104.20.21.113",))
    calls = []
    monkeypatch.setattr(socket, "create_connection", lambda address, **kw: calls.append(address) or sentinel)
    assert sms._connect_sms_socket(("api.sms8.net", 443), 3) is sentinel
    assert calls == [("104.20.21.113", 443)]
    conn = sms._SmsHTTPSConnection("api.sms8.net", timeout=3)
    assert conn.host == "api.sms8.net"
    assert conn._context.verify_mode == ssl.CERT_REQUIRED
    assert conn._context.check_hostname


def test_redirect_to_private_ip_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: dns_answers("127.0.0.1"))
    handler = sms._ValidatedSmsRedirect()
    req = urllib.request.Request("https://sms.example.test/")
    with pytest.raises(ValueError, match="本机"):
        handler.redirect_request(req, None, 302, "Found", {}, "https://127.0.0.1/secret")


def test_old_poll_helper_uses_sms8_fields(monkeypatch, tmp_path):
    manager(monkeypatch, tmp_path)
    assert inbox._poll_imported_sms_code("+62123456789") == ""
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: sms8("456789"))
    assert inbox._poll_imported_sms_code("+62123456789") == "456789"
    assert inbox._poll_imported_sms_code("+62123456789", {"456789"}) == ""


def test_main_server_read_code_uses_same_parser(monkeypatch):
    from gopay import server
    monkeypatch.setattr(server, "_load_gopay_phone_pool", lambda: [
        {"phone": "+62123456789", "sms_url": "https://sms.example.test/"}
    ])
    monkeypatch.setattr(server, "read_imported_sms_url", lambda *a, **kw: sms8())
    assert server._poll_imported_sms_code("+62123456789") == ""
    monkeypatch.setattr(server, "read_imported_sms_url", lambda *a, **kw: sms8("246810"))
    assert server._poll_imported_sms_code("+62123456789") == "246810"


def test_pool_import_updates_sms_url_for_existing_phone(monkeypatch, tmp_path):
    from gopay import server

    path = tmp_path / "gopay_phone_pool.json"
    path.write_text(json.dumps([
        {
            "phone": "+62 8123456789",
            "sms_url": "https://sms.example.test/old",
            "status": "registered",
        }
    ]), encoding="utf-8")
    monkeypatch.setattr(server, "POOL", path)
    monkeypatch.setattr(server, "validate_imported_sms_url", lambda value: value)
    result = server._import_gopay_phone_pool(
        "+628123456789----https://sms.example.test/new?token=fixture"
    )
    rows = json.loads(path.read_text(encoding="utf-8"))
    assert result == {"inserted": 0, "updated": 1, "total": 1}
    assert rows[0]["sms_url"].endswith("/new?token=fixture")
    assert rows[0]["status"] == "available"
    assert rows[0]["account_state"] == "unregistered"


def test_registration_run_wires_auto_reader_without_live_registration(monkeypatch, tmp_path):
    from opai.core import gopay_protocol_worker as worker
    mgr, job = manager(monkeypatch, tmp_path)
    monkeypatch.setattr(worker, "_get_envelope_did", lambda: "")
    observed = []

    def fake_register(**kwargs):
        observed.append(bool(job.get("_pool_sms_url")))
        monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: sms8("123456"))
        observed.append(kwargs["wait_code"]("signup", 2))
        monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: sms8("654321"))
        observed.append(kwargs["wait_code"]("pin", 2))
        return {"phone": job["phone"], "local": "123456789", "balance": 0}

    monkeypatch.setattr(worker, "_register_one_from_phone", fake_register)
    mgr._run(
        job_id="fixture", source="pool", phone=job["phone"], pin="147258",
        country_code="+62", signed_up_country="ID", proxy="", auth_mode="protocol",
        login_existing=False, change_pin_after_login=False, new_pin="",
        relogin_after_register=False, claim_envelope_after_register=False,
        sms_url="https://sms.example.test/api/record?token=selected-fixture",
    )
    assert observed == [True, "123456", "654321"]
    assert job["status"] == "success"


def payment_manager(monkeypatch, tmp_path, reader):
    config = tmp_path / "config"
    config.mkdir(exist_ok=True)
    pool_url = "https://sms.example.test/api/record?token=payment-private-fixture"
    (config / "gopay_phone_pool.json").write_text(json.dumps([
        {"phone": "+62123456789", "sms_url": pool_url}
    ]), encoding="utf-8")
    accounts_path = config / "gopay_worker_accounts.json"
    accounts_path.write_text(json.dumps([
        {
            "phone": "+62123456789",
            "local": "123456789",
            "registered_at": "2026-11-01T00:00:00+00:00",
            "balance": 1,
            "pin": "147258",
            "pin_setup_status": "configured",
            "activation_id": "web-pool-fixture",
            "sms_activation_status": "unavailable",
        }
    ]), encoding="utf-8")
    monkeypatch.setattr(inbox, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(inbox, "IMPORTED_SMS_POLL_SECONDS", 0.01)
    monkeypatch.setenv("OPAI_GOPAY_ACCOUNTS_FILE", str(accounts_path))
    monkeypatch.setattr(inbox, "read_imported_sms_url", reader)
    mgr = inbox._WebPaymentManager(inbox.InboxStore(tmp_path / "payment_inbox.sqlite3"))
    now = inbox._now_iso()
    job = {
        "id": "payment-fixture",
        "phone": "+62123456789",
        "status": "running",
        "message": "fixture",
        "created_at": now,
        "updated_at": now,
        "prompt": None,
        "logs": [],
        "_otp": [],
    }
    mgr._jobs[job["id"]] = job
    mgr._conds[job["id"]] = threading.Condition(mgr._lock)
    mgr._prepare_pool_payment_otp(job["id"], job["phone"])
    return mgr, job, pool_url


def test_payment_pool_otp_reads_new_code_and_skips_history(monkeypatch, tmp_path):
    mgr, job, _url = payment_manager(monkeypatch, tmp_path, lambda *a, **kw: sms8("1111"))
    replies = iter([sms8("1111"), sms8("5281")])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: next(replies))

    assert mgr._wait_otp(job["id"], job["phone"], 2) == "5281"
    assert job["status"] == "running"
    assert job["prompt"] is None
    assert any(row["message"] == "支付 OTP 已从号码池短信接口获取，自动提交" for row in job["logs"])


def test_payment_pool_otp_failed_baseline_recovers_before_accepting_code(monkeypatch, tmp_path):
    def unavailable(*_args, **_kwargs):
        raise urllib.error.URLError("fixture unavailable")

    mgr, job, _url = payment_manager(monkeypatch, tmp_path, unavailable)
    replies = iter([sms8("1111"), sms8("2222")])
    monkeypatch.setattr(inbox, "read_imported_sms_url", lambda *a, **kw: next(replies))

    assert mgr._wait_otp(job["id"], job["phone"], 2) == "2222"
    assert any("历史基线已补齐" in row["message"] for row in job["logs"])


def test_payment_pool_private_fields_are_not_public_or_persisted(monkeypatch, tmp_path):
    mgr, job, pool_url = payment_manager(monkeypatch, tmp_path, lambda *a, **kw: sms8("1111"))

    public = json.dumps(mgr.get(job["id"]), ensure_ascii=False)
    persisted = (tmp_path / "config" / "payment_tasks.json").read_text(encoding="utf-8")
    for payload in (public, persisted):
        assert pool_url not in payload
        assert "payment-private-fixture" not in payload
        assert "_pool_sms_url" not in payload
        assert "_pool_otp_ignored_hashes" not in payload


def test_account_list_reports_phone_pool_auto_sms_and_migrates_last_used(monkeypatch, tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    registered_at = "2026-11-01T02:03:00+00:00"
    accounts_path = config / "gopay_worker_accounts.json"
    accounts_path.write_text(json.dumps([
        {
            "phone": "+62123456789",
            "local": "123456789",
            "registered_at": registered_at,
            "balance": 1,
            "activation_id": "web-pool-fixture",
            "sms_activation_status": "unavailable",
        }
    ]), encoding="utf-8")
    (config / "gopay_phone_pool.json").write_text(json.dumps([
        {
            "phone": "+62123456789",
            "sms_url": "https://sms.example.test/api/record?token=account-private-fixture",
        }
    ]), encoding="utf-8")
    monkeypatch.setattr(inbox, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(inbox, "_gopay_accounts_path", lambda: accounts_path)

    account = inbox._load_gopay_accounts()[0]
    saved = json.loads(accounts_path.read_text(encoding="utf-8"))[0]

    assert account["sms_auto_capable"] is True
    assert account["sms_auto_source"] == "phone_pool"
    assert account["sms_activation_label"] == "号码池自动接码"
    assert account["last_used_at"] == registered_at
    assert saved["last_used_at"] == registered_at
    assert "sms_url" not in account
    assert "account-private-fixture" not in json.dumps(account, ensure_ascii=False)


def test_last_used_at_updates_and_survives_binding_release(monkeypatch, tmp_path):
    accounts_path = tmp_path / "gopay_worker_accounts.json"
    accounts_path.write_text(json.dumps([
        {"phone": "+62123456789", "local": "123456789", "balance": 1}
    ]), encoding="utf-8")
    monkeypatch.setattr(inbox, "_gopay_accounts_path", lambda: accounts_path)
    timestamps = iter(["2026-11-06T01:00:00+00:00", "2026-11-06T02:30:00+00:00"])
    monkeypatch.setattr(inbox, "_now_iso", lambda: next(timestamps))

    assert inbox._reserve_gopay_midtrans_binding(
        "+62123456789",
        job_id="job-1",
        order_id="order-1",
        midtrans_url="https://app.midtrans.com/snap/v4/redirection/fixture",
    )
    inbox._update_gopay_midtrans_binding_status(
        "+62123456789",
        "failed",
        message="fixture",
    )
    account = json.loads(accounts_path.read_text(encoding="utf-8"))[0]
    assert account["last_used_at"] == "2026-11-06T02:30:00+00:00"

    inbox._clear_gopay_midtrans_binding(account)
    assert account["last_used_at"] == "2026-11-06T02:30:00+00:00"
    assert "midtrans_binding_updated_at" not in account
