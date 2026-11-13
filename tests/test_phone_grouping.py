import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import gopay.server as server
from opai.core import sms_helpers


def test_phone_pool_classifies_local_accounts_and_explicit_states(monkeypatch, tmp_path):
    pool_path = tmp_path / "gopay_phone_pool.json"
    pool_path.write_text(json.dumps([
        {"phone": "+628111111111", "sms_url": "https://sms.test/1", "status": "available"},
        {"phone": "+628222222222", "sms_url": "https://sms.test/2", "status": "available", "account_state": "login_required"},
        {"phone": "+628333333333", "sms_url": "https://sms.test/3", "status": "available", "account_state": "unregistered"},
    ]), encoding="utf-8")
    monkeypatch.setattr(server, "POOL", pool_path)
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: [{"phone": "628333333333", "local": "8333333333"}])

    rows = server._load_gopay_phone_pool()

    assert [row["account_state"] for row in rows] == ["unregistered", "login_required", "registered"]


def test_selected_pool_rows_follow_requested_order_and_mode(monkeypatch, tmp_path):
    pool_path = tmp_path / "gopay_phone_pool.json"
    pool_path.write_text(json.dumps([
        {"phone": "+628111111111", "sms_url": "https://sms.test/1", "account_state": "unregistered"},
        {"phone": "+628222222222", "sms_url": "https://sms.test/2", "account_state": "login_required"},
        {"phone": "+628333333333", "sms_url": "https://sms.test/3", "account_state": "unregistered"},
    ]), encoding="utf-8")
    monkeypatch.setattr(server, "POOL", pool_path)
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: [])

    selected = server._select_pool_rows(["+628333333333", "+628111111111"], False, 99)

    assert [row["phone"] for row in selected] == ["+628333333333", "+628111111111"]
    with pytest.raises(ValueError, match="不能执行注册"):
        server._select_pool_rows(["+628222222222"], False, 1)


def test_pool_state_can_be_changed_in_bulk(monkeypatch, tmp_path):
    pool_path = tmp_path / "gopay_phone_pool.json"
    pool_path.write_text(json.dumps([
        {"phone": "+628111111111", "sms_url": "https://sms.test/1", "account_state": "unregistered"},
        {"phone": "+628222222222", "sms_url": "https://sms.test/2", "account_state": "unregistered"},
    ]), encoding="utf-8")
    monkeypatch.setattr(server, "POOL", pool_path)
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: [])

    result = server._set_pool_account_state(["+628111111111", "+628222222222"], "login_required")
    saved = json.loads(pool_path.read_text(encoding="utf-8"))

    assert result["updated"] == 2
    assert {row["account_state"] for row in saved} == {"login_required"}


def test_phone_change_recycles_old_pool_number(monkeypatch, tmp_path):
    rows = [{"phone": "628123456789", "local": "8123456789", "phone_type": "short_term"}]
    pool_path = tmp_path / "gopay_phone_pool.json"
    pool_path.write_text(json.dumps([
        {"phone": "+628123456789", "sms_url": "https://sms.test/old", "account_state": "registered"},
        {"phone": "+6289912345678", "sms_url": "https://sms.test/new", "account_state": "login_required"},
    ]), encoding="utf-8")
    monkeypatch.setattr(server, "POOL", pool_path)
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: rows)
    monkeypatch.setattr(server, "_find_gopay_account", lambda phone: (rows[0], 0) if str(phone).endswith("8123456789") else (None, -1))
    monkeypatch.setattr(server, "_write_gopay_accounts_raw", lambda value: rows.__setitem__(slice(None), value))

    server._sync_phone_change("628123456789", "+62 899 1234 5678", "short_term")
    saved = {server._phone_key(row["phone"]): row for row in json.loads(pool_path.read_text(encoding="utf-8"))}

    assert saved["628123456789"]["account_state"] == "unregistered"
    assert saved["6289912345678"]["account_state"] == "registered"


def test_phone_type_is_persisted(monkeypatch):
    rows = [{"phone": "628123456789", "local": "8123456789"}]
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: rows)
    monkeypatch.setattr(server, "_find_gopay_account", lambda phone: (rows[0], 0))
    written = []
    monkeypatch.setattr(server, "_write_gopay_accounts_raw", lambda value: written.extend(value))

    result = server._set_account_phone_type("628123456789", "long_term")

    assert result["phone_type"] == "long_term"
    assert written[0]["phone_type"] == "long_term"


def test_completed_phone_change_replaces_local_identifier_and_tokens(monkeypatch):
    rows = [{"phone": "628123456789", "local": "8123456789", "access_token": "old", "refresh_token": "old"}]
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: rows)
    monkeypatch.setattr(server, "_find_gopay_account", lambda phone: (rows[0], 0) if str(phone).endswith("8123456789") else (None, -1))
    monkeypatch.setattr(server, "_write_gopay_accounts_raw", lambda value: None)

    result = server._sync_phone_change("628123456789", "+62 899 1234 5678", "short_term")

    assert result["phone"] == "6289912345678"
    assert result["local"] == "89912345678"
    assert result["phone_type"] == "short_term"
    assert "access_token" not in result
    assert "refresh_token" not in result


def test_short_to_short_change_is_marked_as_test_only(monkeypatch):
    rows = [{"phone": "628123456789", "local": "8123456789", "phone_type": "short_term"}]
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: rows)
    monkeypatch.setattr(server, "_find_gopay_account", lambda phone: (rows[0], 0) if str(phone).endswith("8123456789") else (None, -1))
    monkeypatch.setattr(server, "_write_gopay_accounts_raw", lambda value: None)

    result = server._test_short_phone_change("628123456789", "6289912345678")

    assert result["phone_type"] == "short_term"
    assert result["phone_change_test"] is True


def test_smsbower_phone_change_start_rents_new_number_without_persisting_key(monkeypatch, tmp_path):
    rows = [{"phone": "628123456789", "local": "8123456789", "phone_type": "short_term", "pin": "147258"}]
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    monkeypatch.setattr(
        server,
        "_find_gopay_account",
        lambda phone: (rows[0], 0) if str(phone).endswith("8123456789") else (None, -1),
    )
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: ("+6289912345678", "987654"))
    launched = []
    monkeypatch.setattr(server, "_launch_smsbower_phone_change_worker", lambda job_id: launched.append(job_id) or True)

    task = server._start_smsbower_phone_change("628123456789")

    assert task["new_phone"] == "6289912345678"
    assert task["provider"] == "smsbower"
    assert task["automation_mode"] == "protocol"
    assert "activation_id" not in task
    assert launched == [task["id"]]
    persisted = json.loads(server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))
    assert persisted["tasks"][0]["activation_id"] == "987654"
    assert "secret-key" not in server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8")


def test_phone_change_uses_bound_proxy_provider_before_buying_number(monkeypatch, tmp_path):
    rows = [{"phone": "628123456789", "local": "8123456789", "phone_type": "short_term", "pin": "147258"}]
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    monkeypatch.setattr(server, "_find_gopay_account", lambda phone: (rows[0], 0) if str(phone).endswith("8123456789") else (None, -1))
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: ("+6289912345678", "987654"))
    monkeypatch.setattr(server, "_launch_smsbower_phone_change_worker", lambda _job_id: True)
    monkeypatch.setattr(server, "resolve_provider_proxy", lambda purpose, country, session_id="", **_kwargs: {
        "url": "http://user:pass@proxy.example:9000",
        "provider_id": 7,
        "provider_name": "Provider 7",
        "country": country,
        "session_id": session_id,
        "preview": "http://***:***@proxy.example:9000",
    })
    observed = []
    monkeypatch.setattr(
        "opai.core.gojek_client.probe_proxy_egress",
        lambda proxy, timeout_sec=12: observed.append(proxy) or {"ok": True, "ip": "203.0.113.8", "status": 200},
    )

    task = server._start_smsbower_phone_change("628123456789")

    assert observed == ["http://user:pass@proxy.example:9000"]
    assert task["proxy_provider_id"] == 7
    assert task["proxy_provider_name"] == "Provider 7"
    assert task["proxy_exit_ip"] == "203.0.113.8"
    assert "pass" not in json.dumps(task)


def test_smsbower_phone_change_poll_returns_code_but_persists_only_hash(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    server._write_phone_change_tasks([
        {
            "id": "change-1",
            "old_phone": "628123456789",
            "new_phone": "6289912345678",
            "activation_id": "987654",
            "status": "number_acquired",
        }
    ])
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_wait_code", lambda _key, _aid, timeout: "246810")

    result = server._poll_smsbower_phone_change_code("change-1", 5)

    assert result["code"] == "246810"
    persisted_text = server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8")
    persisted = json.loads(persisted_text)["tasks"][0]
    assert "246810" not in persisted_text
    assert persisted["status"] == "code_received"
    assert len(persisted["code_hash"]) == 64


def test_smsbower_get_number_uses_min_and_max_price(monkeypatch):
    captured = []
    monkeypatch.setenv("OPAI_SMSBOWER_SERVICE", "ni")
    monkeypatch.setenv("OPAI_SMSBOWER_COUNTRY", "6")
    monkeypatch.setenv("OPAI_SMSBOWER_MIN_PRICE", "0.125")
    monkeypatch.setenv("OPAI_SMSBOWER_MAX_PRICE", "0.875")
    monkeypatch.setenv("OPAI_SMSBOWER_GETNUMBER_RETRIES", "1")

    def fake_sms_api(_key, action, params, retries=1):
        captured.append((action, dict(params), retries))
        return "ACCESS_NUMBER:987654:6289912345678"

    monkeypatch.setattr(sms_helpers, "sms_api", fake_sms_api)

    assert sms_helpers.sms_get_number("secret-key") == ("+6289912345678", "987654")
    assert captured == [(
        "getNumber",
        {"service": "ni", "country": "6", "minPrice": "0.125", "maxPrice": "0.875"},
        1,
    )]


def test_sms_config_persists_valid_price_range(monkeypatch, tmp_path):
    config_path = tmp_path / "sms.env"
    monkeypatch.setenv("OPAI_GOPAY_SMS_ENV_FILE", str(config_path))
    for key in (
        "OPAI_SMSBOWER_API_KEY",
        "OPAI_SMSBOWER_API_KEY_FILE",
        "OPAI_SMSBOWER_API_BASE_URL",
        "OPAI_SMSBOWER_SERVICE",
        "OPAI_SMSBOWER_COUNTRY",
        "OPAI_SMSBOWER_MIN_PRICE",
        "OPAI_SMSBOWER_MAX_PRICE",
        "OPAI_HEROSMS_API_KEY",
        "OPAI_HEROSMS_API_BASE_URL",
        "OPAI_HEROSMS_SERVICE",
        "OPAI_HEROSMS_COUNTRY",
        "OPAI_HEROSMS_MIN_PRICE",
        "OPAI_HEROSMS_MAX_PRICE",
    ):
        monkeypatch.setenv(key, "")

    result = server._write_sms_config({
        "api_key": "secret-key",
        "api_base_url": "https://smsbower.page",
        "service": "ni",
        "country": "6",
        "min_price": "0.1",
        "max_price": "0.9",
    })

    saved = config_path.read_text(encoding="utf-8")
    assert "OPAI_SMSBOWER_MIN_PRICE=0.1" in saved
    assert "OPAI_SMSBOWER_MAX_PRICE=0.9" in saved
    assert result["min_price"] == "0.1"
    assert result["max_price"] == "0.9"

    with pytest.raises(ValueError, match="最低价格不能高于最高价格"):
        server._write_sms_config({"min_price": "1.2", "max_price": "0.8"})
    with pytest.raises(ValueError, match="必须同时设置最高价格"):
        server._write_sms_config({"min_price": "0.2", "max_price": ""})


def test_smsbower_phone_change_timeout_cancels_and_rotates_number(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    server._write_phone_change_tasks([{
        "id": "change-rotate",
        "old_phone": "628123456789",
        "new_phone": "628111111111",
        "activation_id": "111111",
        "attempt_count": 1,
        "max_attempts": 10,
        "status": "number_acquired",
        "logs": [],
    }])
    monkeypatch.setattr(server, "_find_gopay_account", lambda _phone: (None, -1))
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_wait_code", lambda _key, _aid, timeout: None)
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: ("+628222222222", "222222"))
    cancelled = []
    monkeypatch.setattr(server, "_cancel_sms_activation_with_retry", lambda _key, aid: cancelled.append(aid))

    result = server._poll_smsbower_phone_change_code("change-rotate", 1)

    assert result["rotated"] is True
    assert result["new_phone"] == "628222222222"
    assert result["attempt_count"] == 2
    assert result["max_attempts"] == 10
    assert result["status"] == "number_acquired"
    assert "activation_id" not in result
    assert cancelled == ["111111"]
    persisted = json.loads(server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))["tasks"][0]
    assert persisted["activation_id"] == "222222"
    assert any("等待 1 秒未收到 OTP" in row["message"] for row in persisted["logs"])
    assert any("第 2/10 个换绑号码已购买" in row["message"] for row in persisted["logs"])


def test_smsbower_phone_change_stops_after_tenth_number(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    server._write_phone_change_tasks([{
        "id": "change-limit",
        "old_phone": "628123456789",
        "new_phone": "628999999999",
        "activation_id": "999999",
        "attempt_count": 10,
        "max_attempts": 10,
        "status": "number_acquired",
        "logs": [],
    }])
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_wait_code", lambda _key, _aid, timeout: None)
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: pytest.fail("must not buy an 11th number"))
    cancelled = []
    monkeypatch.setattr(server, "_cancel_sms_activation_with_retry", lambda _key, aid: cancelled.append(aid))

    result = server._poll_smsbower_phone_change_code("change-limit", 1)

    assert result["status"] == "failed"
    assert result["exhausted"] is True
    assert result["attempt_count"] == 10
    assert cancelled == ["999999"]
    assert "已尝试 10 个换绑号码" in result["message"]


def test_smsbower_phone_change_complete_transfers_activation_and_consumed_hash(monkeypatch, tmp_path):
    rows = [{
        "phone": "628123456789",
        "local": "8123456789",
        "phone_type": "short_term",
        "activation_id": "111111",
        "access_token": "old",
        "refresh_token": "old",
    }]
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: rows)
    monkeypatch.setattr(
        server,
        "_find_gopay_account",
        lambda phone: (rows[0], 0) if str(phone).endswith("8123456789") else (None, -1),
    )
    monkeypatch.setattr(server, "_write_gopay_accounts_raw", lambda value: None)
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_request_another", lambda _key, _aid: True)
    completed_old = []
    monkeypatch.setattr(sms_helpers, "sms_done", lambda _key, aid: completed_old.append(aid) or True)
    server._write_phone_change_tasks([
        {
            "id": "change-2",
            "old_phone": "628123456789",
            "new_phone": "6289912345678",
            "phone_type": "short_term",
            "activation_id": "987654",
            "previous_activation_id": "111111",
            "status": "code_received",
            "code_hash": "a" * 64,
        }
    ])

    result = server._complete_smsbower_phone_change("change-2")

    assert result["ok"] is True
    assert result["retry_ready"] is True
    assert result["account"]["phone"] == "6289912345678"
    assert result["account"]["activation_id"] == "987654"
    assert result["account"]["sms_activation_status"] == "active"
    assert result["account"]["sms_consumed_code_hashes"] == ["a" * 64]
    assert "access_token" not in result["account"]
    assert completed_old == ["111111"]
    persisted = json.loads(server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))["tasks"][0]
    assert persisted["status"] == "completed"


def test_smsbower_phone_change_http_routes_end_to_end(monkeypatch, tmp_path):
    rows = [{"phone": "628123456789", "local": "8123456789", "phone_type": "long_term", "pin": "147258"}]

    def find_account(phone):
        target = "".join(ch for ch in str(phone) if ch.isdigit())
        for index, row in enumerate(rows):
            if target in {row.get("phone"), row.get("local")}:
                return row, index
        return None, -1

    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    monkeypatch.setattr(server, "_load_gopay_accounts_raw", lambda: rows)
    monkeypatch.setattr(server, "_find_gopay_account", find_account)
    monkeypatch.setattr(server, "_write_gopay_accounts_raw", lambda value: rows.__setitem__(slice(None), value))
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: ("+6289912345678", "987654"))
    monkeypatch.setattr(server, "_launch_smsbower_phone_change_worker", lambda _job_id: True)
    monkeypatch.setattr(server, "_cancel_sms_activation_with_retry", lambda _key, _aid: None)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_port}"

    def post(path, payload=None):
        request = urllib.request.Request(
            base + path,
            data=json.dumps(payload or {}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    try:
        status, task = post(
            "/api/accounts/628123456789/smsbower-phone-change/start",
            {"phone_type": "long_term"},
        )
        assert status == 201
        assert task["new_phone"] == "6289912345678"
        assert task["phone_type"] == "long_term"
        assert task["automation_mode"] == "protocol"
        status, otp = post(f"/api/phone-change-tasks/{task['id']}/code", {"timeout_sec": 5})
        assert status == 200
        assert otp["background"] is True
        assert otp["code"] == ""
        status, cancelled = post(f"/api/phone-change-tasks/{task['id']}/cancel")
        assert status == 200
        assert cancelled["task"]["status"] == "cancelled"
        with urllib.request.urlopen(base + "/api/phone-change-tasks", timeout=5) as response:
            listed = json.loads(response.read().decode("utf-8"))
        assert listed["tasks"][0]["status"] == "cancelled"
        assert "activation_id" not in listed["tasks"][0]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
