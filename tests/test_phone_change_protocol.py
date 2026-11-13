import json
from types import SimpleNamespace

import pytest

from opai.core import sms_helpers
from opai.core import gopay_protocol_worker as protocol_worker
from opai.core.gojek_client import AuthState, CLIENT_ID, CLIENT_SECRET, GojekClient

import gopay.server as server


def test_existing_login_does_not_blame_pin_after_pin_token_was_issued(monkeypatch):
    client = SimpleNamespace(
        auth=SimpleNamespace(login_method="goto_pin", pin_token="verified-pin-token")
    )
    client.login = lambda *_args, **_kwargs: {
        "status": 400,
        "body": {"errors": [{"code": "GoPay-1000"}]},
    }
    monkeypatch.setattr(protocol_worker.GojekClient, "from_phone", lambda *_args, **_kwargs: client)
    messages = []

    result = protocol_worker._login_one_manual_existing(
        phone="628123456789",
        pin="147258",
        proxy="",
        wait_code=lambda *_args: None,
        status_cb=messages.append,
        return_failure=True,
    )

    assert result["failed"] is True
    assert "PIN 已验证" in result["error"]
    assert "这不是 PIN 错误" in result["error"]
    assert "请填写原 PIN" not in result["error"]


def test_reinstalled_device_seed_is_persisted_and_reused(monkeypatch, tmp_path):
    accounts_path = tmp_path / "accounts.json"
    monkeypatch.setattr(protocol_worker, "ACCOUNTS_FILE", str(accounts_path))
    monkeypatch.setattr(protocol_worker, "_check_balance", lambda _client: 0)
    monkeypatch.setattr(protocol_worker, "_inbox_push_account", lambda *_args, **_kwargs: None)
    client = GojekClient.from_phone(
        "628123456789",
        device_seed="reinstall-20261113",
    )
    client.auth.access_token = "access-token"
    client.auth.refresh_token = "refresh-token"
    client.auth.account_id = "account-id"

    protocol_worker._save_account(
        "628123456789",
        "8123456789",
        "147258",
        "manual-login",
        client,
    )

    saved = json.loads(accounts_path.read_text(encoding="utf-8"))[0]
    assert saved["device_seed_suffix"] == "reinstall-20261113"
    restored = server._gopay_client_from_account(saved, saved["phone"])
    assert restored.device_seed_suffix == "reinstall-20261113"
    assert restored.model == client.model
    assert restored.xm1_template == client.xm1_template
    assert restored.uniqueid == client.uniqueid


def test_har_phone_change_request_sequence_uses_pin_and_cvs_sms():
    client = object.__new__(GojekClient)
    client.auth = AuthState(access_token="access-token")
    client.version = "2.16.1"
    calls = []

    def gojek_patch(path, body=None, extra_headers=None):
        calls.append(("gojek_patch", path, body, dict(extra_headers or {})))
        if path == "/v6/customers" and "Pin-Token" not in (extra_headers or {}):
            return {
                "status": 206,
                "body": {"data": {"challenge_id": "challenge-1", "client_id": "client-1"}},
            }
        if path == "/v6/customers":
            return {"status": 200, "body": {"data": {"pv_token": "pv-token"}}}
        raise AssertionError(path)

    def pin_verify(pin, challenge_id="", client_id="", extra_headers=None):
        calls.append(("pin_verify", pin, challenge_id, client_id, dict(extra_headers or {})))
        client.auth.pin_token = "pin-token"
        return {"status": 200, "body": {"data": {"token": "pin-token"}}}

    def sso_post(path, body, extra_headers=None, sign_path=None):
        calls.append(("sso_post", path, dict(body), dict(extra_headers or {}), sign_path))
        assert path == "/cvs/v1/methods"
        return {
            "status": 200,
            "body": {"data": {"verification_id": "verification-1", "methods": ["otp_wa", "otp_sms"]}},
        }

    def sso_initiate(body, extra_headers=None):
        calls.append(("sso_initiate", dict(body), dict(extra_headers or {})))
        return {"status": 200, "body": {"data": {"otp_token": "otp-token", "otp_length": 4}}}

    client._gojek_api_patch = gojek_patch
    client.pin_verify = pin_verify
    client._sso_post = sso_post
    client._sso_cvs_initiate = sso_initiate

    result = client.phone_change_request_otp("+628123456789", "147258")

    assert result["status"] == 200
    assert calls[0][0:3] == ("gojek_patch", "/v6/customers", {"phone": "+628123456789"})
    assert calls[0][3]["Country-Code"] == "ID"
    assert calls[0][3]["X-AppType"] == "GOPAY"
    assert calls[0][3]["X-Help-Version"] == "2.16.1"
    assert calls[0][3]["X-DeviceToken"] == ""
    assert calls[1][0:4] == ("pin_verify", "147258", "challenge-1", "client-1")
    assert calls[1][4]["SDK-Version"] == "2.16.1"
    assert calls[1][4]["X-Verification"] == "PIN"
    assert calls[1][4]["X-DeviceToken"] == ""
    assert calls[2][0:3] == ("gojek_patch", "/v6/customers", {"phone": "+628123456789"})
    assert calls[2][3]["Pin-Token"] == "pin-token"
    methods = calls[3]
    assert methods[1] == "/cvs/v1/methods"
    assert methods[2]["flow"] == "gojek_edit_profile"
    assert methods[2]["phone_number"] == "8123456789"
    assert methods[3] == {
        "Accept": None,
        "Authorization": None,
        "Content-Type": "application/json",
        "X-DeviceToken": "",
    }
    initiated = calls[4]
    assert initiated[1]["verification_method"] == "otp_sms"
    assert initiated[1]["flow"] == "gojek_edit_profile"
    assert initiated[2] == {
        "Accept": None,
        "Authorization": None,
        "Content-Type": "application/json",
        "X-DeviceToken": "",
    }
    assert client.auth.profile_verification_token == "pv-token"
    assert client.auth.otp_token == "otp-token"


def test_har_phone_change_verify_commits_with_pv_and_bearer_verification_tokens():
    client = object.__new__(GojekClient)
    client.version = "2.16.1"
    client.auth = AuthState(
        access_token="access-token",
        transaction_id="transaction-1",
        verification_id="verification-1",
        otp_token="otp-token",
        otp_channel="otp_sms",
        profile_verification_token="pv-token",
    )
    calls = []

    def sso_post(path, body, extra_headers=None, sign_path=None):
        calls.append(("sso_post", path, dict(body), dict(extra_headers or {}), sign_path))
        return {"status": 200, "body": {"data": {"verification_token": "verification-token"}}}

    def gojek_patch(path, body=None, extra_headers=None):
        calls.append(("gojek_patch", path, body, dict(extra_headers or {})))
        return {"status": 200, "body": {"data": {"message": "ok"}}}

    client._sso_post = sso_post
    client._gojek_api_patch = gojek_patch

    result = client.phone_change_verify_otp("2468")

    assert result["status"] == 200
    verify = calls[0]
    assert verify[1] == "/cvs/v1/verify"
    assert verify[2]["flow"] == "gojek_edit_profile"
    assert verify[2]["data"] == {"otp": "2468", "otp_token": "otp-token"}
    assert verify[3] == {
        "Accept": None,
        "Authorization": None,
        "Content-Type": "application/json",
        "X-DeviceToken": "",
    }
    commit = calls[1]
    assert commit[1] == "/v6/customers/verificationUpdateProfile"
    assert commit[2] is None
    assert commit[3]["PVToken"] == "pv-token"
    assert commit[3]["Verification-Token"] == "Bearer verification-token"
    assert commit[3]["Content-Type"] is None
    assert commit[3]["X-DeviceToken"] == ""


def test_phone_change_signed_headers_match_har_surface():
    client = GojekClient.from_phone("+628123456789")
    client.auth.access_token = "access-token"
    client.version = "2.16.1"
    client.app_build = "2161"
    headers = client._gojek_api_signed_headers(
        "/v6/customers",
        "PATCH",
        json.dumps({"phone": "+628999999999"}, separators=(",", ":")),
        client._phone_change_gojek_headers(),
    )
    assert headers["Country-Code"] == "ID"
    assert headers["X-AppType"] == "GOPAY"
    assert headers["X-Help-Version"] == "2.16.1"
    assert "Accept" not in headers
    assert headers["X-DeviceToken"] == ""
    assert "User-uuid" not in headers
    assert "X-PushTokenType" not in headers
    assert "X-Dark-Mode" not in headers
    assert "support-sdk-version" not in headers


def test_sso_signing_uses_the_final_authorization_header(monkeypatch):
    client = GojekClient.from_phone("+628123456789")
    client.auth.access_token = "access-token"
    captured = {}

    def fake_sign_v2(**kwargs):
        captured["sign"] = kwargs
        return {"X-E1": "signed-e1", "X-E2": "signed-e2"}

    class FakeResponse:
        status_code = 200
        text = "{}"

        @staticmethod
        def json():
            return {}

    class FakeSession:
        @staticmethod
        def post(url, headers, data, timeout_seconds):
            captured["request"] = {
                "url": url,
                "headers": dict(headers),
                "data": data,
                "timeout_seconds": timeout_seconds,
            }
            return FakeResponse()

    monkeypatch.setattr("opai.core.gojek_client.sign_v2", fake_sign_v2)
    client._session = FakeSession()

    result = client._sso_post(
        "/cvs/v1/methods",
        {"flow": "gojek_edit_profile"},
        client._phone_change_sso_headers(),
    )

    assert result["status"] == 200
    assert captured["sign"]["token"] == ""
    assert "Authorization" not in captured["request"]["headers"]
    assert captured["request"]["url"] == "https://accounts.goto-products.com/cvs/v1/methods"


def test_phone_change_auto_relogin_uses_dedicated_login_app_identity(monkeypatch):
    account = {
        "phone": "628123456789",
        "pin": "147258",
        "proxy": "http://old-proxy.example:8000",
    }
    updated = {
        **account,
        "access_token": "fresh-access",
        "refresh_token": "fresh-refresh",
    }
    captured = {}

    monkeypatch.setattr(server, "_load_gopay_phone_pool", lambda: [{
        "phone": account["phone"],
        "sms_url": "https://sms.example.test/record",
    }])
    monkeypatch.setattr(server, "read_imported_sms_url", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(server, "extract_imported_sms_codes", lambda _payload: [])
    monkeypatch.setattr(server, "_update_phone_change_progress", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_find_gopay_account", lambda _phone: (updated, 0))
    monkeypatch.setattr(server, "PHONE_CHANGE_LOGIN_APP_VERSION", "2.22.1")
    monkeypatch.setattr(server, "PHONE_CHANGE_LOGIN_APP_BUILD", "2221")
    monkeypatch.setattr(server, "PHONE_CHANGE_LOGIN_PREFER_SMS", True)

    def fake_login(**kwargs):
        captured.update(kwargs)
        return {"phone": "+628123456789", "logged_in_existing": True}

    monkeypatch.setattr(
        "opai.core.gopay_protocol_worker._login_one_manual_existing",
        fake_login,
    )

    result, index = server._auto_relogin_for_phone_change(
        "identity-check",
        account,
        proxy_override="http://change-proxy.example:9000",
    )

    assert result == updated
    assert index == 0
    assert captured["proxy"] == "http://change-proxy.example:9000"
    assert captured["app_version"] == "2.22.1"
    assert captured["app_build"] == "2221"
    assert captured["prefer_otp_sms"] is True


def test_gopay_2221_uses_cvs_v2_header_only_onefa_token(monkeypatch):
    client = GojekClient.from_phone("628123456789")
    client.version = "2.22.1"
    client.auth.onefa_token = "onefa-token"
    client.auth.account_id = "account-id"
    captured = {}

    def fake_sso_post(path, body, extra_headers=None, sign_path=None):
        captured.update({
            "path": path,
            "body": body,
            "headers": dict(extra_headers or {}),
            "sign_path": sign_path,
        })
        return {
            "status": 403,
            "body": {
                "data": {
                    "2fa_token": "twofa-token",
                    "methods": ["otp_sms"],
                    "verification_id": "verification-id",
                }
            },
        }

    monkeypatch.setattr(client, "_sso_post", fake_sso_post)
    result = client.issue_token("cvs", client.auth.onefa_token)

    assert result["status"] == 403
    assert captured["path"] == "/goto-auth/token"
    assert captured["body"] == {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "cvs_v2",
        "token": None,
        "ext_user_token": None,
    }
    assert captured["headers"] == {"verification-token": "onefa-token"}
    assert client.auth.twofa_token == "twofa-token"
    assert client.auth.twofa_methods == ["otp_sms"]
    assert client.auth.verification_id == "verification-id"


def test_gopay_2161_keeps_legacy_cvs_token_request(monkeypatch):
    client = GojekClient.from_phone("628123456789")
    client.version = "2.16.1"
    client.auth.onefa_token = "onefa-token"
    client.auth.account_id = "account-id"
    captured = {}

    def fake_sso_post(path, body, extra_headers=None, sign_path=None):
        captured.update({"path": path, "body": body, "headers": dict(extra_headers or {})})
        return {"status": 400, "body": {}}

    monkeypatch.setattr(client, "_sso_post", fake_sso_post)
    client.issue_token("cvs", client.auth.onefa_token)

    assert captured["body"]["grant_type"] == "cvs"
    assert captured["body"]["token"] == "onefa-token"
    assert captured["body"]["account_id"] == "account-id"
    assert captured["body"]["ext_user_token"] is None
    assert captured["headers"] == {"verification-token": "onefa-token"}


def test_gopay_2221_pin_cvs_verify_uses_verification_token(monkeypatch):
    client = GojekClient.from_phone("628123456789")
    client.version = "2.22.1"
    client.auth.pin_challenge_id = "challenge-id"
    client.auth.pin_token = "pin-token"
    client.auth.verification_id = "verification-id"
    captured = {}

    def fake_sso_post(path, body, extra_headers=None, sign_path=None):
        captured.update({"path": path, "body": body})
        return {"status": 200, "body": {"data": {"verification_token": "jwe-token"}}}

    monkeypatch.setattr(client, "_sso_post", fake_sso_post)
    result = client.verify_pin_via_cvs()

    assert result["status"] == 200
    assert captured["path"] == "/cvs/v1/verify"
    assert captured["body"]["data"] == {"verification_token": "pin-token"}
    assert client.auth.verification_token == "jwe-token"


def test_gopay_2161_pin_cvs_verify_keeps_challenge_and_validation_jwt(monkeypatch):
    client = GojekClient.from_phone("628123456789")
    client.version = "2.16.1"
    client.auth.pin_challenge_id = "challenge-id"
    client.auth.pin_token = "pin-token"
    client.auth.verification_id = "verification-id"
    captured = {}

    def fake_sso_post(path, body, extra_headers=None, sign_path=None):
        captured.update({"path": path, "body": body})
        return {"status": 400, "body": {}}

    monkeypatch.setattr(client, "_sso_post", fake_sso_post)
    client.verify_pin_via_cvs()

    assert captured["body"]["data"] == {
        "challenge_id": "challenge-id",
        "validation_jwt": "pin-token",
    }


def test_gopay_1000_is_not_misclassified_as_bad_phone_number():
    system_error = {
        "status": 400,
        "body": {"errors": [{"code": "GoPay-1000", "message": "Internal server error"}]},
    }
    bad_number = {
        "status": 400,
        "body": {"errors": [{"code": "invalid_phone", "message": "Invalid phone number"}]},
    }
    assert server._phone_change_number_rejected(system_error) is False
    assert server._phone_change_number_rejected(bad_number) is True


def test_background_phone_change_rotates_then_completes_without_user_confirmation(monkeypatch, tmp_path):
    account = {
        "phone": "628123456789",
        "local": "8123456789",
        "phone_type": "short_term",
        "pin": "147258",
        "access_token": "old-access",
        "refresh_token": "old-refresh",
    }
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    server._write_phone_change_tasks([{
        "id": "auto-change",
        "old_phone": account["phone"],
        "new_phone": "628111111111",
        "phone_type": "short_term",
        "provider": "smsbower",
        "automation_mode": "protocol",
        "activation_id": "111111",
        "previous_activation_id": "999999",
        "attempt_count": 1,
        "max_attempts": 10,
        "status": "number_acquired",
        "logs": [],
    }])

    def find_account(phone):
        digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
        return (account, 0) if digits in {account["phone"], account["local"]} else (None, -1)

    requested = []
    verified = []

    class FakeClient:
        def __init__(self):
            self.version = "2.10.0"
            self.app_build = "2100"
            self.auth = SimpleNamespace(
                access_token="new-access",
                refresh_token="new-refresh",
            )

        def refresh_token(self):
            return {"status": 200, "body": {"data": {}}}

        def phone_change_request_otp(self, phone, pin):
            requested.append((phone, pin, self.version, self.app_build))
            return {"status": 200, "body": {"data": {}}}

        def phone_change_verify_otp(self, code):
            verified.append(code)
            return {"status": 200, "body": {"data": {"message": "ok"}}}

    monkeypatch.setattr(server, "_find_gopay_account", find_account)
    monkeypatch.setattr(server, "_gopay_client_from_account", lambda _account, _phone: FakeClient())
    monkeypatch.setattr(server, "_log_phone_change_network", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_save_gopay_account_tokens_and_pin", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_sync_phone_change", lambda _old, new, *_args, **_kwargs: {"phone": new})
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: ("+628222222222", "222222"))
    replies = iter([None, "2468"])
    monkeypatch.setattr(sms_helpers, "sms_wait_code", lambda _key, _aid, timeout: next(replies))
    monkeypatch.setattr(sms_helpers, "sms_request_another", lambda _key, _aid: True)
    monkeypatch.setattr(sms_helpers, "sms_done", lambda _key, _aid: True)
    monkeypatch.setattr(
        "opai.core.gopay_protocol_worker._login_one_manual_existing",
        lambda **_kwargs: {"phone": "+628222222222", "logged_in_existing": True},
    )
    cancelled = []
    monkeypatch.setattr(server, "_cancel_sms_activation_with_retry", lambda _key, aid: cancelled.append(aid))

    server._run_smsbower_phone_change("auto-change")

    task = json.loads(server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))["tasks"][0]
    assert task["status"] == "completed"
    assert task["attempt_count"] == 2
    assert task["new_phone"] == "628222222222"
    assert requested == [
        ("628111111111", "147258", "2.16.1", "2161"),
        ("628222222222", "147258", "2.16.1", "2161"),
    ]
    assert verified == ["2468"]
    assert cancelled == ["111111"]
    persisted = server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8")
    assert "2468" not in persisted
    assert any("保存最终 token" in row["message"] for row in task["logs"])


def test_background_phone_change_auto_relogs_when_refresh_token_is_revoked(monkeypatch, tmp_path):
    stale_account = {
        "phone": "628123456789",
        "local": "8123456789",
        "pin": "147258",
        "access_token": "revoked-access",
        "refresh_token": "revoked-refresh",
    }
    refreshed_account = {
        **stale_account,
        "access_token": "fresh-access",
        "refresh_token": "fresh-refresh",
    }
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    server._write_phone_change_tasks([{
        "id": "auto-relogin",
        "old_phone": stale_account["phone"],
        "new_phone": "628333333333",
        "phone_type": "short_term",
        "provider": "smsbower",
        "automation_mode": "protocol",
        "activation_id": "333333",
        "attempt_count": 1,
        "max_attempts": 10,
        "status": "number_acquired",
        "logs": [],
    }])
    current_account = {"value": stale_account}

    def find_account(phone):
        digits = "".join(ch for ch in str(phone or "") if ch.isdigit())
        account = current_account["value"]
        return (account, 0) if digits in {account["phone"], account["local"]} else (None, -1)

    class RevokedClient:
        def __init__(self):
            self.version = "2.10.0"
            self.app_build = "2100"
            self.auth = SimpleNamespace(access_token="revoked-access", refresh_token="revoked-refresh")

        def refresh_token(self):
            return {"status": 400, "body": {"error": {"code": "1000"}}}

    class FreshClient:
        def __init__(self):
            self.version = "2.10.0"
            self.app_build = "2100"
            self.auth = SimpleNamespace(access_token="fresh-access", refresh_token="fresh-refresh")

        def refresh_token(self):
            return {"status": 200, "body": {"data": {}}}

        def phone_change_request_otp(self, _phone, _pin):
            return {"status": 200, "body": {"data": {}}}

        def phone_change_verify_otp(self, _code):
            return {"status": 200, "body": {"data": {"message": "ok"}}}

    clients = iter([RevokedClient(), FreshClient()])
    relogins = []

    def auto_relogin(job_id, account, timeout_sec=240, proxy_override=""):
        relogins.append((job_id, account["access_token"], timeout_sec, proxy_override))
        current_account["value"] = refreshed_account
        return refreshed_account, 0

    monkeypatch.setattr(server, "_find_gopay_account", find_account)
    monkeypatch.setattr(server, "_gopay_client_from_account", lambda _account, _phone: next(clients))
    monkeypatch.setattr(server, "_log_phone_change_network", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_auto_relogin_for_phone_change", auto_relogin)
    monkeypatch.setattr(server, "_save_gopay_account_tokens_and_pin", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_sync_phone_change", lambda _old, new, *_args, **_kwargs: {"phone": new})
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_wait_code", lambda _key, _aid, timeout: "8642")
    monkeypatch.setattr(sms_helpers, "sms_request_another", lambda _key, _aid: True)
    monkeypatch.setattr(sms_helpers, "sms_done", lambda _key, _aid: True)
    monkeypatch.setattr(
        "opai.core.gopay_protocol_worker._login_one_manual_existing",
        lambda **_kwargs: {"phone": "+628333333333", "logged_in_existing": True},
    )
    monkeypatch.setattr(server, "_cancel_sms_activation_with_retry", lambda *_args, **_kwargs: None)

    server._run_smsbower_phone_change("auto-relogin")

    task = json.loads(server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))["tasks"][0]
    assert task["status"] == "completed"
    assert relogins == [("auto-relogin", "revoked-access", 240, "")]
    assert any("自动重新登录" in row["message"] for row in task["logs"])


def test_gopay_1000_stops_without_buying_more_numbers(monkeypatch, tmp_path):
    account = {
        "phone": "628123456789",
        "local": "8123456789",
        "pin": "147258",
        "access_token": "access",
        "refresh_token": "refresh",
    }
    monkeypatch.setattr(server, "PHONE_CHANGE_TASKS_FILE", tmp_path / "phone_change_tasks.json")
    server._write_phone_change_tasks([{
        "id": "system-error",
        "old_phone": account["phone"],
        "new_phone": "628333333333",
        "phone_type": "short_term",
        "provider": "smsbower",
        "automation_mode": "protocol",
        "activation_id": "333333",
        "activation_release_requested": False,
        "attempt_count": 1,
        "max_attempts": 10,
        "status": "number_acquired",
        "logs": [],
    }])

    class Client:
        def __init__(self):
            self.version = "2.16.1"
            self.app_build = "2161"
            self.proxy = ""
            self.auth = SimpleNamespace(access_token="access", refresh_token="refresh")

        def refresh_token(self):
            return {"status": 200, "body": {"data": {}}}

        def phone_change_request_otp(self, _phone, _pin):
            return {
                "status": 400,
                "body": {"errors": [{"code": "GoPay-1000", "message": "Internal server error"}]},
            }

    monkeypatch.setattr(server, "_find_gopay_account", lambda _phone: (account, 0))
    monkeypatch.setattr(server, "_gopay_client_from_account", lambda _account, _phone: Client())
    monkeypatch.setattr(server, "_save_gopay_account_tokens_and_pin", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_log_phone_change_network", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_resolve_phone_change_proxy", lambda *_args, **_kwargs: ("", {}))
    monkeypatch.setattr(sms_helpers, "get_sms_api_key", lambda _value="": "secret-key")
    monkeypatch.setattr(sms_helpers, "sms_get_number", lambda _key: pytest.fail("must not buy another number"))
    cancelled = []
    monkeypatch.setattr(server, "_cancel_sms_activation_with_retry", lambda _key, aid: cancelled.append(aid))

    server._run_smsbower_phone_change("system-error")

    task = json.loads(server.PHONE_CHANGE_TASKS_FILE.read_text(encoding="utf-8"))["tasks"][0]
    assert task["status"] == "failed"
    assert task["attempt_count"] == 1
    assert "GoPay-1000" in task["message"]
    assert cancelled == ["333333"]
