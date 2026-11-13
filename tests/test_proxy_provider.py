import http.client
import json
import threading

import pytest

import gopay.server as server
from opai.core import proxy_provider


def configure_store(monkeypatch, tmp_path):
    path = tmp_path / "proxy_providers.json"
    monkeypatch.setenv("OPAI_GOPAY_PROXY_PROVIDERS_FILE", str(path))
    return path


def test_proxy_provider_password_is_hidden_and_templates_resolve(monkeypatch, tmp_path):
    path = configure_store(monkeypatch, tmp_path)
    saved = proxy_provider.save_provider({
        "name": "IPRoyal ID",
        "kind": "iproyal",
        "enabled": True,
        "scheme": "http",
        "host": "proxy.iproyal.net",
        "port": 9000,
        "username": "client-name",
        "username_template": "{username}_area-{country}_session-{session}",
        "password": "private-password",
        "ttl_minutes": 30,
    })
    assert saved["password_configured"] is True
    assert "password" not in saved
    assert "private-password" not in json.dumps(saved)

    proxy_provider.save_bindings([{
        "purpose": "phone_change",
        "enabled": True,
        "provider_id": saved["id"],
        "country": "id",
    }])
    resolved = proxy_provider.resolve_proxy("phone_change", session_id="sticky7")
    assert resolved["provider_name"] == "IPRoyal ID"
    assert resolved["country"] == "ID"
    assert "client-name_area-ID_session-sticky7" in resolved["url"]
    assert "private-password" in resolved["url"]
    assert "private-password" not in resolved["preview"]
    assert "private-password" in path.read_text(encoding="utf-8")


def test_proxy_provider_url_pool_rotates_and_delete_blocks_bound_provider(monkeypatch, tmp_path):
    configure_store(monkeypatch, tmp_path)
    provider = proxy_provider.save_provider({
        "name": "Pool",
        "kind": "custom",
        "enabled": True,
        "url_templates": (
            "host1.example:8000:user:{password}-{country_lower}-session-{session}\n"
            "host2.example:8000:user:{password}-{country_lower}-session-{session}"
        ),
        "password": "secret",
    })
    first = proxy_provider.resolve_proxy("", "ID", provider_id=provider["id"], session_id="s1", index=0)
    second = proxy_provider.resolve_proxy("", "ID", provider_id=provider["id"], session_id="s2", index=1)
    assert "host1.example:8000" in first["url"]
    assert "host2.example:8000" in second["url"]
    assert "id-session-s1" in first["url"]

    proxy_provider.save_bindings([{
        "purpose": "registration",
        "enabled": True,
        "provider_id": provider["id"],
        "country": "ID",
    }])
    with pytest.raises(ValueError, match="业务绑定"):
        proxy_provider.delete_provider(provider["id"])


def test_proxy_provider_http_routes_and_test_endpoint(monkeypatch, tmp_path):
    configure_store(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "opai.core.gojek_client.probe_proxy_egress",
        lambda proxy, timeout_sec=12: {"ok": True, "ip": "203.0.113.9", "status": 200},
    )
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)

    def request(method, path, payload=None):
        body = json.dumps(payload or {}) if payload is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read())

    try:
        status, provider = request("POST", "/api/proxy/providers", {
            "name": "Fixture",
            "kind": "custom",
            "enabled": True,
            "scheme": "http",
            "host": "proxy.example.test",
            "port": 8000,
            "username": "user",
            "password": "secret",
        })
        assert status == 201
        assert provider["password_configured"] is True
        assert "password" not in provider

        status, listed = request("GET", "/api/proxy/providers")
        assert status == 200
        assert listed["providers"][0]["name"] == "Fixture"
        assert "secret" not in json.dumps(listed)

        status, tested = request("POST", f"/api/proxy/providers/{provider['id']}/test", {"country": "ID"})
        assert status == 200
        assert tested["ok"] is True
        assert tested["ip"] == "203.0.113.9"

        status, bound = request("POST", "/api/proxy/bindings", {"bindings": [{
            "purpose": "payment",
            "enabled": True,
            "provider_id": provider["id"],
            "country": "ID",
        }]})
        assert status == 200
        assert bound["bindings"]["payment"]["enabled"] is True
    finally:
        conn.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
