import http.client
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import gopay.server as gopay_server
from opai.core.file_utils import atomic_write_json
from opai.core import sms_helpers


def _serve(handler):
    server = gopay_server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_main_http_security_headers_origin_and_body_limit():
    server, thread = _serve(gopay_server.Handler)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        response.read()
        assert response.status == 200
        assert response.getheader("Content-Security-Policy")
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("X-Frame-Options") == "DENY"
        conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/api/accounts", headers={"Origin": "https://evil.example"})
        response = conn.getresponse()
        assert response.status == 403
        assert json.loads(response.read()) == {"error": "untrusted_origin"}
        conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request(
            "POST",
            "/api/phone-pool/import",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(gopay_server.MAX_JSON_BODY_BYTES + 1)},
        )
        response = conn.getresponse()
        assert response.status == 413
        assert json.loads(response.read())["error"] == "request_too_large"
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_imported_sms_url_rejects_local_and_file_schemes(monkeypatch):
    with pytest.raises(ValueError, match="HTTPS"):
        sms_helpers.validate_imported_sms_url("file:///tmp/code.txt")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="本机"):
        sms_helpers.validate_imported_sms_url("https://sms.example.test/code")


def test_atomic_write_json_replaces_complete_document(tmp_path):
    path = tmp_path / "nested" / "state.json"
    atomic_write_json(path, {"status": "first"})
    atomic_write_json(path, {"status": "second", "rows": [1, 2, 3]})
    assert json.loads(path.read_text(encoding="utf-8")) == {"status": "second", "rows": [1, 2, 3]}
    assert not list(path.parent.glob(f".{path.name}.*.tmp"))


def test_runtime_env_is_loaded_before_protocol_imports():
    runtime_path = Path("config/runtime.env")
    pairs = {}
    for raw in runtime_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            pairs[key.strip()] = value.strip().strip('"').strip("'")
    expected = pairs.get("OPAI_GOPAY_APP_VERSION")
    if not expected:
        pytest.skip("runtime.env does not define OPAI_GOPAY_APP_VERSION")
    env = os.environ.copy()
    env.pop("OPAI_GOPAY_APP_VERSION", None)
    env["PYTHONPATH"] = str(Path("app/src").resolve())
    env["PYTHONUTF8"] = "1"
    probe = subprocess.run(
        [sys.executable, "-c", "import gopay.server; from opai.core import gojek_client; print(gojek_client.GOPAY_APP_VERSION)"],
        cwd=Path.cwd(), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == expected
