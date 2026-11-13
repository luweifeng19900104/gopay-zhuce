import pytest

import gopay.server as server
from opai.core import captcha_provider, gopay_browser_payment, gojek_client
from opai.core.proxy_utils import normalize_proxy_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("proxy.example.com:8080:user:pass", "http://user:pass@proxy.example.com:8080"),
        ("proxy.example.com:8080@user:pass", "http://user:pass@proxy.example.com:8080"),
        ("user:pass:proxy.example.com:8080", "http://user:pass@proxy.example.com:8080"),
        ("user:pass@proxy.example.com:8080", "http://user:pass@proxy.example.com:8080"),
    ],
)
def test_common_proxy_formats_normalize_to_http(raw, expected):
    assert normalize_proxy_url(raw) == expected
    assert gojek_client.normalize_proxy_url(raw) == expected


def test_proxy_normalization_preserves_protocol_and_supports_plain_host_port():
    assert normalize_proxy_url("https://user:pass@proxy.example.com:8443") == "https://user:pass@proxy.example.com:8443"
    assert normalize_proxy_url("socks5://user:pass@proxy.example.com:1080") == "socks5://user:pass@proxy.example.com:1080"
    assert normalize_proxy_url("proxy.example.com:8080") == "http://proxy.example.com:8080"


def test_proxy_pool_normalizes_then_deduplicates_all_four_formats():
    values = [
        "proxy.example.com:8080:user:pass",
        "proxy.example.com:8080@user:pass",
        "user:pass:proxy.example.com:8080",
        "user:pass@proxy.example.com:8080",
    ]
    assert server._parse_proxy_list(values) == ["http://user:pass@proxy.example.com:8080"]


@pytest.mark.parametrize(
    "raw",
    [
        "proxy.example.com:8080:user:pass",
        "proxy.example.com:8080@user:pass",
        "user:pass:proxy.example.com:8080",
        "user:pass@proxy.example.com:8080",
    ],
)
def test_browser_and_captcha_proxy_settings_accept_all_formats(raw):
    expected = {
        "server": "http://proxy.example.com:8080",
        "username": "user",
        "password": "pass",
    }
    assert gopay_browser_payment._proxy_settings(raw) == expected
    assert captcha_provider._browser_proxy_settings(raw) == expected
