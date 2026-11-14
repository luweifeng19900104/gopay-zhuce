import json
import shutil
import subprocess
from pathlib import Path

import pytest


HTML_PATH = Path("gopay/index.html")


def _parse_proxy(raw: str) -> dict[str, str]:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the proxy provider UI parser test")
    script = r"""
const fs = require('fs');
const html = fs.readFileSync('gopay/index.html', 'utf8');
function load(name) {
  const start = html.indexOf('function ' + name + '(');
  if (start < 0) throw new Error('missing function ' + name);
  const next = html.indexOf('\n    function ', start + 10);
  (0, eval)(html.slice(start, next < 0 ? html.length : next));
}
[
  'proxyPort',
  'proxyHostScore',
  'splitProxyHostPort',
  'normalizeProxyValue',
  'parseProxyCredential',
  'parseProxyInputValue',
].forEach(load);
process.stdout.write(JSON.stringify(parseProxyInputValue(process.argv[1])));
"""
    result = subprocess.run(
        [node, "-e", script, raw],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_udeal_proxy_paste_is_split_into_structured_fields() -> None:
    parsed = _parse_proxy(
        "us.udealproxy.com:6666:"
        "userId-7261-custom-19992-region-id-session-QeJrT-sessTime-120:"
        "IQ7eUy"
    )

    assert parsed == {
        "scheme": "http",
        "host": "us.udealproxy.com",
        "port": "6666",
        "username": "userId-7261-custom-19992-region",
        "password": "IQ7eUy",
        "usernameTemplate": (
            "{username}-{country_lower}-session-{session}-sessTime-{ttl}"
        ),
        "passwordTemplate": "{password}",
        "ttl": "120",
    }


def test_proxy_provider_form_wires_live_parsing_and_structured_save() -> None:
    html = HTML_PATH.read_text(encoding="utf-8")

    assert 'proxyProviderURLTemplates").addEventListener("input"' in html
    assert 'proxyProviderParseTimer=setTimeout(parseCustomProxyInput,180)' in html
    assert 'url_templates:parsedSingle?"":templates' in html
