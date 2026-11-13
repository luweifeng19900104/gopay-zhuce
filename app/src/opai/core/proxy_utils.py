"""Proxy input normalization shared by registration and payment flows."""
from __future__ import annotations


def _port(value: str) -> str:
    text = str(value or "").strip()
    if not text.isdigit():
        return ""
    number = int(text)
    return text if 1 <= number <= 65535 else ""


def _host_score(value: str) -> int:
    text = str(value or "").strip().strip("[]")
    if not text:
        return 0
    score = 0
    if text.lower() == "localhost":
        score += 3
    if "." in text or ":" in text:
        score += 2
    if text.replace("-", "").replace("_", "").isalnum():
        score += 1
    return score


def _host_port(value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if text.startswith("[") and "]:" in text:
        host, port = text.rsplit(":", 1)
    elif ":" in text:
        host, port = text.rsplit(":", 1)
    else:
        return "", ""
    port = _port(port)
    return (host.strip(), port) if host.strip() and port else ("", "")


def normalize_proxy_url(raw: str) -> str:
    """Return a proxy URL, accepting the common four-field provider formats.

    Inputs without a scheme default to HTTP. Supported credential layouts are:
    host:port:user:password, host:port@user:password,
    user:password:host:port, and user:password@host:port.
    """
    value = str(raw or "").strip()
    if not value:
        return ""
    if "://" in value:
        return value

    if value.count("@") == 1:
        left, right = value.split("@", 1)
        left_host, left_port = _host_port(left)
        right_host, right_port = _host_port(right)
        if left_host and left_port and ":" in right:
            user, password = right.split(":", 1)
            if user and password and (
                not right_port or _host_score(left_host) >= _host_score(right_host)
            ):
                return f"http://{user}:{password}@{left_host}:{left_port}"
        return f"http://{value}"

    parts = value.split(":")
    if len(parts) >= 4:
        first_port = _port(parts[1])
        last_port = _port(parts[-1])
        first_host = parts[0].strip()
        last_host = parts[-2].strip()

        host_first = bool(first_host and first_port and parts[2].strip() and parts[3:])
        auth_first = bool(parts[0].strip() and parts[1:-2] and last_host and last_port)
        if host_first and auth_first:
            host_first = _host_score(first_host) >= _host_score(last_host)
            auth_first = not host_first

        if host_first:
            user = parts[2].strip()
            password = ":".join(parts[3:])
            if password:
                return f"http://{user}:{password}@{first_host}:{first_port}"
        if auth_first:
            user = parts[0].strip()
            password = ":".join(parts[1:-2])
            if password:
                return f"http://{user}:{password}@{last_host}:{last_port}"

    return f"http://{value}"
