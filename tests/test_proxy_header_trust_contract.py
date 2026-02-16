"""tests/test_proxy_header_trust_contract.py

Contract tests for proxy header trust boundaries.

What we want to pin:
- X-Forwarded-* must be trusted ONLY when the immediate client is a trusted proxy.
- Otherwise, spoofable headers must be ignored.

We test this at the helper-function level because Starlette TestClient always uses
"testclient" as client.host (treated as trusted for testability).
"""

from __future__ import annotations

import importlib

from starlette.requests import Request


def _reload_app(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.sqlite3"))
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("AUTH_MODE", "cookie")
    monkeypatch.setenv("SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("DEV_PASSWORD", "dev")
    monkeypatch.delenv("P1_CONTRACT_VERIFIED", raising=False)

    import app as appmod

    importlib.reload(appmod)
    return appmod


def _make_request(*, client_host: str, scheme: str = "http", headers: dict[str, str] | None = None) -> Request:
    hdrs = []
    for k, v in (headers or {}).items():
        hdrs.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.3", "version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": scheme,
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": hdrs,
        "client": (client_host, 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_is_https_ignores_xfp_when_client_untrusted(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path)

    req = _make_request(
        client_host="8.8.8.8",  # not in TRUSTED_PROXY_CIDRS by default
        scheme="http",
        headers={"x-forwarded-proto": "https"},
    )

    assert appmod._is_trusted_proxy(req) is False
    assert appmod._is_https(req) is False, "untrusted client must not be able to spoof HTTPS"


def test_is_https_trusts_xfp_when_client_is_trusted_proxy(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path)

    req = _make_request(
        client_host="127.0.0.1",  # default TRUSTED_PROXY_CIDRS includes 127.0.0.1/32
        scheme="http",
        headers={"x-forwarded-proto": "https"},
    )

    assert appmod._is_trusted_proxy(req) is True
    assert appmod._is_https(req) is True


def test_is_local_host_requires_xff_leftmost_local_when_behind_trusted_proxy(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path)

    # Immediate client is a trusted proxy, but the originating client (xff leftmost) is not local.
    req = _make_request(
        client_host="127.0.0.1",
        scheme="http",
        headers={"x-forwarded-for": "8.8.8.8, 127.0.0.1"},
    )

    assert appmod._is_trusted_proxy(req) is True
    assert appmod._is_local_host(req) is False, "trusted proxy + non-local XFF must not be treated as localhost"


def test_is_local_host_allows_local_xff_leftmost_when_behind_trusted_proxy(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path)

    req = _make_request(
        client_host="127.0.0.1",
        scheme="http",
        headers={"x-forwarded-for": "127.0.0.1, 127.0.0.1"},
    )

    assert appmod._is_trusted_proxy(req) is True
    assert appmod._is_local_host(req) is True
