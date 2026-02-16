from __future__ import annotations

import pytest
from starlette.requests import Request

import app


def _build_request(*, client_host: str, headers: dict[str, str] | None = None) -> Request:
    headers_items: list[tuple[bytes, bytes]] = []
    headers_items.append((b"host", b"testserver"))

    if headers:
        for k, v in headers.items():
            headers_items.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.3", "version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/auth/login",
        "raw_path": b"/auth/login",
        "query_string": b"",
        "headers": headers_items,
        "client": (client_host, 12345),
        "server": ("testserver", 80),
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, _receive)


def _reset_env(monkeypatch: pytest.MonkeyPatch, *, public_tunnel: str = "0") -> None:
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("AUTH_MODE", "cookie")
    monkeypatch.setenv("SESSION_SECRET", "test-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("DEV_PASSWORD", "dev114514")
    monkeypatch.setenv("OPERATOR_PASSWORD", "operator")
    monkeypatch.setenv("VIEWER_PASSWORD", "viewer")
    monkeypatch.setenv("PUBLIC_TUNNEL", public_tunnel)

    # settings キャッシュを確実に捨てて、env を反映させる
    if hasattr(app, "_SETTINGS"):
        app._SETTINGS = None  # type: ignore[attr-defined]

    app.init_settings()

    # state がある場合だけ安全に書き込む（環境差で落ちにくい）
    settings = app.get_settings()
    if hasattr(app, "app") and hasattr(app.app, "state"):
        app.app.state.mode = settings.mode  # type: ignore[attr-defined]


def test_dev_password_allowed_on_loopback(monkeypatch: pytest.MonkeyPatch):
    _reset_env(monkeypatch, public_tunnel="0")
    req = _build_request(client_host="127.0.0.1")
    assert app._dev_password_allowed(req) is True


def test_dev_password_rejected_on_remote_ip(monkeypatch: pytest.MonkeyPatch):
    _reset_env(monkeypatch, public_tunnel="0")
    req = _build_request(client_host="8.8.8.8")
    assert app._dev_password_allowed(req) is False


def test_dev_password_rejected_when_xff_remote_even_if_seen_as_loopback(monkeypatch: pytest.MonkeyPatch):
    """
    nginx/リバプロ越しの典型：
    request.client.host が 127 に見えるが、XFF は外部IP。
    ここで通ると事故るので、必ず False。
    """
    _reset_env(monkeypatch, public_tunnel="0")
    req = _build_request(
        client_host="127.0.0.1",
        headers={"x-forwarded-for": "203.0.113.9"},
    )
    assert app._dev_password_allowed(req) is False


def test_dev_password_always_rejected_when_public_tunnel(monkeypatch: pytest.MonkeyPatch):
    """
    start.py が PUBLIC_TUNNEL=1 を立てる運用前提。
    これが True なら、loopback でも問答無用で禁止。
    """
    _reset_env(monkeypatch, public_tunnel="1")
    req = _build_request(client_host="127.0.0.1")
    assert app._dev_password_allowed(req) is False
