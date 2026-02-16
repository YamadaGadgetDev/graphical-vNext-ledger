from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
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


def _reset_env(monkeypatch: pytest.MonkeyPatch, *, public_tunnel: str) -> None:
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("AUTH_MODE", "cookie")
    monkeypatch.setenv("SESSION_SECRET", "s")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("OPERATOR_PASSWORD", "operator")
    monkeypatch.setenv("VIEWER_PASSWORD", "viewer")
    monkeypatch.setenv("DEV_PASSWORD", "dev")
    monkeypatch.setenv("PUBLIC_TUNNEL", public_tunnel)

    if hasattr(app, "_SETTINGS"):
        app._SETTINGS = None  # type: ignore[attr-defined]

    app.init_settings()

    settings = app.get_settings()
    if hasattr(app, "app") and hasattr(app.app, "state"):
        app.app.state.mode = settings.mode  # type: ignore[attr-defined]


def test_public_tunnel_forces_dev_password_denied_even_on_loopback(monkeypatch: pytest.MonkeyPatch):
    """
    PUBLIC_TUNNEL=1 のときは、loopback であっても dev は絶対に禁止。
    （TestClient の host 揺れに依存せず、Request 直生成で契約固定）
    """
    _reset_env(monkeypatch, public_tunnel="1")
    req = _build_request(client_host="127.0.0.1")
    assert app._dev_password_allowed(req) is False


def test_public_tunnel_does_not_break_admin_login(monkeypatch: pytest.MonkeyPatch):
    """
    PUBLIC_TUNNEL=1 は dev を閉じるだけで、admin/operator/viewer のログインまで殺さない。
    """
    _reset_env(monkeypatch, public_tunnel="1")
    c = TestClient(app.app)
    r = c.post("/auth/login", json={"password": "admin"}, headers={"accept": "application/json"})
    assert r.status_code == 200


def test_public_tunnel_denies_dev_login(monkeypatch: pytest.MonkeyPatch):
    """
    PUBLIC_TUNNEL=1 なら /auth/login の dev は必ず拒否される。
    ※ TestClient の client.host は loopback にならないことが多いが、
       いずれにせよ public_tunnel の時点で禁止なのでここは安定して拒否になる。
    """
    _reset_env(monkeypatch, public_tunnel="1")
    c = TestClient(app.app)
    r = c.post("/auth/login", json={"password": "dev"}, headers={"accept": "application/json"})
    assert r.status_code in {401, 403}
