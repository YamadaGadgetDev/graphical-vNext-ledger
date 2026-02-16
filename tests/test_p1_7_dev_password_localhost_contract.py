from __future__ import annotations

import pytest
from starlette.requests import Request

import app


def _build_request(
    *,
    client_host: str,
    host_header: str = "example.com",  # "host" でも "host:port" でもOK（serverはhost部だけ使う）
    scheme: str = "http",
    path: str = "/auth/login",
    headers: dict[str, str] | None = None,
) -> Request:
    """
    Starlette のバージョン差（Request(scope) だけでOK/receive必須）を吸収するため、
    receive を必ず渡して Request を生成する。

    - host は headers の Host を使う（scope['server'] もそれに合わせる）
    - host_header は "host" / "host:port" どちらでもOK（serverはhost部だけ使う）
    """
    headers_items: list[tuple[bytes, bytes]] = []

    # Host は常に入れる
    headers_items.append((b"host", host_header.encode("latin-1")))

    if headers:
        for k, v in headers.items():
            headers_items.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    server_host = host_header.split(":", 1)[0]

    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.3", "version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers_items,
        "client": (client_host, 12345),
        "server": (server_host, 80),
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, _receive)


def test_dev_password_allowed_on_localhost(p1_7_cookie_env):
    dev_pw = p1_7_cookie_env["DEV_PASSWORD"]

    req = app.LoginRequest(password=dev_pw)
    request = _build_request(client_host="127.0.0.1", host_header="localhost")

    resp = app.login(request, req)
    assert resp.status_code == 200


def test_dev_password_denied_from_non_localhost(p1_7_cookie_env):
    dev_pw = p1_7_cookie_env["DEV_PASSWORD"]

    req = app.LoginRequest(password=dev_pw)
    request = _build_request(client_host="8.8.8.8", host_header="ngrok.example")

    with pytest.raises(app.HTTPException) as e:
        app.login(request, req)

    assert e.value.status_code == 401


def test_dev_password_denied_even_if_host_is_localhost_but_client_is_remote(p1_7_cookie_env):
    dev_pw = p1_7_cookie_env["DEV_PASSWORD"]

    req = app.LoginRequest(password=dev_pw)
    request = _build_request(client_host="8.8.8.8", host_header="localhost")

    with pytest.raises(app.HTTPException) as e:
        app.login(request, req)

    assert e.value.status_code == 401
