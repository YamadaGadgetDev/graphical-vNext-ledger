# tests/test_p1_6_session_rate_audit_contract.py

from __future__ import annotations

import os
from datetime import datetime
from http.cookiejar import CookieJar

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

import app


# -----------------------------
# Header/Cookie helpers
# -----------------------------

def _set_cookie_lines(response) -> list[str]:
    """Return Set-Cookie header lines across httpx/requests-style test clients."""
    h = response.headers
    # httpx.Headers
    if hasattr(h, "get_list"):
        return [str(v) for v in h.get_list("set-cookie")]
    # requests-like
    if hasattr(h, "getlist"):
        return [str(v) for v in h.getlist("set-cookie")]
    v = h.get("set-cookie")
    return [str(v)] if v else []


def _pop_cookie_value_one(client: TestClient, name: str, *, prefer_domain: str = "testserver") -> str:
    """
    Get one cookie value without CookieConflict, then delete all cookies with the same name
    across all domain/path scopes to avoid test pollution.
    """
    jar: CookieJar = client.cookies.jar  # type: ignore[attr-defined]

    matches = [c for c in jar if c.name == name]
    assert matches, f"cookie not found: {name}"

    # Pick order:
    # 1) exact prefer_domain
    # 2) host-only (domain_specified=False)
    # 3) first
    picked = next((c for c in matches if (c.domain or "") == prefer_domain), None)
    if picked is None:
        picked = next((c for c in matches if not getattr(c, "domain_specified", False)), None)
    if picked is None:
        picked = matches[0]

    value = picked.value
    assert value is not None, f"cookie value is None: {name}"

    # Clean up all same-name cookies to avoid cross-test mixing
    for c in list(matches):
        try:
            jar.clear(domain=c.domain, path=c.path, name=c.name)  # type: ignore[arg-type]
        except KeyError:
            pass

    return value


# -----------------------------
# Real Starlette Request builder (type-checker friendly)
# -----------------------------

def _build_request(
    *,
    scheme: str = "http",
    client_host: str = "127.0.0.1",
    path: str = "/",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    """Create a real Starlette Request (so type checkers stay happy)."""
    headers_items: list[tuple[bytes, bytes]] = []

    if headers:
        for k, v in headers.items():
            headers_items.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers_items.append((b"cookie", cookie_str.encode("latin-1")))

    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers_items,
        "client": (client_host, 12345),
        "server": ("testserver", 80),
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, _receive)


def _set_mode_for_test(monkeypatch: pytest.MonkeyPatch, mode: str):
    monkeypatch.setenv("MODE", mode)

    # テストの都合で最低限だけ入れる（既存仕様に合わせて調整してOK）
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("OPERATOR_PASSWORD", "operator")
    monkeypatch.setenv("VIEWER_PASSWORD", "viewer")
    monkeypatch.setenv("SESSION_SECRET", "test-secret")

    # ★重要：prod では DEV_PASSWORD を絶対に入れない（契約）
    if mode == "prod":
        monkeypatch.delenv("DEV_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("DEV_PASSWORD", "dev")

    # settings を読み直すならここでクリア（既存実装に合わせて）
    if hasattr(app, "_SETTINGS"):
        app._SETTINGS = None
    app.init_settings()


# -----------------------------
# Contracts
# -----------------------------

def test_session_cookie_secure_flag_contract_prod_only(monkeypatch: pytest.MonkeyPatch):
    """Contract: Secure cookies only when MODE=prod AND request is https."""
    # local mode + http => not Secure
    _set_mode_for_test(monkeypatch, "local")
    req_local = _build_request(scheme="http")
    resp_local = Response("ok")
    app._issue_session_cookie(resp_local, req_local, {"role": "dev"})
    set_cookie_local = resp_local.headers.get("set-cookie", "").lower()
    assert "secure" not in set_cookie_local

    # prod + https => Secure
    _set_mode_for_test(monkeypatch, "prod")
    req_prod = _build_request(scheme="https")
    resp_prod = Response("ok")
    app._issue_session_cookie(resp_prod, req_prod, {"role": "dev"})
    set_cookie_prod = resp_prod.headers.get("set-cookie", "").lower()
    assert "secure" in set_cookie_prod


def test_login_issues_session_and_csrf_cookies(client):
    """Contract: login sets session cookie (HttpOnly) and CSRF cookie (not HttpOnly)."""
    r = client.post(
        "/auth/login",
        json={"password": os.getenv("DEV_PASSWORD", "dev")},
        headers={"accept": "application/json"},
    )
    assert r.status_code == 200

    joined = "\n".join(_set_cookie_lines(r)).lower()

    assert app.SESSION_COOKIE.lower() in joined
    assert "httponly" in joined  # session cookie
    assert app.CSRF_COOKIE.lower() in joined

    # CSRF cookie is explicitly not HttpOnly
    csrf_lines = [line for line in joined.split("\n") if app.CSRF_COOKIE.lower() in line]
    assert csrf_lines, "CSRF Set-Cookie header missing"
    assert "httponly" not in csrf_lines[0]


def test_session_cookie_is_signed_and_tamper_is_rejected(client):
    """Contract: changing a single byte in session cookie invalidates the session."""
    r = client.post(
        "/auth/login",
        json={"password": os.getenv("DEV_PASSWORD", "dev")},
        headers={"accept": "application/json"},
    )
    assert r.status_code == 200

    # ✅ avoid CookieConflict; also clean up so this test is self-contained
    session_cookie = _pop_cookie_value_one(client, app.SESSION_COOKIE, prefer_domain="testserver")

    tampered = session_cookie[:-1] + ("A" if session_cookie[-1] != "A" else "B")

    other = TestClient(app.app)
    # domain/path fixed so we don't accidentally create duplicates
    other.cookies.set(app.SESSION_COOKIE, tampered, domain="testserver", path="/")

    r2 = other.get("/auth/me", headers={"accept": "application/json"})
    assert r2.status_code in {401, 403}


def test_csrf_contract_cookie_present_requires_header_for_browsery_accept(client):
    """Contract: when CSRF cookie exists, Accept */* (browsery) requires x-csrf-token."""
    r = client.post(
        "/auth/login",
        json={"password": os.getenv("DEV_PASSWORD", "dev")},
        headers={"accept": "application/json"},
    )
    assert r.status_code == 200

    csrf = client.cookies.get(app.CSRF_COOKIE)
    assert csrf

    # Missing CSRF header + ambiguous Accept => 403 (browsery)
    r1 = client.post("/scan", json={"root": "."}, headers={"accept": "*/*"})
    assert r1.status_code == 403

    # With header => OK (contract is "not 403")
    r2 = client.post(
        "/scan",
        json={"root": "."},
        headers={"accept": "*/*", app.CSRF_HEADER: csrf},
    )
    assert r2.status_code in {200, 202}


def test_scan_lock_contract_is_exclusive_and_fail_fast(test_db):
    """Contract: scan lock is exclusive and fail-fast (second acquire returns None)."""
    now = datetime.now().isoformat(timespec="seconds")
    with app.db() as con:
        t1 = app._try_acquire_scan_lock(con, now=now, full=False)
        assert t1 is not None

        t2 = app._try_acquire_scan_lock(con, now=now, full=False)
        assert t2 is None

        app._release_scan_lock(con, token=t1)


def test_audit_log_contract_note_events_recorded_on_patch(client):
    """Contract: PATCH /notes/{slug} writes note_events rows for each effective change."""
    r = client.post(
        "/auth/login",
        json={"password": os.getenv("DEV_PASSWORD", "dev")},
        headers={"accept": "application/json"},
    )
    assert r.status_code == 200

    before = client.get("/notes/test", headers={"accept": "application/json"}).json()["note"]["events"]
    before_n = len(before)

    # Update priority (Accept JSON => CSRF skipped by contract)
    r2 = client.patch(
        "/notes/test",
        json={"priority": 2},
        headers={"accept": "application/json"},
    )
    assert r2.status_code == 200
    assert r2.json().get("priority") == 2

    after = client.get("/notes/test", headers={"accept": "application/json"}).json()["note"]["events"]
    assert len(after) == before_n + 1
    latest = after[0]
    assert latest["event_type"] == "priority"
    assert latest["new_value"] == "2"


def test_audit_log_contract_empty_patch_is_noop_and_writes_no_event(client):
    """Contract: empty PATCH {} returns 204 and does not create note_events."""
    r = client.post(
        "/auth/login",
        json={"password": os.getenv("DEV_PASSWORD", "dev")},
        headers={"accept": "application/json"},
    )
    assert r.status_code == 200

    before = client.get("/notes/test", headers={"accept": "application/json"}).json()["note"]["events"]
    before_n = len(before)

    r2 = client.patch(
        "/notes/test",
        json={},
        headers={"accept": "application/json"},
    )
    assert r2.status_code == 204

    after = client.get("/notes/test", headers={"accept": "application/json"}).json()["note"]["events"]
    assert len(after) == before_n
