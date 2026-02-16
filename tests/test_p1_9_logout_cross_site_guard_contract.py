# tests/test_p1_9_logout_cross_site_guard_contract.py

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app
from tests.helpers.contract_utils import reset_settings, set_cookie_lines


def _set_min_env(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_settings(
        monkeypatch,
        MODE="local",
        AUTH_MODE="cookie",
        ALLOW_LOCAL_JSON_NOAUTH="1",
        SESSION_SECRET="test-secret",
        ADMIN_PASSWORD="admin",
        DEV_PASSWORD="dev",
        CSP_MODE="off",
    )


def test_logout_blocks_cross_site_origin(monkeypatch: pytest.MonkeyPatch):
    _set_min_env(monkeypatch)
    with TestClient(app.app) as c:
        r = c.post("/auth/logout", headers={"Origin": "https://evil.example", "Accept": "application/json"})
        assert r.status_code == 403


def test_logout_allows_same_origin(monkeypatch: pytest.MonkeyPatch):
    _set_min_env(monkeypatch)
    with TestClient(app.app) as c:
        r = c.post("/auth/logout", headers={"Origin": "http://testserver", "Accept": "application/json"})
        assert r.status_code == 200
        assert r.json().get("ok") is True


def test_logout_blocks_cross_site_fetch_metadata_when_present(monkeypatch: pytest.MonkeyPatch):
    _set_min_env(monkeypatch)
    with TestClient(app.app) as c:
        r = c.post("/auth/logout", headers={"Sec-Fetch-Site": "cross-site", "Accept": "application/json"})
        assert r.status_code == 403


def test_logout_allows_non_browser_clients_without_origin_and_does_not_clear_cookie_when_absent(monkeypatch: pytest.MonkeyPatch):
    """
    Contract:
    - Origin が無い正当クライアント（CLI等）は通す
    - ただし cookie が来ていない場合、session cookie deletion を返さない
      （嫌がらせログアウトの抜け筋を減らす）
    """
    _set_min_env(monkeypatch)
    with TestClient(app.app) as c:
        r = c.post("/auth/logout", headers={"Accept": "application/json"})
        assert r.status_code == 200
        assert r.json().get("ok") is True

        lines = set_cookie_lines(r)
        assert all(not l.lower().startswith(app.SESSION_COOKIE.lower() + "=") for l in lines), lines
