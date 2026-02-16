# tests/test_p1_9_export_scan_history_auth_contract.py

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app
from tests.helpers.contract_utils import reset_settings


def test_scan_history_prod_requires_auth(monkeypatch: pytest.MonkeyPatch):
    """
    Contract (prod):
    - /export/scan_history must NOT be accessible without auth.
    """
    reset_settings(
        monkeypatch,
        MODE="prod",
        AUTH_MODE="cookie",
        P1_CONTRACT_VERIFIED="1",
        REQUIRE_AUTH_ALL="1",
        ALLOW_LOCAL_JSON_NOAUTH="0",
        SESSION_SECRET="x" * 64,
        ADMIN_PASSWORD="adminpw",
        DEV_PASSWORD="",  # prod では禁止
        OPERATOR_PASSWORD="operator",
        VIEWER_PASSWORD="viewer",
        CSP_MODE="off",
    )

    with TestClient(app.app) as c:
        r = c.get("/export/scan_history", headers={"Accept": "application/json"})
        assert r.status_code in (401, 403)


def test_scan_history_local_allows_noauth_when_allow_local_json_noauth_enabled(monkeypatch: pytest.MonkeyPatch):
    """
    Contract (local convenience):
    - MODE=local かつ ALLOW_LOCAL_JSON_NOAUTH=1 のとき、
      /export/scan_history は localhost + JSON 明示なら未ログインで通る。
    """
    reset_settings(
        monkeypatch,
        MODE="local",
        AUTH_MODE="cookie",
        ALLOW_LOCAL_JSON_NOAUTH="1",
        SESSION_SECRET="test-secret",
        ADMIN_PASSWORD="admin",
        DEV_PASSWORD="dev",
        OPERATOR_PASSWORD="operator",
        VIEWER_PASSWORD="viewer",
        CSP_MODE="off",
    )

    with TestClient(app.app) as c:
        r = c.get("/export/scan_history", headers={"Accept": "application/json"})
        assert r.status_code == 200
        assert "recent" in r.json()


def test_scan_history_local_noauth_requires_json_accept(monkeypatch: pytest.MonkeyPatch):
    """
    Contract (local convenience safety):
    - ALLOW_LOCAL_JSON_NOAUTH=1 でも、Accept が text/html のような HTML 優先なら no-auth を許さない
      （_wants_json が True のときだけ例外が開く）。
    """
    reset_settings(
        monkeypatch,
        MODE="local",
        AUTH_MODE="cookie",
        ALLOW_LOCAL_JSON_NOAUTH="1",
        SESSION_SECRET="test-secret",
        ADMIN_PASSWORD="admin",
        DEV_PASSWORD="dev",
        OPERATOR_PASSWORD="operator",
        VIEWER_PASSWORD="viewer",
        CSP_MODE="off",
    )

    with TestClient(app.app) as c:
        r = c.get("/export/scan_history", headers={"Accept": "text/html"})
        assert r.status_code in (401, 403)


def test_scan_history_local_requires_auth_when_allow_local_json_noauth_disabled(monkeypatch: pytest.MonkeyPatch):
    """
    Contract:
    - MODE=local でも ALLOW_LOCAL_JSON_NOAUTH=0 のとき、
      /export/scan_history は未ログインで通してはいけない。
    - operator でログインすれば通る。
    """
    reset_settings(
        monkeypatch,
        MODE="local",
        AUTH_MODE="cookie",
        ALLOW_LOCAL_JSON_NOAUTH="0",
        SESSION_SECRET="test-secret",
        ADMIN_PASSWORD="admin",
        DEV_PASSWORD="dev",
        OPERATOR_PASSWORD="operator",
        VIEWER_PASSWORD="viewer",
        CSP_MODE="off",
    )

    with TestClient(app.app) as c:
        r0 = c.get("/export/scan_history", headers={"Accept": "application/json"})
        assert r0.status_code in (401, 403)

        r1 = c.post("/auth/login", headers={"Accept": "application/json"}, json={"password": "operator"})
        assert r1.status_code == 200

        r2 = c.get("/export/scan_history", headers={"Accept": "application/json"})
        assert r2.status_code == 200
        assert "recent" in r2.json()


def test_scan_history_viewer_is_rejected(monkeypatch: pytest.MonkeyPatch):
    """
    Contract:
    - viewer は /export/scan_history を読めない（operator 以上が必要）
    - かつ、operator は読める（対照群）
    """
    reset_settings(
        monkeypatch,
        MODE="local",
        AUTH_MODE="cookie",
        ALLOW_LOCAL_JSON_NOAUTH="0",
        SESSION_SECRET="test-secret",
        ADMIN_PASSWORD="admin",
        DEV_PASSWORD="dev",
        OPERATOR_PASSWORD="operator",
        VIEWER_PASSWORD="viewer",
        CSP_MODE="off",
    )

    # viewer -> 403
    with TestClient(app.app) as c:
        r1 = c.post("/auth/login", headers={"Accept": "application/json"}, json={"password": "viewer"})
        assert r1.status_code == 200
        assert r1.json().get("role") == "viewer"

        r2 = c.get("/export/scan_history", headers={"Accept": "application/json"})
        assert r2.status_code == 403

    # operator (control) -> 200
    with TestClient(app.app) as c2:
        r3 = c2.post("/auth/login", headers={"Accept": "application/json"}, json={"password": "operator"})
        assert r3.status_code == 200
        assert r3.json().get("role") == "operator"

        r4 = c2.get("/export/scan_history", headers={"Accept": "application/json"})
        assert r4.status_code == 200
        assert "recent" in r4.json()
