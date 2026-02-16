"""tests/test_content_negotiation_contract.py

Contract tests for minimal, high-value content negotiation behavior.

We do NOT attempt to cover every Accept/Content-Type combination.
Instead we pin the behaviors that prevent past regressions:
- /notes/table must return HTML when Accept: text/html
- /notes/table must return JSON when Accept: application/json
- Both variants must include `Vary: Accept` to prevent cache poisoning.

These tests use module reload to avoid relying on any global conftest settings.
"""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


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


def test_notes_table_content_negotiation_and_vary(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path)

    # Seed at least one note via scan (keeps the test resilient to schema evolution).
    (tmp_path / "a.py").write_text("# NOTE(vNext): nego_test\n", encoding="utf-8")

    with TestClient(appmod.app) as c:
        # Login to pass /scan and /notes/table authz.
        r = c.post("/auth/login", json={"password": "admin"})
        assert r.status_code == 200

        # Cookie auth + /scan は CSRF ヘッダ必須（UI の ui.js 相当を再現）
        csrf = c.cookies.get("csrf_token")
        assert csrf, "login must set csrf_token cookie"

        r = c.post(
            "/scan?full=0",
            headers={"accept": "application/json", "x-csrf-token": csrf},
            json={"root": str(tmp_path)},
        )
        assert r.status_code == 200

        # JSON variant
        rj = c.get("/notes/table", headers={"accept": "application/json"})
        assert rj.status_code == 200
        assert "application/json" in (rj.headers.get("content-type") or "")
        assert "Accept" in (rj.headers.get("Vary") or ""), "JSON must set Vary: Accept"
        assert isinstance(rj.json().get("notes"), list)

        # HTML variant
        rh = c.get("/notes/table", headers={"accept": "text/html"})
        assert rh.status_code == 200
        assert "text/html" in (rh.headers.get("content-type") or "")
        assert "Accept" in (rh.headers.get("Vary") or ""), "HTML must set Vary: Accept"
        assert "<table" in rh.text.lower(), "HTML response should include a table"
