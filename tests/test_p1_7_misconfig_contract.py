# tests/test_p1_7_misconfig_contract.py

from __future__ import annotations

import pytest
import app

from tests.helpers.contract_utils import reset_settings


def test_prod_refuses_allow_local_json_noauth(monkeypatch: pytest.MonkeyPatch):
    # MODE=prod で ALLOW_LOCAL_JSON_NOAUTH=1 は即死（事故ルート防止）
    monkeypatch.setenv("MODE", "prod")
    monkeypatch.setenv("REQUIRE_AUTH_ALL", "1")
    monkeypatch.setenv("DEV_PASSWORD", "")          # prodでは空必須
    monkeypatch.setenv("SESSION_SECRET", "s")       # prodでは必須
    monkeypatch.setenv("ALLOW_LOCAL_JSON_NOAUTH", "1")

    app._SETTINGS = None  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        app.init_settings()


def test_prod_refuses_dev_password_set(monkeypatch: pytest.MonkeyPatch):
    # prodでDEV_PASSWORD残留 → 即死
    monkeypatch.setenv("MODE", "prod")
    monkeypatch.setenv("REQUIRE_AUTH_ALL", "1")
    monkeypatch.setenv("DEV_PASSWORD", "dev")       # ←残ってたら事故
    monkeypatch.setenv("SESSION_SECRET", "s")

    app._SETTINGS = None  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        app.init_settings()


def test_prod_requires_session_secret(monkeypatch: pytest.MonkeyPatch):
    # prodでSESSION_SECRET無し → 即死
    monkeypatch.setenv("MODE", "prod")
    monkeypatch.setenv("REQUIRE_AUTH_ALL", "1")
    monkeypatch.setenv("DEV_PASSWORD", "")
    monkeypatch.delenv("SESSION_SECRET", raising=False)

    app._SETTINGS = None  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        app.init_settings()


def test_local_refuses_require_auth_all(monkeypatch: pytest.MonkeyPatch):
    # localでREQUIRE_AUTH_ALL=1 は禁止（運用事故防止）
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("REQUIRE_AUTH_ALL", "1")

    app._SETTINGS = None  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        app.init_settings()


def test_local_refuses_apikey_auth_mode(monkeypatch: pytest.MonkeyPatch):
    # localはcookie-only（ここがブレるとテストも本体も壊れる）
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("AUTH_MODE", "apikey")

    app._SETTINGS = None  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError):
        app.init_settings()
