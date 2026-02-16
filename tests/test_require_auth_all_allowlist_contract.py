# tests/test_require_auth_all_allowlist_contract.py
from __future__ import annotations

import importlib.util
import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_isolated_app():
    app_py = _repo_root() / "app.py"
    name = f"_isolated_app_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def _bootstrap(mod) -> None:
    if hasattr(mod, "_SETTINGS"):
        mod._SETTINGS = None  # type: ignore[attr-defined]
    mod.init_settings()
    mod.init_db()
    s = mod.get_settings()
    mod.app.state.csp_mode = s.csp_mode
    mod.app.state.csp_policy = mod._build_csp_policy(s) if s.csp_mode != "off" else None
    mod.app.state.mode = s.mode
    mod.app.state.auth_mode = s.auth_mode
    mod.app.state.require_auth_all = getattr(s, "require_auth_all", False)
    mod.app.state.allow_local_json_noauth = getattr(s, "allow_local_json_noauth", False)
    mod.app.state.csp_use_reporting_api = getattr(s, "csp_use_reporting_api", False)
    mod.app.state.csp_report_uri = getattr(s, "csp_report_uri", "")


def test_require_auth_all_is_rejected_outside_prod_cookie(tmp_path: Path):
    """
    現行実装に合わせた “設定バリデーション” 契約。

    - MODE=local で REQUIRE_AUTH_ALL=1 はエラー
    - AUTH_MODE=apikey で REQUIRE_AUTH_ALL=1 はエラー
    """
    # --- local ---
    os.environ.update(
        {
            "MODE": "local",
            "AUTH_MODE": "cookie",
            "REQUIRE_AUTH_ALL": "1",
            "SESSION_SECRET": "test-secret",
            "ADMIN_PASSWORD": "admin",
            "DB_PATH": str(tmp_path / "a.sqlite3"),
        }
    )
    mod = _load_isolated_app()
    with pytest.raises(RuntimeError):
        mod.init_settings()

    # --- prod + apikey ---
    os.environ.update(
        {
            "MODE": "prod",
            "AUTH_MODE": "apikey",
            "REQUIRE_AUTH_ALL": "1",
            "SESSION_SECRET": "test-secret",
            "ADMIN_PASSWORD": "admin",
            "P1_CONTRACT_VERIFIED": "1",
            "DB_PATH": str(tmp_path / "b.sqlite3"),
        }
    )
    mod = _load_isolated_app()
    with pytest.raises(RuntimeError):
        mod.init_settings()


def test_prod_cookie_require_auth_all_keeps_minimum_public_surface(tmp_path: Path):
    db_path = tmp_path / "ledger.sqlite3"
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "a.md").write_text("# vNext: allowlist-test\n", encoding="utf-8")

    # ★重要：他テストからの残留を消す
    os.environ.pop("DEV_PASSWORD", None)

    os.environ.update(
        {
            "MODE": "prod",
            "AUTH_MODE": "cookie",
            "REQUIRE_AUTH_ALL": "1",
            "ALLOW_LOCAL_JSON_NOAUTH": "0",
            "SESSION_SECRET": "prod-secret",
            "ADMIN_PASSWORD": "admin",
            # prod では DEV_PASSWORD を置かない（契約）
            "OPERATOR_PASSWORD": "operator",
            "VIEWER_PASSWORD": "viewer",
            "P1_CONTRACT_VERIFIED": "1",
            "DB_PATH": str(db_path),
            "LEDGER_REPO_ROOT": str(repo_root),
            "CSP_MODE": "off",
        }
    )

    mod = _load_isolated_app()
    _bootstrap(mod)

    with TestClient(mod.app) as c:
        # 公開入口は生きている（login page）
        r_login = c.post(
            "/auth/login",
            json={"password": "admin"},
            headers={"accept": "application/json"},
        )
        assert r_login.status_code == 200

        # CSP report endpoint is public (204)
        r_csp = c.post("/__csp_report", headers={"content-type": "application/csp-report"})
        assert r_csp.status_code == 204

        # notes は未ログインで保護（実装により 401/403 または秘匿 404）
        with TestClient(mod.app) as anon:
            r_notes = anon.get("/notes/test", headers={"accept": "application/json"})
            assert r_notes.status_code in {401, 403, 404}

