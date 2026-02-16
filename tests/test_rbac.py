# tests/test_rbac.py
from __future__ import annotations

import importlib.util
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _repo_root() -> Path:
    # tests/ 配下を想定
    return Path(__file__).resolve().parents[1]


def _load_isolated_app():
    """
    conftest.py が import app 済みでも影響しないように、
    app.py を “別モジュール名” でロードして分離する。
    """
    app_py = _repo_root() / "app.py"
    name = f"_isolated_app_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def _bootstrap(mod) -> None:
    """tests では lifespan が走らないので、必要な初期化だけ自前で行う。"""
    # settings cache clear
    if hasattr(mod, "_SETTINGS"):
        mod._SETTINGS = None  # type: ignore[attr-defined]

    mod.init_settings()
    mod.init_db()

    s = mod.get_settings()
    # middleware が参照する state を合わせる
    mod.app.state.csp_mode = s.csp_mode
    mod.app.state.csp_policy = mod._build_csp_policy(s) if s.csp_mode != "off" else None
    mod.app.state.mode = s.mode
    mod.app.state.auth_mode = s.auth_mode
    mod.app.state.require_auth_all = getattr(s, "require_auth_all", False)
    mod.app.state.allow_local_json_noauth = getattr(s, "allow_local_json_noauth", False)
    mod.app.state.csp_use_reporting_api = getattr(s, "csp_use_reporting_api", False)
    mod.app.state.csp_report_uri = getattr(s, "csp_report_uri", "")


def _ensure_note(mod, slug: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    con = mod.db()
    try:
        con.execute("DELETE FROM notes WHERE slug = ?", (slug,))
        con.execute(
            "INSERT INTO notes (slug, status, priority, risk_level, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (slug, "open", None, None, now, now),
        )
        con.commit()
    finally:
        con.close()


def _login(client: TestClient, password: str) -> None:
    r = client.post(
        "/auth/login",
        json={"password": password},
        headers={"accept": "application/json"},
    )
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("accept", ["application/json"])
def test_rbac_matrix_matches_current_implementation(tmp_path: Path, accept: str):
    """
    2026-01 現行実装に合わせた RBAC 契約（テストが“理想”ではなく“現実”を固定する）

    - 未ログイン: /notes/* は 401
    - viewer: 読める（/notes/table, /notes/{slug}）。更新/scan は不可。
    - operator: 更新は可（PATCH）。diff scan も可（RBAC契約: operator, admin, dev）。
    - dev: diff scan は可。full scan も可（admin相当）。
    - admin: 更新/削除/scan(full含む) すべて可。
    """
    # ---- env (local) ----
    os.environ["MODE"] = "local"
    os.environ["AUTH_MODE"] = "cookie"
    os.environ["SESSION_SECRET"] = "test-secret"
    os.environ["ADMIN_PASSWORD"] = "admin"
    os.environ["DEV_PASSWORD"] = "dev"
    os.environ["OPERATOR_PASSWORD"] = "operator"
    os.environ["VIEWER_PASSWORD"] = "viewer"
    os.environ["DB_PATH"] = str(tmp_path / "ledger.sqlite3")
    # local の例外（json no-auth）は OFF（RBACを見たい）
    os.environ["ALLOW_LOCAL_JSON_NOAUTH"] = "0"
    os.environ["CSP_MODE"] = "off"

    mod = _load_isolated_app()
    _bootstrap(mod)

    slug = "rbac-test"
    _ensure_note(mod, slug)

    # scan 用の repo root は明示（scan の root バリデーション回避）
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "a.md").write_text(f"# vNext: {slug}\n", encoding="utf-8")

    def mk(base_url: str = "http://127.0.0.1") -> TestClient:
        return TestClient(mod.app, base_url=base_url)

    # ---- unauth ----
    c = mk()
    r = c.get("/notes/table", headers={"accept": accept})
    assert r.status_code == 401

    # ---- viewer ----
    c = mk()
    _login(c, "viewer")

    r = c.get("/notes/table", headers={"accept": accept})
    assert r.status_code == 200
    r = c.get(f"/notes/{slug}", headers={"accept": accept})
    assert r.status_code == 200

    r = c.patch(f"/notes/{slug}", json={"status": "doing"}, headers={"accept": accept})
    assert r.status_code == 403

    r = c.post("/scan", json={"root": str(repo_root)}, headers={"accept": accept})
    assert r.status_code in (401, 403)  # 実装上は 403

    # ---- operator ----
    c = mk()
    _login(c, "operator")

    r = c.patch(f"/notes/{slug}", json={"status": "doing"}, headers={"accept": accept})
    assert r.status_code == 200, r.text

    # RBAC契約: operator は diff scan 可能（operator, admin, dev）
    r = c.post("/scan", json={"root": str(repo_root)}, headers={"accept": accept})
    assert r.status_code == 200, r.text

    # RBAC契約: operator は full scan 不可（admin, dev のみ）
    r = c.post("/scan?full=1", json={"root": str(repo_root)}, headers={"accept": accept})
    assert r.status_code == 403

    # ---- dev (legacy) ----
    c = mk()
    _login(c, "dev")

    # diff scan は可
    r = c.post("/scan", json={"root": str(repo_root)}, headers={"accept": accept})
    assert r.status_code == 200, r.text

    # full scan も dev に許可（admin相当の権限）
    r = c.post("/scan?full=1", json={"root": str(repo_root)}, headers={"accept": accept})
    assert r.status_code == 200, r.text

    # ---- admin ----
    c = mk()
    _login(c, "admin")

    r = c.post("/scan?full=1", json={"root": str(repo_root)}, headers={"accept": accept})
    assert r.status_code == 200, r.text

    r = c.delete(f"/notes/{slug}", headers={"accept": accept})
    assert r.status_code == 204
