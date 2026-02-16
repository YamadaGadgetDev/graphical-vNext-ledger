import importlib
from pathlib import Path

from fastapi.testclient import TestClient


def _make_client(monkeypatch, tmp_path: Path, *, require_all: bool):
    # app.py は import-time に DB_PATH を読むので、reload 前に env をセット
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.sqlite3"))

    monkeypatch.setenv("MODE", "prod")
    monkeypatch.setenv("AUTH_MODE", "cookie")

    # settings が読むので最低限入れる
    monkeypatch.setenv("SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "adminpw")
    monkeypatch.delenv("DEV_PASSWORD", raising=False)  # ★ prod では dev password を置かない

    # prod では絶対に 0（安全弁）
    monkeypatch.setenv("ALLOW_LOCAL_JSON_NOAUTH", "0")

    # deny-by-default
    monkeypatch.setenv("REQUIRE_AUTH_ALL", "1" if require_all else "0")

    # prod起動の契約ゲート：CI通過済みフラグがないと起動自体が禁止
    monkeypatch.setenv("P1_CONTRACT_VERIFIED", "1")

    import app as appmod
    importlib.reload(appmod)
    return appmod


def test_require_auth_all_keeps_root_public(monkeypatch, tmp_path):
    appmod = _make_client(monkeypatch, tmp_path, require_all=True)
    with TestClient(appmod.app) as c:
        r = c.get("/")
        assert r.status_code == 200


def test_require_auth_all_blocks_protected_endpoints_without_login(monkeypatch, tmp_path):
    appmod = _make_client(monkeypatch, tmp_path, require_all=True)
    with TestClient(appmod.app) as c:
        r = c.get("/notes/table", headers={"Accept": "text/html"})
        assert r.status_code == 401


def test_require_auth_all_allows_after_login_cookie(monkeypatch, tmp_path):
    appmod = _make_client(monkeypatch, tmp_path, require_all=True)
    with TestClient(appmod.app) as c:
        # login -> Set-Cookie session
        r = c.post("/auth/login", headers={"Accept": "application/json"}, json={"password": "adminpw"})
        assert r.status_code == 200

        r2 = c.get("/notes/table", headers={"Accept": "text/html"})
        assert r2.status_code == 200
