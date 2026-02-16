# tests/test_p1_7_session_fixation_and_xss_contract.py

from __future__ import annotations

from datetime import datetime
from typing import Union

import pytest
from fastapi.testclient import TestClient

import app
from tests.helpers.contract_utils import (
    assert_cookie_deleted,
    extract_cookie_value,
    reset_settings,
    set_cookie_lines,
)

DBValue = Union[str, int, float, None]
DEV_PW = "devpw"
ADMIN_PW = "adminpw"  # ★追加

# このテストが要求する「最小の必須 env」をここに固定する
COMMON_ENV = dict(
    MODE="local",
    AUTH_MODE="cookie",
    SESSION_SECRET="s",
    ADMIN_PASSWORD=ADMIN_PW,     # ★ここ
    VIEWER_PASSWORD="viewer",
    OPERATOR_PASSWORD="operator",
    DEV_PASSWORD=DEV_PW,
)



def _insert_note(slug: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")

    with app.db() as con:
        cols = [r[1] for r in con.execute("PRAGMA table_info(notes)").fetchall()]

        data: dict[str, DBValue] = {
            "slug": slug,
            "status": "open",
            "created_at": now,
            "updated_at": now,
        }

        def _set_if(k: str, v: DBValue) -> None:
            if k in cols:
                data[k] = v

        _set_if("is_archived", 0)
        _set_if("is_deleted", 0)
        _set_if("revived_count", 0)
        _set_if("priority", None)

        keys = [k for k in data.keys() if k in cols]
        placeholders = ",".join(["?"] * len(keys))
        sql = f"INSERT OR REPLACE INTO notes ({','.join(keys)}) VALUES ({placeholders})"
        con.execute(sql, [data[k] for k in keys])
        con.commit()


def test_login_rotates_session_cookie_prevent_fixation(monkeypatch: pytest.MonkeyPatch):
    """
    Contract: ログイン成功時に session cookie は必ず更新される（session fixation 防止）
    """
    reset_settings(monkeypatch, **COMMON_ENV)

    c = TestClient(app.app)

    # 先に「攻撃者が埋めた」想定のセッションを入れる（値は何でも良い）
    old = "evil-session"
    c.cookies.set(app.SESSION_COOKIE, old, domain="testserver", path="/")

    r = c.post(
        "/auth/login",
        json={"password": ADMIN_PW},   # ★ここ
        headers={"accept": "application/json"},
    )

    assert r.status_code == 200

    lines = set_cookie_lines(r)
    new_val = extract_cookie_value(lines, app.SESSION_COOKIE)
    assert new_val, "login must set session cookie"
    assert new_val != old, "session cookie must rotate on login"

    # 新しいセッションで /auth/me が通ること（契約）
    r2 = c.get("/auth/me", headers={"accept": "application/json"})
    assert r2.status_code == 200


def test_logout_clears_session_cookie(monkeypatch: pytest.MonkeyPatch):
    """
    Contract: /auth/logout は session cookie を確実に削除する
    """
    reset_settings(monkeypatch, **COMMON_ENV)

    c = TestClient(app.app)
    r = c.post(
        "/auth/login",
        json={"password": ADMIN_PW},   # ★ここ
        headers={"accept": "application/json"},
    )

    assert r.status_code == 200

    r2 = c.post("/auth/logout", headers={"accept": "application/json"})
    assert r2.status_code in {200, 204}

    lines = set_cookie_lines(r2)
    assert_cookie_deleted(lines, app.SESSION_COOKIE)

    # ログアウト後は /auth/me が落ちる（401/403）
    r3 = c.get("/auth/me", headers={"accept": "application/json"})
    assert r3.status_code in {401, 403}


def test_notes_table_escapes_untrusted_values(client):
    slug = "<script>alert(1)</script>"
    _insert_note(slug)

    r = client.get("/notes/table", headers={"accept": "text/html"})
    assert r.status_code == 200

    html = r.text
    assert slug not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html



