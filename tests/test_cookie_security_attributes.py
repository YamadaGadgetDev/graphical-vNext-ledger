"""tests/test_cookie_security_attributes.py

Security contract tests for session/CSRF cookies.

We keep these tests deliberately minimal:
- HttpOnly and SameSite are invariants.
- Secure is required only when MODE=prod and the request is HTTPS.

These tests use module reload to avoid relying on any global conftest settings.
"""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _get_set_cookie_headers(resp) -> list[str]:
    """Return Set-Cookie headers as a list (robust across requests/urllib3 versions)."""
    raw = getattr(resp, "raw", None)
    if raw is not None and hasattr(raw, "headers"):
        h = raw.headers
        for attr in ("getlist", "get_all"):
            if hasattr(h, attr):
                try:
                    return list(getattr(h, attr)("Set-Cookie"))
                except TypeError:
                    # Some versions require lowercase; fall through.
                    pass

    # Fallback: requests may expose a single combined header.
    sc = resp.headers.get("set-cookie")
    if not sc:
        return []

    # Naive split that is safe enough for our assertions:
    # we only care about substring presence on per-cookie header strings.
    parts: list[str] = []
    buf = ""
    for token in sc.split(", "):
        if token.startswith("vnext_session=") or token.startswith("csrf_token="):
            if buf:
                parts.append(buf)
            buf = token
        else:
            buf = (buf + ", " + token) if buf else token
    if buf:
        parts.append(buf)
    return parts


def _find_cookie(sc_headers: list[str], name: str) -> str:
    prefix = (name + "=").lower()
    for h in sc_headers:
        if h.lower().startswith(prefix):
            return h
    return ""


def _reload_app(monkeypatch, tmp_path, *, mode: str):
    """Reload app module with a fresh env configuration."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.sqlite3"))
    monkeypatch.setenv("MODE", mode)
    monkeypatch.setenv("AUTH_MODE", "cookie")
    monkeypatch.setenv("SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")

    # ★ prod で TestClient(lifespan) を通すには必須
    if mode == "prod":
        monkeypatch.setenv("P1_CONTRACT_VERIFIED", "1")
        monkeypatch.delenv("DEV_PASSWORD", raising=False)
    else:
        monkeypatch.delenv("P1_CONTRACT_VERIFIED", raising=False)
        monkeypatch.setenv("DEV_PASSWORD", "dev")

    import app as appmod
    importlib.reload(appmod)
    return appmod


def test_login_cookies_local_are_not_secure(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path, mode="local")

    with TestClient(appmod.app) as c:
        r = c.post("/auth/login", json={"password": "admin"})
        assert r.status_code == 200

        sc = _get_set_cookie_headers(r)
        sess = _find_cookie(sc, "vnext_session")
        csrf = _find_cookie(sc, "csrf_token")
        assert sess, "vnext_session Set-Cookie must be present"
        assert csrf, "csrf_token Set-Cookie must be present"

        assert "httponly" in sess.lower()
        assert "samesite=lax" in sess.lower()
        assert "secure" not in sess.lower(), "MODE=local must not mark cookies Secure"

        assert "httponly" not in csrf.lower(), "CSRF cookie must not be HttpOnly (JS must read it)"
        assert "samesite=lax" in csrf.lower()
        assert "secure" not in csrf.lower(), "MODE=local must not mark cookies Secure"


def test_login_cookies_prod_https_are_secure(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path, mode="prod")

    with TestClient(appmod.app) as c:
        r = c.post(
            "/auth/login",
            headers={"x-forwarded-proto": "https"},
            json={"password": "admin"},
        )
        assert r.status_code == 200

        sc = _get_set_cookie_headers(r)
        sess = _find_cookie(sc, "vnext_session")
        csrf = _find_cookie(sc, "csrf_token")
        assert sess, "vnext_session Set-Cookie must be present"
        assert csrf, "csrf_token Set-Cookie must be present"

        assert "httponly" in sess.lower()
        assert "samesite=lax" in sess.lower()
        assert "secure" in sess.lower(), "MODE=prod + HTTPS must mark session cookie Secure"

        assert "httponly" not in csrf.lower(), "CSRF cookie must not be HttpOnly (JS must read it)"
        assert "samesite=lax" in csrf.lower()
        assert "secure" in csrf.lower(), "MODE=prod + HTTPS must mark CSRF cookie Secure"
