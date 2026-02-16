"""tests/test_scan_empty_body_contract.py

Regression test: /scan must not 422 when Content-Type: application/json but body is empty.

Background:
- A past UI bug sent Content-Type: application/json with an empty body, producing 422.
- Current design intentionally provides a default body (ScanRequest) so that this failsafe
  path works, as long as a valid root can be resolved.

We pin the behavior that matters:
- The request should not be rejected with 422.
- When we provide a safe LEDGER_REPO_ROOT, the call should succeed and scan that root.

This test runs unauthenticated, relying on MODE=local + local-host + wants_json exception.
"""

from __future__ import annotations

import importlib
from fastapi.testclient import TestClient


def _reload_app(monkeypatch, tmp_path):
    # --- hard reset / deterministic env ---
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.sqlite3"))
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("AUTH_MODE", "cookie")
    monkeypatch.setenv("SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("ADMIN_PASSWORD", "admin")
    monkeypatch.setenv("DEV_PASSWORD", "dev")

    # local-json no-auth を明示（このテストの前提）
    monkeypatch.setenv("ALLOW_LOCAL_JSON_NOAUTH", "1")

    # CSP は主題ではないので静かに（どっちでもいいがテストのノイズを減らす）
    monkeypatch.setenv("CSP_MODE", "off")

    # 重要: 他テストが残しがちな env を掃除（“環境汚染”耐性）
    monkeypatch.delenv("P1_CONTRACT_VERIFIED", raising=False)
    monkeypatch.delenv("REQUIRE_AUTH_ALL", raising=False)  # ←今回のクラッシュ原因
    monkeypatch.delenv("LEDGER_REPO_ROOT_STRICT", raising=False)

    # root 解決を決め打ち（安全・確実）
    monkeypatch.setenv("LEDGER_REPO_ROOT", str(tmp_path))

    import app as appmod
    importlib.reload(appmod)
    return appmod


def test_scan_empty_json_body_is_not_422(monkeypatch, tmp_path):
    appmod = _reload_app(monkeypatch, tmp_path)

    # Provide at least one file so the scan loop does real work.
    (tmp_path / "a.py").write_text("# vNext: empty_body_test\n", encoding="utf-8")

    # “local-host” 扱いに寄せる（no-auth JSON 例外の前提を確実にする）
    with TestClient(appmod.app, base_url="http://127.0.0.1:8000") as c:
        r = c.post(
            "/scan?full=0",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
            },
            content=b"",  # empty body
        )

        assert r.status_code != 422, "Empty JSON body must not trigger FastAPI 422"
        assert r.status_code == 200, f"Expected success with fallback body, got {r.status_code}: {r.text}"

        body = r.json()
        assert body.get("scanned_root") == str(tmp_path)
