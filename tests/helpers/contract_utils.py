# tests/helpers/contract_utils.py

from __future__ import annotations

from typing import Iterable

import pytest
from starlette.responses import Response

import app


def reset_settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    """
    app.get_settings() のキャッシュと app.state を同期して、テスト内でMODE等を切り替え可能にする。
    """
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    # clear cached settings and re-init
    app._SETTINGS = None  # type: ignore[attr-defined]
    app.init_settings()

    # keep app.state consistent (middleware reads app.app.state.*)
    s = app.get_settings()
    app.app.state.mode = s.mode
    app.app.state.auth_mode = s.auth_mode
    app.app.state.require_auth_all = s.require_auth_all
    app.app.state.allow_local_json_noauth = s.allow_local_json_noauth

    # CSP state（conftest と同等に揃える）
    app.app.state.csp_mode = s.csp_mode
    app.app.state.csp_policy = app._build_csp_policy(s) if s.csp_mode != "off" else None
    app.app.state.csp_use_reporting_api = s.csp_use_reporting_api
    app.app.state.csp_report_uri = s.csp_report_uri


def set_cookie_lines(response) -> list[str]:
    """
    httpx / requests どちらでも Set-Cookie を行単位で取れるようにする。
    """
    h = response.headers
    if hasattr(h, "get_list"):
        return [str(v) for v in h.get_list("set-cookie")]
    if hasattr(h, "getlist"):
        return [str(v) for v in h.getlist("set-cookie")]
    v = h.get("set-cookie")
    return [str(v)] if v else []


def extract_cookie_value(set_cookie_lines: Iterable[str], cookie_name: str) -> str | None:
    """
    Set-Cookie 群から cookie_name=... の値だけ抜く（最初の一致を採用）
    """
    name_eq = cookie_name + "="
    for line in set_cookie_lines:
        # "name=value; Path=/; ..."
        if line.startswith(name_eq):
            return line[len(name_eq):].split(";", 1)[0]
    return None


def assert_cookie_deleted(set_cookie_lines: Iterable[str], cookie_name: str) -> None:
    """
    delete_cookie の契約：Max-Age=0 or Expires=過去 を含む。
    """
    target = [l.lower() for l in set_cookie_lines if l.lower().startswith(cookie_name.lower() + "=")]
    assert target, f"Missing Set-Cookie deletion line for {cookie_name}"
    joined = "\n".join(target)
    assert ("max-age=0" in joined) or ("expires=" in joined), f"{cookie_name} not deleted: {joined}"
