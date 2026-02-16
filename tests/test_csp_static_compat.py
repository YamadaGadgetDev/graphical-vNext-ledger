# tests/test_csp_static_compat.py
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _pick_path(*candidates: Path) -> Path:
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]  # best-effort


def test_ui_js_has_no_eval_equivalents():
    root = _repo_root()
    js_path = _pick_path(root / "static" / "ui.js", root / "ui.js")

    js = js_path.read_text(encoding="utf-8")

    assert not re.search(r"\beval\s*\(", js), "Do not use eval()"
    assert not re.search(r"new\s+Function\b", js), "Do not use new Function()"

    # setTimeout("...") / setInterval("...") は eval 相当
    assert not re.search(r"setTimeout\s*\(\s*['\"]", js), "Use setTimeout(() => ..., ms)"
    assert not re.search(r"setInterval\s*\(\s*['\"]", js), "Use setInterval(() => ..., ms)"


def test_static_html_is_csp_enforce_compatible_when_strict_enabled():
    """
    CSP tighten（enforce）に入れる時だけ、静的HTMLの inline を禁止する。

    - ふだん（CSP_MODE=off/report）: このテストは “警告なしスルー”
    - tighten（CSP_MODE=enforce もしくは VNEXT_CSP_STATIC_STRICT=1）: inline style/script を検出したら落とす

    失敗したら、あなたの `extract_css.py` で <style> を外出しし、
    inline <script> も ui.js へ移してから tighten へ。
    """
    strict = (
        (os.getenv("CSP_MODE", "").strip().lower() == "enforce")
        or (os.getenv("VNEXT_CSP_STATIC_STRICT", "0").strip() == "1")
    )

    if not strict:
        pytest.skip("CSP enforce/tighten 時のみ strict チェックを有効化する")

    root = _repo_root()
    html_path = _pick_path(root / "static" / "index.htmx", root / "index.htmx")
    html = html_path.read_text(encoding="utf-8")

    # <style> タグは禁止（外部CSSへ）
    assert not re.search(r"<style\b", html, flags=re.IGNORECASE), "Inline <style> found. Extract to static/style.css"

    # style 属性は禁止（class に寄せる）
    assert not re.search(r"\sstyle\s*=", html, flags=re.IGNORECASE), "Inline style= found. Move to CSS/classes"

    # inline <script>（src無し）禁止
    for m in re.finditer(r"<script\b([^>]*)>", html, flags=re.IGNORECASE):
        attrs = m.group(1) or ""
        if re.search(r"\bsrc\s*=", attrs, flags=re.IGNORECASE):
            continue
        assert False, "Inline <script> found. Move logic to /static/ui.js"

    # on* ハンドラ（onclick等）禁止
    assert not re.search(r"\son\w+\s*=", html, flags=re.IGNORECASE), "Inline event handler found (onclick=...)."


def test_csp_policy_contract_is_strict():
    """
    実装側の CSP 方針（unsafe-inline/eval を許可しない）が維持されていること。
    これは “静的” なので、MODE/CSP_MODE に依存せず常に固定して良い。
    """
    # ここは app.py を import してもOK（ポリシー文字列の静的契約だけを見る）
    import app

    # local/prod どちらでも build は同一方針
    os.environ.setdefault("MODE", "local")
    os.environ.setdefault("SESSION_SECRET", "test-secret")
    os.environ.setdefault("ADMIN_PASSWORD", "admin")
    os.environ.setdefault("CSP_MODE", "off")

    app._SETTINGS = None  # type: ignore[attr-defined]
    app.init_settings()
    s = app.get_settings()
    pol = app._build_csp_policy(s)

    assert "style-src 'self'" in pol
    assert "'unsafe-inline'" not in pol
    assert "script-src 'self'" in pol
    assert "'unsafe-eval'" not in pol
