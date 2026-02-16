"""RBAC 契約ガードテスト — 静的解析による再破断検知.

このテストは app.py / render.py / static/index.htmx / ui.js を
テキストとして読み込み、RBAC 契約に違反するパターンを検出する。

違反例:
  - role != "admin"  （dev=admin 同値契約を破る直書き）
  - ROLE_ORDER で dev != admin  （3箇所の同期ズレ）
  - {"admin", "dev"} のハードコード（_is_adminish を使うべき）

NOTE: このテストは「ソースコードの文字列パターン」を検査する。
      ロジックの正しさは test_rbac.py が担保する。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------- paths ----------
_ROOT = Path(__file__).resolve().parent.parent
APP_PY = _ROOT / "app.py"
RENDER_PY = _ROOT / "render.py"
UI_JS = _ROOT / "static" / "ui.js"
INDEX_HTMX = _ROOT / "static" / "index.htmx"


# ============================================================
# 1. role == "admin" / role != "admin" 直書き検出
# ============================================================

# 許可リスト: これらの行は直書きが正当な理由がある
# ⚠️ 各エントリは「この部分文字列が行に含まれていれば許可」の意味。
#    広すぎるパターンは抜け道になるため、必要最小限に絞ること。
#    「adminish」のような"コメントにも出現する語"は入れない。
_ROLE_CMP_ALLOWLIST: set[str] = {
    # _is_adminish 定義の内部（2要素セットのみ許可、単独 {"admin"} は不可）
    'def _is_adminish',
    'role in {"admin", "dev"}',
    'role in {"dev", "admin"}',
    # _ensure_min_role の引数としての "admin" リテラル（閾値指定）
    '_ensure_min_role(request, "admin")',
    '_ensure_min_role(request, "dev")',
    # テストコード内のログイン呼び出し
    '_login(c, "admin")',
    '_login(c, "dev")',
}


def _is_allowed(line: str, *, in_docstring: bool) -> bool:
    """許可リストのいずれかのパターンが行に含まれていれば True.

    Args:
        line: ソース行（インデント含む）
        in_docstring: 呼び出し時点で docstring 内にいるかどうか
    """
    stripped = line.strip()
    # 純粋なコメント行は常に許可
    if stripped.startswith('#'):
        return True
    # docstring 内は常に許可（状態機械で判定）
    if in_docstring:
        return True
    # ワンライナー docstring: 開いて閉じるトリプルクォートが同一行にある
    if (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 6) or \
       (stripped.startswith("'''") and stripped.endswith("'''") and len(stripped) > 6):
        return True
    return any(pattern in line for pattern in _ROLE_CMP_ALLOWLIST)


def _toggle_docstring(line: str, in_docstring: bool) -> bool:
    """トリプルクォートの出現を追跡して docstring 状態を更新する.

    Returns:
        更新後の in_docstring 状態
    """
    stripped = line.strip()
    for quote in ('"""', "'''"):
        count = stripped.count(quote)
        if count == 0:
            continue
        if count >= 2:
            # 開いて閉じる（ワンライナー docstring）→ 状態変化なし
            continue
        # 奇数個（通常1個）→ トグル
        in_docstring = not in_docstring
    return in_docstring


# admin との直接比較パターン（ロジック内で dev=admin 契約を破る可能性）
_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    # == / != による直接比較
    re.compile(r'''role\s*!=\s*["']admin["']'''),
    re.compile(r'''role\s*==\s*["']admin["']'''),
    re.compile(r'''role\s*!=\s*["']dev["']'''),
    re.compile(r'''role\s*==\s*["']dev["']'''),
    # not in {"admin"} / not in {"dev"} — _is_adminish を使うべき
    re.compile(r'''role\s+not\s+in\s*\{[^}]*["']admin["'][^}]*\}'''),
    re.compile(r'''role\s+not\s+in\s*\{[^}]*["']dev["'][^}]*\}'''),
    # 単独要素セット: role in {"admin"} は role == "admin" と等価 — 抜け道防止
    re.compile(r'''role\s+in\s*\{\s*["']admin["']\s*\}'''),
    re.compile(r'''role\s+in\s*\{\s*["']dev["']\s*\}'''),
]


class TestNoDirectRoleComparison:
    """app.py 内に role == "admin" / role != "admin" の直書きがないこと."""

    def test_no_dangerous_role_comparison_in_app(self) -> None:
        source = APP_PY.read_text(encoding="utf-8")
        violations: list[str] = []
        in_docstring = False

        for i, line in enumerate(source.splitlines(), 1):
            # docstring 状態を更新（行の判定より先に）
            prev_state = in_docstring
            in_docstring = _toggle_docstring(line, in_docstring)

            # 許可判定: prev_state を使う（開始行自体は docstring の「中」）
            # ただしトリプルクォート開始行は _is_allowed 内でワンライナー判定する
            check_state = prev_state or (in_docstring and not prev_state)
            if _is_allowed(line, in_docstring=check_state):
                continue
            for pat in _DANGEROUS_PATTERNS:
                if pat.search(line):
                    violations.append(f"  L{i}: {line.strip()}")
                    break

        if violations:
            msg = (
                "app.py に role の直接比較が残っています。\n"
                "_is_adminish() または _ensure_min_role() を使ってください:\n"
                + "\n".join(violations)
            )
            pytest.fail(msg)


# ============================================================
# 2. ROLE_ORDER 3点同期チェック
# ============================================================

def _extract_role_order_from_app() -> dict[str, int]:
    """app.py の ROLE_ORDER 辞書リテラルをパースする."""
    source = APP_PY.read_text(encoding="utf-8")
    m = re.search(r'ROLE_ORDER[^=]*=\s*\{([^}]+)\}', source)
    assert m, "app.py に ROLE_ORDER 定義が見つかりません"
    pairs: dict[str, int] = {}
    for token in m.group(1).split(','):
        token = token.strip()
        if not token:
            continue
        km = re.match(r'''["'](\w+)["']\s*:\s*(\d+)''', token)
        assert km, f"ROLE_ORDER のパースに失敗: {token}"
        pairs[km.group(1)] = int(km.group(2))
    return pairs


def _extract_role_order_from_render() -> dict[str, int]:
    """render.py の _role_order() 関数から返り値マップを推定する."""
    source = RENDER_PY.read_text(encoding="utf-8")
    # パターン: role == "xxx" → return N  /  role in {"xxx", ...} → return N
    pairs: dict[str, int] = {}
    for m in re.finditer(
        r'''role\s*==\s*["'](\w+)["'][^:]*:\s*\n?\s*return\s+(\d+)''', source
    ):
        pairs[m.group(1)] = int(m.group(2))
    for m in re.finditer(
        r'''role\s+in\s*\{([^}]+)\}[^:]*:\s*\n?\s*return\s+(\d+)''', source
    ):
        val = int(m.group(2))
        for rm in re.finditer(r'''["'](\w+)["']''', m.group(1)):
            pairs[rm.group(1)] = val
    return pairs


def _extract_role_order_from_ui_js() -> dict[str, int]:
    """ui.js の ROLE_ORDER オブジェクトリテラルをパースする."""
    if not UI_JS.exists():
        pytest.skip("ui.js が見つかりません（UI変更なしの環境）")
    source = UI_JS.read_text(encoding="utf-8")
    m = re.search(r'ROLE_ORDER\s*=\s*\{([^}]+)\}', source)
    assert m, "ui.js に ROLE_ORDER 定義が見つかりません"
    pairs: dict[str, int] = {}
    for token in m.group(1).split(','):
        token = token.strip()
        if not token:
            continue
        km = re.match(r'(\w+)\s*:\s*(\d+)', token)
        assert km, f"ui.js ROLE_ORDER のパースに失敗: {token}"
        pairs[km.group(1)] = int(km.group(2))
    return pairs


class TestRoleOrderConsistency:
    """ROLE_ORDER が app.py / render.py / ui.js で一致すること."""

    def test_dev_equals_admin_in_app(self) -> None:
        ro = _extract_role_order_from_app()
        assert "dev" in ro, "app.py ROLE_ORDER に dev がありません"
        assert "admin" in ro, "app.py ROLE_ORDER に admin がありません"
        assert ro["dev"] == ro["admin"], (
            f"app.py: dev={ro['dev']} != admin={ro['admin']}  — "
            "dev=admin 同値契約に違反しています"
        )

    def test_dev_equals_admin_in_render(self) -> None:
        ro = _extract_role_order_from_render()
        assert "dev" in ro, "render.py _role_order に dev がありません"
        assert "admin" in ro, "render.py _role_order に admin がありません"
        assert ro["dev"] == ro["admin"], (
            f"render.py: dev={ro['dev']} != admin={ro['admin']}  — "
            "dev=admin 同値契約に違反しています"
        )

    def test_dev_equals_admin_in_ui_js(self) -> None:
        ro = _extract_role_order_from_ui_js()
        assert "dev" in ro, "ui.js ROLE_ORDER に dev がありません"
        assert "admin" in ro, "ui.js ROLE_ORDER に admin がありません"
        assert ro["dev"] == ro["admin"], (
            f"ui.js: dev={ro['dev']} != admin={ro['admin']}  — "
            "dev=admin 同値契約に違反しています"
        )

    def test_three_sources_agree(self) -> None:
        """3箇所の ROLE_ORDER が完全一致すること."""
        app_ro = _extract_role_order_from_app()
        render_ro = _extract_role_order_from_render()
        ui_ro = _extract_role_order_from_ui_js()

        # 全ロールについて3箇所が一致
        all_roles = set(app_ro) | set(render_ro) | set(ui_ro)
        mismatches: list[str] = []
        for role in sorted(all_roles):
            vals = {
                "app.py": app_ro.get(role, "MISSING"),
                "render.py": render_ro.get(role, "MISSING"),
                "ui.js": ui_ro.get(role, "MISSING"),
            }
            unique = set(str(v) for v in vals.values())
            if len(unique) > 1:
                mismatches.append(f"  {role}: {vals}")

        if mismatches:
            pytest.fail(
                "ROLE_ORDER が3箇所で不一致です:\n"
                + "\n".join(mismatches)
            )


# ============================================================
# 3. {"admin", "dev"} ハードコード検出
# ============================================================

# {"admin", "dev"} や {"dev", "admin"} のセットリテラル
_HARDCODED_ADMINISH = re.compile(
    r'''\{["'](?:admin|dev)["'],\s*["'](?:admin|dev)["']\}'''
)


class TestNoHardcodedAdminishSet:
    """app.py 内に {"admin", "dev"} のハードコードがないこと.

    _is_adminish() に集約されているべき。
    ただし _is_adminish 定義内と _scan_allowed_roles 定義内は許可。
    """

    def test_no_hardcoded_adminish_set(self) -> None:
        source = APP_PY.read_text(encoding="utf-8")
        violations: list[str] = []

        # _is_adminish と _scan_allowed_roles の定義範囲を特定
        in_allowed_func = False
        allowed_funcs = {"_is_adminish", "_scan_allowed_roles"}

        for i, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()

            # 関数定義の開始を検出
            if stripped.startswith("def "):
                func_name = stripped.split("(")[0].replace("def ", "")
                in_allowed_func = func_name in allowed_funcs

            # 許可された関数内 / コメント行 / ROLE_ORDER 行はスキップ
            if in_allowed_func or stripped.startswith('#') or 'ROLE_ORDER' in line:
                continue

            if _HARDCODED_ADMINISH.search(line):
                violations.append(f"  L{i}: {stripped}")

        if violations:
            pytest.fail(
                '{"admin", "dev"} のハードコードが残っています。\n'
                "_is_adminish() を使ってください:\n"
                + "\n".join(violations)
            )
