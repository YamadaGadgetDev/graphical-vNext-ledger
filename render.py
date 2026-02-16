# render.py
import html
from pathlib import Path
from urllib.parse import quote


def esc(s: str | None) -> str:
    """HTML escape for any user/DB-derived text inserted into HTML strings."""
    return html.escape(s or "", quote=True)


def _role_order(role: str) -> int:
    """
    UI側のロール判定（RBAC契約準拠）
    dev は admin と完全に同一（2）
    """
    role = (role or "").strip()
    if role in {"admin", "dev"}:
        return 2
    if role == "operator":
        return 1
    if role == "viewer":
        return 0
    return -1


def render_notes_table(notes: list[dict], role: str = "viewer", deleted_mode: bool = False) -> str:
    """Render a simple HTML table.

    Note: This returns a full HTML document for compatibility with direct navigation.
    It is still safe to swap into HTMX targets, but nested <html> is not pretty.
    If you later want a fragment mode, split this into *_fragment + wrapper.
    """
    role_n = role if role in {"viewer", "operator", "admin", "dev"} else "viewer"
    can_admin = (_role_order(role_n) >= 2)

    rows: list[str] = []
    for n in notes:
        status = esc(n.get("status"))
        priority = n.get("priority")
        priority_s = "-" if priority is None else str(priority)
        slug = str(n.get("slug") or "")
        slug_url = quote(slug, safe="")
        ev = int(n.get("evidence_count") or 0)

        deleted = int(n.get("is_deleted") or 0)
        deleted_badge = " 🗑" if deleted else ""

        actions = ""
        if can_admin:
            if deleted_mode:
                actions = (
                    f'<button type="button" class="js-restore" data-slug="{esc(slug)}">Restore</button> '
                    f'<button type="button" class="js-purge" data-slug="{esc(slug)}">Purge</button>'
                )
            else:
                actions = f'<button type="button" class="js-delete" data-slug="{esc(slug)}">Delete</button>'
        # viewer/operator: actions blank (open via slug link)

        rows.append(
            f"""<tr>
<td><span class="badge status-{status}">{status}</span></td>
<td>{esc(priority_s)}</td>
<td><a href="/notes/{slug_url}" class="js-open-note" data-slug="{esc(slug)}"><code>{esc(slug)}</code></a>{deleted_badge}</td>
<td>{ev}</td>
<td>{actions}</td>
</tr>"""
        )

    title = "vNext Ledger — Trash" if deleted_mode else "vNext Ledger"
    return f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{esc(title)}</title>
</head>
<body>
  <table border="1">
    <thead>
      <tr>
        <th>Status</th>
        <th>Priority</th>
        <th>Slug</th>
        <th>Evidence</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""


def render_note_modal(note: dict, role: str = "viewer") -> str:
    """Render note detail as a modal-friendly HTML fragment (no <html> wrapper)."""
    slug = str(note.get("slug") or "")
    status = str(note.get("status") or "open")

    # priority: int | None (contract: null | 1..3)
    priority = note.get("priority")
    if priority not in (None, 1, 2, 3):
        # Defensive: if DB contains unexpected value, show as None but do not crash the UI.
        priority = None

    # risk_level: DB may contain None / "none" / "high" / "critical" (or legacy empty string)
    risk_raw = note.get("risk_level")
    risk = (str(risk_raw).strip().lower() if risk_raw is not None else "")
    if risk == "" or risk == "null":
        risk = "none"
    if risk not in ("none", "high", "critical"):
        risk = "none"

    events = note.get("events") or []
    evidence = note.get("evidence") or []
    can_edit = (_role_order(role) >= _role_order("operator"))
    disabled = "" if can_edit else "disabled"

    # ---- select options (contract-aligned) ----
    # "stale" is typically set by scan, but the API allows it; show it only when current is stale.
    status_choices = ["open", "doing", "parked", "done"]
    if status == "stale":
        status_choices.append("stale")

    def _options(choices, current):
        parts = []
        for c in choices:
            sel = " selected" if str(c) == str(current) else ""
            parts.append(f'<option value="{esc(str(c))}"{sel}>{esc(str(c))}</option>')
        return "\n".join(parts)

    def _priority_options(current):
        parts = []
        # null option
        parts.append('<option value=""{sel}>{label}</option>'.format(
            sel=" selected" if current is None else "",
            label=esc("-- 未設定"),
        ))
        for c in (1, 2, 3):
            sel = " selected" if current == c else ""
            parts.append(f'<option value="{c}"{sel}>{c}</option>')
        return "\n".join(parts)

    def _risk_options(current):
        # risk is always one of (none, high, critical)
        choices = ("none", "high", "critical")
        labels = {"none": "none", "high": "high", "critical": "critical"}
        parts = []
        for c in choices:
            sel = " selected" if c == current else ""
            parts.append(f'<option value="{esc(c)}"{sel}>{esc(labels[c])}</option>')
        return "\n".join(parts)

    status_html = f'''<select id="modal-status" data-field="status"
        data-slug="{esc(slug)}" data-original="{esc(status)}" {disabled}>
        {_options(status_choices, status)}
    </select>'''

    priority_orig = "" if priority is None else str(priority)
    priority_html = f'''<select id="modal-priority" data-field="priority"
        data-slug="{esc(slug)}" data-original="{esc(priority_orig)}" {disabled}>
        {_priority_options(priority)}
    </select>'''

    risk_html = f'''<select id="modal-risk" data-field="risk_level"
        data-slug="{esc(slug)}" data-original="{esc(risk)}" {disabled}>
        {_risk_options(risk)}
    </select>'''

    # ---- events list ----
    ev_items = []
    for ev in events:
        etype = esc(ev.get("event_type") or "")
        old_v = esc(ev.get("old_value") or "-")
        new_v = esc(ev.get("new_value") or "-")
        at = esc(ev.get("changed_at") or "")

        if etype == "comment":
            ev_items.append(
                f'<li class="event-comment">'
                f'<span class="event-time">{at}</span> '
                f'<span class="event-type">💬 comment</span><br>'
                f'<span class="event-body">{new_v}</span>'
                f'</li>'
            )
        else:
            ev_items.append(
                f'<li class="event-change">'
                f'<span class="event-time">{at}</span> '
                f'<span class="event-type">{etype}</span> '
                f'<span class="event-diff">{old_v} → {new_v}</span>'
                f'</li>'
            )

    # ---- evidence list ----
    evi_items = []
    for e in evidence:
        fp = esc(e.get("filepath") or "")
        ln = e.get("line_no")
        sn = esc(e.get("snippet") or "")
        evi_items.append(f'<li><code>{fp}</code>:{esc(str(ln) if ln is not None else "-")}: {sn}</li>')

    # ---- comment section (operator+) ----
    comment_section = ""
    if can_edit:
        comment_section = f'''
    <div class="modal-section">
      <h3>💬 コメント</h3>
      <textarea id="modal-comment" rows="3" data-slug="{esc(slug)}"
                placeholder="判断理由・指示・提案を記録..."></textarea>
      <div class="modal-actions">
        <button type="button" class="js-submit-comment primary"
                data-slug="{esc(slug)}">送信</button>
      </div>
    </div>'''

    return f'''<div class="modal note-modal">
  <div class="modal-header">
    <h2><code>{esc(slug)}</code></h2>
    <button type="button" class="modal-close js-close-modal" aria-label="Close">&times;</button>
  </div>

  <div class="modal-section modal-fields">
    <label>Status {status_html}</label>
    <label>Priority {priority_html}</label>
    <label>Risk {risk_html}</label>
  </div>

  {comment_section}

  <div class="modal-section">
    <h3>📜 履歴</h3>
    <ul class="event-list">
      {"".join(ev_items) or "<li>(none)</li>"}
    </ul>
  </div>

  <div class="modal-section">
    <h3>📂 Evidence</h3>
    <ul class="evidence-list">
      {"".join(evi_items) or "<li>(none)</li>"}
    </ul>
  </div>
</div>'''


def render_note_detail(note: dict) -> str:
    slug = str(note.get("slug") or "")
    status = esc(note.get("status"))
    priority = note.get("priority")
    risk = esc(note.get("risk_level") or "")
    evidence = note.get("evidence") or []
    events = note.get("events") or []

    ev_items = []
    for e in evidence:
        fp = esc(e.get("filepath"))
        ln = e.get("line_no")
        sn = esc(e.get("snippet"))
        ev_items.append(f"<li><code>{fp}</code>:{esc(str(ln) if ln is not None else '-')}: {sn}</li>")

    ev2_items = []
    for ev in events:
        ev2_items.append(
            "<li>"
            f"{esc(ev.get('changed_at'))} — <code>{esc(ev.get('event_type'))}</code> "
            f"{esc(ev.get('old_value'))} → {esc(ev.get('new_value'))}"
            "</li>"
        )

    return f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{esc(slug)}</title>
</head>
<body>
  <h1><code>{esc(slug)}</code></h1>
  <p>Status: <b>{status}</b></p>
  <p>Priority: <b>{esc('-' if priority is None else str(priority))}</b></p>
  <p>Risk: <b>{risk or '-'}</b></p>

  <h2>Evidence</h2>
  <ul>{''.join(ev_items) or '<li>(none)</li>'}</ul>

  <h2>Events</h2>
  <ul>{''.join(ev2_items) or '<li>(none)</li>'}</ul>
</body>
</html>"""
def render_summary(data: dict, allowed_statuses: list[str]) -> str:
    """Render /export/summary HTML (for HTMX swap into #result).

    data keys (from app.py):
      - total: int
      - by_status: dict[str,int]
      - last_scan_at: str | None
    """
    total = int(data.get("total") or 0)
    by_status = data.get("by_status") or {}
    last_scan = esc(str(data.get("last_scan_at") or "Never"))

    rows = []
    for st in allowed_statuses:
        cnt = int(by_status.get(st, 0))
        rows.append(f"<tr><td><code>{esc(st)}</code></td><td>{cnt}</td></tr>")

    return f"""<div>
  <h3>Summary</h3>
  <p><strong>Total:</strong> {total} / <strong>Last scan:</strong> {last_scan}</p>
  <table>
    <thead><tr><th>Status</th><th>Count</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>"""


def render_metrics(data: dict) -> str:
    """Render /export/metrics HTML (for HTMX swap into #result)."""
    exported_at = esc(str(data.get("exported_at") or ""))
    last_scan = esc(str(data.get("last_scan_at") or "Never"))
    limit = int(data.get("limit") or 0)

    agg = data.get("aggregate") or {}
    agg_all = data.get("aggregate_all") or {}

    def _kv_table(d: dict, title: str) -> str:
        items = []
        for k, v in d.items():
            items.append(f"<tr><td><code>{esc(str(k))}</code></td><td>{esc(str(v))}</td></tr>")
        return f"""<h4>{esc(title)}</h4>
<table>
  <tbody>{''.join(items) or '<tr><td colspan="2">(none)</td></tr>'}</tbody>
</table>"""

    # recent scans
    recent = data.get("recent") or []
    recent_rows = []
    for r in recent:
        r = r or {}
        recent_rows.append(
            "<tr>"
            f"<td>{esc(str(r.get('scanned_at') or ''))}</td>"
            f"<td>{'full' if int(r.get('full') or 0) else 'diff'}</td>"
            f"<td>{esc(str(r.get('files_scanned') or 0))}</td>"
            f"<td>{esc(str(r.get('slugs_found') or 0))}</td>"
            f"<td>{esc(str(r.get('evidence_added') or 0))}</td>"
            "</tr>"
        )

    resolved_root = esc(str(data.get("resolved_root") or ""))
    order = (data.get("root_resolution") or {}).get("order") or []
    order_html = "<ol>" + "".join(f"<li><code>{esc(str(x))}</code></li>" for x in order) + "</ol>"

    return f"""<div>
  <h3>Metrics</h3>
  <p><strong>Exported at:</strong> {exported_at} / <strong>Last scan:</strong> {last_scan} / <strong>Limit:</strong> {limit}</p>
  <p><strong>Resolved root:</strong> <code>{resolved_root}</code></p>
  <details>
    <summary>Root resolution order</summary>
    {order_html}
  </details>

  {_kv_table(agg, 'Aggregate (recent window)')}
  {_kv_table(agg_all, 'Aggregate (all time)')}

  <h4>Recent scans</h4>
  <table>
    <thead><tr><th>scanned_at</th><th>mode</th><th>files</th><th>slugs</th><th>evidence</th></tr></thead>
    <tbody>{''.join(recent_rows) or '<tr><td colspan="5">(none)</td></tr>'}</tbody>
  </table>
</div>"""


def render_scan_result(
    *,
    full: bool,
    root_path: Path,
    files_scanned: int,
    slugs_found: int,
    evidence_added: int,
    done_forced: int,
    stale_marked: int,
    revived_count: int,
    orphan_files_removed: int,
) -> str:
    """Render /scan HTML result for swapping into #result."""
    mode = "full" if full else "diff"
    return f"""<div>
  <h3>Scan complete</h3>
  <ul>
    <li><strong>mode:</strong> <code>{esc(mode)}</code></li>
    <li><strong>root:</strong> <code>{esc(str(root_path))}</code></li>
    <li><strong>files_scanned:</strong> {int(files_scanned)}</li>
    <li><strong>slugs_found:</strong> {int(slugs_found)}</li>
    <li><strong>evidence_added:</strong> {int(evidence_added)}</li>
    <li><strong>done_forced:</strong> {int(done_forced)}</li>
    <li><strong>stale_marked:</strong> {int(stale_marked)}</li>
    <li><strong>revived_count:</strong> {int(revived_count)}</li>
    <li><strong>orphan_files_removed:</strong> {int(orphan_files_removed)}</li>
  </ul>
</div>"""


def render_no_ui() -> str:
    """Fallback HTML when index.htmx is missing."""
    return """<div>
  <h1>vNext Ledger</h1>
  <p>UI is not installed.</p>
  <p>Expected: <code>static/index.htmx</code></p>
</div>"""
