// static/ui.js
// vNext Ledger UI glue: CSP-friendly (no inline JS), HTMX helpers, and small UX tweaks.
(() => {
  'use strict';

  // Normalize full-width alnum (IME) into half-width ASCII.
  // (We intentionally do NOT attempt kana/romaji auto-conversion to avoid surprising behavior.)
  function normalizeHalfwidth(s) {
    s = (s || '');
    return s.replace(/[Ａ-Ｚａ-ｚ０-９]/g, function(ch) {
      return String.fromCharCode(ch.charCodeAt(0) - 0xFEE0);
    });
  }

  // ---- constants (align with app.py) ----
  const CSRF_COOKIE = 'csrf_token';
  const CSRF_HEADER = 'x-csrf-token';

  const ID = Object.freeze({
    result: 'result',
    filters: 'filters',
    modal: 'modal',
    clearFilters: 'clearFilters',
    sort: 'sort',
    dir: 'dir',

    // filter fields
    q: 'q',
    status: 'status',
    priority: 'priority',
    comment: 'comment',
    risk_level: 'risk_level',
    since: 'since',
    until: 'until',
  });

  // ---- tiny DOM helpers ----
  const el = (id) => document.getElementById(id);

  function triggerFiltersRefresh() {
    const f = el(ID.filters);
    if (f && window.htmx) window.htmx.trigger(f, 'refresh');
  }

  // ---- cookie (safe, no-regex) ----
  function getCookie(name) {
    const key = name + '=';
    const cookies = (document.cookie || '').split(';').map(s => s.trim());
    for (const c of cookies) {
      if (c.startsWith(key)) return decodeURIComponent(c.slice(key.length));
    }
    return null;
  }

  // ---- Modal helpers (CSP-friendly: do NOT touch style=) ----
  function closeModal() {
    const m = el(ID.modal);
    if (!m) return;
    m.classList.remove('show');
    m.hidden = true;
    m.innerHTML = '';
  }

  function openModal(html) {
    const m = el(ID.modal);
    if (!m) return;
    m.innerHTML = html;
    m.classList.add('show');
    m.hidden = false;
  }

  // ---- Sort: keep state in hidden inputs, then refresh filters ----
  function sortToggle(key) {
    const s = el(ID.sort);
    const d = el(ID.dir);
    if (!s || !d) return;

    if (s.value === key) {
      d.value = (d.value === 'asc') ? 'desc' : 'asc';
    } else {
      s.value = key;
      d.value = 'asc';
    }

    triggerFiltersRefresh();
  }

  // Expose: if HTMX fragments call these (onclick等を今後消しても、互換として残せる)
  window.VNextUI = Object.freeze({
    getCookie,
    closeModal,
    openModal,
    sortToggle,
    triggerFiltersRefresh,
  });
  // 互換：既存フラグメントが直接呼ぶ可能性があるので残す
  window.closeModal = closeModal;
  window.openModal = openModal;
  window.sortToggle = sortToggle;

  // ---- HTMX hooks ----

  // Inject CSRF token for non-GET requests
  document.body.addEventListener('htmx:configRequest', (evt) => {
    const verb = String(evt.detail?.verb || '').toUpperCase();
    if (verb === 'GET' || verb === 'HEAD' || verb === 'OPTIONS') return;

    const token = getCookie(CSRF_COOKIE);
    if (!token) return;

    evt.detail.headers[CSRF_HEADER] = token;
  });

  // Result panel: show then auto-hide (timer is de-duped)
  let resultHideTimer = null;
  document.body.addEventListener('htmx:afterSwap', (evt) => {
    if (evt.detail?.target?.id !== ID.result) return;

    const r = el(ID.result);
    if (!r) return;

    r.classList.add('show');

    if (resultHideTimer) clearTimeout(resultHideTimer);
    resultHideTimer = setTimeout(() => {
      r.classList.remove('show');
      resultHideTimer = null;
    }, 10_000);
  });

  // scan complete => refresh filters (path-based)
  document.body.addEventListener('htmx:afterRequest', (evt) => {
    const path = evt.detail?.pathInfo?.requestPath || evt.detail?.requestConfig?.path || '';
    if (typeof path === 'string' && path.includes('/scan')) {
      triggerFiltersRefresh();
    }
  });

  // ---- DOM events (delegation: survives HTMX swaps) ----

  // Clear filters button
  document.body.addEventListener('click', (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const btn = t.closest(`#${ID.clearFilters}`);
    if (!btn) return;

    e.preventDefault();

    const idsToClear = [
      ID.q,
      ID.status,
      ID.priority,
      ID.comment,
      ID.risk_level,
      ID.since,
      ID.until,
    ];

    for (const id of idsToClear) {
      const node = el(id);
      if (!node) continue;
      if ('value' in node) node.value = '';
    }

    triggerFiltersRefresh();
  });

  
// ---- RBAC + Auth bootstrap (UI gate only; security is server-side) ----
const ROLE_ORDER = { viewer: 0, operator: 1, dev: 2, admin: 2 };
let currentRole = null; // null = unauth

const AUTH = Object.freeze({
  overlay: 'authOverlay',
  form: 'authForm',
  pw: 'authPassword',
  msg: 'authMsg',
  open: 'openLogin',
  badge: 'roleBadge',
  logout: 'authLogout',
});

function _a(id) { return document.getElementById(id); }

function setRole(role) {
  const r = (role || '').toLowerCase();
  currentRole = (r in ROLE_ORDER) ? r : null;

  // for CSS/inspection
  document.documentElement.dataset.role = currentRole || 'anon';

  // badge
  const badge = _a(AUTH.badge);
  if (badge) badge.textContent = 'role: ' + (currentRole || '?');

  // reveal elements that require role
  document.querySelectorAll('[data-min-role]').forEach((node) => {
    const min = (node.getAttribute('data-min-role') || '').toLowerCase();
    const ok =
      currentRole &&
      (min in ROLE_ORDER) &&
      ROLE_ORDER[currentRole] >= ROLE_ORDER[min];
    node.hidden = !ok;
  });
}

let _authOverlayReady = false;
let _authOverlayLoading = null;

function _overlayPresent() {
  return Boolean(_a(AUTH.overlay));
}

function _wireAuthOverlayHandlersOnce() {
  if (_a(AUTH.form) && _a(AUTH.form)._vnextBound) return;
  const form = _a(AUTH.form);
  if (form) {
    form._vnextBound = true;
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();

      const pwEl = _a(AUTH.pw);
      const msgEl = _a(AUTH.msg);

      const raw = String(pwEl?.value || '');
      const pw = normalizeHalfwidth(raw.trim());

      if (!pw) {
        if (msgEl) msgEl.textContent = 'パスワードを入力してください。';
        return;
      }

      // IMEが日本語だと、かな/漢字が混ざって一致しない（そのまま401連打になる）ので
      // 送信前に明示的に止めて、ユーザーに原因を返す。
      if (/[^\x20-\x7E]/.test(pw)) {
        if (msgEl) msgEl.textContent = '半角英数字で入力してください（IMEが日本語のままの可能性があります）。';
        return;
      }

      if (msgEl) msgEl.textContent = 'ログイン中…';

      try {
        const role = await loginWithPassword(pw);

        if (!role) {
          if (msgEl) msgEl.textContent = 'パスワードが一致しません（viewer / operator / dev / admin）。';
          return;
        }
        
        if (pwEl) pwEl.value = '';
        if (msgEl) msgEl.textContent = `Logged in: ${role}`;
        
        setRole(role);
        hideAuthOverlay();
        startAuthedLoop();
      } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        if (msgEl) msgEl.textContent = `ログイン失敗: ${msg}`;
        console.warn('login failed', e);
      }
    });
  }

  const lo = _a(AUTH.logout);
  if (lo && !lo._vnextBound) {
    lo._vnextBound = true;
    lo.addEventListener('click', async () => {
      await doLogout();
      setRole(null);
      stopAuthedLoop();
      showAuthOverlay('Logged out. Please login again.', true);
    });
  }

  // Password visibility toggle
  const togglePw = document.getElementById('authTogglePw');
  if (togglePw && !togglePw._vnextBound) {
    togglePw._vnextBound = true;
    togglePw.addEventListener('click', () => {
      const pw = _a(AUTH.pw);
      if (!pw) return;
      const isPassword = pw.type === 'password';
      pw.type = isPassword ? 'text' : 'password';
      togglePw.textContent = isPassword ? '🙈' : '👁';
      togglePw.setAttribute('aria-pressed', String(isPassword));
    });
  }
}

async function ensureAuthOverlayLoaded() {
  if (_authOverlayReady && _overlayPresent()) return true;
  if (_authOverlayLoading) return await _authOverlayLoading;

  _authOverlayLoading = (async () => {
    if (_overlayPresent()) {
      _authOverlayReady = true;
      _wireAuthOverlayHandlersOnce();
      return true;
    }

    const mount =
      document.querySelector('[data-auth-overlay-mount]') ||
      document.getElementById('authOverlayMount') ||
      document.body;

    const res = await fetch('/static/fragments/auth_overlay.html', {
      method: 'GET',
      headers: { 'Accept': 'text/html' },
      credentials: 'include',
    });
    if (!res.ok) return false;

    const html = await res.text();

    // inject
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    while (tmp.firstChild) mount.appendChild(tmp.firstChild);

    _authOverlayReady = true;
    _wireAuthOverlayHandlersOnce();
    return true;
  })().finally(() => {
    _authOverlayLoading = null;
  });

  return await _authOverlayLoading;
}

function _showAuthOverlayNow(message, locked) {
  const ov = _a(AUTH.overlay);
  const msg = _a(AUTH.msg);
  if (msg) msg.textContent = message || '';
  if (ov) {
    ov.classList.remove('hidden');
    ov.setAttribute('aria-hidden', 'false');
  }
  if (locked) document.body.classList.add('auth-locked');
}

function showAuthOverlay(message, locked) {
  // async safe: callers may not await
  ensureAuthOverlayLoaded().then((ok) => {
    if (!ok) return;
    _showAuthOverlayNow(message, locked);
    const pw = _a(AUTH.pw);
    if (pw) pw.focus();
  });
}

function hideAuthOverlay() {
  const ov = _a(AUTH.overlay);
  if (ov) {
    ov.classList.add('hidden');
    ov.setAttribute('aria-hidden', 'true');
  }
  document.body.classList.remove('auth-locked');
}

let authedTimer = null;

function startAuthedLoop() {
  if (authedTimer) return;
  triggerFiltersRefresh(); // initial load
  authedTimer = window.setInterval(() => {
    triggerFiltersRefresh();
  }, 30_000);
}

function stopAuthedLoop() {
  if (!authedTimer) return;
  window.clearInterval(authedTimer);
  authedTimer = null;
}

async function fetchAuthMeRole() {
  try {
    const res = await fetch('/auth/me', {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      credentials: 'include',
    });
    if (!res.ok) return null;
    const j = await res.json().catch(() => null);
    return j && j.role ? String(j.role) : null;
  } catch (_) {
    return null;
  }
}

async function loginWithPassword(pw) {
  const res = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'Accept': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ password: pw }),
  });
  if (!res.ok) return null;
  const j = await res.json().catch(() => null);
  return j && j.role ? String(j.role) : null;
}

async function doLogout() {
  try {
    await fetch('/auth/logout', {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
      credentials: 'include',
    });
  } catch (_) {}
}

async function bootstrapAuth() {
  const role = await fetchAuthMeRole();
  if (!role) {
    setRole(null);
    stopAuthedLoop();
    showAuthOverlay('セッションがありません。パスワードを入力してください。', true);
    return;
  }
  setRole(role);
  hideAuthOverlay();
  startAuthedLoop();
}

// Any 401 from HTMX => lock immediately (stop spam)
document.body.addEventListener('htmx:responseError', (e) => {
  const xhr = e.detail && e.detail.xhr;
  if (xhr && xhr.status === 401) {
    closeModal();
    setRole(null);
    stopAuthedLoop();
    showAuthOverlay('Session expired. Please login again.', true);
  }
});

// Auth overlay wiring (no inline JS)
document.addEventListener('DOMContentLoaded', () => {
  const openBtn = _a(AUTH.open);
  if (openBtn) {
    openBtn.addEventListener('click', () => {
      showAuthOverlay('権限を変更するには別のパスワードを入力してください。', false);
    });
  }

  // init (auth -> start)
  bootstrapAuth();
});


// ---- Admin-only Trash toggle (requires #deleted hidden input) ----
const toggleTrash = el('toggleTrash');
if (toggleTrash) {
  toggleTrash.addEventListener('click', () => {
    const deleted = el('deleted');
    if (!deleted) return;
    deleted.value = (deleted.value === 'only') ? '' : 'only';
    toggleTrash.textContent = (deleted.value === 'only') ? '🗑 Trash: ON' : '🗑 Trash';
    triggerFiltersRefresh();
  });
}

// ---- Admin delete / restore / purge (no inline onclick; CSP-safe) ----
function _csrfHeader() {
  const token = getCookie('csrf_token');
  return token ? { 'x-csrf-token': token } : {};
}

async function _do(method, url) {
  const res = await fetch(url, { method, headers: { ..._csrfHeader() } });
  if (res.status === 401) {
    // session expired / not logged in
    closeModal();
    setRole(null);
    stopAuthedLoop();
    showAuthOverlay('未ログインです（401）。ログインしてください。', true);
    return false;
  }
  if (res.status === 403) {
    alert('権限がありません（403）。');
    return false;
  }
  if (!res.ok && res.status !== 204) {
    const t = await res.text().catch(() => '');
    alert(`操作に失敗しました（${res.status}）。\n${t}`);
    return false;
  }
  return true;
}

function _short(s, n) {
  s = String(s || '');
  return (s.length > n) ? (s.slice(0, n) + '…') : s;
}

  // ---- Note detail modal (fetch HTML fragment) ----
  async function _openNoteModal(slug) {
    const url = `/notes/${encodeURIComponent(slug)}?modal=1`;
    const res = await fetch(url, {
      method: 'GET',
      credentials: 'same-origin',
      headers: {
        'Accept': 'text/html',
        ..._csrfHeader(),
      },
    });

    if (res.status === 401) {
      showAuthOverlay('未ログインです（401）。ログインしてください。', true);
      return;
    }
    if (!res.ok) {
      alert(`読み込み失敗 (${res.status})`);
      return;
    }

    const html = await res.text();
    openModal(html);
  }

  // ---- Note PATCH helper (JSON) ----
  async function _patchNote(slug, payload) {
    const url = `/notes/${encodeURIComponent(slug)}`;
    const res = await fetch(url, {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ..._csrfHeader(),
      },
      body: JSON.stringify(payload),
    });

    if (res.status === 204) return { ok: true, noop: true };
    if (res.status === 200) return { ok: true, noop: false };

    if (res.status === 401) {
      closeModal();
      setRole(null);
      stopAuthedLoop();
      showAuthOverlay('未ログインです（401）。ログインしてください。', true);
      return { ok: false, noop: false };
    }
    if (res.status === 403) {
      alert('権限がありません（403）。');
      return { ok: false, noop: false };
    }

    const t = await res.text().catch(() => '');
    alert(`保存失敗 (${res.status})\n${t}`);
    return { ok: false, noop: false };
  }

  async function _refreshModal(slug) {
    // モーダル全体を再取得して差し替える（部分更新は禁止：複雑化を避ける）
    await _openNoteModal(slug);
  }

  function _flashOk(afterEl, text = '✓') {
    const span = document.createElement('span');
    span.textContent = ` ${text}`;
    span.className = 'flash-ok';
    afterEl.insertAdjacentElement('afterend', span);
    window.setTimeout(() => span.remove(), 1200);
  }

  document.body.addEventListener('click', async (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    // (A) Modal close button
    if (t.closest('.js-close-modal')) {
      e.preventDefault();
      closeModal();
      return;
    }

    // (B) Comment submit
    const commentBtn = t.closest('button.js-submit-comment[data-slug]');
    if (commentBtn) {
      e.preventDefault();

      const slug = commentBtn.getAttribute('data-slug');
      if (!slug) return;

      const ta = document.getElementById('modal-comment');
      const text = String((ta && ta.value) || '').trim();
      if (!text) return; // 空コメントは送らない

      commentBtn.disabled = true;
      const r = await _patchNote(slug, { comment: text });
      commentBtn.disabled = false;

      if (r.ok && !r.noop) {
        if (ta) ta.value = '';
        await _refreshModal(slug);      // 履歴に反映
        triggerFiltersRefresh();        // テーブル反映
      }
      return;
    }

    // (C) Open note modal (slug link)
    const openLink = t.closest('a.js-open-note[data-slug]');
    if (openLink) {
      // 修飾キー/中クリックはブラウザ既定（新タブ等）を尊重して何もしない
      if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;

      e.preventDefault();
      const slug = openLink.getAttribute('data-slug');
      if (!slug) return;
      await _openNoteModal(slug);
      return;
    }

    // (D) Admin delete / restore / purge — 既存UX（日本語警告＋purge二重confirm）を維持
    const btn = t.closest('button.js-delete[data-slug], button.js-restore[data-slug], button.js-purge[data-slug]');
    if (!btn) return;

    const slug = btn.getAttribute('data-slug');
    if (!slug) return;

    if (btn.classList.contains('js-delete')) {
      e.preventDefault();
      const msg = `⚠️ 論理削除します（Trash行き）\n\nslug: ${_short(slug, 160)}`;
      if (!confirm(msg)) return;
      const ok = await _do('DELETE', `/notes/${encodeURIComponent(slug)}`);
      if (ok) triggerFiltersRefresh();
      return;
    }

    if (btn.classList.contains('js-restore')) {
      e.preventDefault();
      const msg = `この判断を復元しますか？\n\nslug: ${_short(slug, 160)}`;
      if (!confirm(msg)) return;
      const ok = await _do('POST', `/notes/${encodeURIComponent(slug)}/restore`);
      if (ok) triggerFiltersRefresh();
      return;
    }

    if (btn.classList.contains('js-purge')) {
      e.preventDefault();
      const msg1 = `🔥 完全削除（復元不可）しますか？\n\nslug: ${_short(slug, 160)}`;
      if (!confirm(msg1)) return;
      const msg2 = `⚠️ 本当に削除します。取り消せません。\n\nslug: ${_short(slug, 160)}`;
      if (!confirm(msg2)) return;
      const ok = await _do('DELETE', `/notes/${encodeURIComponent(slug)}/purge`);
      if (ok) triggerFiltersRefresh();
      return;
    }
  });

  // ---- Instant save: select change -> PATCH ----
  document.body.addEventListener('change', async (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const sel = t.closest('select[data-field][data-slug][data-original]');
    if (!sel) return;
    if (sel.disabled) return;

    const slug = sel.getAttribute('data-slug');
    const field = sel.getAttribute('data-field');
    const original = sel.getAttribute('data-original') ?? '';

    if (!slug || !field) return;

    // no-op guard (do not send PATCH)
    if (sel.value === original) return;

    // build payload (contract-aligned)
    let payloadValue = sel.value;
    if (field === 'priority') {
      payloadValue = (payloadValue === '') ? null : Number(payloadValue);
    }

    sel.disabled = true;
    const r = await _patchNote(slug, { [field]: payloadValue });
    sel.disabled = false;

    if (r.ok) {
      // Update original and show a small confirmation
      sel.setAttribute('data-original', sel.value);
      if (!r.noop) _flashOk(sel, '✓');
      triggerFiltersRefresh();
    } else {
      // rollback UI to original
      sel.value = original;
    }
  });

// Modal close on backdrop click
  document.body.addEventListener('click', (e) => {
    const m = el(ID.modal);
    if (!m) return;
    if (e.target === m) closeModal();
  });

  // (任意のUX) Escでモーダル閉じ
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
  });
})();
