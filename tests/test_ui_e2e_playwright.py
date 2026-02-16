"""tests/test_ui_e2e_playwright.py

E2E tests for UI using Playwright (optional).

To run these tests:
1. Install: pip install pytest-playwright
2. Install browsers: playwright install chromium
3. Run: pytest tests/test_ui_e2e_playwright.py

These tests verify:
- Auth overlay modal appears
- IME warning is shown for full-width input
- Login flow works end-to-end
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Generator

import pytest

# Check if playwright is available
try:
    from playwright.sync_api import Page, expect
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not PLAYWRIGHT_AVAILABLE,
    reason="Playwright not installed (pip install pytest-playwright)"
)


@pytest.fixture(scope="module")
def server() -> Generator[str, None, None]:
    """Start the app server for E2E tests."""
    # Start uvicorn in background
    proc = subprocess.Popen(
        ["uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8765"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    # Wait for server to be ready
    time.sleep(2)
    
    yield "http://127.0.0.1:8765"
    
    # Cleanup
    proc.terminate()
    proc.wait()


@pytest.mark.e2e
def test_auth_overlay_appears_on_load(page: Page, server: str):
    """Contract: Auth overlay must appear when user visits the site."""
    page.goto(server)
    
    # Wait for auth overlay to appear
    overlay = page.locator("#authOverlay")
    expect(overlay).to_be_visible(timeout=5000)
    
    # Assert: overlay contains expected elements
    expect(page.locator("#authForm")).to_be_visible()
    expect(page.locator("#authPassword")).to_be_visible()
    expect(page.locator("#authMsg")).to_be_visible()


@pytest.mark.e2e
def test_ime_warning_appears_for_fullwidth_input(page: Page, server: str):
    """Contract: IME warning must appear when full-width characters are entered."""
    page.goto(server)
    
    # Wait for overlay
    expect(page.locator("#authOverlay")).to_be_visible(timeout=5000)
    
    # Enter full-width password (Japanese IME)
    pw_input = page.locator("#authPassword")
    pw_input.fill("ａｄｍｉｎ１２３")  # Full-width
    
    # Submit form
    page.locator("#authForm button[type='submit']").click()
    
    # Assert: IME warning appears
    msg = page.locator("#authMsg")
    expect(msg).to_contain_text("半角英数字で入力してください")


@pytest.mark.e2e
def test_login_success_closes_overlay(page: Page, server: str):
    """Contract: Successful login must close the auth overlay."""
    admin_pw = os.getenv("ADMIN_PASSWORD")
    if not admin_pw:
        pytest.skip("ADMIN_PASSWORD not set")
    
    page.goto(server)
    
    # Wait for overlay
    expect(page.locator("#authOverlay")).to_be_visible(timeout=5000)
    
    # Enter correct password
    pw_input = page.locator("#authPassword")
    pw_input.fill(admin_pw)
    
    # Submit form
    page.locator("#authForm button[type='submit']").click()
    
    # Wait for login to complete
    time.sleep(1)
    
    # Assert: overlay is hidden
    overlay = page.locator("#authOverlay")
    expect(overlay).to_be_hidden(timeout=5000)


@pytest.mark.e2e
def test_wrong_password_shows_error(page: Page, server: str):
    """Contract: Wrong password must show error message."""
    page.goto(server)
    
    # Wait for overlay
    expect(page.locator("#authOverlay")).to_be_visible(timeout=5000)
    
    # Enter wrong password
    pw_input = page.locator("#authPassword")
    pw_input.fill("wrong-password-12345")
    
    # Submit form
    page.locator("#authForm button[type='submit']").click()
    
    # Wait for error message
    time.sleep(1)
    
    # Assert: error message appears
    msg = page.locator("#authMsg")
    expect(msg).to_contain_text("パスワードが一致しません")


@pytest.mark.e2e
def test_role_badge_updates_after_login(page: Page, server: str):
    """Contract: Role badge must update to show current role after login."""
    admin_pw = os.getenv("ADMIN_PASSWORD")
    if not admin_pw:
        pytest.skip("ADMIN_PASSWORD not set")
    
    page.goto(server)
    
    # Wait for overlay and login
    expect(page.locator("#authOverlay")).to_be_visible(timeout=5000)
    page.locator("#authPassword").fill(admin_pw)
    page.locator("#authForm button[type='submit']").click()
    
    # Wait for login
    time.sleep(1)
    
    # Assert: role badge shows correct role
    badge = page.locator("#roleBadge")
    expect(badge).to_contain_text("role: admin")


@pytest.mark.e2e
def test_empty_password_shows_warning(page: Page, server: str):
    """Contract: Empty password must show appropriate message."""
    page.goto(server)
    
    # Wait for overlay
    expect(page.locator("#authOverlay")).to_be_visible(timeout=5000)
    
    # Submit without entering password
    page.locator("#authForm button[type='submit']").click()
    
    # Assert: warning appears
    msg = page.locator("#authMsg")
    expect(msg).to_contain_text("パスワードを入力してください")
