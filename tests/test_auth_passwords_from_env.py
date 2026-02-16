"""tests/test_auth_passwords_from_env.py

Contract test: All passwords defined in .env must work for login.

This test ensures that:
1. Every password defined in environment variables can successfully authenticate
2. Each password grants the correct role
3. Invalid passwords are rejected with 401
4. Session cookies are properly issued
"""

from __future__ import annotations

import os
from typing import Optional

import pytest
from fastapi.testclient import TestClient

import app


def _get_env_passwords() -> dict[str, Optional[str]]:
    """Extract all password settings from environment."""
    return {
        "admin": os.getenv("ADMIN_PASSWORD"),
        "dev": os.getenv("DEV_PASSWORD"),
        "operator": os.getenv("OPERATOR_PASSWORD"),
        "viewer": os.getenv("VIEWER_PASSWORD"),
    }


def test_all_defined_passwords_can_login():
    """Contract: Every password defined in .env must successfully authenticate."""
    passwords = _get_env_passwords()
    
    for expected_role, password in passwords.items():
        if not password:
            # Skip undefined passwords (e.g., DEV_PASSWORD commented out)
            continue
        
        # Use fresh client for each role to avoid cookie conflicts
        with TestClient(app.app) as client:
            # Attempt login
            resp = client.post(
                "/auth/login",
                json={"password": password},
                headers={"Accept": "application/json"},
            )
            
            # Assert: login succeeds
            assert resp.status_code == 200, (
                f"Login failed for {expected_role} with password from .env. "
                f"Status: {resp.status_code}, Body: {resp.text}"
            )
            
            # Assert: correct role is returned
            data = resp.json()
            assert "role" in data, f"Response for {expected_role} missing 'role' field"
            actual_role = data["role"]
            
            assert actual_role == expected_role, (
                f"Expected role '{expected_role}' but got '{actual_role}' "
                f"for password from {expected_role.upper()}_PASSWORD"
            )
            
            # Assert: session cookie is set (check cookie jar directly)
            cookie_names = [c.name for c in client.cookies.jar]
            assert "vnext_session" in cookie_names, (
                f"Session cookie not set for {expected_role}"
            )


def test_wrong_password_returns_401(client: TestClient):
    """Contract: Invalid passwords must be rejected with 401."""
    resp = client.post(
        "/auth/login",
        json={"password": "this-is-wrong-password-12345"},
        headers={"Accept": "application/json"},
    )
    
    assert resp.status_code == 401, (
        f"Expected 401 for wrong password, got {resp.status_code}"
    )


def test_all_roles_can_call_auth_me(client: TestClient):
    """Contract: After login, /auth/me must return the correct role."""
    passwords = _get_env_passwords()
    
    for expected_role, password in passwords.items():
        if not password:
            continue
        
        # Fresh client for each role
        with TestClient(app.app) as c:
            # Login
            r1 = c.post(
                "/auth/login",
                json={"password": password},
                headers={"Accept": "application/json"},
            )
            assert r1.status_code == 200
            
            # Call /auth/me
            r2 = c.get("/auth/me", headers={"Accept": "application/json"})
            assert r2.status_code == 200, (
                f"/auth/me failed for {expected_role}: {r2.status_code}"
            )
            
            data = r2.json()
            assert data.get("role") == expected_role, (
                f"/auth/me returned wrong role for {expected_role}: {data}"
            )


def test_auth_overlay_is_accessible():
    """Contract: Auth overlay fragment must be accessible via HTTP."""
    # This doesn't test if it renders in browser, but ensures the file exists
    # and is served correctly
    with TestClient(app.app) as client:
        resp = client.get(
            "/static/fragments/auth_overlay.html",
            headers={"Accept": "text/html"},
        )
        
        assert resp.status_code == 200, (
            f"Auth overlay not accessible: {resp.status_code}"
        )
        
        # Assert: contains expected IDs
        html = resp.text
        assert 'id="authOverlay"' in html, "Auth overlay missing #authOverlay"
        assert 'id="authForm"' in html, "Auth overlay missing #authForm"
        assert 'id="authPassword"' in html, "Auth overlay missing #authPassword"
        assert 'id="authMsg"' in html, "Auth overlay missing #authMsg"


def test_session_persists_across_requests(client: TestClient):
    """Contract: Session cookie must persist across multiple requests."""
    passwords = _get_env_passwords()
    admin_pw = passwords.get("admin")
    
    if not admin_pw:
        pytest.skip("ADMIN_PASSWORD not set")
    
    # Login
    r1 = client.post(
        "/auth/login",
        json={"password": admin_pw},
        headers={"Accept": "application/json"},
    )
    assert r1.status_code == 200
    
    # Make multiple requests - session should persist
    for _ in range(3):
        r = client.get("/auth/me", headers={"Accept": "application/json"})
        assert r.status_code == 200
        assert r.json().get("role") == "admin"


def test_logout_clears_session():
    """Contract: Logout must invalidate session."""
    passwords = _get_env_passwords()
    admin_pw = passwords.get("admin")
    
    if not admin_pw:
        pytest.skip("ADMIN_PASSWORD not set")
    
    # Use fresh client
    with TestClient(app.app) as client:
        # Login
        r1 = client.post(
            "/auth/login",
            json={"password": admin_pw},
            headers={"Accept": "application/json"},
        )
        assert r1.status_code == 200
        
        # Verify logged in
        r2 = client.get("/auth/me", headers={"Accept": "application/json"})
        assert r2.status_code == 200
        assert r2.json().get("role") == "admin"
        
        # Logout
        r3 = client.post(
            "/auth/logout",
            headers={"Accept": "application/json"},
        )
        assert r3.status_code in (200, 204)
        
        # Verify session cookie is cleared (check for max-age=0 or deletion)
        # Note: If DEV_PASSWORD is not set, localhost auto-login may grant "dev" role
        # So we check if the role changed from "admin" or if we get 401
        r4 = client.get("/auth/me", headers={"Accept": "application/json"})
        
        # Accept either:
        # - 401 (session fully cleared)
        # - 200 with role != "admin" (localhost auto-login kicked in)
        if r4.status_code == 200:
            # If localhost auto-login is active, role should not be "admin"
            new_role = r4.json().get("role")
            assert new_role != "admin", (
                f"Session should be cleared after logout, but still got admin role. "
                f"Response: {r4.json()}"
            )
        else:
            assert r4.status_code == 401, (
                f"Expected 401 or 200 (with auto-login), got {r4.status_code}"
            )
