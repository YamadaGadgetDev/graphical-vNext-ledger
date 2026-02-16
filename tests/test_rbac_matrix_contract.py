# # tests/test_rbac_matrix_contract.py
# from __future__ import annotations

# import os
# import pytest


# def _pw(role: str) -> str:
#     # conftest が env をセットしている前提だが、無くても落ちないよう fallback
#     env_map = {
#         "admin": "ADMIN_PASSWORD",
#         "operator": "OPERATOR_PASSWORD",
#         "viewer": "VIEWER_PASSWORD",
#         "dev": "DEV_PASSWORD",
#     }
#     key = env_map[role]
#     fallback = {"admin": "admin", "operator": "operator", "viewer": "viewer", "dev": "dev"}[role]
#     return (os.getenv(key) or fallback).strip()


# def _login_json(client, role: str) -> None:
#     r = client.post(
#         "/auth/login",
#         json={"password": _pw(role)},
#         headers={"accept": "application/json"},
#     )
#     assert r.status_code == 200


# def _call(client, method: str, path: str):
#     method = method.upper()
#     if method == "GET":
#         return client.get(path, headers={"accept": "application/json"})
#     if method == "POST":
#         # scanなど想定（必要ならここを増やす）
#         body = {"root": "."} if path == "/scan" else {}
#         return client.post(path, json=body, headers={"accept": "application/json"})
#     if method == "PATCH":
#         return client.patch(path, json={"priority": 2}, headers={"accept": "application/json"})
#     raise ValueError(f"unsupported method: {method}")


# # 期待: まずは境界だけ固める（細部の 200/204 差は吸収）
# MATRIX = [
#     # ---- scan ----
#     ("viewer",  "POST", "/scan",       {401, 403, 404}),
#     ("operator","POST", "/scan",       {200, 202}),
#     ("admin",   "POST", "/scan",       {200, 202}),
#     ("dev",     "POST", "/scan",       {200, 202}),  # dev は operator 相当のはず

#     # ---- export ----
#     ("viewer",  "GET",  "/export",     {401, 403, 404, 302}),
#     ("operator","GET",  "/export",     {200}),
#     ("admin",   "GET",  "/export",     {200}),
#     ("dev",     "GET",  "/export",     {200}),

#     # ---- notes read ----
#     ("viewer",  "GET",  "/notes/test", {200}),
#     ("operator","GET",  "/notes/test", {200}),
#     ("admin",   "GET",  "/notes/test", {200}),
#     ("dev",     "GET",  "/notes/test", {200}),

#     # ---- notes patch ----
#     ("viewer",  "PATCH","/notes/test", {401, 403, 404}),
#     ("operator","PATCH","/notes/test", {200, 204}),
#     ("admin",   "PATCH","/notes/test", {200, 204}),
#     ("dev",     "PATCH","/notes/test", {200, 204}),
# ]


# @pytest.mark.parametrize("role,method,path,expect", MATRIX)
# def test_rbac_matrix_contract(client, role: str, method: str, path: str, expect: set[int]):
#     _login_json(client, role)
#     resp = _call(client, method, path)
#     assert resp.status_code in expect, (role, method, path, resp.status_code, resp.text[:300])
