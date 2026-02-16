# # tests/test_deny_by_default_contract.py
# from __future__ import annotations

# import pytest


# @pytest.mark.parametrize(
#     "method,path,kwargs,deny",
#     [
#         ("POST", "/scan",  {"json": {"root": "."}}, {401, 403, 404}),
#         ("GET",  "/export",{},                  {401, 403, 404, 302}),
#         ("GET",  "/notes/test", {"headers": {"accept": "application/json"}}, {401, 403, 404}),
#         ("PATCH","/notes/test",{"json": {"priority": 2}, "headers": {"accept": "application/json"}}, {401, 403, 404}),
#     ],
# )
# def test_deny_by_default_unauth_cannot_hit_sensitive_routes(client, method, path, kwargs, deny):
#     # 未ログインのまま叩く
#     method = method.upper()
#     if method == "GET":
#         r = client.get(path, **kwargs)
#     elif method == "POST":
#         r = client.post(path, **kwargs)
#     elif method == "PATCH":
#         r = client.patch(path, **kwargs)
#     else:
#         raise ValueError(method)

#     assert r.status_code in deny, (method, path, r.status_code, r.text[:300])
