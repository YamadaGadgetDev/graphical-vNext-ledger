# tests/test_accept_negotiation.py

from __future__ import annotations

from typing import Mapping, Protocol, cast
from types import MappingProxyType

from starlette.requests import Request
import app


class RequestLike(Protocol):
    """app helper が必要とする最小インターフェース: headers を読み取れること。"""

    @property
    def headers(self) -> Mapping[str, str]: ...


class DummyRequest:
    def __init__(self, headers: dict[str, str] | None = None):
        # 内部はdictで持つ（可変でもOK）
        self._headers: dict[str, str] = {k.lower(): v for k, v in (headers or {}).items()}

    @property
    def headers(self) -> Mapping[str, str]:
        # 外には読み取り専用Mappingとして見せる（Pylance対策）
        return MappingProxyType(self._headers)


def _req(headers: dict[str, str]) -> RequestLike:
    return DummyRequest(headers)


def _as_request(r: RequestLike) -> Request:
    # app 側が Request 注釈なのでここで cast
    return cast(Request, r)


def test_wants_json_accept_json_wins() -> None:
    r = _as_request(_req({"accept": "application/json"}))
    assert app._wants_json(r) is True
    assert app._wants_html(r) is False


def test_wants_html_accept_html_wins_even_if_content_type_json() -> None:
    r = _as_request(_req({"accept": "text/html,*/*", "content-type": "application/json"}))
    assert app._wants_json(r) is False
    assert app._wants_html(r) is True


def test_wants_json_neutral_accept_uses_content_type_hint() -> None:
    r = _as_request(_req({"accept": "*/*", "content-type": "application/json"}))
    assert app._wants_json(r) is True
    assert app._wants_html(r) is False


def test_wants_html_neutral_accept_defaults_to_html_when_not_json_body() -> None:
    r = _as_request(_req({"accept": "*/*", "content-type": "text/plain"}))
    assert app._wants_json(r) is False
    assert app._wants_html(r) is True


def test_accepts_json_accept_only_requires_accept_header_not_content_type() -> None:
    r = _as_request(_req({"accept": "*/*", "content-type": "application/json"}))
    assert app._accepts_json_accept_only(r) is False


def test_accepts_json_accept_only_true_when_accept_declares_json() -> None:
    r = _as_request(_req({"accept": "application/json"}))
    assert app._accepts_json_accept_only(r) is True


def test_accepts_json_accept_only_html_and_json_mixed_still_true() -> None:
    r = _as_request(_req({"accept": "text/html,application/json"}))
    assert app._accepts_json_accept_only(r) is True
    assert app._wants_json(r) is False
    assert app._wants_html(r) is True
