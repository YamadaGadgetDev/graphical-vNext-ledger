# tests/test_note_modal_contract.py
from __future__ import annotations


def test_note_modal_fragment_contract(client):
    """modal=1 は HTML フラグメント（<html> を含まない）"""
    r = client.get("/notes/test?modal=1", headers={"Accept": "text/html"})
    assert r.status_code == 200

    body = r.text
    low = body.lower()

    assert "<html" not in low
    assert "note-modal" in body  # class name contract
    assert 'id="modal-status"' in body
    assert 'id="modal-priority"' in body
    assert 'id="modal-risk"' in body


def test_note_modal_priority_and_risk_choices_contract(client):
    """priority は 1..3、risk は none/high/critical のみ（UI契約）"""
    r = client.get("/notes/test?modal=1", headers={"Accept": "text/html"})
    assert r.status_code == 200
    body = r.text

    # priority choices are 1..3 only
    assert '<option value="1"' in body
    assert '<option value="2"' in body
    assert '<option value="3"' in body
    assert '<option value="4"' not in body
    assert '<option value="5"' not in body

    # risk choices are none/high/critical only
    assert '<option value="none"' in body
    assert '<option value="high"' in body
    assert '<option value="critical"' in body
