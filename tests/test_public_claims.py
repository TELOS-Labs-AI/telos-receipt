"""README and docstring claims match what the builders do.

Each claim is paired with the behaviour it describes, so the text cannot drift
from the code in either direction.
"""

from pathlib import Path

import telos_receipt as t

README = Path(__file__).resolve().parent.parent / "README.md"
ISSUED = "2026-11-14T00:00:00Z"
ACTION = {
    "action_name": "write_file",
    "action_params": {"path": "/tmp/x"},
    "agent_id": "demo-agent",
    "verdict": "EXECUTE",
    "composite_score": 0.81,
    "scores": {"purpose": 0.9},
    "pa_id": "pa::demo-agent::v1",
    "issued_at": ISSUED,
}


def _row(name):
    return next(ln for ln in README.read_text(encoding="utf-8").splitlines() if ln.startswith(f"| {name} |"))


def _flat():
    return " ".join(README.read_text(encoding="utf-8").split())


def test_issued_at_row_describes_a_format_check():
    # Behaviour: the calendar is not checked.
    assert t.build_receipt("note", {"v": 1}, "a", issued_at="2026-02-30T00:00:00Z")["issued_at"].startswith("2026-02-30")
    row = _row("`issued_at`")
    assert "RFC 3339 date-time format" in row
    assert "calendar values such as `2026-02-30` are not validated" in row
    assert "not a valid RFC 3339 string" not in _flat()


def test_surrogate_row_says_pairs_are_accepted_and_names_the_pair_key_checks():
    pair = "\ud83d\ude00"
    assert t.build_receipt("note", {"v": pair}, "a", issued_at=ISSUED)["payload"] == {"v": pair}
    row = _row("every payload string and key")
    assert "a surrogate pair is accepted" in row
    assert "`TV-PARSE-001`" in row and "`TV-HASH-004`" in row


def test_number_type_rule_says_the_builder_keeps_the_callers_numeric_types():
    r = t.build_action_receipt(**{**ACTION, "composite_score": 1, "scores": {"purpose": 1, "scope": 0.5}})
    assert type(r["payload"]["composite_score"]) is int
    assert type(r["payload"]["scores"]["purpose"]) is int
    assert type(r["payload"]["scores"]["scope"]) is float
    text = _flat()
    assert "puts floats (`composite_score`, `scores`) into the payload" not in text
    assert "with the caller's numeric types" in text


def test_action_receipt_docstring_states_what_the_params_digest_can_reveal():
    a = t.build_action_receipt(**ACTION)
    b = t.build_action_receipt(**{**ACTION, "verdict": "INERT"})
    assert "action_params" not in a["payload"]
    # Same arguments, same digest: equality is visible across receipts.
    assert a["payload"]["action_params_hash"] == b["payload"]["action_params_hash"]
    doc = " ".join(t.build_action_receipt.__doc__.split())
    assert "without leaking" not in doc
    assert "raw params are omitted" in doc
    assert "reveals when two receipts scored the same arguments" in doc
    assert "guess" in doc
