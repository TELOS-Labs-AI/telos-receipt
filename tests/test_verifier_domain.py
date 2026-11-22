"""build_* refuses what telos-verify would fail, and only that.

Every invalid case is built beside the valid baseline it mutates, so a
refusal is attributable to the one field that changed. The rules mirror
telos-verify's telos/0.1-unsigned checks: TV-SCHEMA-001 (issued_at form,
string members), TV-S2-002..006 (action_governed field forms) and
TV-CANON-001/002 (canonical number and string domain).
"""

import pytest

import telos_receipt
from telos_receipt import build_action_receipt, build_receipt, verify_receipt

ISSUED = "2026-11-14T00:00:00+00:00"
BASE = {
    "action_name": "write_file",
    "action_params": {"path": "/tmp/x"},
    "agent_id": "demo-agent",
    "verdict": "EXECUTE",
    "composite_score": 0.81,
    "scores": {"purpose": 0.9, "scope": 0.8},
    "pa_id": "pa::demo-agent::v1",
    "issued_at": ISSUED,
}


def test_public_verdict_vocabulary_is_the_verifiers_0_1_list():
    assert telos_receipt.ACTION_VERDICTS == ("EXECUTE", "CLARIFY", "SUGGEST", "ESCALATE", "INERT")
    assert "ACTION_VERDICTS" in telos_receipt.__all__


def test_valid_baseline_builds_and_verifies():
    assert verify_receipt(build_action_receipt(**BASE))["match"] is True


@pytest.mark.parametrize("verdict", ["EXECUTE", "CLARIFY", "SUGGEST", "ESCALATE", "INERT"])
def test_every_public_verdict_is_accepted(verdict):
    assert build_action_receipt(**{**BASE, "verdict": verdict})["payload"]["verdict"] == verdict


@pytest.mark.parametrize(
    "value",
    [0, 0.0, 1, 0.0001, -0.0001, 9.999e15, 2**53 - 1, -(2**53 - 1), 1.5, -0.2],
)
def test_numbers_inside_the_canonical_domain_are_accepted(value):
    r = build_action_receipt(**{**BASE, "composite_score": value, "scores": {"purpose": value}})
    assert r["payload"]["composite_score"] == value


@pytest.mark.parametrize(
    "override, check",
    [
        ({"verdict": "ALLOW"}, "TV-S2-002"),
        ({"verdict": "execute"}, "TV-S2-002"),
        ({"verdict": "ALIGNMENT"}, "TV-S2-002"),  # a 0.3 label, not valid on 0.1
        ({"pa_id": ""}, "TV-S2-006"),
        ({"scores": {"": 0.5}}, "TV-S2-005"),
        ({"composite_score": 1e-05}, "TV-CANON-001"),
        ({"composite_score": 1e16}, "TV-CANON-001"),
        ({"composite_score": -0.0}, "TV-CANON-001"),
        ({"scores": {"purpose": 2**53}}, "TV-CANON-001"),
        ({"scores": {"purpose": -(2**60)}}, "TV-CANON-001"),
        ({"action_name": "w\ud800"}, "TV-CANON-002"),
        ({"scores": {"p\udfff": 0.5}}, "TV-CANON-002"),
        ({"issued_at": "2026-11-14 00:00"}, "TV-SCHEMA-001"),
        ({"issued_at": "2026-11-14T00:00:00"}, "TV-SCHEMA-001"),
    ],
)
def test_values_telos_verify_fails_are_refused_beside_the_valid_baseline(override, check):
    build_action_receipt(**BASE)  # unmutated neighbour builds
    with pytest.raises(ValueError, match=check):
        build_action_receipt(**{**BASE, **override})


@pytest.mark.parametrize(
    "override, check",
    [
        ({"verdict": None}, "TV-S2-002"),
        ({"composite_score": True}, "TV-S2-003"),
        ({"composite_score": "0.8"}, "TV-S2-003"),
        ({"scores": [0.5]}, "TV-S2-004"),
        ({"scores": {"purpose": False}}, "TV-S2-004"),
        ({"scores": {"purpose": None}}, "TV-S2-004"),
        ({"pa_id": None}, "TV-SCHEMA-001"),
        ({"action_name": 7}, "TV-SCHEMA-001"),
        ({"agent_id": None}, "TV-SCHEMA-001"),
    ],
)
def test_wrong_types_are_refused_beside_the_valid_baseline(override, check):
    build_action_receipt(**BASE)
    with pytest.raises(TypeError, match=check):
        build_action_receipt(**{**BASE, **override})


def test_generic_receipt_payload_is_held_to_the_canonical_domain():
    assert build_receipt("note", {"v": 0.5}, "demo-agent", issued_at=ISSUED)["payload"] == {"v": 0.5}
    with pytest.raises(ValueError, match="TV-CANON-001"):
        build_receipt("note", {"nested": [{"v": 1e-05}]}, "demo-agent", issued_at=ISSUED)


def test_generic_receipt_issued_at_and_kind_forms():
    build_receipt("note", {"v": 1}, "demo-agent", issued_at="2026-11-14T00:00:00.123456Z")
    with pytest.raises(ValueError, match="TV-SCHEMA-001"):
        build_receipt("note", {"v": 1}, "demo-agent", issued_at="yesterday")
    with pytest.raises(TypeError, match="TV-SCHEMA-001"):
        build_receipt(None, {"v": 1}, "demo-agent", issued_at=ISSUED)


def test_default_issued_at_is_accepted():
    assert verify_receipt(build_receipt("note", {"v": 1}, "demo-agent"))["match"] is True


def test_action_params_are_hashed_not_domain_checked():
    # action_params never enter the payload (only their hash does), so the
    # verifier's domain does not apply to them; the SDK must not refuse them.
    r = build_action_receipt(**{**BASE, "action_params": {"n": 1e-05, "big": 2**60}})
    assert r["payload"]["action_params_hash"].startswith("sha256:")


def test_compute_integrity_hash_contract_is_unchanged():
    # The hash function is not a receipt builder; known-answer vectors hold.
    assert telos_receipt.compute_integrity_hash({"v": 1e-05}).startswith("sha256:")
    assert (
        telos_receipt.compute_integrity_hash({"v": 1.0})
        == "sha256:f3c8be97307d38261061fa08e74365e54a239cddb1d189f3bea18022adbe2f35"
    )


AG_PAYLOAD = {
    "action_name": "write_file",
    "action_params_hash": "sha256:" + "0" * 64,
    "verdict": "EXECUTE",
    "composite_score": 0.81,
    "scores": {"purpose": 0.9},
    "pa_id": "pa::demo-agent::v1",
}


@pytest.mark.parametrize("payload", [[], "x", None, 1])
def test_generic_builder_requires_an_object_payload(payload):
    build_receipt("note", {}, "demo-agent", issued_at=ISSUED)
    with pytest.raises(TypeError, match="TV-SCHEMA-001"):
        build_receipt("note", payload, "demo-agent", issued_at=ISSUED)


@pytest.mark.parametrize(
    "payload, exc, check",
    [
        ({}, ValueError, "TV-SCHEMA-001"),
        ({k: v for k, v in AG_PAYLOAD.items() if k != "pa_id"}, ValueError, "TV-SCHEMA-001"),
        ({**AG_PAYLOAD, "note": "x"}, ValueError, "TV-SCHEMA-001"),
        ({**AG_PAYLOAD, "verdict": "ALLOW"}, ValueError, "TV-S2-002"),
        ({**AG_PAYLOAD, "action_name": 7}, TypeError, "TV-SCHEMA-001"),
        ({**AG_PAYLOAD, "action_params_hash": "abc"}, ValueError, "TV-SCHEMA-001"),
        ({**AG_PAYLOAD, "composite_score": "0.8"}, TypeError, "TV-S2-003"),
        ({**AG_PAYLOAD, "pa_id": ""}, ValueError, "TV-S2-006"),
        ({**AG_PAYLOAD, "sequence": 0}, ValueError, "TV-CHAIN-004"),
        ({**AG_PAYLOAD, "sequence": "0", "previous_receipt_integrity_hash": None}, TypeError, "TV-CHAIN-001"),
    ],
)
def test_generic_builder_applies_action_governed_rules(payload, exc, check):
    build_receipt("action_governed", AG_PAYLOAD, "demo-agent", issued_at=ISSUED)
    with pytest.raises(exc, match=check):
        build_receipt("action_governed", payload, "demo-agent", issued_at=ISSUED)


def test_generic_builder_admits_the_chain_pair():
    p = {**AG_PAYLOAD, "sequence": 0, "previous_receipt_integrity_hash": None}
    assert build_receipt("action_governed", p, "demo-agent", issued_at=ISSUED)["payload"]["sequence"] == 0


@pytest.mark.parametrize(
    "payload, exc, check",
    [
        ({"v": 1, "sequence": 0}, ValueError, "TV-CHAIN-004"),
        ({"v": 1, "previous_receipt_integrity_hash": None}, ValueError, "TV-CHAIN-004"),
        ({"v": 1, "sequence": False, "previous_receipt_integrity_hash": None}, TypeError, "TV-CHAIN-001"),
        ({"v": 1, "sequence": "0", "previous_receipt_integrity_hash": None}, TypeError, "TV-CHAIN-001"),
    ],
)
def test_generic_builder_applies_chain_member_rules_to_every_kind(payload, exc, check):
    build_receipt("note", {"v": 1, "sequence": 0, "previous_receipt_integrity_hash": None}, "a")
    with pytest.raises(exc, match=check):
        build_receipt("note", payload, "a")
