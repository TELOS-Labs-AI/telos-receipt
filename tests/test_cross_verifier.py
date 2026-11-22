"""Builder refusals agree with the independent telos-verify CLI (R2/X1, review r2).

For every case below:
  * "ok"     -- the SDK builds the receipt and telos-verify exits 0;
  * "refuse" -- the SDK raises, AND the same receipt assembled by hand (correct
                integrity hash, SDK bypassed) does not pass telos-verify
                (exit 1 FAILED or 2 INCOMPLETE). That pairing is what makes the
                refusal a statement about the verifier, not about the SDK.

Each refusal sits next to the valid neighbour it mutates. Point TELOS_VERIFY at
a telos-verify checkout (the directory holding telos_verify.py) to run these;
without it the module is skipped and says so.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import telos_receipt as t

VERIFY_DIR = os.environ.get("TELOS_VERIFY", "")
pytestmark = pytest.mark.skipif(
    not (VERIFY_DIR and (Path(VERIFY_DIR) / "telos_verify.py").is_file()),
    reason="set TELOS_VERIFY to a telos-verify checkout to run the cross-verifier tests",
)

ISSUED = "2026-11-14T00:00:00+00:00"
ACTION = {
    "action_name": "write_file",
    "action_params": {"path": "/tmp/x"},
    "agent_id": "demo-agent",
    "verdict": "EXECUTE",
    "composite_score": 0.81,
    "scores": {"purpose": 0.9, "scope": 0.8},
    "pa_id": "pa::demo-agent::v1",
    "issued_at": ISSUED,
}
AG = {
    "action_name": "write_file",
    "action_params_hash": t.compute_integrity_hash({"path": "/tmp/x"}),
    "verdict": "EXECUTE",
    "composite_score": 0.81,
    "scores": {"purpose": 0.9, "scope": 0.8},
    "pa_id": "pa::demo-agent::v1",
}


def _without(d, key):
    return {k: v for k, v in d.items() if k != key}


def _cli(receipt, tmp_path, name):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(receipt))
    proc = subprocess.run(
        [sys.executable, "-s", "-B", "telos_verify.py", str(path), "--quiet"],
        cwd=VERIFY_DIR, capture_output=True, text=True, timeout=60, check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _by_hand(kind, payload, agent_id="demo-agent", issued_at=ISSUED, engine=t.ENGINE_LABEL):
    """The receipt build_receipt would write, assembled without its checks."""
    return {
        "receipt_version": t.RECEIPT_VERSION,
        "kind": kind,
        "agent_id": agent_id,
        "payload": payload,
        "issued_at": issued_at,
        "integrity_hash": t.compute_integrity_hash(payload),
        "covered_fields": t.COVERED,
        "signing_status": t.SIGNING_STATUS,
        "signature": None,
        "engine": engine,
    }


# (case id, kind, payload) for build_receipt
GENERIC_CASES = [
    ("ok-generic-object", "ok", "note", {"v": 1}),
    ("ok-generic-empty-object", "ok", "note", {}),
    ("refuse-generic-list", "refuse", "note", []),
    ("refuse-generic-string", "refuse", "note", "x"),
    ("refuse-generic-null", "refuse", "note", None),
    ("ok-ag-complete", "ok", "action_governed", AG),
    ("ok-ag-chain-genesis", "ok", "action_governed",
     {**AG, "sequence": 0, "previous_receipt_integrity_hash": None}),
    ("ok-ag-chain-later", "ok", "action_governed",
     {**AG, "sequence": 3, "previous_receipt_integrity_hash": "sha256:" + "a" * 64}),
    ("refuse-ag-empty", "refuse", "action_governed", {}),
    ("refuse-ag-list", "refuse", "action_governed", []),
    ("refuse-ag-missing-pa_id", "refuse", "action_governed", _without(AG, "pa_id")),
    ("refuse-ag-missing-action_params_hash", "refuse", "action_governed",
     _without(AG, "action_params_hash")),
    ("refuse-ag-undeclared-member", "refuse", "action_governed", {**AG, "note": "x"}),
    ("refuse-ag-verdict-ALLOW", "refuse", "action_governed", {**AG, "verdict": "ALLOW"}),
    ("refuse-ag-verdict-0.3-label", "refuse", "action_governed", {**AG, "verdict": "ALIGNMENT"}),
    ("refuse-ag-action_name-int", "refuse", "action_governed", {**AG, "action_name": 7}),
    ("refuse-ag-pa_id-int", "refuse", "action_governed", {**AG, "pa_id": 7}),
    ("refuse-ag-pa_id-empty", "refuse", "action_governed", {**AG, "pa_id": ""}),
    ("refuse-ag-params-hash-form", "refuse", "action_governed", {**AG, "action_params_hash": "abc"}),
    ("refuse-ag-params-hash-int", "refuse", "action_governed", {**AG, "action_params_hash": 7}),
    ("refuse-ag-verdict-int", "refuse", "action_governed", {**AG, "verdict": 1}),
    ("refuse-ag-composite-string", "refuse", "action_governed", {**AG, "composite_score": "0.8"}),
    ("refuse-ag-composite-bool", "refuse", "action_governed", {**AG, "composite_score": True}),
    ("refuse-ag-scores-list", "refuse", "action_governed", {**AG, "scores": [0.5]}),
    ("refuse-ag-scores-bool", "refuse", "action_governed", {**AG, "scores": {"purpose": True}}),
    ("refuse-ag-scores-empty-label", "refuse", "action_governed", {**AG, "scores": {"": 0.5}}),
    ("refuse-ag-sequence-alone", "refuse", "action_governed", {**AG, "sequence": 0}),
    ("refuse-ag-previous-alone", "refuse", "action_governed",
     {**AG, "previous_receipt_integrity_hash": None}),
    ("refuse-ag-sequence-string", "refuse", "action_governed",
     {**AG, "sequence": "0", "previous_receipt_integrity_hash": None}),
    ("refuse-ag-sequence-bool", "refuse", "action_governed",
     {**AG, "sequence": False, "previous_receipt_integrity_hash": None}),
    ("refuse-ag-domain-float", "refuse", "action_governed", {**AG, "composite_score": 1e-05}),
    ("refuse-generic-domain-int", "refuse", "note", {"v": 2**60}),
    ("refuse-generic-domain-negative-zero", "refuse", "note", {"v": -0.0}),
    ("refuse-generic-surrogate-value", "refuse", "note", {"v": "\ud800"}),
    ("refuse-generic-surrogate-key", "refuse", "note", {"\udfff": 1}),
    # A paired surrogate is one astral character once parsed; the verifier accepts it.
    ("ok-generic-surrogate-pair-value", "ok", "note", {"v": "\ud83d\ude00"}),
    ("ok-generic-surrogate-pair-key", "ok", "note", {"\ud83d\ude00": 1}),
    ("refuse-generic-surrogate-reversed", "refuse", "note", {"v": "\ude00\ud83d"}),
    ("refuse-generic-surrogate-high-at-end", "refuse", "note", {"v": "a\ud83d"}),
    ("ok-generic-surrogate-pair-key-order-kept", "ok", "note", {"\ud83d\ude00": 1, "\ud7ff": 2}),
    ("refuse-generic-surrogate-pair-key-reorders", "refuse", "note", {"\ud83d\ude00": 1, "\uffff": 2}),
    ("refuse-generic-surrogate-pair-key-repeats", "refuse", "note", {"\ud83d\ude00": 1, "\U0001f600": 2}),
    # Chain-member rules apply to every kind, not only action_governed (review r2-2).
    ("ok-generic-chain-genesis", "ok", "note", {"v": 1, "sequence": 0, "previous_receipt_integrity_hash": None}),
    ("ok-generic-chain-later", "ok", "note",
     {"v": 1, "sequence": 3, "previous_receipt_integrity_hash": "sha256:" + "a" * 64}),
    ("refuse-generic-sequence-alone", "refuse", "note", {"v": 1, "sequence": 0}),
    ("refuse-generic-previous-alone", "refuse", "note", {"v": 1, "previous_receipt_integrity_hash": None}),
    ("refuse-generic-sequence-bool", "refuse", "note",
     {"v": 1, "sequence": False, "previous_receipt_integrity_hash": None}),
    ("refuse-generic-sequence-string", "refuse", "note",
     {"v": 1, "sequence": "0", "previous_receipt_integrity_hash": None}),
    ("refuse-generic-sequence-float", "refuse", "note",
     {"v": 1, "sequence": 1.5, "previous_receipt_integrity_hash": None}),
]


@pytest.mark.parametrize("case, expect, kind, payload", GENERIC_CASES, ids=[c[0] for c in GENERIC_CASES])
def test_build_receipt_agrees_with_telos_verify(case, expect, kind, payload, tmp_path):
    neighbour = t.build_receipt("action_governed", AG, "demo-agent", issued_at=ISSUED)
    assert _cli(neighbour, tmp_path, "neighbour")[0] == 0
    if expect == "ok":
        rc, out = _cli(t.build_receipt(kind, payload, "demo-agent", issued_at=ISSUED), tmp_path, case)
        assert rc == 0, out
    else:
        with pytest.raises((TypeError, ValueError)):
            t.build_receipt(kind, payload, "demo-agent", issued_at=ISSUED)
        rc, out = _cli(_by_hand(kind, payload), tmp_path, case)
        assert rc in (1, 2), out


ACTION_CASES = [
    ("ok-action-baseline", "ok", {}),
    ("ok-action-every-verdict-SUGGEST", "ok", {"verdict": "SUGGEST"}),
    ("ok-action-INERT", "ok", {"verdict": "INERT"}),
    ("ok-action-boundary-floats", "ok", {"composite_score": 0.0001, "scores": {"p": 9.999e15}}),
    ("ok-action-boundary-ints", "ok", {"composite_score": 2**53 - 1, "scores": {"p": -(2**53 - 1)}}),
    ("refuse-action-ALLOW", "refuse", {"verdict": "ALLOW"}),
    ("refuse-action-1e-05", "refuse", {"composite_score": 1e-05}),
    ("refuse-action-2pow60", "refuse", {"scores": {"p": 2**60}}),
    ("refuse-action-pa_id-empty", "refuse", {"pa_id": ""}),
    ("refuse-action-empty-label", "refuse", {"scores": {"": 0.5}}),
    ("refuse-action-action_name-int", "refuse", {"action_name": 7}),
    ("refuse-action-pa_id-int", "refuse", {"pa_id": 7}),
    ("refuse-action-verdict-int", "refuse", {"verdict": 1}),
    ("refuse-action-composite-bool", "refuse", {"composite_score": True}),
    ("refuse-action-composite-string", "refuse", {"composite_score": "0.8"}),
    ("refuse-action-scores-list", "refuse", {"scores": [0.5]}),
    ("refuse-action-scores-string-value", "refuse", {"scores": {"p": "0.5"}}),
    ("refuse-action-negative-zero", "refuse", {"composite_score": -0.0}),
    ("refuse-action-surrogate-label", "refuse", {"scores": {"\ud800": 0.5}}),
    ("refuse-action-surrogate-action_name", "refuse", {"action_name": "\udc00"}),
    ("ok-action-surrogate-pair-label", "ok", {"scores": {"\ud83d\ude00": 0.5}}),
    ("refuse-action-surrogate-pair-label-reorders", "refuse", {"scores": {"\ud83d\ude00": 0.5, "\uffff": 0.5}}),
]


@pytest.mark.parametrize("case, expect, override", ACTION_CASES, ids=[c[0] for c in ACTION_CASES])
def test_build_action_receipt_agrees_with_telos_verify(case, expect, override, tmp_path):
    kw = {**ACTION, **override}
    if expect == "ok":
        rc, out = _cli(t.build_action_receipt(**kw), tmp_path, case)
        assert rc == 0, out
    else:
        with pytest.raises((TypeError, ValueError)):
            t.build_action_receipt(**kw)
        payload = {
            "action_name": kw["action_name"],
            "action_params_hash": t.compute_integrity_hash(kw["action_params"]),
            "verdict": kw["verdict"],
            "composite_score": kw["composite_score"],
            "scores": kw["scores"],
            "pa_id": kw["pa_id"],
        }
        rc, out = _cli(_by_hand("action_governed", payload), tmp_path, case)
        assert rc in (1, 2), out


# Envelope rows (kind, agent_id, engine, issued_at), for both builders. Each
# override is applied to a valid receipt; the hand-built twin carries it too.
ENVELOPE_CASES = [
    ("ok-envelope-baseline", "ok", {}),
    ("ok-issued-at-fraction-offset", "ok", {"issued_at": "2026-11-14T00:00:00.123456789-05:00"}),
    # Both tools check the format only; neither validates calendar values.
    ("ok-issued-at-format-only-feb-30", "ok", {"issued_at": "2026-02-30T00:00:00Z"}),
    ("refuse-agent_id-int", "refuse", {"agent_id": 7}),
    ("refuse-engine-int", "refuse", {"engine": 7}),
    ("refuse-engine-none", "refuse", {"engine": None}),
    ("refuse-issued-at-no-zone", "refuse", {"issued_at": "2026-11-14T00:00:00"}),
    ("refuse-issued-at-date-only", "refuse", {"issued_at": "2026-11-14"}),
    ("refuse-issued-at-space", "refuse", {"issued_at": "2026-11-14 00:00:00Z"}),
    ("refuse-issued-at-trailing-newline", "refuse", {"issued_at": "2026-11-14T00:00:00Z\n"}),
    ("refuse-issued-at-int", "refuse", {"issued_at": 1763078400}),
]


@pytest.mark.parametrize("case, expect, override", ENVELOPE_CASES, ids=[c[0] for c in ENVELOPE_CASES])
@pytest.mark.parametrize("builder", ["build_receipt", "build_action_receipt"])
def test_envelope_rows_agree_with_telos_verify(builder, case, expect, override, tmp_path):
    env = {"agent_id": "demo-agent", "issued_at": ISSUED, "engine": t.ENGINE_LABEL, **override}

    def build():
        if builder == "build_receipt":
            return t.build_receipt("action_governed", AG, env["agent_id"],
                                   issued_at=env["issued_at"], engine=env["engine"])
        return t.build_action_receipt(**{**ACTION, **env})

    if expect == "ok":
        rc, out = _cli(build(), tmp_path, case)
        assert rc == 0, out
    else:
        with pytest.raises((TypeError, ValueError)):
            build()
        rc, out = _cli(_by_hand("action_governed", AG, **env), tmp_path, case)
        assert rc in (1, 2), out


@pytest.mark.parametrize("kind", [7, None, b"note"], ids=["kind-int", "kind-none", "kind-bytes"])
def test_kind_must_be_str_and_telos_verify_agrees(kind, tmp_path):
    ok = t.build_receipt("note", {"v": 1}, "demo-agent", issued_at=ISSUED)
    assert _cli(ok, tmp_path, "neighbour")[0] == 0
    with pytest.raises(TypeError):
        t.build_receipt(kind, {"v": 1}, "demo-agent", issued_at=ISSUED)
    bad = _by_hand("note", {"v": 1})
    # JSON has no bytes; a list is the nearest non-str form for that case.
    bad["kind"] = ["note"] if isinstance(kind, bytes) else kind
    rc, out = _cli(bad, tmp_path, "bad-kind")
    assert rc in (1, 2), out
