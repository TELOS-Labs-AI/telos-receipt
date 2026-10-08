"""Envelope refusal oracles: valid input beside each invalid input."""

import hashlib
import json

import pytest

import telos_receipt as sdk


def valid(payload=None):
    payload = {"values": [True, None, "text", 2], "finite": 1.5} if payload is None else payload
    # Independent canonicalization: a mutated SDK hash must not create its own oracle.
    pin = "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {"payload": payload, "integrity_hash": pin}


class HostileDict(dict):
    def __contains__(self, key):
        raise KeyboardInterrupt("must never call rejected subclass")


class HostileStr(str):
    def startswith(self, *args):
        raise SystemExit("must never call rejected subclass")


@pytest.mark.parametrize("verify", [sdk._verify, sdk.verify_receipt], ids=["internal", "public"])
@pytest.mark.parametrize("case", [
    "object-type", "object-subclass", "missing-payload", "missing-hash", "hash-type",
    "hash-subclass", "hash-prefix", "hash-short", "hash-long", "hash-uppercase",
    "hash-nonhex", "hash-newline", "hash-mismatch",
])
def test_envelope_refusal_beside_valid(verify, case):
    good = valid()
    assert verify(good)["match"] is True
    bad = dict(good)
    if case == "object-type":
        bad = []
    elif case == "object-subclass":
        bad = HostileDict(good)
    elif case == "missing-payload":
        del bad["payload"]
    elif case == "missing-hash":
        del bad["integrity_hash"]
    elif case == "hash-type":
        bad["integrity_hash"] = 7
    elif case == "hash-subclass":
        bad["integrity_hash"] = HostileStr(good["integrity_hash"])
    elif case == "hash-prefix":
        bad["integrity_hash"] = good["integrity_hash"].replace("sha256:", "sha512:")
    elif case == "hash-short":
        bad["integrity_hash"] = "sha256:" + "0" * 63
    elif case == "hash-long":
        bad["integrity_hash"] = "sha256:" + "0" * 65
    elif case == "hash-uppercase":
        bad["integrity_hash"] = "sha256:" + "A" * 64
    elif case == "hash-nonhex":
        bad["integrity_hash"] = "sha256:" + "g" * 64
    elif case == "hash-newline":
        bad["integrity_hash"] += "\n"
    else:
        bad["payload"] = {"altered": True}
    result = verify(bad)
    assert result["match"] is False
    assert result["signature_verified"] is False
    if case.startswith("object-"):
        assert result["reason"] == "receipt is not a JSON object"
    elif case == "missing-payload":
        assert result["reason"] == "missing required field: payload"
    elif case in ("missing-hash", "hash-type", "hash-subclass", "hash-prefix"):
        assert result["reason"] == "missing or malformed integrity_hash (expected 'sha256:<hex>')"
    elif case == "hash-mismatch":
        assert result["reason"].startswith("MISMATCH:")
        assert result["recomputed_integrity_hash"] != good["integrity_hash"]
    else:
        assert result["reason"].startswith("malformed integrity_hash:")


def nested(kind, depth):
    value = 0
    for _ in range(depth):
        value = {"child": value} if kind == "dict" else [value]
    return value


@pytest.mark.parametrize("case", [
    "nonfinite", "dict-depth", "key-type", "list-depth", "unsupported", "subclass", "circular",
])
def test_payload_refusal_beside_valid(case):
    good = {"valid": [1.5, True, None]}
    bad, error = {"bad": object()}, TypeError
    if case == "nonfinite":
        bad, error = {"bad": float("inf")}, ValueError
    elif case in ("dict-depth", "list-depth"):
        kind = case.split("-")[0]
        good = nested(kind, sdk.MAX_DEPTH)
        bad, error = nested(kind, sdk.MAX_DEPTH + 1), ValueError
    elif case == "key-type":
        bad = {"valid": 1, 2: "coerced"}
    elif case == "subclass":
        bad = HostileDict(good)
    elif case == "circular":
        bad, error = [good], ValueError
        bad.append(bad)
    sdk._prevalidate(good)
    envelope = valid(good)
    assert sdk.verify_receipt(envelope)["match"] is True
    with pytest.raises(error):
        sdk._prevalidate(bad)
    for verify in (sdk._verify, sdk.verify_receipt):
        assert verify(envelope)["match"] is True
        result = verify({**envelope, "payload": bad})
        assert result["match"] is False
        assert result["recomputed_integrity_hash"] is None
        assert result["reason"].startswith("payload has no canonical JSON form")


@pytest.mark.parametrize("error", [TypeError, ValueError, RecursionError])
def test_canonicalization_exception_refuses_beside_valid(monkeypatch, error):
    envelope = valid()
    assert sdk.verify_receipt(envelope)["match"] is True

    def fail(payload):
        raise error("synthetic encoder failure")

    monkeypatch.setattr(sdk, "compute_integrity_hash", fail)
    for verify in (sdk._verify, sdk.verify_receipt):
        result = verify(envelope)
        assert result["match"] is False
        assert result["reason"].startswith("payload has no canonical JSON form")


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_unexpected_exception_refuses_beside_valid(monkeypatch, error):
    envelope = valid()
    assert sdk.verify_receipt(envelope)["match"] is True

    def fail(payload):
        raise error("synthetic unexpected failure")

    monkeypatch.setattr(sdk, "compute_integrity_hash", fail)
    result = sdk.verify_receipt(envelope)
    assert result["match"] is False
    assert result["reason"] == "unexpected error while verifying (hostile or malformed input)"
    assert result["recomputed_integrity_hash"] is None
