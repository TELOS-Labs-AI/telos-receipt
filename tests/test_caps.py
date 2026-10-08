"""Independent bounded-input controls, with valid neighbors and repaired hashes."""

import base64
import hashlib
import io
import json
from pathlib import Path

import pytest

import telos_receipt
from telos_receipt import native
from telos_receipt._native_vendor import hermes_v2 as adapter
from telos_receipt._native_vendor import verify_native_v2 as verifier


def request():
    return json.loads((Path(__file__).parent / "native-request.json").read_text())


def carrier(raw):
    return {
        **request(),
        "receipts_base64": base64.b64encode(raw).decode(),
        "expected_sha256": hashlib.sha256(raw).hexdigest(),
    }


def row(previous=None, args=None):
    result = json.loads(base64.b64decode(request()["receipts_base64"]))
    if previous is not None:
        result["previous_receipt_hash"] = previous
    if args is not None:
        result["args"] = args
    source = adapter.inspect_source(json.dumps(result).encode())
    result["canonical_input_hash"] = hashlib.sha256(adapter.canonical_input_hash_preimage(source)).hexdigest()
    result["receipt_hash"] = hashlib.sha256(
        json.dumps(
            {k: v for k, v in result.items() if k != "receipt_hash"}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    return result


def serialize(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def refused(value, code):
    assert telos_receipt.verify_native_receipts(request())["status"] == "PASS"
    result = telos_receipt.verify_native_receipts(value)
    assert result["status"] == "UNAVAILABLE"
    assert result["problems"] == [code]


def test_encoded_size_cap():
    refused({**request(), "receipts_base64": "A" * 1398105}, "INPUT_TOO_LARGE")


def test_native_total_byte_cap():
    raw = base64.b64decode(request()["receipts_base64"])
    refused(carrier(raw + b" " * (1048577 - len(raw))), "INPUT_TOO_LARGE")


def test_native_row_byte_cap_beside_valid_row():
    good = row()
    first = serialize(good)
    second = serialize(row(good["receipt_hash"]))
    bounded = second[:-1] + b" " * (65536 - len(second)) + b"\n"
    assert telos_receipt.verify_native_receipts(carrier(first + bounded))["status"] == "PASS"
    refused(carrier(first + bounded[:-1] + b" \n"), "ROW_TOO_LARGE")


def test_native_row_count_cap():
    previous = request()["start_previous"]
    rows = []
    for _ in range(33):
        value = row(previous)
        rows.append(serialize(value))
        previous = value["receipt_hash"]
    assert telos_receipt.verify_native_receipts(carrier(b"".join(rows[:32])))["status"] == "PASS"
    refused(carrier(b"".join(rows)), "TOO_MANY_ROWS")


def test_native_json_depth_cap_beside_valid_row():
    good = row()
    nested = 0
    for _ in range(23):
        nested = [nested]
    allowed = row(good["receipt_hash"], {"nested": nested})
    # root -> args -> nested adds two levels, so 22 lists reach depth 24.
    allowed["args"]["nested"] = nested[0]
    allowed = row(good["receipt_hash"], allowed["args"])
    assert telos_receipt.verify_native_receipts(carrier(serialize(good) + serialize(allowed)))["status"] == "PASS"
    bad = row(good["receipt_hash"], {"nested": nested})
    refused(carrier(serialize(good) + serialize(bad)), "JSON_LIMIT")


def test_native_container_size_cap_beside_valid_row():
    good = row()
    allowed = row(good["receipt_hash"], {"items": [0] * 4096})
    assert telos_receipt.verify_native_receipts(carrier(serialize(good) + serialize(allowed)))["status"] == "PASS"
    bad = row(good["receipt_hash"], {"items": [0] * 4097})
    refused(carrier(serialize(good) + serialize(bad)), "JSON_LIMIT")


@pytest.mark.parametrize("kind", ["string", "key"])
def test_native_scalar_size_cap_without_row_cap_masking(kind):
    # Exercise this target directly: serialized input also trips the row byte cap.
    def value(size):
        return ["x" * size] if kind == "string" else {"x" * size: 0}

    verifier._json_bounds([{"valid": True}, value(65536)])
    with pytest.raises(verifier.Refusal, match="JSON_LIMIT"):
        verifier._json_bounds([{"valid": True}, value(65537)])


@pytest.mark.parametrize("kind", ["dict", "list"])
def test_envelope_depth_cap(kind):
    value = 0
    for _ in range(telos_receipt.MAX_DEPTH):
        value = {"child": value} if kind == "dict" else [value]
    assert telos_receipt.compute_integrity_hash(value).startswith("sha256:")
    bad = {"child": value} if kind == "dict" else [value]
    with pytest.raises(ValueError, match="maximum nesting depth"):
        telos_receipt.compute_integrity_hash(bad)


def test_cli_size_cap(monkeypatch):
    def invoke(raw):
        output = io.StringIO()
        monkeypatch.setattr(native.sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
        monkeypatch.setattr(native.sys, "stdout", output)
        code = native.main()
        return code, json.loads(output.getvalue())

    raw = json.dumps(request()).encode()
    assert invoke(raw)[0] == 0
    code, result = invoke(raw + b" " * (1500001 - len(raw)))
    assert code == 2
    assert result["problems"] == ["REQUEST_SHAPE_INVALID"]
