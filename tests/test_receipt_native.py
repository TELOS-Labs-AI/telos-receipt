"""Native byte integrity, with synthetic fixtures and paired negative controls."""
import base64
import builtins
import hashlib
import json
from pathlib import Path

import pytest
import telos_receipt

FIXTURE = Path(__file__).parent / "native-request.json"


def request():
    return json.loads(FIXTURE.read_text())


def verify(value):
    api = getattr(telos_receipt, "verify_native_receipts", None)
    assert callable(api), "native receipt API is missing"
    return api(value)


def repack(value, rows):
    raw = b"".join(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in rows)
    return {**value, "receipts_base64": base64.b64encode(raw).decode(),
            "expected_sha256": hashlib.sha256(raw).hexdigest()}


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_valid_native_receipt_is_unsigned_integrity_only():
    result = verify(request())
    assert result["status"] == "PASS"
    assert result["native_report"]["trust_class"] == "UNSIGNED"
    assert len(result["native_report"]["per_record"]) == 1
    assert result["signature_verified"] is False
    assert result["scoring"]["status"] == "UNSUPPORTED"
    assert result["authenticity"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("field,code", [
    ("args", "CANONICAL_INPUT_HASH_MISMATCH"),
    ("verdict", "VERDICT_HASH_MISMATCH"),
    ("receipt_hash", "RECEIPT_HASH_MISMATCH"),
    ("previous_receipt_hash", "PREDECESSOR_MISMATCH"),
])
def test_tamper_fails_even_with_repaired_outer_integrity(field, code):
    value = request()
    assert verify(value)["status"] == "PASS"
    row = json.loads(base64.b64decode(value["receipts_base64"]))
    row[field] = {"tampered": True} if field in ("args", "verdict") else "f" * 64
    if field != "receipt_hash":
        row["receipt_hash"] = canonical_hash({k: v for k, v in row.items() if k != "receipt_hash"})
    result = verify(repack(value, [row]))
    assert result["status"] == "FAIL"
    assert code in result["problems"]


def test_changed_bytes_fail_the_supplied_file_pin():
    value = request()
    assert verify(value)["status"] == "PASS"
    raw = base64.b64decode(value["receipts_base64"]) + b" "
    result = verify({**value, "receipts_base64": base64.b64encode(raw).decode()})
    assert result["status"] == "FAIL"
    assert "RECEIPTS_PIN_MISMATCH" in result["problems"]


@pytest.mark.parametrize("bad", [None, [], "text", 7, True])
def test_nonobject_request_is_refused_beside_valid_request(bad):
    assert verify(request())["status"] == "PASS"
    result = verify(bad)
    assert result["status"] == "UNAVAILABLE"
    assert "REQUEST_SHAPE_INVALID" in result["problems"]


@pytest.mark.parametrize("bad", [None, [], "text", 7, True])
def test_nonobject_row_refuses_whole_load_beside_valid_row(bad):
    value = request()
    assert verify(value)["status"] == "PASS"
    row = json.loads(base64.b64decode(value["receipts_base64"]))
    result = verify(repack(value, [row, bad]))
    assert result["status"] == "UNAVAILABLE"
    assert "UNSUPPORTED_SCHEMA" in result["problems"]
    assert len(result["native_report"]["per_record"]) == 2


def test_missing_native_extra_is_unavailable_even_after_success(monkeypatch):
    assert verify(request())["status"] == "PASS"
    original = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ModuleNotFoundError("synthetic missing optional dependency", name="cryptography")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_crypto)
    result = verify(request())
    assert result["status"] == "UNAVAILABLE"
    assert "NATIVE_DEPENDENCY_UNAVAILABLE" in result["problems"]
    assert result["signature_verified"] is False


def test_existing_unsigned_envelope_remains_compatible():
    value = telos_receipt.build_receipt("synthetic", {"v": 1}, "demo-agent")
    assert telos_receipt.verify_receipt(value)["match"] is True
    value["payload"]["v"] = 2
    assert telos_receipt.verify_receipt(value)["match"] is False
