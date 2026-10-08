"""Each SDK-native refusal returns its exact code beside a valid PASS."""

import base64
import builtins
import json
from pathlib import Path

import pytest

from telos_receipt import native


def request():
    return json.loads((Path(__file__).parent / "native-request.json").read_text())


def assert_refused(result, code):
    assert result["status"] == "UNAVAILABLE"
    assert result["problems"] == [code]
    assert result["native_report"] is None
    assert result["signature_verified"] is False


@pytest.mark.parametrize("field,value,code", [
    ("data", None, "RECEIPT_INPUT_MISSING"),
    ("data", bytearray(b"invalid"), "INPUT_TYPE"),
    ("expected_sha256", None, "EXPECTED_PIN_MISSING"),
    ("expected_sha256", 7, "EXPECTED_PIN_INVALID"),
    ("expected_sha256", "g" * 64, "EXPECTED_PIN_INVALID"),
    ("expected_sha256", "A" * 64, "EXPECTED_PIN_INVALID"),
    ("start_previous", None, "PREDECESSOR_INPUT_MISSING"),
    ("start_previous", 7, "PREDECESSOR_INPUT_INVALID"),
    ("start_previous", "g" * 64, "PREDECESSOR_INPUT_INVALID"),
    ("start_previous", "A" * 64, "PREDECESSOR_INPUT_INVALID"),
])
def test_retained_bytes_refusal_beside_valid(field, value, code):
    good = request()
    inputs = {"data": base64.b64decode(good["receipts_base64"]),
              "expected_sha256": good["expected_sha256"], "start_previous": good["start_previous"]}
    assert native.assess_retained_bytes(**inputs)["status"] == "PASS"
    assert_refused(native.assess_retained_bytes(**{**inputs, field: value}), code)


@pytest.mark.parametrize("case,code", [
    ("not-object", "REQUEST_SHAPE_INVALID"),
    ("extra-field", "REQUEST_SHAPE_INVALID"),
    ("missing-bytes", "RECEIPT_INPUT_MISSING"),
    ("null-bytes", "RECEIPT_INPUT_MISSING"),
    ("type-bytes", "INPUT_TYPE"),
    ("encoded-size", "INPUT_TOO_LARGE"),
    ("base64-junk", "INVALID_BASE64"),
    ("base64-padding", "INVALID_BASE64"),
])
def test_request_refusal_beside_valid(case, code):
    good = request()
    assert native.assess_request(good)["status"] == "PASS"
    bad = dict(good)
    if case == "not-object":
        bad = []
    elif case == "extra-field":
        bad["unknown"] = True
    elif case == "missing-bytes":
        del bad["receipts_base64"]
    elif case == "null-bytes":
        bad["receipts_base64"] = None
    elif case == "type-bytes":
        bad["receipts_base64"] = 7
    elif case == "encoded-size":
        bad["receipts_base64"] = "A" * 1398105
    elif case == "base64-junk":
        # Nonvalidating decode yields the unchanged valid fixture and would PASS.
        bad["receipts_base64"] = "!\n" + good["receipts_base64"]
    else:
        bad["receipts_base64"] = "A"
    assert_refused(native.assess_request(bad), code)


@pytest.mark.parametrize("case,code", [
    ("source-pin", "VERIFIER_SOURCE_PIN_MISMATCH"),
    ("source-unavailable", "VERIFIER_SOURCE_UNAVAILABLE"),
    ("dependency", "NATIVE_DEPENDENCY_UNAVAILABLE"),
])
def test_environment_refusal_beside_valid(monkeypatch, case, code):
    good = request()
    assert native.assess_request(good)["status"] == "PASS"
    if case == "dependency":
        original = builtins.__import__

        def without_crypto(name, *args, **kwargs):
            if name == "cryptography":
                raise ImportError("synthetic missing native extra")
            return original(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", without_crypto)
    else:
        original = Path.read_bytes

        def source_read(path):
            if path.name == "hermes_v2.py":
                if case == "source-unavailable":
                    raise OSError("synthetic missing verifier source")
                return b"synthetic source drift"
            return original(path)

        monkeypatch.setattr(Path, "read_bytes", source_read)
    assert_refused(native.assess_request(good), code)
