"""Offline native-v2 byte integrity; no signer, scorer or live engine."""
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
import sys

from . import __version__

PINS = {
    "hermes_v2.py": "6eb37e9f8018ff98a6d4546f707de17cb64b53038a6d7311bf7ba89ab79e24bf",
    "verify_native_v2.py": "98bfab078eb85fde1f740c8c7e165965f02d6cdc38257b5e0b93b404b1f6835d",
}


def _result():
    return {
        "receipt_sdk_version": __version__,
        "scope": "NATIVE_BYTE_INTEGRITY_ONLY",
        "activity": "RETROSPECTIVE_RECOMPUTATION_OF_RETAINED_HASHES_NOT_SCORES",
        "status": "UNAVAILABLE",
        "problems": [],
        "native_report": None,
        "scoring": {"status": "UNSUPPORTED", "reason": "HISTORICAL_MEASUREMENT_INPUTS_MISSING"},
        "signature_verified": False,
        "authenticity": "NOT_ESTABLISHED",
        "complete_workflow": "NOT_ESTABLISHED",
        "independent_population": "NOT_ESTABLISHED",
        "predecessor_provenance": "CALLER_SUPPLIED_NOT_AUTHENTICATED_BY_THIS_CHECK",
        "coverage": "ONLY_SUPPLIED_ROWS_NOT_ORIGINAL_ACTION_POPULATION",
    }


def _refuse(code):
    result = _result()
    result["problems"] = [code]
    return result


def assess_retained_bytes(data: bytes | None, expected_sha256: str | None,
                          start_previous: str | None) -> dict:
    """Assess explicit bytes against caller-supplied pins and predecessor.

    These comparison inputs do not establish trusted custody or genesis.
    Missing input never selects default data or a scorer.
    """
    if data is None:
        return _refuse("RECEIPT_INPUT_MISSING")
    if type(data) is not bytes:
        return _refuse("INPUT_TYPE")
    if expected_sha256 is None:
        return _refuse("EXPECTED_PIN_MISSING")
    if type(expected_sha256) is not str or re.fullmatch("[0-9a-f]{64}", expected_sha256) is None:
        return _refuse("EXPECTED_PIN_INVALID")
    if start_previous is None:
        return _refuse("PREDECESSOR_INPUT_MISSING")
    if type(start_previous) is not str or re.fullmatch("[0-9a-f]{64}", start_previous) is None:
        return _refuse("PREDECESSOR_INPUT_INVALID")
    vendor = Path(__file__).parent / "_native_vendor"
    try:
        for filename, pin in PINS.items():
            if hashlib.sha256((vendor / filename).read_bytes()).hexdigest() != pin:
                return _refuse("VERIFIER_SOURCE_PIN_MISMATCH")
    except OSError:
        return _refuse("VERIFIER_SOURCE_UNAVAILABLE")
    try:
        # Import on every assessment, including when an adapter is already cached.
        import cryptography  # noqa: F401 -- availability is part of the native contract
        from ._native_vendor import hermes_v2 as adapter, verify_native_v2 as verifier
    except ImportError:
        return _refuse("NATIVE_DEPENDENCY_UNAVAILABLE")
    native = verifier.assess_bytes(data, expected_sha256, start_previous, adapter)
    result = _result()
    result["native_report"] = native
    result["status"] = native["integrity_status"]
    result["problems"] = [problem["code"] for problem in native["problems"]]
    return result


def assess_request(request: object) -> dict:
    """Closed JSON carrier shared by CLI and MCP; contains no file paths."""
    if type(request) is not dict or set(request) - {"receipts_base64", "expected_sha256", "start_previous"}:
        return _refuse("REQUEST_SHAPE_INVALID")
    encoded = request.get("receipts_base64")
    if encoded is None:
        return _refuse("RECEIPT_INPUT_MISSING")
    if type(encoded) is not str:
        return _refuse("INPUT_TYPE")
    if len(encoded) > 1398104:
        return _refuse("INPUT_TOO_LARGE")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return _refuse("INVALID_BASE64")
    return assess_retained_bytes(data, request.get("expected_sha256"), request.get("start_previous"))


__all__ = ["assess_retained_bytes", "assess_request", "__version__"]


def main():
    raw = sys.stdin.buffer.read(1500001)
    try:
        if len(raw) > 1500000:
            raise ValueError("bounded input")
        request = json.loads(raw)
    except (ValueError, UnicodeError):
        request = None
    result = assess_request(request)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return {"PASS": 0, "FAIL": 1, "UNAVAILABLE": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
