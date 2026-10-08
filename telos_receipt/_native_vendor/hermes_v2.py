# MIT License
#
# Copyright (c) 2025 Nous Research
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Adapted from the TELOS-Labs-AI/hermes-agent fork.
# Local changes: package-only byte assessment; no host-specific loaders.

"""Hermes-v2 source boundary; no live paths, discovery, or native promotion."""
from dataclasses import dataclass
import hashlib
import hmac as stdlib_hmac
import json
import math

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA_VERSION = "telos.operational.tool_call.v2"
RECEIPT_HASH_EXCLUSIONS = frozenset(
    {
        "receipt_hash",
        "signature",
        "hmac",
        "governance_proof",
        "transport_metadata",
    }
)
CANONICAL_INPUT_FIELDS = (
    "schema_version",
    "profile_id",
    "session_id",
    "task_id",
    "turn_id",
    "api_request_id",
    "tool_call_id",
    "tool_name",
    "args",
    "classification",
    "pa_hash",
    "config_hash",
)


@dataclass(frozen=True)
class HermesV2Source:
    raw: bytes
    receipt: object
    status: str
    reasons: tuple[str, ...]


def _reject_non_finite(constant: str):
    raise ValueError(f"non-finite JSON constant: {constant}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON float: {value}")
    return parsed


def inspect_source(raw: bytes) -> HermesV2Source:
    if type(raw) is not bytes:
        raise TypeError("Hermes source must be exact bytes")
    receipt = json.loads(
        raw.decode("utf-8"),
        parse_constant=_reject_non_finite,
        parse_float=_parse_finite_float,
    )
    supported = (
        type(receipt) is dict
        and receipt.get("schema_version") == SCHEMA_VERSION
        and type(receipt.get("version")) is int
        and receipt["version"] == 2
    )
    if supported:
        return HermesV2Source(raw, receipt, "supported-source-format", ())
    return HermesV2Source(
        raw,
        receipt,
        "unsupported-source-format",
        ("unsupported-source-format",),
    )


def _supported_receipt(source: HermesV2Source) -> dict:
    if source.status != "supported-source-format" or type(source.receipt) is not dict:
        raise ValueError("unsupported-source-format")
    return source.receipt


def _jsonable(value):
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite synthetic float")
        return value
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return str(value)


def _canonical_json(value) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def synthetic_oracle_source(receipt: object) -> HermesV2Source:
    """Round-trip an explicit synthetic receipt through the producer JSON codec."""
    raw = (
        json.dumps(
            _jsonable(receipt),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")
    source = inspect_source(raw)
    if source.status != "supported-source-format":
        raise ValueError("unsupported-source-format")
    return source


def canonical_input_hash_preimage(source: HermesV2Source) -> bytes:
    receipt = _supported_receipt(source)
    return _canonical_json({key: receipt.get(key) for key in CANONICAL_INPUT_FIELDS})


def verdict_hash_preimage(source: HermesV2Source) -> bytes:
    receipt = _supported_receipt(source)
    return _canonical_json(receipt.get("verdict") or {})


def receipt_hash_preimage(source: HermesV2Source) -> bytes:
    receipt = _supported_receipt(source)
    payload = {
        key: value
        for key, value in receipt.items()
        if key not in RECEIPT_HASH_EXCLUSIONS
    }
    return _canonical_json(payload)


def producer_fallback_hash(label: str) -> str:
    return hashlib.sha256(f"missing:{label}".encode("utf-8")).hexdigest()


def assess_nonbinding_source_claims(source: HermesV2Source) -> dict:
    receipt = _supported_receipt(source)
    pa_sentinel = receipt.get("pa_hash") == producer_fallback_hash("pa")
    config_sentinel = receipt.get("config_hash") == producer_fallback_hash("config")
    model_sentinel = receipt.get("scorer_model_hash") == hashlib.sha256(
        str(receipt.get("scorer_version")).encode("utf-8")
    ).hexdigest()
    reasons = []
    if pa_sentinel:
        reasons.append("sentinel-pa-nonbinding")
    if config_sentinel:
        reasons.append("sentinel-config-nonbinding")
    if model_sentinel:
        reasons.append("sentinel-model-nonbinding")
    return {
        "status": "source-claims-nonbinding",
        "reasons": tuple(reasons),
        "pa_source_value": (
            "SENTINEL_FALLBACK" if pa_sentinel else "SOURCE_FIELD_UNVERIFIED"
        ),
        "config_source_value": (
            "SENTINEL_FALLBACK" if config_sentinel else "SOURCE_FIELD_UNVERIFIED"
        ),
        "model_source_value": (
            "SENTINEL_FALLBACK" if model_sentinel else "SOURCE_FIELD_UNVERIFIED"
        ),
        "pa_binding": "NOT_CLAIMED",
        "config_binding": "NOT_CLAIMED",
        "model_binding": "NOT_CLAIMED",
        "native_authority": "NOT_CLAIMED",
        "native_authentication": "NOT_CLAIMED",
        "native_authorship": "NOT_CLAIMED",
        "wgt_coverage": "NOT_CLAIMED",
    }


def _verify_hash(source: HermesV2Source, field: str, preimage: bytes) -> dict:
    receipt = _supported_receipt(source)
    computed = hashlib.sha256(preimage).hexdigest()
    passed = type(receipt.get(field)) is str and receipt[field] == computed
    return {
        "status": "hash-chain-recomputed" if passed else "source-check-failed",
        "reasons": () if passed else (field.replace("_", "-") + "-mismatch",),
        field: "PASS" if passed else "FAIL",
        f"computed_{field}": computed,
    }


def verify_canonical_input_hash(source: HermesV2Source) -> dict:
    return _verify_hash(
        source,
        "canonical_input_hash",
        canonical_input_hash_preimage(source),
    )


def verify_verdict_hash(source: HermesV2Source) -> dict:
    return _verify_hash(source, "verdict_hash", verdict_hash_preimage(source))


def verify_receipt_hash(source: HermesV2Source) -> dict:
    return _verify_hash(source, "receipt_hash", receipt_hash_preimage(source))


def _foreign_proof_result(field: str, passed: bool | None, reason: str) -> dict:
    if passed is None:
        status = "source-proof-not-supplied"
        reasons = ()
        check = "NOT_SUPPLIED"
    else:
        status = "source-domain-proof-verified" if passed else "source-check-failed"
        reasons = () if passed else (reason,)
        check = "PASS" if passed else "FAIL"
    return {
        "status": status,
        "reasons": reasons,
        field: check,
        "proof_domain": "hermes-v2-canonical-json",
        "native_authentication": "NOT_CLAIMED",
        "native_authorship": "NOT_CLAIMED",
        "wgt_coverage": "NOT_CLAIMED",
        "verified_genesis": "NOT_CLAIMED",
    }


def verify_foreign_ed25519(source: HermesV2Source, public_key: bytes) -> dict:
    receipt = _supported_receipt(source)
    supplied = receipt.get("signature")
    if supplied is None:
        return _foreign_proof_result(
            "foreign_ed25519",
            None,
            "foreign-signature-invalid",
        )
    passed = False
    if type(supplied) is str and type(public_key) is bytes:
        try:
            signature = bytes.fromhex(supplied)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature,
                receipt_hash_preimage(source),
            )
            passed = True
        except (InvalidSignature, ValueError):
            pass
    return _foreign_proof_result(
        "foreign_ed25519",
        passed,
        "foreign-signature-invalid",
    )


def verify_foreign_hmac_sha512(
    source: HermesV2Source, hmac_key: bytes | str
) -> dict:
    receipt = _supported_receipt(source)
    supplied = receipt.get("hmac")
    if supplied is None:
        return _foreign_proof_result(
            "foreign_hmac_sha512",
            None,
            "foreign-hmac-invalid",
        )
    if type(hmac_key) is str:
        key_bytes = hmac_key.encode("utf-8")
    elif type(hmac_key) is bytes:
        key_bytes = hmac_key
    else:
        raise TypeError("Hermes foreign HMAC key must be bytes or str")
    expected = stdlib_hmac.new(
        key_bytes,
        receipt_hash_preimage(source),
        hashlib.sha512,
    ).hexdigest()
    passed = type(supplied) is str and stdlib_hmac.compare_digest(
        supplied.encode("utf-8"),
        expected.encode("utf-8"),
    )
    return _foreign_proof_result(
        "foreign_hmac_sha512",
        passed,
        "foreign-hmac-invalid",
    )


def verify_previous_receipt_link(
    source: HermesV2Source, expected_previous_receipt_hash: str | None
) -> dict:
    if source.status != "supported-source-format" or type(source.receipt) is not dict:
        raise ValueError("unsupported-source-format")
    linked_hash = source.receipt.get("previous_receipt_hash")
    if type(linked_hash) is not str:
        return {
            "status": "source-check-failed",
            "reasons": ("previous-receipt-link-invalid",),
            "previous_receipt_link": "FAIL",
            "origin": "NOT_CLAIMED",
        }
    if linked_hash == "":
        return {
            "status": "origin-indeterminate",
            "reasons": ("origin-indeterminate",),
            "previous_receipt_link": "INDETERMINATE",
            "origin": "INDETERMINATE",
        }
    passed = (
        type(expected_previous_receipt_hash) is str
        and linked_hash == expected_previous_receipt_hash
    )
    return {
        "status": "hash-chain-recomputed" if passed else "source-check-failed",
        "reasons": () if passed else ("previous-receipt-link-mismatch",),
        "previous_receipt_link": "PASS" if passed else "FAIL",
        "origin": "NOT_CLAIMED",
    }
