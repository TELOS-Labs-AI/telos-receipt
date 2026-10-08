"""telos-receipt: the canonical unsigned integrity-hash receipt contract.

This is the single source of truth for the TELOS receipt envelope. Both the
agent-facing trust surface (which serves + verifies receipts) and the telos-mcp
governance server (which mints receipts when it scores an action) speak THIS
shape, so a receipt minted by one verifies on the other with no translation.

The unsigned envelope uses only the standard library. Native receipt byte
integrity is optional and requires the native extra. Both paths are offline.

The integrity hash is a SHA-256 over the canonical-JSON serialization of the
receipt `payload`. Recomputing it confirms the payload matches the hash recorded
in the receipt: it detects alteration of the payload relative to that recorded
hash. It is key-free, so it is NOT a digital signature: anyone can recompute it
(or mint a fresh payload + matching hash), and it says nothing about who issued
the receipt or when. That honesty is the point. When the signing ceremony lands,
a real signature populates the `signature` field and `signing_status` flips to
the signed value, without changing this hash or the envelope shape.

Go-live swap (no schema break, no re-architecture):
  - The governance engine flips from stub to real (it computes real verdicts /
    scores; the payload it commits to becomes real, not synthetic).
  - The signer flips from null to a real signature: `signature` is filled and
    `signing_status` changes. Every field already exists; nothing moves.

Canonical form: json.dumps(payload, sort_keys=True, separators=(",", ":"),
allow_nan=False), over JSON-native, finite payloads only. A value with no
canonical JSON form (set/bytes/datetime/object) or a non-finite float is REFUSED
(the build raises; verify reports a controlled mismatch), because such inputs have
no deterministic hash. Determinism: same payload in -> same hash out, on every
run, on every machine.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any

__version__ = "0.1.1"

RECEIPT_VERSION = "telos/0.1-unsigned"
SIGNING_STATUS = "unsigned_integrity_hash"
ENGINE_LABEL = "telos v0.1 (unsigned integrity-hash; no governance engine wired)"
HASH_PREFIX = "sha256:"

# A payload nested deeper than this is refused identically on every supported
# runtime. Real receipt payloads are a handful of levels deep; the cap exists so
# the accept/refuse boundary is a documented contract constant instead of
# whatever recursion limit a given Python build happens to have.
MAX_DEPTH = 200

_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Fields the integrity hash covers. Anything outside `payload` (issued_at,
# signature, engine label) is metadata and is intentionally NOT hashed, so the
# same logical payload yields the same hash regardless of when it was served.
COVERED = "payload (canonical JSON, sort_keys, compact separators)"

# Public surface: these names. `__version__` is included on purpose
# (callers pin against it; a public version attribute is part of the contract),
# and MAX_DEPTH is public because the depth cap is part of the accept/refuse
# contract.
__all__ = [
    "COVERED",
    "ENGINE_LABEL",
    "HASH_PREFIX",
    "MAX_DEPTH",
    "RECEIPT_VERSION",
    "SIGNING_STATUS",
    "__version__",
    "build_action_receipt",
    "build_receipt",
    "compute_integrity_hash",
    "verify_native_receipts",
    "verify_receipt",
]


def _prevalidate(value: Any, depth: int = 0) -> None:
    # STRICT JSON-native gate, checked BEFORE serialization. json.dumps alone is
    # not strict enough: it coerces int/bool/None dict keys to strings and tuples
    # to arrays, so distinct Python payloads would mint the SAME hash (a collision
    # by coercion), and a hostile container subclass could run arbitrary code
    # during encoding. Exact types only:
    #   containers  exactly dict / list   (subclasses and tuples refused)
    #   dict keys   exactly str
    #   scalars     exactly str / int / float (finite) / bool / None
    # Refusals use the same controlled paths as before: TypeError for a value
    # with no canonical form, ValueError for non-finite floats and for nesting
    # beyond MAX_DEPTH (the runtime-independent depth contract).
    if value is None:
        return
    t = type(value)
    if t is str or t is bool or t is int:
        return
    if t is float:
        if not math.isfinite(value):
            raise ValueError("payload contains a non-finite float (NaN/Infinity); no canonical JSON form")
        return
    if t is dict:
        if depth >= MAX_DEPTH:
            raise ValueError(f"payload exceeds the maximum nesting depth ({MAX_DEPTH})")
        for k, v in value.items():
            if type(k) is not str:
                # Type-only message: never invoke repr()/str() (or any dunder)
                # on a rejected value -- a hostile __repr__ would turn this
                # controlled TypeError into an arbitrary escape.
                raise TypeError(
                    f"payload dict key of type {type(k).__name__} is not str; "
                    "key coercion would let distinct payloads mint the same hash"
                )
            _prevalidate(v, depth + 1)
        return
    if t is list:
        if depth >= MAX_DEPTH:
            raise ValueError(f"payload exceeds the maximum nesting depth ({MAX_DEPTH})")
        for item in value:
            _prevalidate(item, depth + 1)
        return
    raise TypeError(
        f"payload value of type {type(value).__name__} is not JSON-native "
        "(exactly dict/list/str/int/float/bool/None); no canonical JSON form"
    )


def _canonical(payload: Any) -> bytes:
    # STRICT canonical JSON: exact-type prevalidation first (see _prevalidate),
    # then no `default=` coercion and allow_nan=False. A value with no canonical
    # JSON form (set/frozenset/bytes/datetime/custom object/subclass), a
    # non-finite float (NaN/Infinity), or nesting beyond MAX_DEPTH has NO
    # deterministic, RFC-8259 hash -- so we REFUSE it (raise) rather than
    # silently hashing an order-dependent str()/repr or a coerced form. Callers
    # pass JSON-native, finite payloads; verify catches the raise and returns
    # match:false so hostile input never crashes it. For payloads that pass the
    # gate, the serialized bytes are identical to what this function has always
    # produced -- the gate only adds refusals at the edges.
    _prevalidate(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def compute_integrity_hash(payload: Any) -> str:
    """Return 'sha256:<hex>' over the canonical-JSON form of `payload`.

    `payload` must be strictly JSON-native and finite: containers exactly
    dict/list, dict keys exactly str, scalars exactly str/int/float/bool/None,
    nested at most MAX_DEPTH (200) levels. A non-conforming value raises
    TypeError; a NaN/Infinity float, a circular reference, or nesting beyond
    MAX_DEPTH raises ValueError. There is no canonical hash for such inputs, so
    refusing them keeps the hash deterministic on every run/process/machine and
    on every supported Python version.
    """
    return HASH_PREFIX + hashlib.sha256(_canonical(payload)).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_receipt(
    kind: str,
    payload: dict[str, Any],
    agent_id: str,
    issued_at: str | None = None,
    engine: str = ENGINE_LABEL,
) -> dict[str, Any]:
    """Build an unsigned integrity-hash receipt.

    `signature` is explicitly null and `signing_status` declares the unsigned
    state, so no reader can mistake this for a digital signature. The envelope
    shape is stable: a later signed build only fills `signature` and changes
    `signing_status`.

    `engine` labels which engine produced the payload (e.g. the trust surface,
    or the MCP governance scorer in stub mode). It is metadata, not hashed.
    """
    issued = issued_at if issued_at is not None else _now_iso()
    return {
        "receipt_version": RECEIPT_VERSION,
        "kind": kind,
        "agent_id": agent_id,
        "payload": payload,
        "issued_at": issued,
        "integrity_hash": compute_integrity_hash(payload),
        "covered_fields": COVERED,
        "signing_status": SIGNING_STATUS,
        "signature": None,
        "engine": engine,
    }


def build_action_receipt(
    action_name: str,
    action_params: dict[str, Any],
    agent_id: str,
    verdict: str,
    composite_score: float,
    scores: dict[str, float],
    pa_id: str,
    issued_at: str | None = None,
    engine: str = ENGINE_LABEL,
) -> dict[str, Any]:
    """Build a governed-action receipt: the result of scoring one action.

    This is the receipt a governance scorer emits per action. The payload
    commits to the governance result (verdict + per-dimension scores + the PA
    it was measured against) and to *which* action was scored via a hash of the
    action params -- the raw params are deliberately not echoed, so the receipt
    is publishable without leaking the action's arguments.

    The envelope is the same `build_receipt` shape the trust surface verifies,
    so a receipt minted here verifies there unchanged.

    `action_params` must be JSON-native and finite (the values that cross an MCP/
    HTTP boundary always are). A non-serializable or non-finite value raises,
    rather than committing to a process-dependent hash.
    """
    payload = {
        "action_name": action_name,
        "action_params_hash": compute_integrity_hash(action_params),
        "verdict": verdict,
        "composite_score": composite_score,
        "scores": scores,
        "pa_id": pa_id,
    }
    return build_receipt(
        kind="action_governed",
        payload=payload,
        agent_id=agent_id,
        issued_at=issued_at,
        engine=engine,
    )


def verify_receipt(receipt: Any) -> dict[str, Any]:
    """Recompute the integrity hash over `receipt['payload']` and compare.

    Pure, offline, key-free. Returns a dict with `match` (bool) and a `reason`.
    Rejects malformed input (not exactly a dict, missing payload/integrity_hash,
    integrity_hash not exactly str, wrong hash format) with `match: false` and a
    clear reason, never raising -- for ANY input, hostile subclasses included.
    The receipt must be exactly `dict` and its `integrity_hash` exactly `str`
    (same exact-type discipline as the payload gate): subclasses are refused
    before any of their methods can run.

    This validates the payload<->integrity_hash binding ONLY. It does not read,
    trust, or validate the receipt's `signature` or `signing_status` fields; the
    result's `signature_verified` is always False and its `signing_status` is the
    library's own unsigned constant, never the receipt's self-declared value.
    """
    try:
        return _verify(receipt)
    except BaseException:  # noqa: BLE001 -- the never-raises contract is absolute:
        # a hostile object (e.g. a container subclass that raises mid-iteration,
        # an overridden __getitem__/__eq__, a __repr__ raising KeyboardInterrupt)
        # must normalize to a controlled mismatch, never escape to the caller.
        # BaseException, not Exception: the contract claims ANY input, and a
        # hostile dunder can raise KeyboardInterrupt/SystemExit on purpose. The
        # exact-type gates in _verify/_prevalidate stop hostile code from ever
        # running, so the only interrupt this can swallow on the valid path is a
        # genuine Ctrl-C landing inside a sub-millisecond pure computation --
        # the process stays interruptible at its next point.
        return _result(False, None, "unexpected error while verifying (hostile or malformed input)")


def _verify(receipt: Any) -> dict[str, Any]:
    # Exact type, not isinstance: a dict SUBCLASS could override __contains__/
    # get/__getitem__ to raise (KeyboardInterrupt included) or lie. Refusing it
    # here, before any of its methods run, keeps the refusal side-effect-free.
    if type(receipt) is not dict:
        return _result(False, None, "receipt is not a JSON object")
    if "payload" not in receipt:
        return _result(False, receipt.get("integrity_hash"), "missing required field: payload")
    stated = receipt.get("integrity_hash")
    # Exact str for the same reason: a str subclass controls startswith/__eq__,
    # so it could raise here or return a non-boolean from the == below.
    if type(stated) is not str or not stated.startswith(HASH_PREFIX):
        return _result(False, stated, "missing or malformed integrity_hash (expected 'sha256:<hex>')")
    if _HASH_RE.fullmatch(stated) is None:
        # Diagnose the hash itself before recomputing anything: a stated hash
        # that is not 'sha256:' + exactly 64 lowercase hex chars is MALFORMED --
        # reporting it as "payload altered" would misdirect the operator.
        return _result(
            False,
            stated,
            "malformed integrity_hash: expected 'sha256:' followed by exactly 64 lowercase hex characters",
        )
    try:
        recomputed = compute_integrity_hash(receipt["payload"])
    except (TypeError, ValueError, RecursionError):
        # Hostile payload with no canonical JSON form: a non-serializable type, a
        # non-finite float, a circular reference, or nesting too deep to encode.
        # Honor the never-raises contract -- report a controlled mismatch.
        return _result(
            False,
            stated,
            "payload has no canonical JSON form (non-serializable, non-finite, circular, or too deeply nested)",
        )
    # `recomputed` is our own hexdigest-derived exact str; `stated` is exact str
    # by the gate above, so == is real str equality. bool() pins the contract
    # (`match` is exactly bool) even if either side ever changes.
    match = bool(recomputed == stated)
    reason = (
        "payload matches the recorded integrity_hash (not altered relative to the hash)"
        if match
        else "MISMATCH: recomputed hash differs from stated integrity_hash (payload was altered)"
    )
    return {
        "match": match,
        "stated_integrity_hash": stated,
        "recomputed_integrity_hash": recomputed,
        "covered_fields": COVERED,
        "signature_verified": False,
        "signing_status": SIGNING_STATUS,
        "note": "integrity hash is key-free; it confirms the payload matches the recorded hash, not who issued it or when",
        "reason": reason,
    }


def _result(match: bool, stated: Any, reason: str) -> dict[str, Any]:
    return {
        "match": match,
        "stated_integrity_hash": stated,
        "recomputed_integrity_hash": None,
        "covered_fields": COVERED,
        "signature_verified": False,
        "signing_status": SIGNING_STATUS,
        "note": "integrity hash is key-free; it confirms the payload matches the recorded hash, not who issued it or when",
        "reason": reason,
    }


def verify_native_receipts(request: object) -> dict:
    """Assess supplied native-v2 bytes; does not verify signatures or scores."""
    from .native import assess_request
    return assess_request(request)
