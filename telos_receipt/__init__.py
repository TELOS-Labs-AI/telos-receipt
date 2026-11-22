"""telos-receipt: the canonical unsigned integrity-hash receipt contract.

This is the single source of truth for the TELOS receipt envelope. The telos-mcp
governance server mints receipts with it, and the independent telos-verify CLI
checks them. The builders refuse the per-receipt inputs telos-verify fails that
are listed in the README ("What the builders refuse"); chain contiguity across
receipts is left to the verifier.

The unsigned envelope uses only the standard library. Native receipt byte
integrity is optional and requires the native extra. Both paths are offline.

The integrity hash is a SHA-256 over the canonical-JSON serialization of the
receipt `payload`. Recomputing it confirms the payload matches the hash recorded
in the receipt: it detects alteration of the payload relative to that recorded
hash. It is key-free, so it is NOT a digital signature: anyone can recompute it
(or mint a fresh payload + matching hash), and it says nothing about who issued
the receipt or when. That honesty is the point. Signed receipts are separate
contract versions (telos/0.2-ed25519, telos/0.3-ed25519, defined by telos-verify)
with their own `receipt_version`; this package writes telos/0.1-unsigned only.

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

# The verdict labels telos-verify accepts on telos/0.1-unsigned receipts
# (check TV-S2-002). The builders refuse any other label on an action_governed payload.
ACTION_VERDICTS = ("EXECUTE", "CLARIFY", "SUGGEST", "ESCALATE", "INERT")

# Canonical number domain (telos-verify TV-CANON-001). Inside it, Python's
# float repr and the ECMAScript Number-to-String algorithm emit the same digits
# for every non-integral float, so a receipt built here hashes identically in
# a JavaScript verifier except for the integral-float case (rule 6, README).
MAX_SAFE_INT = 2**53 - 1
_FLOAT_MIN_ABS = 1e-4
_FLOAT_MAX_ABS = 1e16

_RFC3339_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)

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
    "ACTION_VERDICTS",
    "COVERED",
    "ENGINE_LABEL",
    "HASH_PREFIX",
    "MAX_DEPTH",
    "MAX_SAFE_INT",
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


def _has_unpaired_surrogate(s: str) -> bool:
    # A high surrogate immediately followed by a low one is a valid UTF-16 pair:
    # the canonical bytes escape it as two \u escapes that a JSON parser reads
    # back as one astral character, which telos-verify accepts. Any other
    # surrogate code unit has no character to stand for.
    i, n = 0, len(s)
    while i < n:
        c = ord(s[i])
        if 0xD800 <= c <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(s[i + 1]) <= 0xDFFF:
            i += 2
            continue
        if 0xD800 <= c <= 0xDFFF:
            return True
        i += 1
    return False


def _reparse_problem(canonical: bytes) -> str | None:
    # telos-verify parses the receipt and recomputes the canonical bytes from
    # the parsed value. A key written as a surrogate pair becomes one astral
    # character there, which can repeat another key or sort to a different
    # place. Either way the receipt would fail, so name the check it would fail.
    repeated = []

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                repeated.append(k)
            out[k] = v
        return out

    again = json.dumps(
        json.loads(canonical, object_pairs_hook=pairs), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if repeated:
        return "TV-PARSE-001: payload: a key written as a surrogate pair repeats another key once parsed"
    if again != canonical:
        return "TV-HASH-004: payload: a key written as a surrogate pair sorts differently once parsed"
    return None


def _domain_problem(value: Any, where: str) -> str | None:
    # Walk a payload that already passed _prevalidate (exact JSON-native types)
    # and report the first value outside telos-verify's canonical domain.
    t = type(value)
    if t is int:
        if abs(value) > MAX_SAFE_INT:
            return f"TV-CANON-001: {where}: integer beyond 2^53-1"
        return None
    if t is float:
        if value == 0.0 and math.copysign(1.0, value) < 0:
            return f"TV-CANON-001: {where}: negative zero"
        if value != 0.0 and not (_FLOAT_MIN_ABS <= abs(value) < _FLOAT_MAX_ABS):
            return f"TV-CANON-001: {where}: float outside 0.0001 <= |x| < 1e16 ({value!r})"
        return None
    if t is str:
        if _has_unpaired_surrogate(value):
            return f"TV-CANON-002: {where}: string contains an unpaired surrogate"
        return None
    if t is list:
        for i, item in enumerate(value):
            problem = _domain_problem(item, f"{where}[{i}]")
            if problem:
                return problem
        return None
    if t is dict:
        for k, v in value.items():
            if _has_unpaired_surrogate(k):
                return f"TV-CANON-002: {where}: key contains an unpaired surrogate"
            problem = _domain_problem(v, f"{where}.{k}")
            if problem:
                return problem
    return None


def _is_number(value: Any) -> bool:
    return type(value) is int or type(value) is float


ACTION_GOVERNED = "action_governed"
_AG_REQUIRED = ("action_name", "action_params_hash", "verdict", "composite_score", "scores", "pa_id")
_AG_CHAIN = ("sequence", "previous_receipt_integrity_hash")


def _check_chain_members(p: dict[str, Any]) -> None:
    # telos-verify's per-receipt chain rules, applied to a payload of ANY kind:
    # the two chain members appear together (TV-CHAIN-004) and `sequence` is an
    # exact int (TV-CHAIN-001). Contiguity and linkage need the other receipts
    # and stay with the verifier.
    if ("sequence" in p) != ("previous_receipt_integrity_hash" in p):
        raise ValueError("TV-CHAIN-004: `sequence` and `previous_receipt_integrity_hash` must appear together")
    if "sequence" in p and type(p["sequence"]) is not int:
        raise TypeError(f"TV-CHAIN-001: `sequence` must be int, not {type(p['sequence']).__name__}")


def _check_action_governed(p: dict[str, Any]) -> None:
    # telos-verify's per-receipt rules for an action_governed payload on
    # telos/0.1-unsigned: members (TV-SCHEMA-001) and field forms (TV-S2-002..006).
    # The chain members it admits are checked for every kind by _check_chain_members.
    missing = [m for m in _AG_REQUIRED if m not in p]
    if missing:
        raise ValueError("TV-SCHEMA-001: action_governed payload lacks " + ", ".join(missing))
    extra = sorted(set(p) - set(_AG_REQUIRED) - set(_AG_CHAIN))
    if extra:
        raise ValueError("TV-SCHEMA-001: action_governed payload has undeclared member(s) " + ", ".join(extra))
    for name in ("action_name", "pa_id"):
        if type(p[name]) is not str:
            raise TypeError(f"TV-SCHEMA-001: `{name}` must be str, not {type(p[name]).__name__}")
    aph = p["action_params_hash"]
    if type(aph) is not str:
        raise TypeError(f"TV-SCHEMA-001: `action_params_hash` must be str, not {type(aph).__name__}")
    if _HASH_RE.fullmatch(aph) is None:
        raise ValueError("TV-SCHEMA-001: `action_params_hash` must be 'sha256:' plus 64 lowercase hex characters")
    if p["pa_id"] == "":
        raise ValueError("TV-S2-006: `pa_id` must not be empty")
    verdict = p["verdict"]
    if type(verdict) is not str:
        raise TypeError(f"TV-S2-002: `verdict` must be str, not {type(verdict).__name__}")
    if verdict not in ACTION_VERDICTS:
        raise ValueError(f"TV-S2-002: verdict {verdict!r} is not one of {', '.join(ACTION_VERDICTS)}")
    if not _is_number(p["composite_score"]):
        raise TypeError(
            f"TV-S2-003: `composite_score` must be int or float, not {type(p['composite_score']).__name__}"
        )
    scores = p["scores"]
    if type(scores) is not dict:
        raise TypeError(f"TV-S2-004: `scores` must be a dict, not {type(scores).__name__}")
    for label, value in scores.items():
        if label == "":
            raise ValueError("TV-S2-005: every `scores` label must be a non-empty str")
        if not _is_number(value):
            raise TypeError(f"TV-S2-004: scores[{label!r}] must be int or float, not {type(value).__name__}")


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
    state, so no reader can mistake this for a digital signature. Signed
    receipts are a different `receipt_version`, not a filled-in 0.1 receipt.

    `engine` labels which engine produced the payload (e.g. the MCP
    governance scorer in stub mode). It is metadata, not hashed.

    The receipt is refused (mostly TypeError for a wrong type and ValueError for
    a value out of range; `issued_at` raises ValueError for any invalid input,
    including a non-str; the README table lists the class per rule) when
    telos-verify would fail it: `kind`, `agent_id` and
    `engine` must be str, `issued_at` must match the RFC 3339 date-time format
    with a zone (a format check, the same one telos-verify applies; calendar
    values such as 2026-02-30 are not validated), and every payload number and
    string must lie in the canonical domain (integers within +/-(2^53-1);
    non-zero floats with 0.0001 <= |x| < 1e16 and no -0.0; no unpaired
    surrogates; a surrogate pair is accepted, but a key written as one must not
    repeat another key or change the key order once parsed). `payload` must be
    a dict. For every kind,
    `sequence` and `previous_receipt_integrity_hash` appear together or not at
    all, and `sequence` is an int. When `kind` is "action_governed" the payload
    must also meet that kind's member and field rules (see
    build_action_receipt). Check ids in the messages are telos-verify's.
    """
    for name, value in (("kind", kind), ("agent_id", agent_id), ("engine", engine)):
        if type(value) is not str:
            raise TypeError(f"TV-SCHEMA-001: `{name}` must be str, not {type(value).__name__}")
    issued = issued_at if issued_at is not None else _now_iso()
    if type(issued) is not str or _RFC3339_RE.match(issued) is None:
        raise ValueError(
            "TV-SCHEMA-001: `issued_at` must match the RFC 3339 date-time format with a zone, "
            "e.g. 2026-01-01T00:00:00Z (a format check: calendar values are not validated)"
        )
    if type(payload) is not dict:
        raise TypeError(f"TV-SCHEMA-001: `payload` must be a JSON object (dict), not {type(payload).__name__}")
    integrity_hash = compute_integrity_hash(payload)
    problem = _domain_problem(payload, "payload") or _reparse_problem(_canonical(payload))
    if problem:
        raise ValueError(problem)
    _check_chain_members(payload)
    if kind == ACTION_GOVERNED:
        _check_action_governed(payload)
    return {
        "receipt_version": RECEIPT_VERSION,
        "kind": kind,
        "agent_id": agent_id,
        "payload": payload,
        "issued_at": issued,
        "integrity_hash": integrity_hash,
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
    action params. The raw params are omitted; only their SHA-256 digest
    enters the payload. The digest is deterministic, so it reveals when two
    receipts scored the same arguments, and anyone who can guess low-entropy
    arguments (a short path, a yes/no flag) can confirm a guess by hashing it.

    The envelope is the same `build_receipt` shape, so telos-verify checks a
    receipt minted here with no translation.

    `action_params` must be JSON-native and finite (the values that cross an MCP/
    HTTP boundary always are). A non-serializable or non-finite value raises,
    rather than committing to a process-dependent hash. Only their hash enters
    the payload, so they are not held to the canonical number domain.

    The governance fields are refused (by build_receipt) when telos-verify would fail them:
    `verdict` must be one of ACTION_VERDICTS (TV-S2-002); `composite_score` a
    number (TV-S2-003); `scores` a dict of numbers (TV-S2-004) with non-empty
    labels (TV-S2-005); `pa_id` a non-empty str (TV-S2-006); `action_name` a
    str. bool is not a number here. Ranges are not checked: on 0.1 the verifier
    imposes none beyond the canonical domain (see build_receipt).
    """
    # The governance fields are checked once, in build_receipt, for every
    # action_governed payload whichever builder produced it.
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
