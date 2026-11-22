# telos-receipt

The canonical **unsigned integrity-hash receipt contract** for TELOS AI Labs.

This package writes `telos/0.1-unsigned` receipts and recomputes their integrity
hash. Two other public repositories use the same envelope:

- [telos-mcp](https://github.com/TELOS-Labs-AI/telos-mcp) mints a receipt with
  this package each time its (stub) governance scorer scores an action.
- [telos-verify](https://github.com/TELOS-Labs-AI/telos-verify) is the offline
  command-line verifier. It checks a receipt's structure, field forms and
  integrity hash. The builders here refuse the specific inputs listed in
  [What the builders refuse](#what-the-builders-refuse), each of which telos-verify
  fails on a single receipt.

The unsigned envelope API uses only the Python standard library. Optional
native-v2 receipt verification requires `telos-receipt[native]`. Both APIs run
offline.

## Install

```bash
pip install telos-receipt            # envelope API, no dependencies
pip install 'telos-receipt[native]'  # adds verify_native_receipts (needs cryptography)
```

Requires Python 3.10 or later.

## The envelope

```json
{
  "receipt_version": "telos/0.1-unsigned",
  "kind": "action_governed",
  "agent_id": "...",
  "payload": { "...": "..." },
  "issued_at": "<iso8601>",
  "integrity_hash": "sha256:<hex over canonical payload>",
  "covered_fields": "payload (canonical JSON, sort_keys, compact separators)",
  "signing_status": "unsigned_integrity_hash",
  "signature": null,
  "engine": "telos v0.1 (unsigned integrity-hash; no governance engine wired)"
}
```

**Canonical form, stated exactly** (independent verifiers MUST match all six or payloads will falsely mismatch): keys sorted, compact separators (`,` `:`), NaN/Infinity refused, and **ASCII-escaped output** (Python `json.dumps` default `ensure_ascii=True`: non-ASCII characters serialize as `\uXXXX` escapes, including UTF-16 surrogate pairs for astral characters). A verifier emitting raw UTF-8 will compute a different hash on any non-ASCII payload. Two further rules govern numbers, because the action receipt carries floats:

5. **Number formatting.** Floats serialize as Python's shortest round-trip `repr`: `0.1` emits `0.1`, not `0.10000000000000001`. This is **not** the same as the ECMAScript Number-to-String algorithm (`JSON.stringify`): Python emits `1.0` and `1e-05` where ECMAScript emits `1` and `0.00001`. Within the canonical number domain that `build_receipt` enforces (non-zero floats with 0.0001 <= |x| < 1e16) the two agree on every non-integral float; they still differ on integral floats such as `1.0`, which rule 6 makes significant. A non-Python verifier MUST reproduce Python's formatting, including the trailing `.0`, or float-bearing payloads will mismatch.
6. **Number type is significant.** JSON has a single number type, but this contract preserves the payload's Python type: `1` (int) and `1.0` (float) are distinct inputs producing distinct hashes. A reimplementation that collapses `1.0` to `1` cannot reproduce a float-typed hash. `build_action_receipt` puts floats (`composite_score`, `scores`) into the payload, so this rule is load-bearing for action receipts.

### Known-answer vectors

Recomputed from this package on CPython 3.11 / 3.12 / 3.14 (byte-identical on all three). Each entry is the exact ASCII-escaped canonical JSON that `compute_integrity_hash` produces (the string that is UTF-8 encoded and SHA-256'd), followed by the hash it returns. Copy the escaped string verbatim. The second vector is a non-ASCII payload (`e` + combining accent U+0301, Cyrillic, and an astral emoji), shown as its escaped canonical form because that is what actually gets hashed:

```
{"action":"wrote_file","path":"demo.txt"}
    sha256:acd144a9dc2a2d19c13d1ef5119759ae963c406d7e980b017e00cb163517f692

{"msg":"cafe\u0301 \u043c\u0438\u0440 \ud83d\ude80"}
    sha256:f9c77a03300b6507b66feccb530a6e3ed9eb0fe80f27c3a269559de15d0a0911

{"composite_score":0.1,"scores":{"purpose":0.9,"scope":0.8}}
    sha256:3d3fbf211d5c93140e5a55713c571544718b1d59c581e19e134a74664b025f54

{"v":1}
    sha256:afbf9d0f3560b0fd7795e81c42a0a79ee6b6fc67e064f77826aee642cad28d91

{"v":1.0}
    sha256:f3c8be97307d38261061fa08e74365e54a239cddb1d189f3bea18022adbe2f35
```

The float payload exercises rule 5; the last two vectors differ by number type alone (rule 6).

## What the integrity hash does and does not tell you

- **Does:** confirm the `payload` matches the `integrity_hash` recorded in the
  receipt (it detects alteration of the payload relative to that hash).
- **Does NOT:** prove who issued it, when, or that the payload+hash pair was not
  minted fresh. Anyone can compute the same hash over any payload. Authorship
  and time need a signature, which this contract does not provide yet.

`verify_receipt` checks the payload-to-hash binding ONLY. It does not read, trust,
or validate a receipt's `signature` or `signing_status` fields; its result always
reports `signature_verified: false` and the library's own unsigned
`signing_status` constant, never the receipt's self-declared value.

## Signed receipts

This package writes unsigned `telos/0.1-unsigned` receipts only. Signing is not a
fill-in of the `signature` field on a 0.1 receipt: telos-verify defines signed
receipts as separate versions (`telos/0.2-ed25519`, and `telos/0.3-ed25519`, which
adds payload fields and uses a different verdict vocabulary), and it reports a
0.1 receipt that carries a signature as INCOMPLETE (`TV-SIG-001`). See the version
table at the top of the
[telos-verify README](https://github.com/TELOS-Labs-AI/telos-verify#readme).

## API

```python
from telos_receipt import build_receipt, build_action_receipt, verify_receipt

r = build_action_receipt(
    action_name="write_file",
    action_params={"path": "/tmp/x"},
    agent_id="demo-agent",
    verdict="EXECUTE",
    composite_score=0.81,
    scores={"purpose": 0.9, "scope": 0.8},
    pa_id="pa::demo-agent::v1",
)
assert verify_receipt(r)["match"] is True
```

To check the same receipt with the independent verifier:

```bash
python -c 'import json, telos_receipt as t; print(json.dumps(t.build_action_receipt(
    action_name="write_file", action_params={"path": "/tmp/x"}, agent_id="demo-agent",
    verdict="EXECUTE", composite_score=0.81, scores={"purpose": 0.9, "scope": 0.8},
    pa_id="pa::demo-agent::v1")))' > receipt.json
git clone https://github.com/TELOS-Labs-AI/telos-verify.git
python3 telos-verify/telos_verify.py receipt.json   # exit 0: VERIFIED (unsigned integrity only)
```

### What the builders refuse

Each builder raises on the inputs below rather than write a receipt that
telos-verify fails. Each of these refusals starts its message with the telos-verify
check id from the "Check" column (for example `TV-S2-005: ...`). The
"Applies to" column says which builder checks which row: `build_action_receipt`
fixes `kind` and assembles the payload itself, then passes it to `build_receipt`,
so both run the same code for the rows they share. The rules are per receipt:
whether a run of receipts forms a contiguous, correctly linked chain is checked by
telos-verify across files, not here.

| Input | Rule | Check | Applies to | Raises |
|---|---|---|---|---|
| `kind` | `str` | `TV-SCHEMA-001` | `build_receipt` | `TypeError` |
| `agent_id`, `engine` | `str` | `TV-SCHEMA-001` | both | `TypeError` |
| `issued_at` | RFC 3339 date-time with a zone, e.g. `2026-01-01T00:00:00Z` (the default is the current UTC time) | `TV-SCHEMA-001` | both | `ValueError`, for a non-`str` as well as a malformed string |
| `payload` | a `dict` (JSON object) | `TV-SCHEMA-001` | `build_receipt` | `TypeError` |
| `sequence`, `previous_receipt_integrity_hash` | both or neither; `sequence` an `int` | `TV-CHAIN-004`, `TV-CHAIN-001` | `build_receipt`, payload of any `kind` | `ValueError` if one appears without the other; `TypeError` if `sequence` is not an `int` |
| `action_governed` payload members | exactly `action_name`, `action_params_hash`, `verdict`, `composite_score`, `scores`, `pa_id`, plus optionally the chain pair above; none missing, none undeclared | `TV-SCHEMA-001` | `build_receipt` with `kind="action_governed"` | `ValueError` |
| `action_params_hash` | `sha256:` plus 64 lowercase hex characters | `TV-SCHEMA-001` | `build_receipt` with `kind="action_governed"` | `TypeError` if not a `str`; `ValueError` if malformed |
| `action_name` | `str` | `TV-SCHEMA-001` | both (for `build_receipt`, as an `action_governed` payload member) | `TypeError` |
| `verdict` | one of `ACTION_VERDICTS`: `EXECUTE`, `CLARIFY`, `SUGGEST`, `ESCALATE`, `INERT` | `TV-S2-002` | both (as above) | `TypeError` if not a `str`; `ValueError` if another label |
| `composite_score` | an `int` or `float` (not `bool`) | `TV-S2-003` | both (as above) | `TypeError` |
| `scores` | a `dict` of `int`/`float` values with non-empty `str` labels | `TV-S2-004`, `TV-S2-005` | both (as above) | `TypeError` if not a `dict` or a value is not a number; `ValueError` for an empty label |
| `pa_id` | a non-empty `str` | `TV-SCHEMA-001` (not a `str`), `TV-S2-006` (empty) | both (as above) | `TypeError` if not a `str`; `ValueError` if empty |
| every payload number | integers within ±(2^53 − 1); floats not `-0.0` and, unless zero, with 0.0001 <= abs(x) < 1e16 | `TV-CANON-001` | both, payload of any `kind` | `ValueError` |
| every payload string and key | no unpaired UTF-16 surrogate | `TV-CANON-002` | both, payload of any `kind` | `ValueError` |

`tests/test_cross_verifier.py` checks these rows against the telos-verify CLI (set
`TELOS_VERIFY` to a telos-verify checkout; without it those tests are skipped). For
each row, and for each builder the row applies to, at least one input is refused by
the builder, and the same receipt assembled by hand fails the CLI (exit 1 or 2).
Valid receipts built in the same tests pass it (exit 0). The cases are a selection
of inputs per row, not every possible input.

The "Raises" column gives the exception for each row. Wrong types mostly raise
`TypeError` and values outside a rule raise `ValueError`; `issued_at` is the
exception, raising `ValueError` for any input that is not a valid RFC 3339 string,
including one that is not a `str`.

Errors raised while canonicalizing the payload for hashing carry no check id.
`compute_integrity_hash` runs after the envelope checks (kind, agent_id, engine,
issued_at, payload type) and before the payload, chain and action_governed checks.
It raises
`TypeError` for a dict key that is not a `str` (including a non-`str` `scores`
label, e.g. `scores={7: 0.5}`) or a value with no canonical JSON form (for example a
`set`), and `ValueError` for a NaN or infinite float, a circular reference, or
nesting deeper than `MAX_DEPTH`. These messages describe the problem in plain words
without a `TV-` id.
Score ranges are not checked: on `telos/0.1-unsigned` the verifier imposes none.
`action_params` are only hashed (`action_params_hash` is
`compute_integrity_hash(action_params)`), so they are not held to the number domain.

## Native receipt byte integrity

A native-v2 receipt is the JSON Lines receipt format written by the TELOS fork of
[hermes-agent](https://github.com/TELOS-Labs-AI/hermes-agent) (one receipt per
line, each linked to its predecessor by hash). `tests/native-request.json` in this
repository is a complete sample request.

Install `pip install 'telos-receipt[native]'` to use `verify_native_receipts`.
Pass a JSON object with exactly these supported fields:

```python
from telos_receipt import verify_native_receipts

result = verify_native_receipts({
    "receipts_base64": "<base64-encoded native-v2 JSONL bytes>",
    "expected_sha256": "<64 lowercase hex characters over the JSONL bytes>",
    "start_previous": "<64 lowercase hex characters of the predecessor>",
})
```

The verifier compares the supplied byte pin, canonical input hash, verdict hash,
receipt hash and predecessor links for native-v2 receipts. `PASS` means these
byte-integrity comparisons succeeded for the supplied rows. `FAIL` reports a
mismatch. Malformed or incomplete inputs and missing optional dependencies return
`UNAVAILABLE`, never `PASS`; an invalid row prevents the whole load from passing.
Input is capped at 1 MiB, 32 rows and 64 KiB per row.

Receipts are unsigned unless a signature is checked. This API does **not** check
signatures, validate scores or content, establish authorship, authenticate the
caller-supplied predecessor, or demonstrate complete workflow coverage. A supplied
proof is reported as `PROOF_PRESENT_UNVERIFIED`; `signature_verified` stays false.
Anyone can create a new receipt with matching hashes, so byte integrity alone
does not establish authenticity.

`python -m telos_receipt.native` reads this request from standard input and emits
the same JSON result (exit 0 for `PASS`, 1 for `FAIL`, 2 for `UNAVAILABLE`).
Vendored verifier attribution and the MIT permission notice are in `NOTICE`.

## Related TELOS packages

- [telos-mcp](https://github.com/TELOS-Labs-AI/telos-mcp): MCP server whose stub scorer mints receipts with this package.
- [telos-verify](https://github.com/TELOS-Labs-AI/telos-verify): offline command-line verifier for receipts, including signed versions.
