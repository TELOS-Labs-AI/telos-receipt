# telos-receipt

The canonical **unsigned integrity-hash receipt contract** for TELOS AI Labs.

One receipt envelope, spoken by both ends of the trust loop:

- **telos-mcp** mints a receipt when its governance scorer scores an action.
- **telos-trust-surface** serves and verifies receipts other agents fetch.

Because both import this package, a receipt minted by the scorer verifies on the
trust surface unchanged, no translation, no second shape to keep in sync.

The unsigned envelope API uses only the Python standard library. Optional
native-v2 receipt verification requires `telos-receipt[native]`. Both APIs run
offline.

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

5. **Number formatting.** Floats serialize as Python's shortest round-trip `repr` (equivalently the ECMAScript Number-to-String algorithm): `0.1` emits `0.1`, not `0.10000000000000001`. A non-Python verifier MUST reproduce that exact formatting or any float-bearing payload will mismatch.
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

## Going live (no schema break)

Two internals flip; the shape does not move:

1. The governance engine flips stub → real (real verdicts/scores in the payload).
2. The signer flips null → real: `signature` is filled and `signing_status`
   changes. Every field already exists.

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

## Native receipt byte integrity

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

- [telos-mcp](https://github.com/TELOS-Labs-AI/telos-mcp): MCP tools using this receipt contract.
- [telos-trust-surface](https://github.com/TELOS-Labs-AI/telos-trust-surface): receipt serving and verification.
