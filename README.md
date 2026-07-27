# telos-receipt

The canonical **unsigned integrity-hash receipt contract** for TELOS AI Labs.

One receipt envelope, spoken by both ends of the trust loop:

- **telos-mcp** mints a receipt when its governance scorer scores an action.
- **telos-trust-surface** serves and verifies receipts other agents fetch.

Because both import this package, a receipt minted by the scorer verifies on the
trust surface unchanged, no translation, no second shape to keep in sync.

Pure stdlib, zero dependencies, offline, key-free.

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
    agent_id="agent-alpha",
    verdict="EXECUTE",
    composite_score=0.81,
    scores={"purpose": 0.9, "scope": 0.8},
    pa_id="pa::agent-alpha::v1",
)
assert verify_receipt(r)["match"] is True
```
