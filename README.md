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

<!-- DRAFT (0.2.0.dev0): every line of the section below is draft wording, not final until release review. -->
## Reading a kit record (DRAFT)

DRAFT. `telos_receipt.record` reads a kit record with the kit's own reader. A kit record is a directory holding
`receipt.json` and, beside it, optionally `witness.json` and `reading.json`. The reader is carried in this package
byte for byte and pinned by kit commit and file sha256; a copy that differs from the pin answers nothing but
`kit_reader_modified`. This module needs Python 3.11 or later and a POSIX system; the rest of the package keeps
its Python 3.10 floor and never imports this module.

```python
from telos_receipt.record import build_reference, check_record, check_record_dir

result = check_record_dir("path/to/record")  # or check_record(receipt_bytes, witness_bytes, reading_bytes)
if result["ok"]:                         # the reader ran; this is not the record's authenticity
    state = result["witness_state"]      # "WITNESSED" or "NOT_WITNESSED": the reader's own witness state
    report = result["report"]            # the kit reader's report, unchanged
    whose = result["pins"]               # "default": the Witness key the kit pins; "caller": a key you passed
    reader = result["kit_reader"]        # {"commit": ..., "files": {...}}: the reader that answered
```

DRAFT. `ok: true` means the reader ran, not that the record is authentic. Authenticity is the witness state only:
`witness_state`, the state the kit reader returns beside its report. `WITNESSED` binds the supplied digests to a
Witness signature: the row beside the receipt carries a signature that checks, under the Witness key the reader
was given, for this record's digests. It says nothing about observed execution, about commissioning, or about
every reading of the record. Every other case is `NOT_WITNESSED`, with the kit's reason in the report. The report
is the kit reader's statement, not this package's, and the kit's own limits on it apply unchanged. Strings in a
report can come from the record; treat them as data.

DRAFT. `pins` in a result says whose key the row was checked under. `"default"` is the Witness key the kit pins:
no `pins` argument, or `pins=None`, which is the same call.
`"caller"` is a key passed as `pins=`, which exists for canary keys and tests; `WITNESSED` under caller pins says
nothing about the kit's Witness.

DRAFT. Every other answer is a refusal, `{"ok": false, "reason": ...}`, with one of seven reasons:
`kit_reader_modified`, `record_unreadable`, `input_too_large` (receipt over 1,048,576 bytes, row over 4,096,
reading over 32,768), `pins_invalid`, `invalid_argument` (an argument of the wrong type, or an `agent_id` that
UTF-8 cannot carry), `reader_unavailable` (the reader could not be run to an answer: a reader file could not be
opened or read, its temporary files could not be made, written or removed, or it raised) and `reading_invalid`. No
`Exception` raised inside the three function bodies leaves them, for any argument value. Outside that boundary:
argument-binding errors (wrong arity or an unknown keyword) are raised by Python before the function body runs,
and process-control exceptions (`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`) propagate. On a
process-control exception the removal of the temporary directory is attempted; if that removal also fails, the
exception still propagates, no `residual` answer follows, and a directory may be left. The functions run offline and
start no process. `check_record_dir` writes nothing; `check_record` reads the bytes from a private temporary directory,
tries to remove it on every path, and returns a report only after it has seen that the directory is gone. If the
directory could not be removed, the answer is `{"ok": false, "reason": "reader_unavailable", "residual": true}`:
the bytes are still in a private directory under the system's temporary directory, and the answer does not name
it. No other answer has a `residual` key.

DRAFT. The check of the reader is latched at first use: the three reader files are hashed against the pin at the
first call in a process, and the bytes that were hashed are the bytes that run. A later change to those files on
disk is neither used nor detected by a running process. `kit_reader_modified` means a reader file was read in full
and differs from its pin; that answer is latched too. A vendored file that could not be opened or read is
`reader_unavailable` for that call and is not latched: the next call reads and checks all three files again. The
reader files import only each other and a closed list of standard library and `cryptography` modules; an `h0a`
package that is importable or already imported is never used, and `sys.path` is not changed. Importing those
listed modules adds them to `sys.modules` as any import does; nothing already there is replaced or removed. Any
change of reader bytes at a re-pin requires a delta review and refreshed oracle evidence.

DRAFT. The signature check needs the `cryptography` package (the `native` extra installs it); it is imported only
when a row reaches that check. Missing `cryptography`: the answer is still the kit reader's report, and never
`WITNESSED`. `WITNESS_VERIFIER_UNAVAILABLE` is returned for every row that reaches the reader's signature step,
and only for those. A row that is malformed, or is not a row for the pins in use, is refused earlier with its
earlier reason, with or without `cryptography`. A well-formed row for these pins that names another record
reaches the signature step; without `cryptography` it reads `WITNESS_VERIFIER_UNAVAILABLE`, never
`WITNESS_NOT_THIS_RECORD`, because the reader does not report on the content of a row it could not verify. With
`cryptography` that row reads `WITNESS_NOT_THIS_RECORD`; both are `NOT_WITNESSED`.

DRAFT. `build_reference(receipt_bytes, reading_bytes, agent_id=...)` returns an ordinary `telos/0.1-unsigned`
receipt of kind `kit_record_reference` whose payload is four fields: `record_schema`, `record_sha256`,
`config_identity` and `reading_sha256`. `record_sha256` and `config_identity` are the kit reader's own digests
for the record, not digests of the receipt file. `reading_sha256` is the lowercase 64-hex sha256 of the exact
supplied bytes of the reading, or null when no reading is passed. A reading that is passed and is not that
record's saved reading is refused, `reading_invalid`; it is never treated as absent. A `kit_record_reference`
conveys neither identity nor attestation: it names a record, it is unsigned, it carries no statement about the
record it names, and `kind` and `agent_id` are not covered by the payload hash.

## Related TELOS packages

- [telos-mcp](https://github.com/TELOS-Labs-AI/telos-mcp): MCP tools using this receipt contract.
- [telos-trust-surface](https://github.com/TELOS-Labs-AI/telos-trust-surface): receipt serving and verification.
