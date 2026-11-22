# Changelog

## Unreleased

- `build_receipt` and `build_action_receipt` refuse inputs telos-verify fails on `telos/0.1-unsigned`: verdicts outside `ACTION_VERDICTS`, numbers outside the canonical domain, empty `pa_id` or score labels, unpaired surrogates (a surrogate pair is accepted), `issued_at` not in RFC 3339 date-time format (a format check; calendar values are not validated), non-`str` envelope members. Errors name the verifier check id. New public names `ACTION_VERDICTS`, `MAX_SAFE_INT`. `compute_integrity_hash` and `verify_receipt` are unchanged.
- README: install section; telos-verify named as the verifier (the old link to a non-public repository is removed); the float rule no longer claims ECMAScript equivalence; signing is described as a separate contract version; native-v2 receipts are identified.

## 0.1.1

- Add optional `verify_native_receipts` and `telos_receipt.native` for native-v2 byte integrity (`pip install telos-receipt[native]`).
- Compare supplied bytes, native hashes and predecessor links; signatures, scores and content remain unverified.
- Vendor the MIT-licensed verifier with portable imports, source pins and attribution. Missing native dependencies return `UNAVAILABLE`.
- Preserve the unsigned envelope API and development extra.
