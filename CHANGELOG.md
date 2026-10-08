# Changelog

## 0.1.1

- Add optional `verify_native_receipts` and `telos_receipt.native` for native-v2 byte integrity (`pip install telos-receipt[native]`).
- Compare supplied bytes, native hashes and predecessor links; signatures, scores and content remain unverified.
- Vendor the MIT-licensed verifier with portable imports, source pins and attribution. Missing native dependencies return `UNAVAILABLE`.
- Preserve the unsigned envelope API and development extra.
