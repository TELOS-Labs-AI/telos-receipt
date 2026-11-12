# Changelog

## 0.2.0.dev0 (DRAFT: unreleased; the version number and every line of this entry are draft wording)

- DRAFT: add `telos_receipt.record` (`check_record_dir`, `check_record`, `build_reference`): read a kit record with the kit's own reader, vendored byte for byte and pinned to kit commit `64dfcef2bbe8ac411d98841ab1216ed4852a33e9` and the sha256 of its three files. Python 3.11 or later for this module only.
- DRAFT: add the receipt kind `kit_record_reference`: an unsigned envelope naming a kit record by four digests.
- DRAFT: `tools/vendor_kit_reader.py` makes the vendored copies and writes the pin; the source distribution now carries `tools/`.
- DRAFT: the 0.1.1 modules are unchanged byte for byte; `telos_receipt.__version__` still reads `0.1.1`.

## 0.1.1

- Add optional `verify_native_receipts` and `telos_receipt.native` for native-v2 byte integrity (`pip install telos-receipt[native]`).
- Compare supplied bytes, native hashes and predecessor links; signatures, scores and content remain unverified.
- Vendor the MIT-licensed verifier with portable imports, source pins and attribution. Missing native dependencies return `UNAVAILABLE`.
- Preserve the unsigned envelope API and development extra.
