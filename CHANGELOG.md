# Changelog

## 0.2.0.dev0 (DRAFT: unreleased; the version number and every line of this entry are draft wording)

- DRAFT: add `telos_receipt.record` (`check_record_dir`, `check_record`, `build_reference`): read a kit record with the kit's own reader, vendored byte for byte and pinned to kit commit `64dfcef2bbe8ac411d98841ab1216ed4852a33e9` and the sha256 of its three files. Python 3.11 or later for this module only.
- DRAFT: add the receipt kind `kit_record_reference`: an unsigned envelope naming a kit record by four digests.
- DRAFT: a kit record report carries `witness_state` (the kit reader's own witness state) and `pins` (`default` or `caller`); `ok: true` means the reader ran, not that the record is authentic.
- DRAFT: every refusal of `telos_receipt.record` has one of seven fixed reasons (`kit_reader_modified`, `record_unreadable`, `input_too_large`, `pins_invalid`, `invalid_argument`, `reader_unavailable`, `reading_invalid`); its three functions raise no exception for any argument value.
- DRAFT: the kit reader files may import only each other and a closed list of modules; a `kit_record_reference` conveys neither identity nor attestation.
- DRAFT: `check_record` returns a report only after its temporary directory is seen to be gone; a directory that could not be removed is the refusal `reader_unavailable` with `"residual": true`, which does not name it. `pins=None` is the same call as no `pins`.
- DRAFT: `tools/vendor_kit_reader.py` makes the vendored copies and writes the pin; the source distribution now carries `tools/`.
- DRAFT: the 0.1.1 modules are unchanged byte for byte; `telos_receipt.__version__` still reads `0.1.1`.

## 0.1.1

- Add optional `verify_native_receipts` and `telos_receipt.native` for native-v2 byte integrity (`pip install telos-receipt[native]`).
- Compare supplied bytes, native hashes and predecessor links; signatures, scores and content remain unverified.
- Vendor the MIT-licensed verifier with portable imports, source pins and attribution. Missing native dependencies return `UNAVAILABLE`.
- Preserve the unsigned envelope API and development extra.
