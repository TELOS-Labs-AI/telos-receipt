# Changelog

## 0.2.0.dev0 (DRAFT: unreleased; the version number and every line of this entry are draft wording)

- DRAFT: add `telos_receipt.record` (`check_record_dir`, `check_record`, `build_reference`): read a kit record with the kit's own reader, vendored byte for byte and pinned to kit commit `15cc2ebd5d76702c181487ea8b80a4ee786d068e` and the sha256 of its three files. Python 3.11 or later for this module only.
- DRAFT: add the receipt kind `kit_record_reference`: an unsigned envelope naming a kit record by four digests.
- DRAFT: a kit record report carries `witness_state` (the kit reader's own witness state) and `pins` (`default` or `caller`); `ok: true` means the reader ran, not that the record is authentic.
- DRAFT: every refusal of `telos_receipt.record` has one of seven fixed reasons (`kit_reader_modified`, `record_unreadable`, `input_too_large`, `pins_invalid`, `invalid_argument`, `reader_unavailable`, `reading_invalid`); no `Exception` raised inside the three function bodies leaves them, for any argument value. Argument-binding errors (wrong arity or an unknown keyword) are raised by Python before the function body runs, and process-control exceptions (`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`) propagate. On a process-control exception the removal of the temporary directory is attempted; if that removal also fails, the exception still propagates, no `residual` answer follows, and a directory may be left.
- DRAFT: `kit_reader_modified` is answered only for a vendored kit reader file that was read in full and differs from its pin, and it is latched for the process. A vendored file that could not be opened or read is `reader_unavailable` for that call and is not latched: the next call reads and checks all three files again.
- DRAFT: the kit reader files may import only each other and a closed list of modules; a `kit_record_reference` conveys neither identity nor attestation.
- DRAFT: `check_record` returns a report only after its temporary directory is seen to be gone; a directory that could not be removed is the refusal `reader_unavailable` with `"residual": true`, which does not name it. `pins=None` is the same call as no `pins`.
- DRAFT: missing `cryptography`: the answer is still the kit reader's report, and never `WITNESSED`. `WITNESS_VERIFIER_UNAVAILABLE` is returned for every row that reaches the reader's signature step, and only for those. A row that is malformed, or is not a row for the pins in use, is refused earlier with its earlier reason, with or without `cryptography`. A well-formed row for these pins that names another record reaches the signature step; without `cryptography` it reads `WITNESS_VERIFIER_UNAVAILABLE`, never `WITNESS_NOT_THIS_RECORD`, because the reader does not report on the content of a row it could not verify. With `cryptography` that row reads `WITNESS_NOT_THIS_RECORD`; both are `NOT_WITNESSED`.
- DRAFT: `tools/vendor_kit_reader.py` makes the vendored copies and writes the pin; the source distribution now carries `tools/`.
- DRAFT: the 0.1.1 modules are unchanged byte for byte; `telos_receipt.__version__` still reads `0.1.1`.

## 0.1.1

- Add optional `verify_native_receipts` and `telos_receipt.native` for native-v2 byte integrity (`pip install telos-receipt[native]`).
- Compare supplied bytes, native hashes and predecessor links; signatures, scores and content remain unverified.
- Vendor the MIT-licensed verifier with portable imports, source pins and attribution. Missing native dependencies return `UNAVAILABLE`.
- Preserve the unsigned envelope API and development extra.
