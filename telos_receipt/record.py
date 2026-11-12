"""Read a kit record with the kit's own reader, and name one in an ordinary unsigned receipt.

A kit record is a directory holding `receipt.json` and, beside it, optionally `witness.json` and `reading.json`.
This module does not check a record itself. It carries the kit's reader (three files, copied byte for byte into
`_kit_vendor/`) and hands every question to it:

  check_record_dir(path)                    the kit reader's report for the record directory at `path`
  check_record(receipt, witness, reading)   the same report for the same three files given as bytes
  build_reference(receipt, reading)         a `telos/0.1-unsigned` receipt, kind "kit_record_reference", whose
                                            payload names a record by the digests the kit names it by

A report is returned as `{"ok": True, "report": <the kit reader's report, unchanged>, "kit_reader": {"commit": ...,
"files": {...}}}`. What the report's fields mean is the kit's statement, not this package's: its `authenticity` is
WITNESSED only when the row beside the receipt carries a signature that checks under the Witness key the kit pins,
for this record's digests, and the kit's own limits on that statement apply here unchanged. A reference is a plain
unsigned receipt: it carries four digests and no statement about the record they name.

Every other answer is a refusal, `{"ok": False, "reason": ...}`, with one of four reasons:

  kit_reader_modified   a file under `_kit_vendor/` is not the file this module pins; every call answers this
  record_unreadable     no readable regular `receipt.json` there, an input that is not bytes, or (build_reference)
                        a receipt the kit reader does not read as VALID or names no record digest for
  input_too_large       a bytes input over the kit's cap for it (receipt 1,048,576; row 4,096; reading 32,768)
  pins_invalid          `pins` is neither None nor an object with str `public_key`, `fingerprint` and `anchor`

Bad input never raises from check_record_dir or check_record. What can raise is the machine, not the record: no
usable temporary directory for check_record, or, with the reader pinned here, a row that reaches the signature
check on a machine without the `cryptography` package (an ImportError; no report is made without that check).
build_reference raises TypeError for an `agent_id` that is not a str, as a build function does.

The pin. KIT_COMMIT and KIT_FILES below are written by tools/vendor_kit_reader.py together with the copies. Before
the first use in a process the three files are hashed and compared with KIT_FILES, and the bytes that were hashed
are the bytes that run: they are compiled from memory, so no cached bytecode and no later change on disk can stand
in for them. The three files find each other through this loader alone. No module named `h0a` is created or
imported, nothing is added to `sys.path` or `sys.modules`, and an `h0a` package that happens to be importable is
never used.

Offline: no network call and no process. check_record_dir writes nothing. check_record writes its inputs into a
private temporary directory (0700, files 0600), reads that directory with the same reader, and removes it.
`cryptography` is imported by the kit reader, and only when a row reaches its signature check.

Needs Python 3.11 or later (the base package keeps its own floor) and a POSIX file system interface.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import types
from typing import Any, NamedTuple

from . import build_receipt

if sys.version_info < (3, 11):
    raise RuntimeError("telos_receipt.record needs Python 3.11 or later")

__all__ = ["KIT_COMMIT", "KIT_FILES", "REFERENCE_KIND", "Pins", "build_reference", "check_record", "check_record_dir"]

# --- kit reader pin: written by tools/vendor_kit_reader.py, never by hand ---
KIT_COMMIT = "64dfcef2bbe8ac411d98841ab1216ed4852a33e9"
KIT_FILES = {
    "h0a/reading.py": "cf38de959154c70fc1dab3073975d0c9b26ce232d35d15e81d6696729bc38178",
    "h0a/receipt.py": "c7a73c6f20b434b42512aa4a0a0149f06e823fc4dc1f23c429b758548deac439",
    "h0a/witness.py": "88f59d68d13bcca9be19e83f2240eedef71e4e3e7b86514ea57d97d48d22772e",
}
# --- end kit reader pin ---

REFERENCE_KIND = "kit_record_reference"

_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_kit_vendor")
_ORDER = ("reading", "witness", "receipt")  # load order: each file asks only for files loaded before it
_LOCK = threading.Lock()
_LOADED: list[Any] = []  # empty until the first use; then one item, the loaded reader or None when it is not the pin


class Pins(NamedTuple):
    """A Witness key to check a row under, in place of the one the kit pins: for canary keys and tests."""

    public_key: str  # the raw Ed25519 public key, hex
    fingerprint: str  # sha256 of those bytes, hex
    anchor: str  # the chain head the witness log is anchored to


class _Kit(NamedTuple):
    reading: Any
    witness: Any
    receipt: Any


def _refusal(reason: str) -> dict[str, Any]:
    return {"ok": False, "reason": reason}


def _load() -> _Kit | None:
    """The three vendored files as modules, or None when one of them is not the file KIT_FILES pins."""
    sources = {}
    for name in _ORDER:
        try:
            with open(os.path.join(_VENDOR, name + ".py"), "rb") as stream:
                raw = stream.read()
        except OSError:
            return None
        if hashlib.sha256(raw).hexdigest() != KIT_FILES[f"h0a/{name}.py"]:
            return None
        sources[name] = raw
    loaded: dict[str, Any] = {}

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        """`from h0a import <sibling>` inside a vendored file gives the sibling loaded here; all else is Python's."""
        if level == 0 and (name == "h0a" or name.startswith("h0a.")):
            if name == "h0a" and fromlist and all(item in loaded for item in fromlist):
                return types.SimpleNamespace(**{item: loaded[item] for item in fromlist})
            raise ImportError("the pinned kit reader is its three files and no other part of the kit", name=name)
        return builtins.__import__(name, globals, locals, fromlist, level)

    scope = dict(vars(builtins), __import__=importer)
    for name in _ORDER:
        path = os.path.join(_VENDOR, name + ".py")
        module = types.ModuleType("telos_receipt._kit_vendor._pinned_" + name)
        module.__file__ = path
        module.__dict__["__builtins__"] = scope
        # The bytes hashed above, not a second read of the file and not its cached bytecode.
        exec(compile(sources[name], path, "exec", dont_inherit=True), module.__dict__)  # noqa: S102
        loaded[name] = module
    return _Kit(**loaded)


def _kit() -> _Kit | None:
    with _LOCK:
        if not _LOADED:
            _LOADED.append(_load())
        return _LOADED[0]


def _kit_pins(kit: _Kit, pins: Any) -> Any:
    """The kit's own Pins for `pins`: its pinned Witness key for None; None when `pins` is no set of pins."""
    if pins is None:
        return kit.witness.PINS
    try:
        values = (pins.public_key, pins.fingerprint, pins.anchor)
    except AttributeError:
        return None
    if not all(type(value) is str for value in values):
        return None
    return kit.witness.Pins(*values)


def _inputs_refused(kit: _Kit, receipt: Any, witness: Any, reading: Any) -> dict[str, Any] | None:
    """The refusal for inputs that are not bytes or are over the kit's caps, else None."""
    if type(receipt) is not bytes:
        return _refusal("record_unreadable")
    if not all(raw is None or type(raw) is bytes for raw in (witness, reading)):
        return _refusal("record_unreadable")
    if len(receipt) > kit.receipt.MAX_BYTES:
        return _refusal("input_too_large")
    if witness is not None and len(witness) > kit.witness.MAX_ROW_BYTES:
        return _refusal("input_too_large")
    if reading is not None and len(reading) > kit.witness.MAX_READING_BYTES:
        return _refusal("input_too_large")
    return None


def _report(kit: _Kit, receipt_path: str, pins: Any) -> dict[str, Any]:
    """The kit reader's report for the receipt file at receipt_path and the files beside it."""
    try:
        report, _state = kit.receipt.check_record(receipt_path, pins=pins)
    except OSError:
        return _refusal("record_unreadable")
    return {"ok": True, "report": report, "kit_reader": {"commit": KIT_COMMIT, "files": dict(KIT_FILES)}}


def check_record_dir(path: Any, *, pins: Any = None) -> dict[str, Any]:
    """The kit reader's report for the record directory at `path` (str, bytes or os.PathLike).

    `pins=None` checks a Witness row under the key the kit pins; a `Pins` checks it under that key instead.
    A `receipt.json` that is missing, not a regular file, or not readable is refused: `record_unreadable`.
    Reads only; writes nothing.
    """
    kit = _kit()
    if kit is None:
        return _refusal("kit_reader_modified")
    kit_pins = _kit_pins(kit, pins)
    if kit_pins is None:
        return _refusal("pins_invalid")
    try:
        receipt_path = os.path.join(os.fsdecode(path), kit.witness.RECEIPT)
        # The kit reader opens this file and waits for it; only a regular file is certain to answer.
        regular = stat.S_ISREG(os.stat(receipt_path).st_mode)
    except (TypeError, ValueError, OSError):  # not a path; a path no call takes (NUL, lone surrogate); nothing there
        return _refusal("record_unreadable")
    if not regular:
        return _refusal("record_unreadable")
    return _report(kit, receipt_path, kit_pins)


def _put(path: str, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def check_record(
    receipt: bytes, witness: bytes | None = None, reading: bytes | None = None, *, pins: Any = None
) -> dict[str, Any]:
    """The kit reader's report for a record given as the bytes of its files (None for a file that is not there).

    The caps are checked first: an input over the kit's cap for it is refused, `input_too_large`, before anything
    is written. The bytes then go into a private temporary directory, the kit reader reads that directory exactly
    as check_record_dir would, and the directory is removed, also when the reader raises.
    """
    kit = _kit()
    if kit is None:
        return _refusal("kit_reader_modified")
    refused = _inputs_refused(kit, receipt, witness, reading)
    if refused is not None:
        return refused
    kit_pins = _kit_pins(kit, pins)
    if kit_pins is None:
        return _refusal("pins_invalid")
    home = tempfile.mkdtemp(prefix="telos-receipt-record-")  # 0700
    try:
        files = ((kit.witness.RECEIPT, receipt), (kit.witness.WITNESS, witness), (kit.witness.READING, reading))
        for name, raw in files:
            if raw is not None:
                _put(os.path.join(home, name), raw)
        return _report(kit, os.path.join(home, kit.witness.RECEIPT), kit_pins)
    finally:
        shutil.rmtree(home)


def build_reference(receipt: bytes, reading: bytes | None = None, *, agent_id: str) -> dict[str, Any]:
    """An unsigned receipt that names a kit record by its digests: kind "kit_record_reference".

    The payload has exactly four fields: `record_schema`, `record_sha256` and `config_identity` as the kit names
    the record when it asks for a Witness row, and `reading_sha256`, the sha256 of `reading` when the kit reader
    reads those bytes as this record's saved reading, else null. The digests are the kit reader's own. The
    receipt is the ordinary `build_receipt` envelope: `signature` null, verifiable with `verify_receipt`.

    It carries no statement about the record. A receipt the kit reader does not read as VALID, or for which the
    kit names no record digest, gets no reference: `{"ok": False, "reason": "record_unreadable"}`.
    """
    kit = _kit()
    if kit is None:
        return _refusal("kit_reader_modified")
    if type(agent_id) is not str:
        raise TypeError("agent_id must be a str")
    refused = _inputs_refused(kit, receipt, None, reading)
    if refused is not None:
        return refused
    if kit.receipt.check_receipt(receipt)["structure"] != "VALID":
        return _refusal("record_unreadable")
    request = kit.witness.request_bytes(receipt, reading)
    if request is None:
        return _refusal("record_unreadable")
    named = json.loads(request)
    payload = {
        "record_schema": named["record_schema"],
        "record_sha256": named["record_sha256"],
        "config_identity": named["config_identity"],
        "reading_sha256": named.get("reading_sha256"),
    }
    return build_receipt(REFERENCE_KIND, payload, agent_id)
