"""Read a kit record with the kit's own reader, and name one in an ordinary unsigned receipt.

A kit record is a directory holding `receipt.json` and, beside it, optionally `witness.json` and `reading.json`.
This module does not check a record itself. It carries the kit's reader (three files, copied byte for byte into
`_kit_vendor/`) and hands every question to it:

  check_record_dir(path)                    the kit reader's report for the record directory at `path`
  check_record(receipt, witness, reading)   the same report for the same three files given as bytes
  build_reference(receipt, reading)         a `telos/0.1-unsigned` receipt, kind "kit_record_reference", whose
                                            payload names a record by the digests the kit names it by

A report comes back as `{"ok": True, "report": <the kit reader's report: the object it returned, unchanged>,
"witness_state": "WITNESSED" or "NOT_WITNESSED", "pins": "default" or "caller", "kit_reader": {"commit": ...,
"files": {...}}}`.

`ok: True` means the reader ran, not that the record is authentic. Authenticity is the witness state only:
`witness_state`, the state the reader itself returns beside its report. (The report's `authenticity` is the same
word; when the two differ no report is given.) WITNESSED binds the supplied digests to a Witness signature: the row
beside the receipt carries a signature that checks, under the Witness key the reader was given, for this record's
digests. It says nothing about observed execution, about commissioning, or about every reading of the record, and
the kit's own limits on it apply here unchanged. `pins` says whose key that was: "default" is the key the kit pins;
"caller" is a key the caller passed, and a WITNESSED under it says nothing about the kit's Witness. What the other
fields of the report mean is the kit's statement, not this package's. Strings in a report can come from the record:
they are data.

A reference is a plain unsigned receipt: four digests and no statement about the record they name. It conveys
neither identity nor attestation. `kind` and `agent_id` are not covered by the payload hash, so `verify_receipt`
shows only that the payload is the payload that was hashed.

Every other answer is a refusal, `{"ok": False, "reason": ...}`, with one of the seven reasons in REASONS (and,
in the one case named below, `"residual": True` beside it):

  kit_reader_modified   a file under `_kit_vendor/` is not the file this module pins; every call answers this
  record_unreadable     no readable regular `receipt.json` at the path, or (build_reference) a receipt the kit
                        reader does not read as VALID or names no record digest for
  input_too_large       a bytes input over the kit's cap for it (receipt 1,048,576; row 4,096; reading 32,768)
  pins_invalid          `pins` is neither None nor an object with str `public_key`, `fingerprint` and `anchor`
                        that UTF-8 can carry
  invalid_argument      an argument of the wrong type: a record file that is not bytes (or None where the file may
                        be absent), a path that is not str, bytes or os.PathLike, an `agent_id` that is not a str
                        or that UTF-8 cannot carry (a lone surrogate)
  reader_unavailable    the reader could not be run to an answer here: no usable temporary directory, a write
                        there failed, the directory could not be removed, the reader raised or returned something
                        other than a report and a state that agree, or a reader file asked for a module outside its
                        closed list
  reading_invalid       (build_reference) a reading was supplied and the kit reader does not read it as this
                        record's saved reading; a supplied reading is never treated as no reading

No exception leaves the three functions for any value of their arguments, and a failure to write or remove the
temporary files is a refusal, never a report. check_record tries to remove its temporary directory on every path,
also after an error inside, and returns a report only after it has seen that the directory is no longer there. If
the directory could not be removed the answer is
`{"ok": False, "reason": "reader_unavailable", "residual": True}`: the caller's bytes are still in a private
directory under the system's temporary directory, and the answer does not name it. No other answer has a
`residual` key. Two things are not answers and pass through: a call that does not
fit a function's signature (Python's own TypeError, before the function runs), and KeyboardInterrupt or SystemExit
(after the temporary directory is removed).

The pin. KIT_COMMIT and KIT_FILES below are written by tools/vendor_kit_reader.py together with the copies.
Verification is latched at first use: at the first call in a process the three files are read once, hashed and
compared with KIT_FILES, and that outcome stands for the life of the process. The bytes verified are the bytes
executed: they are compiled from memory, so no cached bytecode and no second read of the file can stand in for
them. Later changes to the files on disk are neither used nor detected in a running process; a new process checks
again. The three files find each other through this loader alone and may import only each other and a closed list
of standard library and `cryptography` names (_ALLOWED_IMPORTS). Any other import by a reader file, at load or
later, is the refusal `reader_unavailable` for that call and every later call of the process. No module named
`h0a` is created, imported or looked up: an `h0a` already in `sys.modules`, or importable from `sys.path`, is
never used and is left as it is. No entry that is already in `sys.modules` is replaced or removed, the three
reader modules are never entered there under any name, no name that is or starts with `h0a` is added, and
`sys.path` is not changed. What the reader imports is added to `sys.modules` as any import adds it: the standard
library modules of the closed list at the first call, and `cryptography` at the first call that reaches the
signature check, each with whatever it imports itself. The closed list covers the import statement and
`__import__`; it is not a sandbox, and the reader is trusted because it is the pinned bytes.

Offline: no network call and no process. check_record_dir writes nothing. check_record writes its inputs into a
private temporary directory (0700, files 0600), reads that directory with the same reader, and removes it on
every path (see `residual` above). `cryptography` is imported by the kit reader, and only when a row reaches its
signature check. With the reader pinned here, a row that reaches that check on a machine without `cryptography`
is refused, `reader_unavailable`: no report is made without that check.

Needs Python 3.11 or later (the base package keeps its own floor and never imports this module) and a POSIX file
system interface.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
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

__all__ = ["KIT_COMMIT", "KIT_FILES", "REASONS", "REFERENCE_KIND", "Pins", "build_reference", "check_record",
           "check_record_dir"]

# --- kit reader pin: written by tools/vendor_kit_reader.py, never by hand ---
KIT_COMMIT = "64dfcef2bbe8ac411d98841ab1216ed4852a33e9"
KIT_FILES = {
    "h0a/reading.py": "cf38de959154c70fc1dab3073975d0c9b26ce232d35d15e81d6696729bc38178",
    "h0a/receipt.py": "c7a73c6f20b434b42512aa4a0a0149f06e823fc4dc1f23c429b758548deac439",
    "h0a/witness.py": "88f59d68d13bcca9be19e83f2240eedef71e4e3e7b86514ea57d97d48d22772e",
}
# --- end kit reader pin ---

REFERENCE_KIND = "kit_record_reference"
REASONS = ("kit_reader_modified", "record_unreadable", "input_too_large", "pins_invalid", "invalid_argument",
           "reader_unavailable", "reading_invalid")  # every `reason` of a refusal is one of these

# What the three reader files may import besides each other: module name -> the names `from <module> import` may
# take. tests/test_kit_record.py holds this list equal to what the pinned files do import; a re-pin whose files
# import anything else is refused at run time until this list is changed, by hand, in review.
_ALLOWED_IMPORTS = {
    "argparse": frozenset(),
    "base64": frozenset(),
    "cryptography.exceptions": frozenset({"InvalidSignature"}),
    "cryptography.hazmat.primitives.asymmetric.ed25519": frozenset({"Ed25519PublicKey"}),
    "datetime": frozenset({"datetime", "timezone"}),
    "hashlib": frozenset(),
    "http.client": frozenset(),
    "json": frozenset(),
    "os": frozenset(),
    "pathlib": frozenset({"Path"}),
    "re": frozenset(),
    "subprocess": frozenset(),
    "sys": frozenset(),
    "typing": frozenset({"NamedTuple"}),
    "urllib.parse": frozenset(),
}

_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_kit_vendor")
_ORDER = ("reading", "witness", "receipt")  # load order: each file asks only for files loaded before it
_STATES = ("WITNESSED", "NOT_WITNESSED")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LOCK = threading.Lock()
_LOADED: list[Any] = []  # empty until the first use; then one item: the loaded reader, or "kit_reader_modified"
_OUTSIDE: list[str] = []  # what a reader file asked to import outside the closed list; never emptied


class Pins(NamedTuple):
    """A Witness key to check a row under, in place of the one the kit pins: for canary keys and tests."""

    public_key: str  # the raw Ed25519 public key, hex
    fingerprint: str  # sha256 of those bytes, hex
    anchor: str  # the chain head the witness log is anchored to


class _Kit(NamedTuple):
    reading: Any
    witness: Any
    receipt: Any


def _refusal(reason: str, residual: bool = False) -> dict[str, Any]:
    return {"ok": False, "reason": reason, "residual": True} if residual else {"ok": False, "reason": reason}


def _load(*, _reader: Any = None) -> _Kit | str:
    """The three vendored files as modules, or "kit_reader_modified" when one is not the file KIT_FILES pins.

    `_reader` is for this package's tests alone and no public function passes it: `({name: bytes}, pins)` stands
    in for the three files on disk and for KIT_FILES, so that bytes which match their own pins can be put to the
    import guard below. Everything after the choice of bytes and pins is the one path.
    """
    given, pins = (None, KIT_FILES) if _reader is None else _reader
    sources = {}
    for name in _ORDER:
        try:
            if given is None:
                with open(os.path.join(_VENDOR, name + ".py"), "rb") as stream:
                    raw = stream.read()
            else:
                raw = given[name]
        except OSError:
            return "kit_reader_modified"
        if hashlib.sha256(raw).hexdigest() != pins[f"h0a/{name}.py"]:
            return "kit_reader_modified"
        sources[name] = raw
    loaded: dict[str, Any] = {}

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        """The import statement of a reader file: `from h0a import <sibling>` gives the sibling loaded here, a
        module on the closed list is Python's, and anything else is noted in _OUTSIDE and is no import at all."""
        try:
            wanted = set(fromlist or ())
            sibling = level == 0 and name == "h0a" and bool(wanted) and wanted <= set(loaded)
            listed = level == 0 and name in _ALLOWED_IMPORTS and wanted <= _ALLOWED_IMPORTS[name]
        except Exception:  # noqa: BLE001  (a name or a list that is no name or list of names)
            sibling = listed = False
        if sibling:
            return types.SimpleNamespace(**{item: loaded[item] for item in wanted})
        if listed:
            return builtins.__import__(name, globals, locals, fromlist, level)
        _OUTSIDE.append(repr(name))
        raise ImportError("the pinned kit reader imports its three files and a closed list of modules")

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


def _kit(*, _reader: Any = None) -> _Kit | str:
    """The loaded reader, or the reason every call is refused. Latched: the files are read and checked once.
    (`_reader`: see _load; the public functions call this with no argument.)"""
    with _LOCK:
        if not _LOADED:
            _LOADED.append(_load(_reader=_reader))
        return _LOADED[0]


def _answer(call: Any, *args: Any) -> dict[str, Any]:
    """call(*args), or the refusal for whatever it raised. Once a reader file has asked for a module outside the
    closed list, no call of this process returns anything but that refusal."""
    try:
        result = call(*args)
    except Exception:  # noqa: BLE001  (no exception leaves the public functions; an interrupt is not an Exception)
        return _refusal("reader_unavailable")
    if _OUTSIDE:
        return _refusal("reader_unavailable", result.get("residual") is True)
    return result


def _kit_pins(kit: _Kit, pins: Any) -> Any:
    """The kit's own Pins for `pins`: its pinned Witness key for None; None when `pins` is no set of pins."""
    if pins is None:
        return kit.witness.PINS
    try:
        values = (pins.public_key, pins.fingerprint, pins.anchor)
    except AttributeError:
        return None
    if not all(type(value) is str and _utf8(value) for value in values):
        return None
    return kit.witness.Pins(*values)


def _inputs_refused(kit: _Kit, receipt: Any, witness: Any, reading: Any) -> dict[str, Any] | None:
    """The refusal for inputs that are not bytes or are over the kit's caps, else None."""
    if type(receipt) is not bytes:
        return _refusal("invalid_argument")
    if not all(raw is None or type(raw) is bytes for raw in (witness, reading)):
        return _refusal("invalid_argument")
    if len(receipt) > kit.receipt.MAX_BYTES:
        return _refusal("input_too_large")
    if witness is not None and len(witness) > kit.witness.MAX_ROW_BYTES:
        return _refusal("input_too_large")
    if reading is not None and len(reading) > kit.witness.MAX_READING_BYTES:
        return _refusal("input_too_large")
    return None


def _report(kit: _Kit, receipt_path: str, kit_pins: Any, pins: Any) -> dict[str, Any]:
    """The kit reader's report for the receipt file at receipt_path and the files beside it, under kit_pins: the
    kit's own form of the caller's `pins`. OSError is the reader's, for a receipt it could not open."""
    report, state = kit.receipt.check_record(receipt_path, pins=kit_pins)
    # The reader returns its report and, beside it, the witness state the report was made from. The state is what
    # this module names; a return that is not that pair, or whose two halves differ, is not passed on.
    if type(report) is not dict or type(state) is not dict or state.get("authenticity") not in _STATES:
        return _refusal("reader_unavailable")
    if report.get("authenticity") != state["authenticity"]:
        return _refusal("reader_unavailable")
    whose = "default" if pins is None else "caller"  # None, given or left out, is the key the kit pins
    return {"ok": True, "report": report, "witness_state": state["authenticity"], "pins": whose,
            "kit_reader": {"commit": KIT_COMMIT, "files": dict(KIT_FILES)}}


def _check_record_dir(path: Any, pins: Any) -> dict[str, Any]:
    kit = _kit()
    if type(kit) is str:
        return _refusal(kit)
    kit_pins = _kit_pins(kit, pins)
    if kit_pins is None:
        return _refusal("pins_invalid")
    try:
        receipt_path = os.path.join(os.fsdecode(path), kit.witness.RECEIPT)
        os.fsencode(receipt_path)
    except (TypeError, UnicodeEncodeError):  # not a str, bytes or os.PathLike; a str no encoding carries
        return _refusal("invalid_argument")
    try:
        # The kit reader opens this file and waits for it; only a regular file is certain to answer.
        regular = stat.S_ISREG(os.stat(receipt_path).st_mode)
    except (ValueError, OSError):  # a path no call takes (a NUL); nothing there
        return _refusal("record_unreadable")
    if not regular:
        return _refusal("record_unreadable")
    try:
        return _report(kit, receipt_path, kit_pins, pins)
    except OSError:  # the reader could not open the receipt
        return _refusal("record_unreadable")


def check_record_dir(path: Any, *, pins: Any = None) -> dict[str, Any]:
    """The kit reader's report for the record directory at `path` (str, bytes or os.PathLike).

    `{"ok": True, "report": ..., "witness_state": ..., "pins": ..., "kit_reader": ...}`. `ok: True` means the
    reader ran, not that the record is authentic: authenticity is the witness state only (`witness_state`,
    "WITNESSED" or "NOT_WITNESSED", from the reader's own return). `pins=None` checks a Witness row under the key
    the kit pins ("default"); a `Pins` checks it under that key instead ("caller").
    A `receipt.json` that is missing, not a regular file, or not readable is refused: `record_unreadable`.
    Reads only; writes nothing. Never raises for any value of `path` or `pins`: see REASONS.
    """
    return _answer(_check_record_dir, path, pins)


def _put(path: str, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def _removed(home: str) -> bool:
    """Remove the temporary directory, twice if it takes that. True only when nothing is at that path afterwards:
    a removal that raised nothing is not taken at its word."""
    try:
        for quiet in (False, True):
            try:
                shutil.rmtree(home, ignore_errors=quiet)
            except Exception:  # noqa: BLE001, S110  (the look below is the answer)
                pass
            if not os.path.lexists(home):
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _check_record(receipt: Any, witness: Any, reading: Any, pins: Any) -> dict[str, Any]:
    kit = _kit()
    if type(kit) is str:
        return _refusal(kit)
    refused = _inputs_refused(kit, receipt, witness, reading)
    if refused is not None:
        return refused
    kit_pins = _kit_pins(kit, pins)
    if kit_pins is None:
        return _refusal("pins_invalid")
    home = tempfile.mkdtemp(prefix="telos-receipt-record-")  # 0700
    try:
        try:
            files = ((kit.witness.RECEIPT, receipt), (kit.witness.WITNESS, witness), (kit.witness.READING, reading))
            for name, raw in files:
                if raw is not None:
                    _put(os.path.join(home, name), raw)
            result = _report(kit, os.path.join(home, kit.witness.RECEIPT), kit_pins, pins)
        except Exception:  # noqa: BLE001  (an error inside is a refusal; the directory is removed below either way)
            result = _refusal("reader_unavailable")
    finally:  # also on an interrupt, which then passes through
        gone = _removed(home)
    if not gone:  # whatever the reader answered: the caller's bytes are still on disk, and the path is not told
        return _refusal("reader_unavailable", residual=True)
    return result


def check_record(
    receipt: bytes, witness: bytes | None = None, reading: bytes | None = None, *, pins: Any = None
) -> dict[str, Any]:
    """The kit reader's report for a record given as the bytes of its files (None for a file that is not there).

    The same answer as check_record_dir gives for a directory holding these files. `ok: True` means the reader
    ran, not that the record is authentic: authenticity is the witness state only (`witness_state`).
    The types and the caps are checked first: an input that is not bytes is refused, `invalid_argument`, and one
    over the kit's cap for it, `input_too_large`, before anything is written. The bytes then go into a private
    temporary directory, the kit reader reads that directory exactly as check_record_dir would, and the directory
    is removed on every path. If it cannot be made or written, or the reader raises, the answer is the refusal
    `reader_unavailable`, never a report and never an exception. A report is returned only once the directory is
    seen to be gone; if it could not be removed the answer is `{"ok": False, "reason": "reader_unavailable",
    "residual": True}`, which does not name the directory.
    """
    return _answer(_check_record, receipt, witness, reading, pins)


def _utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _build_reference(receipt: Any, reading: Any, agent_id: Any) -> dict[str, Any]:
    kit = _kit()
    if type(kit) is str:
        return _refusal(kit)
    if type(agent_id) is not str or not _utf8(agent_id):
        return _refusal("invalid_argument")
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
    digests = (payload["record_sha256"], payload["config_identity"])
    # (a digest that is no str at all raises here, which _answer makes the same refusal)
    if type(payload["record_schema"]) is not str or not all(_HEX64.fullmatch(digest) for digest in digests):
        return _refusal("reader_unavailable")
    if reading is not None and payload["reading_sha256"] is None:
        return _refusal("reading_invalid")  # supplied, and not this record's saved reading: never "no reading"
    # the kit names a reading by the sha256 of its bytes; any other value is not a name for the bytes supplied
    if payload["reading_sha256"] != (None if reading is None else hashlib.sha256(reading).hexdigest()):
        return _refusal("reader_unavailable")
    return build_receipt(REFERENCE_KIND, payload, agent_id)


def build_reference(receipt: bytes, reading: bytes | None = None, *, agent_id: str) -> dict[str, Any]:
    """An unsigned receipt that names a kit record by its digests: kind "kit_record_reference".

    The payload has exactly four fields. `record_schema`, `record_sha256` and `config_identity` are the kit
    reader's own names for the record: the values it sends when it asks for a Witness row. `record_sha256` is the
    kit's runtime digest (the sha256 of the kit's canonical bytes of the receipt's `runtime` segment, which the
    reader recomputes) and `config_identity` the kit's digest of the record's configuration; neither is the digest
    of the `receipt` file. `reading_sha256` is the lowercase 64-hex sha256 of the exact supplied bytes of
    `reading`, or null when `reading` is None (absent). All three digests are 64 lowercase hex characters.

    A reference conveys neither identity nor attestation. It carries no statement about the record, and `kind` and
    `agent_id` are not covered by the payload hash: `verify_receipt` shows only that the payload is the payload
    that was hashed. The receipt is the ordinary `build_receipt` envelope, `signature` null.

    Refusals, never an exception: `invalid_argument` for a `receipt` or `reading` that is not bytes or an
    `agent_id` that is not a str UTF-8 can carry; `input_too_large` over the caps of check_record (receipt
    1,048,576 bytes, reading 32,768); `record_unreadable` for a receipt the kit reader does not read as VALID or
    names no record digest for; `reading_invalid` for a supplied reading the kit reader does not read as this
    record's saved reading (it is never treated as absent); `reader_unavailable` when the reader raises.
    """
    return _answer(_build_reference, receipt, reading, agent_id)
