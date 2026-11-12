"""telos_receipt.record: the SDK reads a kit record with the kit's own reader (guarantees S1-S9).

S1 a WITNESSED and a NOT_WITNESSED fixture read exactly as the kit reader reads them, through both functions.
S2 one changed byte in the receipt, the row, the signature or the reading reads as the kit reader reads the changed
   directory, beside the untouched one.
S3 a vendored reader file that differs from its pin by one byte refuses every call (`kit_reader_modified`), beside
   the intact files; the vendoring script reproduces the three files and the pin from a kit checkout.
S4 import hygiene: no `h0a`, no `sys.path` change, `cryptography` only when a row reaches the signature step.
S5 no socket and no process; the temporary directory is private and is gone afterwards, also when the check raises.
S6 the three size caps, each refused one byte over beside the same input at the cap.
S7 `build_reference`: four payload keys, the kit's digests, verifies, validates against the published schema.
S8 Python 3.10 is refused at import beside 3.11. Without `cryptography` a row that reaches the signature step reads
   as the kit reader reads it there (NOT_WITNESSED, WITNESS_VERIFIER_UNAVAILABLE), and a row refused before that
   step keeps its reason, in either order.
S9 the existing modules are byte-identical to 0.1.1.

Amendments 1 and 2 to the contract (classes R1-R5; the tests named test_a2_* are amendment 2's):
R1/A2.1 the reader that runs is the pinned bytes, compiled from memory once; its files import each other and a
   closed list; an `h0a` already imported is never used; what was in `sys.modules` and `sys.path` is as it was.
   The import guard is put to the test through a private loader seam that takes reader bytes with their own pins.
R2/A2.3 the result carries the reader's own witness state and whose pins were used; `pins=None` is no pins.
R3/A2.2 one closed tuple of refusal reasons, no exception, and no report while the temporary directory is still
   there (`residual: True`).
R4 the base package never imports this module; below 3.11 the module raises its one line.
R5 what a reference does not convey, and the DRAFT marking of the public text.

Amendment 6 (class A6FailedRead and the tests named test_a6_2_*):
S15/A6.1 an OSError opening or reading a vendored reader file is `reader_unavailable` for that call and is not
   latched: the next call takes all three files again. A real byte mismatch is `kit_reader_modified` and stays so.
   The faults are put on `open` inside a fresh interpreter, for that interpreter's vendored paths only; real byte
   changes are made in a temporary copy of the package. The vendored files of this tree are never written.
S16/A6.2 a process-control exception propagates; the removal of the temporary directory is attempted, and when
   that also fails the directory is left and nothing is returned. Argument-binding errors are Python's own.

The fixtures under kit_record_fixtures/ were made once by the kit's own entry points with a loopback stub Witness
and a canary Ed25519 key that was never written to disk. `oracle.json` holds the canary PUBLIC pins and what the
kit reader answered for every fixture and every changed directory: `canary_pins` is the kit's
`check_record(path, pins=<canary>)`, `pinned_key_cli` is the line the kit reader command printed (it checks under
the pinned Witness key, so a canary row reads NOT_WITNESSED there), `canary_pins_no_verifier` is the same
`check_record` in a process where importing `cryptography` fails. No test opens a socket or a real key.
"""
import ast
import hashlib
import importlib
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import telos_receipt

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
PACKAGE = ROOT / "telos_receipt"
VENDOR = PACKAGE / "_kit_vendor"
SCRIPT = ROOT / "tools" / "vendor_kit_reader.py"
FIXTURES = TESTS / "kit_record_fixtures"
ORACLE = json.loads((FIXTURES / "oracle.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((TESTS / "receipt-spec.schema.json").read_text(encoding="utf-8"))
NAMES = ("receipt.json", "witness.json", "reading.json")
KIT_NAMES = ("h0a/reading.py", "h0a/receipt.py", "h0a/witness.py")
MODIFIED = {"ok": False, "reason": "kit_reader_modified"}
TOO_LARGE = {"ok": False, "reason": "input_too_large"}
UNREADABLE = {"ok": False, "reason": "record_unreadable"}
PINS_INVALID = {"ok": False, "reason": "pins_invalid"}
INVALID_ARGUMENT = {"ok": False, "reason": "invalid_argument"}
UNAVAILABLE = {"ok": False, "reason": "reader_unavailable"}
RESIDUAL = {"ok": False, "reason": "reader_unavailable", "residual": True}
READING_INVALID = {"ok": False, "reason": "reading_invalid"}
REASONS = ("kit_reader_modified", "record_unreadable", "input_too_large", "pins_invalid", "invalid_argument",
           "reader_unavailable", "reading_invalid")
PIN_BEGIN = "# --- kit reader pin: written by tools/vendor_kit_reader.py, never by hand ---"
PIN_END = "# --- end kit reader pin ---"
# sha256 of each module as the published 0.1.1 wheel carries it (wheel sha256 6a5087f8...46a331)
MODULES_0_1_1 = {
    "__init__.py": "f319ece2c137b665f2541b259c7851444cc4637ef44df873bd57031c4e355dbf",
    "native.py": "9463a9c426e3ece47518363f5546a87ec035cfc9eb8898c4760acf258e56baa6",
    "_native_vendor/__init__.py": "a8cd3c3430642feb055fce798d20d53879228ecab8a4b9635887d3d04a334d7b",
    "_native_vendor/hermes_v2.py": "6eb37e9f8018ff98a6d4546f707de17cb64b53038a6d7311bf7ba89ab79e24bf",
    "_native_vendor/verify_native_v2.py": "98bfab078eb85fde1f740c8c7e165965f02d6cdc38257b5e0b93b404b1f6835d",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def fixture(name):
    """{file name: bytes} of one fixture directory."""
    return {f: (FIXTURES / name / f).read_bytes() for f in ORACLE["fixtures"][name]["files"]}


def changed(variant):
    """{file name: bytes} of one changed directory, rebuilt from its base fixture as oracle.json describes it."""
    files = fixture(variant["base"])
    for taken in variant["take"]:
        files[taken["file"]] = (FIXTURES / taken["from"] / taken["file"]).read_bytes()
    for edit in variant["edits"]:
        data = bytearray(files[edit["file"]])
        assert data[edit["offset"]] == edit["old"] != edit["new"]
        data[edit["offset"]] = edit["new"]
        files[edit["file"]] = bytes(data)
    return files


class Case(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sdk-kit-record-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def record(self):
        """The module under test. A missing module is a failed guarantee, not a broken test."""
        try:
            return importlib.import_module("telos_receipt.record")
        except ImportError as e:
            self.fail(f"telos_receipt.record is missing: {e}")

    def answer(self, call, *args, **kwargs):
        """call(*args, **kwargs); an exception leaving the API is a failed guarantee."""
        try:
            return call(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            self.fail(f"{getattr(call, '__name__', call)} raised {type(e).__name__}: {e}")

    def canary(self):
        return self.record().Pins(**ORACLE["canary_pins"])

    def directory(self, files, name="record"):
        home = os.path.join(self.tmp, name)
        os.mkdir(home)
        for f, raw in files.items():
            with open(os.path.join(home, f), "wb") as stream:
                stream.write(raw)
        return home

    def both(self, files, name, **pins):
        """(check_record_dir result, check_record result) for the same record files."""
        record = self.record()
        by_dir = self.answer(record.check_record_dir, self.directory(files, name), **pins)
        by_bytes = self.answer(record.check_record, files["receipt.json"], files.get("witness.json"),
                               files.get("reading.json"), **pins)
        return by_dir, by_bytes

    def kit_reader(self):
        """By hand: the pin a result must carry, hashed here from the vendored files on disk."""
        return {"commit": ORACLE["kit_commit"],
                "files": {name: sha((VENDOR / name.split("/")[1]).read_bytes()) for name in KIT_NAMES}}

    def ok(self, report, pins="caller", kit_reader=None):
        """By hand: the whole result for a report the kit reader gave. The witness state is the oracle's own."""
        return {"ok": True, "report": report, "witness_state": report["authenticity"], "pins": pins,
                "kit_reader": kit_reader or self.kit_reader()}

    def assert_report(self, result, report, pins="caller"):
        self.assertEqual(result, self.ok(report, pins))

    def copy_package(self, name):
        parent = os.path.join(self.tmp, name)
        shutil.copytree(PACKAGE, os.path.join(parent, "telos_receipt"), ignore=shutil.ignore_patterns("__pycache__"))
        return parent

    def calls(self, parent, **spec):
        out = self.probe(dict({"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / "witnessed")] * 2}, **spec),
                         parent)
        self.assertNotIn("import_raised", out)
        return [(call["dir"], call["bytes"], call["reference"]) for call in out["calls"]]

    def script(self, *args, env=None):
        if not SCRIPT.is_file():
            self.fail("tools/vendor_kit_reader.py is missing")
        done = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, text=True,
                              env=env or {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}, cwd=self.tmp,
                              timeout=120, check=False)
        return done.returncode, done.stdout, done.stderr

    def export(self, name="kit"):
        """A kit export holding the three reader files as this package vendors them."""
        kit = os.path.join(self.tmp, name)
        os.makedirs(os.path.join(kit, "h0a"))
        for f in ("receipt.py", "witness.py", "reading.py"):
            shutil.copyfile(VENDOR / f, os.path.join(kit, "h0a", f))
        return kit

    def probe(self, spec, package_parent=ROOT):
        """Run PROBE in a fresh interpreter and return what it printed."""
        spec = dict(spec, path=[str(package_parent)] + spec.get("path", []))
        env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": self.tmp, "HOME": self.tmp}
        done = subprocess.run([sys.executable, "-B", "-c", PROBE, json.dumps(spec)], capture_output=True, text=True,
                              env=env, cwd=self.tmp, timeout=120, check=False)
        self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
        return json.loads(done.stdout)


# Runs in a fresh interpreter. Prints one JSON object: what was loaded after each step and what each call answered.
PROBE = r'''
import json, sys
spec = json.loads(sys.argv[1])
sys.path[:0] = spec["path"]
for name in spec.get("preimport", []):
    __import__(name)
out = {}
if spec.get("no_cryptography"):
    import builtins
    _real_import = builtins.__import__

    def _no_cryptography(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ModuleNotFoundError("No module named 'cryptography'", name="cryptography")
        return _real_import(name, *args, **kwargs)
    builtins.__import__ = _no_cryptography
opens = {}
if spec.get("count_opens"):  # how often each vendored reader file is opened, by anyone, in this process
    import builtins, os
    _open = builtins.open

    def counting(file, *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)) and "_kit_vendor" in os.fsdecode(file):
            name = os.path.basename(os.fsdecode(file))
            opens[name] = opens.get(name, 0) + 1
        return _open(file, *args, **kwargs)
    builtins.open = counting
planted, touched = {}, []
if spec.get("plant"):
    import types

    def decoy(name):
        module = types.ModuleType(name)
        def missing(attribute, name=name):  # any use of the decoy asks it for a name it does not hold
            if not attribute.startswith("__"):  # (the interpreter's own questions aside)
                touched.append([name, attribute])
            raise AttributeError(attribute)
        module.__getattr__ = missing
        return module
    for name in ("h0a", "h0a.receipt", "h0a.witness", "h0a.reading"):
        planted[name] = sys.modules[name] = decoy(name)
    planted["h0a"].__path__ = []
    for name in ("receipt", "witness", "reading"):
        setattr(planted["h0a"], name, planted["h0a." + name])
    held = {name: sorted(vars(module)) for name, module in planted.items()}

def planted_state():
    return {"same_objects": all(sys.modules.get(name) is module for name, module in planted.items()),
            "same_names": all(sorted(vars(module)) == held[name] for name, module in planted.items()),
            "touched": list(touched), "h0a_modules": sorted(n for n in sys.modules if n.split(".")[0] == "h0a")}

def state():
    names = list(sys.modules)
    return {"record": "telos_receipt.record" in names,
            "h0a": sorted(n for n in names if n == "h0a" or n.startswith("h0a.")),
            "cryptography": "cryptography" in names,
            "vendored": sorted(n for n in names if "_kit_vendor" in (getattr(sys.modules[n], "__file__", None) or "")
                               or "_kit_vendor" in n),
            "bare": sorted(n for n in names if n in ("receipt", "witness", "reading"))}

def h0a_importable():
    try:
        import h0a  # noqa: F401
    except ImportError:
        return False
    return True

def attempt(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except BaseException as e:
        return {"raised": [type(e).__name__, str(e)]}

def raw(directory, name):
    try:
        with open(directory + "/" + name, "rb") as stream:
            return stream.read()
    except FileNotFoundError:
        return None

import telos_receipt
out["after_package"] = dict(state(), attribute=hasattr(telos_receipt, "record"))
if "version" in spec:
    sys.version_info = tuple(spec["version"])
before = list(sys.path)
try:
    import telos_receipt.record as record
except BaseException as e:
    out["import_raised"] = [type(e).__name__, str(e)]
    built = telos_receipt.build_receipt("probe", {"a": 1}, "probe-agent")
    out["after_refusal"] = dict(state(), base_verifies=telos_receipt.verify_receipt(built)["match"])
    print(json.dumps(out))
    sys.exit(0)
out["after_record"] = dict(state(), sys_path_same=sys.path == before)
out["reader_loaded"] = [bool(getattr(record, "_LOADED", None))]
if spec.get("probe_h0a", True):
    out["after_record"]["h0a_importable"] = h0a_importable()
if "seam" in spec:  # reader bytes handed to the private loader together with pins: their own, or the stale ones
    import hashlib, os
    sources, seam_pins = {}, {}
    for name in ("reading", "witness", "receipt"):
        with open(os.path.join(os.path.dirname(record.__file__), "_kit_vendor", name + ".py"), "rb") as stream:
            data = stream.read()
        stale = hashlib.sha256(data).hexdigest()
        data += spec["seam"]["edits"].get(name + ".py", "").encode("ascii")
        sources[name] = data
        seam_pins["h0a/" + name + ".py"] = hashlib.sha256(data).hexdigest() if spec["seam"]["matching"] else stale

    def seamed():
        kit = record._kit(_reader=(sources, seam_pins))
        return kit if isinstance(kit, str) else "loaded"
    out["seam"] = attempt(seamed)
if "pollute" in spec:  # a stand-in loader that loads the reader as the module does and then leaves one mark
    import types
    real_load = record._load

    def polluting(*args, **kwargs):
        kit = real_load(*args, **kwargs)
        kind = spec["pollute"]
        if kind == "h0a":
            sys.modules["h0a"] = kit.receipt
        elif kind == "h0a_child":
            sys.modules["h0a.witness"] = kit.witness
        elif kind == "h0a_prefix":
            sys.modules["h0a_reader"] = types.ModuleType("h0a_reader")
        elif kind == "private_under_another_name":
            sys.modules["innocent_name"] = kit.reading
        elif kind == "private_under_its_own_name":
            sys.modules[kit.witness.__name__] = kit.witness
        elif kind == "replaced":
            sys.modules["sk_s_bystander"] = types.ModuleType("sk_s_bystander")
        elif kind == "removed":  # the bystander is this probe's own module, nobody's dependency
            del sys.modules["sk_s_bystander"]
        elif kind == "path_appended":
            sys.path.append(spec["path"][0])
        elif kind == "path_rebound":
            sys.path = list(sys.path)
        return kit
    record._load = polluting
if spec.get("hygiene"):
    import types
    sys.modules["sk_s_bystander"] = types.ModuleType("sk_s_bystander")
snapshot, path_object, path_before = dict(sys.modules), sys.path, list(sys.path)

def hygiene():
    loaded = getattr(record, "_LOADED", None) or [None]
    private = [] if loaded[0] is None or isinstance(loaded[0], str) else list(loaded[0])
    now = dict(sys.modules)
    return {"reader_loaded": len(private),
            "replaced_or_removed": sorted(n for n, module in snapshot.items() if now.get(n) is not module),
            "h0a_added": sorted(n for n in now if n not in snapshot and n.startswith("h0a")),
            "private_entered": sorted(n for n, module in now.items() if any(module is p for p in private)
                                      or "_kit_vendor" in n or "_pinned_" in n
                                      or "_kit_vendor" in (getattr(module, "__file__", None) or "")),
            "path_same_object": sys.path is path_object, "path_same_contents": list(sys.path) == path_before,
            "cryptography_added": "cryptography" in now and "cryptography" not in snapshot}

pins = {"pins": record.Pins(**spec["pins"])} if "pins" in spec else {}
out["calls"] = []
for directory in spec.get("check", []):
    by_dir = attempt(record.check_record_dir, directory, **pins)
    by_bytes = attempt(record.check_record, raw(directory, "receipt.json"), raw(directory, "witness.json"),
                       raw(directory, "reading.json"), **pins)
    reference = attempt(record.build_reference, raw(directory, "receipt.json"), raw(directory, "reading.json"),
                        agent_id="probe-agent")
    out["calls"].append(dict(state(), dir=by_dir, bytes=by_bytes, reference=reference,
                             sys_path_same=sys.path == before))
    out["reader_loaded"].append(bool(getattr(record, "_LOADED", None)))
    out.setdefault("opens", []).append(dict(opens))
    if spec.get("flip") and len(out["calls"]) == 1:  # one byte of a file on disk changes after the first call
        import io
        with io.open(spec["flip"], "rb") as stream:
            data = bytearray(stream.read())
        data[4] ^= 0x01
        with io.open(spec["flip"], "wb") as stream:
            stream.write(bytes(data))
if planted:
    out["planted"] = planted_state()
if spec.get("hygiene"):
    out["hygiene"] = hygiene()
print(json.dumps(out))
'''


# Runs in a fresh interpreter (A6.1). Takes steps in order and prints, for each "call" step, what the one public
# function answered, which vendored files were opened since the call before, and whether anything is latched.
#   ["fault", file, "open" | "read"]   from now on opening that vendored file, or reading it once open, is an OSError
#   ["clear"]                          no fault from now on
#   ["flip", file] / ["remove", file]  one byte of the file changes on disk / the file is unlinked: copies only
#   ["restore", file]                  the file is on disk again with the bytes it had
#   ["call"]                           the public function named in the spec, once
S15_PROBE = r'''
import builtins, json, os, sys
spec = json.loads(sys.argv[1])
sys.path[:0] = spec["path"]
import telos_receipt.record as record
vendor = os.path.join(os.path.dirname(os.path.abspath(record.__file__)), "_kit_vendor")
real_open = builtins.open
faults, opens, held, out = {}, {}, {}, []
fresh = not record._LOADED and not record._OUTSIDE  # nothing loaded, nothing latched, before the first step


class Unreadable:
    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stream.close()
        return False

    def read(self, *args):
        raise OSError(5, "Input/output error")


def faulty(file, *args, **kwargs):
    if isinstance(file, (str, bytes, os.PathLike)):
        path = os.path.abspath(os.fsdecode(file))
        if os.path.dirname(path) == vendor:  # this interpreter's vendored reader files, and nothing else
            name = os.path.basename(path)
            opens[name] = opens.get(name, 0) + 1
            if faults.get(name) == "open":
                raise OSError(5, "Input/output error", path)
            if faults.get(name) == "read":
                return Unreadable(real_open(file, *args, **kwargs))
    return real_open(file, *args, **kwargs)


builtins.open = faulty


def raw(name):
    try:
        with real_open(os.path.join(spec["record"], name), "rb") as stream:
            return stream.read()
    except FileNotFoundError:
        return None


def call():
    pins = record.Pins(**spec["pins"])
    if spec["function"] == "check_record_dir":
        return record.check_record_dir(spec["record"], pins=pins)
    if spec["function"] == "check_record":
        return record.check_record(raw("receipt.json"), raw("witness.json"), raw("reading.json"), pins=pins)
    return record.build_reference(raw("receipt.json"), raw("reading.json"), agent_id="probe-agent")


def on_disk(name):
    path = os.path.join(vendor, name)
    if not spec.get("copy") or not path.startswith(os.path.join(spec["copy"], "")):
        raise SystemExit("this probe changes vendored files in a temporary copy only")
    return path


for step in spec["steps"]:
    if step[0] == "fault":
        faults[step[1]] = step[2]
    elif step[0] == "clear":
        faults.clear()
    elif step[0] in ("flip", "remove"):
        with real_open(on_disk(step[1]), "rb") as stream:
            held[step[1]] = stream.read()
        if step[0] == "remove":
            os.unlink(on_disk(step[1]))
        else:
            data = bytearray(held[step[1]])
            data[4] ^= 0x01
            with real_open(on_disk(step[1]), "wb") as stream:
                stream.write(bytes(data))
    elif step[0] == "restore":
        with real_open(on_disk(step[1]), "wb") as stream:
            stream.write(held[step[1]])
    else:
        try:
            answer = call()
        except BaseException as e:
            answer = {"raised": [type(e).__name__, str(e)]}
        out.append({"answer": answer, "opened": dict(opens), "latched": bool(record._LOADED)})
        opens.clear()
print(json.dumps({"fresh": fresh, "calls": out}))
'''


class S1SameAnswerAsTheKitReader(Case):
    def test_s1_both_functions_return_the_kit_readers_report_under_the_canary_pins(self):
        states = set()
        for name, kit in ORACLE["fixtures"].items():
            with self.subTest(name):
                by_dir, by_bytes = self.both(fixture(name), name, pins=self.canary())
                self.assert_report(by_dir, kit["canary_pins"])
                self.assert_report(by_bytes, kit["canary_pins"])
                states.add((by_dir["report"]["authenticity"], by_dir["report"].get("witness_reason")))
        # the fixtures are one WITNESSED record and two NOT_WITNESSED ones, so both verdicts were compared
        self.assertEqual(states, {("WITNESSED", None), ("NOT_WITNESSED", "WITNESS_NOT_REQUESTED"),
                                  ("NOT_WITNESSED", "WITNESS_REFUSED")})

    def test_s1_without_pins_both_functions_return_the_line_the_kit_reader_command_printed(self):
        for name, kit in ORACLE["fixtures"].items():
            with self.subTest(name):
                by_dir, by_bytes = self.both(fixture(name), name)
                self.assert_report(by_dir, kit["pinned_key_cli"], "default")
                self.assert_report(by_bytes, kit["pinned_key_cli"], "default")
        # beside it: the canary row is a valid row only for the canary key, never for the pinned Witness key
        witnessed = ORACLE["fixtures"]["witnessed"]
        self.assertEqual((witnessed["canary_pins"]["authenticity"], witnessed["pinned_key_cli"]["authenticity"],
                          witnessed["pinned_key_cli"]["witness_reason"]),
                         ("WITNESSED", "NOT_WITNESSED", "WITNESS_FILE_INVALID"))

    def test_s1_without_pins_the_reader_is_given_the_key_the_kit_pins_and_with_pins_the_callers(self):
        # No fixture can be signed by the real Witness key, so no test here reads WITNESSED under `pins=None`. This
        # one watches the single call into the vendored reader instead and compares the key it is handed with the
        # PINS line of the vendored witness.py, read as text.
        record = self.record()
        line = re.search(rb"^PINS = Pins\(public_key='([0-9a-f]{64})',\s+fingerprint='([0-9a-f]{64})',\s+"
                         rb"anchor='([0-9a-f]{64})'\)$", (VENDOR / "witness.py").read_bytes(), re.MULTILINE)
        if line is None:
            self.fail("the vendored witness.py has no PINS line of the known form")
        kit_pins = tuple(value.decode("ascii") for value in line.groups())
        files = fixture("witnessed")
        self.answer(record.check_record_dir, str(FIXTURES / "witnessed"))  # loads the reader
        reader = record._kit().receipt
        handed, real = [], reader.check_record

        def watched(path, *, pins):
            handed.append(tuple(pins))
            return real(path, pins=pins)
        with mock.patch.object(reader, "check_record", watched):
            self.answer(record.check_record_dir, str(FIXTURES / "witnessed"))
            self.answer(record.check_record, *(files[name] for name in NAMES))
            self.answer(record.check_record_dir, str(FIXTURES / "witnessed"), pins=self.canary())
            self.answer(record.check_record, *(files[name] for name in NAMES), pins=self.canary())
        canary = tuple(ORACLE["canary_pins"][name] for name in ("public_key", "fingerprint", "anchor"))
        self.assertNotEqual(kit_pins, canary)
        self.assertEqual(handed, [kit_pins, kit_pins, canary, canary])

    def test_s1_the_result_names_the_pinned_kit_reader_and_nothing_else(self):
        record = self.record()
        result = self.answer(record.check_record_dir, str(FIXTURES / "witnessed"), pins=self.canary())
        self.assertEqual(sorted(result), ["kit_reader", "ok", "pins", "report", "witness_state"])
        self.assertIs(result["ok"], True)
        self.assertEqual(result["kit_reader"], self.kit_reader())
        self.assertRegex(result["kit_reader"]["commit"], r"\A[0-9a-f]{40}\Z")
        self.assertEqual((record.KIT_COMMIT, record.KIT_FILES), (result["kit_reader"]["commit"],
                                                                 result["kit_reader"]["files"]))
        result["kit_reader"]["files"].clear()  # a caller's change to one result reaches no later result
        self.assertEqual(self.answer(record.check_record_dir, str(FIXTURES / "witnessed"))["kit_reader"],
                         self.kit_reader())


class S2OneChangedByte(Case):
    def test_s2_a_changed_directory_reads_as_the_kit_reader_read_it_beside_the_untouched_one(self):
        self.assertEqual(sorted(v["name"] for v in ORACLE["variants"]),
                         ["reading_byte", "receipt_byte", "receipt_byte_no_row", "row_byte", "row_of_another_record",
                          "signature_byte"])
        for variant in ORACLE["variants"]:
            with self.subTest(variant["name"]):
                base = ORACLE["fixtures"][variant["base"]]
                by_dir, by_bytes = self.both(fixture(variant["base"]), "base-" + variant["name"], pins=self.canary())
                self.assert_report(by_dir, base["canary_pins"])
                self.assert_report(by_bytes, base["canary_pins"])
                files = changed(variant)
                by_dir, by_bytes = self.both(files, variant["name"], pins=self.canary())
                self.assert_report(by_dir, variant["canary_pins"])
                self.assert_report(by_bytes, variant["canary_pins"])
                self.assertNotEqual(variant["canary_pins"], base["canary_pins"])
                by_dir, by_bytes = self.both(files, "pinned-" + variant["name"])
                self.assert_report(by_dir, variant["pinned_key_cli"], "default")
                self.assert_report(by_bytes, variant["pinned_key_cli"], "default")

    def test_s2_no_single_byte_change_of_the_witnessed_record_still_reads_witnessed_with_its_reading(self):
        base = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        self.assertEqual((base["authenticity"], base["reading"]["state"]), ("WITNESSED", "READING_WITNESSED"))
        for name in ("receipt_byte", "row_byte", "signature_byte", "reading_byte"):
            with self.subTest(name):
                variant = next(v for v in ORACLE["variants"] if v["name"] == name)
                self.assertEqual(len(variant["edits"]), 1)
                by_dir, _ = self.both(changed(variant), name, pins=self.canary())
                report = by_dir["report"]
                self.assertNotEqual((report["authenticity"], report["reading"]["state"]),
                                    ("WITNESSED", "READING_WITNESSED"))


class C3Refusals(Case):
    def test_c3_an_unreadable_or_missing_receipt_is_refused_beside_a_readable_one(self):
        record = self.record()
        good = self.directory(fixture("not_witnessed"), "good")
        self.assert_report(self.answer(record.check_record_dir, good, pins=self.canary()),
                           ORACLE["fixtures"]["not_witnessed"]["canary_pins"])
        self.assert_report(self.answer(record.check_record_dir, Path(good), pins=self.canary()),
                           ORACLE["fixtures"]["not_witnessed"]["canary_pins"])
        empty = self.directory({}, "empty")
        holds_a_directory = self.directory({}, "holds-a-directory")
        os.mkdir(os.path.join(holds_a_directory, "receipt.json"))
        for label, path in [("missing directory", os.path.join(self.tmp, "absent")), ("no receipt", empty),
                            ("receipt is a directory", holds_a_directory),
                            ("a file, not a directory", os.path.join(good, "receipt.json"))]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.check_record_dir, path, pins=self.canary()), UNREADABLE)

    def test_c3_a_path_that_is_no_path_is_refused_beside_a_real_one_in_three_shapes(self):
        record = self.record()
        good = self.directory(fixture("not_witnessed"), "good")
        want = ORACLE["fixtures"]["not_witnessed"]["canary_pins"]
        for label, path in [("str", good), ("bytes", os.fsencode(good)), ("Path", Path(good))]:
            with self.subTest(label):
                self.assert_report(self.answer(record.check_record_dir, path, pins=self.canary()), want)
        for label, path in [("None", None), ("int", 7), ("list", [good]), ("dict", {})]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.check_record_dir, path), INVALID_ARGUMENT)

    def test_c3_a_path_no_file_system_call_takes_is_refused_beside_the_same_path_without_the_fault(self):
        record = self.record()
        good = self.directory(fixture("not_witnessed"), "good")
        self.assertIs(self.answer(record.check_record_dir, good)["ok"], True)
        for label, path in [("a NUL", good + "\0"), ("a NUL in bytes", os.fsencode(good) + b"\0")]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.check_record_dir, path), UNREADABLE)
        # a str that cannot be encoded at all (a lone surrogate) is no argument, beside one that names raw bytes
        self.assertEqual(self.answer(record.check_record_dir, good + "\ud800"), INVALID_ARGUMENT)
        self.assertEqual(self.answer(record.check_record_dir, good + "\udcff"), UNREADABLE)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() != 0, "needs a user that file modes apply to")
    def test_c3_a_receipt_this_user_may_not_open_is_refused_beside_the_same_file_made_readable(self):
        record = self.record()
        home = self.directory(fixture("not_witnessed"), "sealed")
        receipt = os.path.join(home, "receipt.json")
        os.chmod(receipt, 0)
        self.assertEqual(self.answer(record.check_record_dir, home, pins=self.canary()), UNREADABLE)
        os.chmod(receipt, 0o600)
        self.assert_report(self.answer(record.check_record_dir, home, pins=self.canary()),
                           ORACLE["fixtures"]["not_witnessed"]["canary_pins"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "this platform has no named pipes")
    def test_c3_a_receipt_that_is_a_named_pipe_is_refused_and_never_waited_on_beside_a_regular_file(self):
        record = self.record()
        good = self.directory(fixture("not_witnessed"), "good")
        self.assertIs(self.answer(record.check_record_dir, good)["ok"], True)
        linked = self.directory({}, "linked")  # a link to a regular file is read, as the kit reader reads it
        os.symlink(os.path.join(good, "receipt.json"), os.path.join(linked, "receipt.json"))
        self.assertEqual(self.answer(record.check_record_dir, linked)["report"]["structure"], "VALID")
        piped = self.directory({}, "piped")
        pipe = os.path.join(piped, "receipt.json")
        os.mkfifo(pipe)
        stop = threading.Event()

        def writer():  # a reader that does open the pipe gets these bytes and returns, instead of waiting for ever
            while not stop.is_set():
                try:
                    fd = os.open(pipe, os.O_WRONLY | os.O_NONBLOCK)
                except OSError:
                    time.sleep(0.01)
                    continue
                with os.fdopen(fd, "wb") as stream:
                    stream.write(b"{}")
                return
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        try:
            result = self.answer(record.check_record_dir, piped)
        finally:
            stop.set()
            thread.join(10)
        self.assertEqual(result, UNREADABLE)

    def test_c3_input_that_is_not_bytes_is_refused_beside_the_same_record_as_bytes(self):
        record = self.record()
        files = fixture("witnessed")
        receipt, row, reading = (files[name] for name in NAMES)
        self.assert_report(self.answer(record.check_record, receipt, row, reading, pins=self.canary()),
                           ORACLE["fixtures"]["witnessed"]["canary_pins"])
        for label, args in [("receipt None", (None, row, reading)), ("receipt str", (receipt.decode(), row, reading)),
                            ("receipt bytearray", (bytearray(receipt), row, reading)),
                            ("row str", (receipt, row.decode(), reading)), ("row list", (receipt, [row], reading)),
                            ("reading str", (receipt, row, reading.decode())), ("reading int", (receipt, row, 7))]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.check_record, *args, pins=self.canary()), INVALID_ARGUMENT)

    def test_c3_bytes_that_are_no_receipt_get_the_readers_report_and_never_an_exception(self):
        self.record()
        for label, raw in [("empty", b""), ("not json", b"not json"), ("an array", b"[1,2]"), ("deep", b"[" * 100000),
                           ("not utf-8", b"\xff\xfe"), ("another schema", b'{"schema":2}')]:
            with self.subTest(label):
                by_dir, by_bytes = self.both({"receipt.json": raw}, "bad-" + label.replace(" ", "-"))
                self.assertEqual(by_dir, by_bytes)
                self.assertIs(by_bytes["ok"], True)
                self.assertIn(by_bytes["report"]["structure"], ("INVALID", "UNSUPPORTED"))
                self.assertEqual((by_bytes["report"]["authenticity"], by_bytes["report"]["witness_reason"]),
                                 ("NOT_WITNESSED", "WITNESS_NOT_REQUESTED"))

    def test_c3_pins_that_are_no_pins_are_refused_beside_the_canary_pins_in_two_shapes(self):
        self.record()
        files = fixture("witnessed")
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        for label, pins in [("record.Pins", self.canary()), ("any object with the three names",
                                                            types.SimpleNamespace(**ORACLE["canary_pins"]))]:
            with self.subTest(label):
                by_dir, by_bytes = self.both(files, "pins-" + label.replace(" ", "-"), pins=pins)
                self.assert_report(by_dir, want)
                self.assert_report(by_bytes, want)
        for label, pins in [("str", "pins"), ("tuple", tuple(ORACLE["canary_pins"].values())), ("dict",
                            dict(ORACLE["canary_pins"])), ("a name missing", types.SimpleNamespace(public_key="a",
                            fingerprint="b")), ("a value that is not str", types.SimpleNamespace(public_key="a",
                            fingerprint="b", anchor=7))]:
            with self.subTest(label):
                by_dir, by_bytes = self.both(files, "nopins-" + label.replace(" ", "-"), pins=pins)
                self.assertEqual((by_dir, by_bytes), (PINS_INVALID, PINS_INVALID))

    def test_c3_pins_whose_values_are_str_subclasses_are_refused_beside_the_same_values_as_plain_str(self):
        record = self.record()

        class Text(str):
            """A str subclass: equal to the plain value, and not a value the reader is handed."""

        files, canary = fixture("witnessed"), ORACLE["canary_pins"]
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        for shape in (record.Pins, types.SimpleNamespace):
            by_dir, by_bytes = self.both(files, "plain-" + shape.__name__, pins=shape(**canary))
            self.assert_report(by_dir, want)
            self.assert_report(by_bytes, want)
            for name in list(canary) + ["all three"]:
                with self.subTest(shape=shape.__name__, subclassed=name):
                    values = {key: Text(value) if name in (key, "all three") else value
                              for key, value in canary.items()}
                    self.assertEqual(values, canary)  # the same words; only their type differs
                    by_dir, by_bytes = self.both(files, f"sub-{shape.__name__}-{name.replace(' ', '-')}",
                                                 pins=shape(**values))
                    self.assertEqual((by_dir, by_bytes), (PINS_INVALID, PINS_INVALID))


class S3PinnedReader(Case):
    def setUp(self):
        super().setUp()
        self.record()  # nothing to pin, copy or vendor without the module: a failed guarantee, not a broken test

    def test_s3_one_changed_byte_in_any_vendored_file_refuses_every_call_beside_the_intact_files(self):
        intact = self.calls(self.copy_package("intact"))
        want = self.ok(ORACLE["fixtures"]["witnessed"]["canary_pins"])
        for by_dir, by_bytes, reference in intact:
            self.assertEqual((by_dir, by_bytes), (want, want))
            self.assertEqual(reference["kind"], "kit_record_reference")
        for name in ("receipt.py", "witness.py", "reading.py"):
            with self.subTest(name):
                parent = self.copy_package("changed-" + name)
                path = os.path.join(parent, "telos_receipt", "_kit_vendor", name)
                data = bytearray(Path(path).read_bytes())
                self.assertEqual(bytes(data[:3]), b'"""')  # byte 4 is inside the file's opening docstring
                data[4] ^= 0x01
                Path(path).write_bytes(bytes(data))
                self.assertEqual(self.calls(parent), [(MODIFIED, MODIFIED, MODIFIED)] * 2)

    def test_s3_a_vendored_file_that_is_gone_is_reader_unavailable_until_it_is_back_beside_the_intact_files(self):
        # A6.1: a file that cannot be opened was not read, so nothing was measured: `reader_unavailable`, not latched
        intact = self.calls(self.copy_package("intact"))
        self.assertIs(intact[0][0]["ok"], True)
        for name in ("receipt.py", "witness.py", "reading.py"):
            with self.subTest(name):
                parent = self.copy_package("gone-" + name)
                path = os.path.join(parent, "telos_receipt", "_kit_vendor", name)
                held = Path(path).read_bytes()
                os.unlink(path)
                self.assertEqual(self.calls(parent), [(UNAVAILABLE, UNAVAILABLE, UNAVAILABLE)] * 2)
                Path(path).write_bytes(held)  # back as it was: a process that starts now answers as the intact one
                again = self.calls(parent)
                self.assertEqual([(by_dir, by_bytes) for by_dir, by_bytes, _ in again],
                                 [(by_dir, by_bytes) for by_dir, by_bytes, _ in intact])
                self.assertEqual([reference["payload"] for _, _, reference in again],
                                 [reference["payload"] for _, _, reference in intact])

    def test_s3_the_pin_in_the_source_is_the_digest_of_each_vendored_file(self):
        record = self.record()
        self.assertEqual(record.KIT_FILES, self.kit_reader()["files"])
        self.assertEqual(record.KIT_COMMIT, ORACLE["kit_commit"])  # the fixtures' oracle is this pin's reader
        self.assertEqual(sorted(p.name for p in VENDOR.iterdir() if p.name != "__pycache__"),
                         ["__init__.py", "reading.py", "receipt.py", "witness.py"])

    # --- the vendoring script ---

    def unpinned_package(self, name="unpinned"):
        """A copy of the package with the three vendored files removed and every pin value zeroed."""
        package = os.path.join(self.copy_package(name), "telos_receipt")
        for f in ("receipt.py", "witness.py", "reading.py"):
            os.unlink(os.path.join(package, "_kit_vendor", f))
        path = os.path.join(package, "record.py")
        text = Path(path).read_text(encoding="utf-8")
        start, end = text.index(PIN_BEGIN), text.index(PIN_END)
        block = re.sub(r"[0-9a-f]{40,64}", lambda found: "0" * len(found.group()), text[start:end])
        self.assertNotEqual(block, text[start:end])
        Path(path).write_text(text[:start] + block + text[end:], encoding="utf-8")
        return package

    def assert_package_is_this_one(self, package):
        for f in ("record.py", "_kit_vendor/receipt.py", "_kit_vendor/witness.py", "_kit_vendor/reading.py"):
            self.assertEqual(Path(package, f).read_bytes(), (PACKAGE / f).read_bytes(), f)

    def test_s3_the_vendoring_script_reproduces_the_three_files_and_the_pin_from_a_kit_export(self):
        commit = ORACLE["kit_commit"]
        package = self.unpinned_package()
        code, out, err = self.script(self.export(), commit, "--package-dir", package, "--check")
        self.assertEqual(code, 1, out + err)  # --check on the unpinned copy: something would change, nothing is written
        self.assertFalse(os.path.exists(os.path.join(package, "_kit_vendor", "receipt.py")))
        code, out, err = self.script(self.export("kit-2"), commit, "--package-dir", package)
        self.assertEqual(code, 0, out + err)
        self.assert_package_is_this_one(package)
        printed = json.loads(out)
        self.assertEqual((printed["commit"], printed["files"], printed["source"]),
                         (commit, self.kit_reader()["files"], "export"))
        code, out, err = self.script(self.export("kit-3"), commit, "--package-dir", package, "--check")
        self.assertEqual((code, json.loads(out)["changed"]), (0, []), err)

    def test_s3_the_vendoring_script_names_a_kit_file_that_differs_beside_the_same_export_unchanged(self):
        commit = ORACLE["kit_commit"]
        code, out, err = self.script(self.export(), commit, "--package-dir", str(PACKAGE), "--check")
        self.assertEqual((code, json.loads(out)["changed"]), (0, []), err)
        kit = self.export("kit-changed")
        with open(os.path.join(kit, "h0a", "witness.py"), "ab") as stream:
            stream.write(b"\n")
        code, out, err = self.script(kit, commit, "--package-dir", str(PACKAGE), "--check")
        self.assertEqual((code, json.loads(out)["changed"]), (1, ["_kit_vendor/witness.py", "record.py"]), err)

    def test_s3_the_vendoring_script_refuses_a_commit_name_that_is_not_one_beside_a_real_one(self):
        package = self.unpinned_package()
        code, out, err = self.script(self.export(), ORACLE["kit_commit"], "--package-dir", package, "--check")
        self.assertEqual(code, 1, out + err)
        for bad in ("64dfcef", "main", "g" * 40, ORACLE["kit_commit"].upper()):
            with self.subTest(bad):
                code, out, err = self.script(self.export("kit-" + bad[:8]), bad, "--package-dir", package)
                self.assertEqual(code, 2, out + err)
                self.assertFalse(os.path.exists(os.path.join(package, "_kit_vendor", "receipt.py")))

    def test_s3_the_vendoring_script_refuses_what_it_cannot_do_and_writes_nothing_beside_the_same_run_whole(self):
        commit = ORACLE["kit_commit"]
        whole = self.unpinned_package("whole")
        code, out, err = self.script(self.export("kit-whole"), commit, "--package-dir", whole)
        self.assertEqual(code, 0, out + err)
        self.assert_package_is_this_one(whole)

        def refused(label, kit, package, wrote="_kit_vendor/receipt.py"):
            with self.subTest(label):
                code, out, err = self.script(kit, commit, "--package-dir", package)
                self.assertEqual((code, out), (2, ""), err)
                self.assertTrue(err.startswith("vendor_kit_reader.py: "), err)
                self.assertFalse(os.path.exists(os.path.join(package, wrote)))
        short = self.export("kit-short")
        os.unlink(os.path.join(short, "h0a", "witness.py"))
        refused("a kit file that is not there", short, self.unpinned_package("for-short"))
        empty = os.path.join(self.tmp, "no-package")
        os.mkdir(empty)
        refused("a package directory without record.py", self.export("kit-empty"), empty)
        for label, change in [("no end marker", lambda text: text.replace(PIN_END, "# gone")),
                              ("two pin blocks", lambda text: text + "\n" + PIN_BEGIN + "\n" + PIN_END + "\n")]:
            package = self.unpinned_package("for-" + label.replace(" ", "-"))
            path = os.path.join(package, "record.py")
            before = change(Path(path).read_text(encoding="utf-8"))
            Path(path).write_text(before, encoding="utf-8")
            refused(label, self.export("kit-" + label.replace(" ", "-")), package)
            self.assertEqual(Path(path).read_text(encoding="utf-8"), before)

    @unittest.skipUnless(shutil.which("git"), "git is not on PATH")
    def test_s3_from_a_git_checkout_the_script_takes_the_named_commits_bytes_not_the_working_trees(self):
        kit = self.export("kit-git")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp, "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_CONFIG_SYSTEM": os.devnull, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "PYTHONDONTWRITEBYTECODE": "1"}

        def git(*args):
            done = subprocess.run(["git", "-C", kit, *args], capture_output=True, text=True, env=env, timeout=120,
                                  check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout.strip()
        git("init", "-q")
        git("add", "h0a")
        git("commit", "-q", "-m", "reader")
        commit = git("rev-parse", "HEAD")
        with open(os.path.join(kit, "h0a", "receipt.py"), "ab") as stream:  # a dirty working tree after the commit
            stream.write(b"# edited after the commit\n")
        package = self.unpinned_package()
        code, out, err = self.script(kit, commit, "--package-dir", package, env=env)
        self.assertEqual(code, 0, out + err)
        printed = json.loads(out)
        self.assertEqual((printed["commit"], printed["files"], printed["source"]),
                         (commit, self.kit_reader()["files"], "git"))
        for f in ("receipt.py", "witness.py", "reading.py"):
            self.assertEqual(Path(package, "_kit_vendor", f).read_bytes(), (VENDOR / f).read_bytes(), f)
        # beside it, each refused and writing nothing: a sha this checkout does not hold, the sha of a tag object
        # (it names the commit but is not the commit), and a later commit that holds no h0a/reading.py
        git("tag", "-a", "named", "-m", "a tag object", commit)
        tag = git("rev-parse", "named")
        self.assertNotEqual(tag, commit)
        git("checkout", "-q", "--", "h0a/receipt.py")
        git("rm", "-q", "h0a/reading.py")
        git("commit", "-q", "-m", "without the reading module")
        later = git("rev-parse", "HEAD")
        for label, sha in [("not held", "0" * 39 + "1"), ("a tag object", tag), ("no reading.py", later)]:
            with self.subTest(label):
                other = self.unpinned_package("unpinned-" + label.replace(" ", "-"))
                code, out, err = self.script(kit, sha, "--package-dir", other, env=env)
                self.assertEqual((code, out), (2, ""), err)
                self.assertFalse(os.path.exists(os.path.join(other, "_kit_vendor", "receipt.py")))

    @unittest.skipUnless(os.environ.get("TELOS_KIT_CHECKOUT"), "TELOS_KIT_CHECKOUT names no kit checkout")
    def test_s3_the_vendored_files_and_the_pin_are_what_the_script_makes_from_the_named_kit_checkout(self):
        code, out, err = self.script(os.environ["TELOS_KIT_CHECKOUT"], ORACLE["kit_commit"], "--package-dir",
                                     str(PACKAGE), "--check", env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual((code, json.loads(out)["changed"], json.loads(out)["files"]),
                         (0, [], self.kit_reader()["files"]), err)


class S4ImportHygiene(Case):
    def test_s4_importing_the_package_loads_no_record_h0a_or_cryptography_module(self):
        self.record()
        out = self.probe({})
        self.assertEqual(out["after_package"], {"record": False, "h0a": [], "cryptography": False, "vendored": [],
                                                "bare": [], "attribute": False})

    def test_s4_importing_record_leaves_sys_path_alone_and_h0a_still_cannot_be_imported(self):
        self.record()
        out = self.probe({})
        self.assertNotIn("import_raised", out)
        self.assertEqual(out["after_record"], {"record": True, "h0a": [], "cryptography": False, "vendored": [],
                                               "bare": [], "sys_path_same": True, "h0a_importable": False})

    def test_s4_cryptography_is_loaded_only_when_a_row_reaches_the_signature_step(self):
        self.record()
        row_byte = self.directory(changed(next(v for v in ORACLE["variants"] if v["name"] == "row_byte")), "row-byte")
        steps = [("not_witnessed", str(FIXTURES / "not_witnessed"), False),  # no witness.json
                 ("refused", str(FIXTURES / "refused"), False),              # witness.json holds a reason, not a row
                 ("row_byte", row_byte, False),                              # a row whose hash fails first
                 ("witnessed", str(FIXTURES / "witnessed"), True)]           # a row that reaches the signature
        out = self.probe({"pins": ORACLE["canary_pins"], "check": [step[1] for step in steps]})
        self.assertNotIn("import_raised", out)
        self.assertIs(out["after_record"]["cryptography"], False)
        for (name, _, loaded), call in zip(steps, out["calls"]):
            with self.subTest(name):
                self.assertIs(call["dir"]["ok"], True)
                self.assertEqual(call["dir"], call["bytes"])
                self.assertIs(call["cryptography"], loaded)
                self.assertEqual((call["h0a"], call["vendored"], call["bare"], call["sys_path_same"]),
                                 ([], [], [], True))
        self.assertEqual(out["calls"][-1]["dir"]["report"]["authenticity"], "WITNESSED")

    def test_s4_an_h0a_package_on_the_path_is_never_the_reader(self):
        self.record()
        decoy = os.path.join(self.tmp, "decoy")
        os.makedirs(os.path.join(decoy, "h0a"))
        Path(decoy, "h0a", "__init__.py").write_bytes(b"")
        for f in ("receipt.py", "reading.py"):
            shutil.copyfile(VENDOR / f, os.path.join(decoy, "h0a", f))
        # the decoy witness module calls everything WITNESSED
        Path(decoy, "h0a", "witness.py").write_bytes((VENDOR / "witness.py").read_bytes() + (
            b"\n\ndef _checked(receipt_raw, witness_raw, pins):\n"
            b"    return {'authenticity': 'WITNESSED', 'reason': None,\n"
            b"            'witness': {'key_fingerprint': 'decoy', 'row': 1, 'timestamp': 'decoy'}}, None\n"))
        spec = {"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / "not_witnessed")], "probe_h0a": False}
        want = self.ok(ORACLE["fixtures"]["not_witnessed"]["canary_pins"])
        for label, path in [("no decoy", []), ("decoy first on the path", [decoy])]:
            with self.subTest(label):
                out = self.probe(dict(spec, path=path))
                self.assertNotIn("import_raised", out)
                call = out["calls"][0]
                self.assertEqual((call["dir"], call["bytes"]), (want, want))
                self.assertEqual(call["h0a"], [])


class Trap(Exception):
    pass


class S5NoNetworkNoProcess(Case):
    def trapped(self):
        """Patches that make every way of opening a socket or starting a process record itself and raise."""
        seen = []

        def trap(name):
            def raiser(*args, **kwargs):
                seen.append(name)
                raise Trap(name)
            return raiser
        targets = [(socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"),
                   (subprocess, "Popen"), (subprocess, "run"), (os, "system"), (os, "posix_spawn"), (os, "fork"),
                   (os, "execv"), (os, "execve")]
        patches = [mock.patch.object(owner, name, trap(owner.__name__ + "." + name)) for owner, name in targets]
        return seen, patches

    def test_s5_both_functions_answer_with_sockets_and_processes_trapped(self):
        record = self.record()
        files = fixture("witnessed")
        home = self.directory(files)
        seen, patches = self.trapped()
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        with self.assertRaises(Trap):  # the traps do fire when something asks
            socket.create_connection(("127.0.0.1", 9))
        with self.assertRaises(Trap):
            subprocess.run(["true"], check=False)
        self.assertEqual(seen, ["socket.create_connection", "subprocess.run"])
        del seen[:]
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        self.assert_report(self.answer(record.check_record_dir, home, pins=self.canary()), want)
        self.assert_report(self.answer(record.check_record, files["receipt.json"], files["witness.json"],
                                       files["reading.json"], pins=self.canary()), want)
        reference = self.answer(record.build_reference, files["receipt.json"], files["reading.json"], agent_id="a")
        self.assertEqual(reference["kind"], "kit_record_reference")
        self.assertEqual(seen, [])

    def spied(self, root, fail_on_read=False):
        """os.open and os.mkdir, recording what is opened or made under root. `modes` is what was on disk, read at the
        moment the reader opened a record file."""
        log = {"made": [], "written": [], "read": [], "modes": []}
        real_open, real_mkdir = os.open, os.mkdir

        def inside(path):
            return os.path.realpath(os.fspath(path)).startswith(os.path.realpath(root) + os.sep)

        def opening(path, flags, mode=0o777, **kwargs):
            if inside(path):
                if flags & (os.O_WRONLY | os.O_RDWR):
                    log["written"].append((os.path.basename(path), bool(flags & os.O_EXCL), mode))
                elif os.path.basename(path) in NAMES:
                    home = os.path.dirname(path)
                    log["read"].append(os.path.basename(path))
                    log["modes"].append((stat.S_IMODE(os.lstat(home).st_mode),
                                         {f: stat.S_IMODE(os.lstat(os.path.join(home, f)).st_mode)
                                          for f in sorted(os.listdir(home))}))
                    if fail_on_read:
                        raise RuntimeError("the check raised inside")
            return real_open(path, flags, mode, **kwargs)

        def making(path, mode=0o777, **kwargs):
            if inside(path):
                log["made"].append((os.path.dirname(os.path.realpath(path)) == os.path.realpath(root), mode))
            return real_mkdir(path, mode, **kwargs)
        return log, [mock.patch.object(os, "open", opening), mock.patch.object(os, "mkdir", making),
                     mock.patch.object(tempfile, "tempdir", root)]

    def test_s5_the_bytes_go_through_a_private_directory_that_is_gone_afterwards(self):
        record = self.record()
        files = fixture("witnessed")
        root = os.path.join(self.tmp, "temporary")
        os.mkdir(root)
        log, patches = self.spied(root)
        for patch in patches:
            patch.start()
        try:
            result = self.answer(record.check_record, files["receipt.json"], files["witness.json"],
                                 files["reading.json"], pins=self.canary())
        finally:
            for patch in patches:
                patch.stop()
        self.assert_report(result, ORACLE["fixtures"]["witnessed"]["canary_pins"])
        self.assertEqual(log["made"], [(True, 0o700)])
        self.assertEqual(sorted(log["written"]), [("reading.json", True, 0o600), ("receipt.json", True, 0o600),
                                                  ("witness.json", True, 0o600)])
        self.assertEqual(log["read"], ["witness.json", "reading.json"])  # the reader's own opens of the two side files
        for directory_mode, file_modes in log["modes"]:
            self.assertEqual(directory_mode, 0o700)
            self.assertEqual(file_modes, {"reading.json": 0o600, "receipt.json": 0o600, "witness.json": 0o600})
        self.assertEqual(os.listdir(root), [])

    def test_s5_the_directory_is_gone_when_the_check_raises_inside_beside_a_check_that_returns(self):
        record = self.record()
        files = fixture("witnessed")
        for label, fail in [("returns", False), ("raises", True)]:
            with self.subTest(label):
                root = os.path.join(self.tmp, "temporary-" + label)
                os.mkdir(root)
                log, patches = self.spied(root, fail_on_read=fail)
                for patch in patches:
                    patch.start()
                try:
                    if fail:
                        self.assertEqual(self.answer(record.check_record, files["receipt.json"],
                                                     files["witness.json"], files["reading.json"],
                                                     pins=self.canary()), UNAVAILABLE)
                    else:
                        self.assertIs(self.answer(record.check_record, files["receipt.json"], files["witness.json"],
                                                  files["reading.json"], pins=self.canary())["ok"], True)
                finally:
                    for patch in patches:
                        patch.stop()
                self.assertEqual(log["made"], [(True, 0o700)])  # the directory was made, so its absence is a removal
                self.assertEqual(os.listdir(root), [])

    def test_s5_reading_a_directory_writes_nothing(self):
        record = self.record()
        home = self.directory(fixture("witnessed"))
        before = {f: (Path(home, f).read_bytes(), os.lstat(os.path.join(home, f)).st_mtime_ns)
                  for f in sorted(os.listdir(home))}
        root = os.path.join(self.tmp, "temporary")
        os.mkdir(root)
        log, patches = self.spied(self.tmp)
        for patch in patches[:2] + [mock.patch.object(tempfile, "tempdir", root)]:
            patch.start()
            self.addCleanup(patch.stop)
        self.assert_report(self.answer(record.check_record_dir, home, pins=self.canary()),
                           ORACLE["fixtures"]["witnessed"]["canary_pins"])
        self.assertEqual((log["made"], log["written"]), ([], []))
        self.assertEqual(log["read"], ["witness.json", "reading.json"])
        self.assertEqual(os.listdir(root), [])
        self.assertEqual({f: (Path(home, f).read_bytes(), os.lstat(os.path.join(home, f)).st_mtime_ns)
                          for f in sorted(os.listdir(home))}, before)


class S6Caps(Case):
    CAPS = (("receipt.json", 1048576), ("witness.json", 4096), ("reading.json", 32768))

    def padded(self, raw, size):
        self.assertLess(len(raw), size)
        return raw + b" " * (size - len(raw))  # trailing JSON whitespace: the same document, exactly `size` bytes

    def test_s6_each_input_one_byte_over_its_cap_is_refused_beside_the_same_input_at_the_cap(self):
        record = self.record()
        files = fixture("witnessed")
        for name, cap in self.CAPS:
            with self.subTest(name):
                at_cap = dict(files, **{name: self.padded(files[name], cap)})
                over = dict(files, **{name: self.padded(files[name], cap + 1)})
                self.assertEqual((len(at_cap[name]), len(over[name])), (cap, cap + 1))
                accepted = self.answer(record.check_record, *(at_cap[f] for f in NAMES), pins=self.canary())
                self.assertIs(accepted["ok"], True)
                self.assertEqual((accepted["report"]["structure"], accepted["report"]["authenticity"]),
                                 ("VALID", "WITNESSED"))
                self.assertEqual(self.answer(record.check_record, *(over[f] for f in NAMES), pins=self.canary()),
                                 TOO_LARGE)

    def test_s6_a_refused_oversize_input_never_reaches_a_temporary_directory(self):
        record = self.record()
        files = fixture("witnessed")
        root = os.path.join(self.tmp, "temporary")
        os.mkdir(root)
        made = []
        real = os.mkdir

        def making(path, mode=0o777, **kwargs):
            made.append(path)
            return real(path, mode, **kwargs)
        with mock.patch.object(tempfile, "tempdir", root), mock.patch.object(os, "mkdir", making):
            self.assertIs(self.answer(record.check_record, *(files[f] for f in NAMES), pins=self.canary())["ok"], True)
            self.assertEqual(len(made), 1)  # beside it: an accepted input does make one
            over = self.padded(files["witness.json"], 4097)
            self.assertEqual(self.answer(record.check_record, files["receipt.json"], over, files["reading.json"]),
                             TOO_LARGE)
            self.assertEqual(len(made), 1)


def explicit_problems(schema, value, where="$"):
    """What `value` breaks in `schema`, for exactly the keywords the published schema file uses. Any other keyword
    is itself reported, so this check cannot silently skip a rule the file gains later."""
    known = {"$schema", "$id", "title", "description", "type", "additionalProperties", "required", "properties",
             "const", "pattern", "enum", "if", "then"}
    problems = [f"{where}: keyword not implemented here: {k}" for k in sorted(set(schema) - known)]
    kinds = {"object": dict, "string": str, "null": type(None), "number": (int, float)}
    if "type" in schema:
        wanted = kinds[schema["type"]]
        if not isinstance(value, wanted) or (schema["type"] == "number" and type(value) is bool):
            return problems + [f"{where}: not of type {schema['type']}"]
    if "const" in schema and value != schema["const"]:
        problems.append(f"{where}: not the const")
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{where}: not in the enum")
    if "pattern" in schema and isinstance(value, str) and re.search(schema["pattern"], value) is None:
        problems.append(f"{where}: pattern")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        problems += [f"{where}: required {k} is missing" for k in schema.get("required", []) if k not in value]
        extra = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                problems += explicit_problems(properties[key], item, where + "." + key)
            elif extra is False:
                problems.append(f"{where}: additional property {key}")
            elif isinstance(extra, dict):
                problems += explicit_problems(extra, item, where + "." + key)
    if "if" in schema and not explicit_problems(schema["if"], value, where):
        problems += explicit_problems(schema.get("then", {}), value, where)
    return problems


class S7Reference(Case):
    ENVELOPE = ("agent_id", "covered_fields", "engine", "integrity_hash", "issued_at", "kind", "payload",
                "receipt_version", "signature", "signing_status")
    PAYLOAD = ("config_identity", "reading_sha256", "record_schema", "record_sha256")

    def reference(self, name="witnessed", reading=True):
        files = fixture(name)
        return self.answer(self.record().build_reference, files["receipt.json"],
                           files["reading.json"] if reading else None, agent_id="agent-under-test")

    def restated(self, change):
        """The witnessed receipt with `change(bundle)` applied and its runtime digest restated to match, by hand."""
        bundle = json.loads(fixture("witnessed")["receipt.json"])
        change(bundle)
        bundle["runtime_sha256"] = sha(canon(bundle["runtime"]))
        return canon(bundle)

    def test_s7_the_reference_is_an_ordinary_unsigned_envelope_with_exactly_the_four_digest_fields(self):
        for name in ("witnessed", "not_witnessed"):
            with self.subTest(name):
                files = fixture(name)
                reference = self.reference(name)
                self.assertEqual(sorted(reference), list(self.ENVELOPE))
                self.assertEqual((reference["receipt_version"], reference["kind"], reference["agent_id"],
                                  reference["signature"], reference["signing_status"]),
                                 ("telos/0.1-unsigned", "kit_record_reference", "agent-under-test", None,
                                  "unsigned_integrity_hash"))
                payload = reference["payload"]
                self.assertEqual(sorted(payload), list(self.PAYLOAD))
                # the kit's own digests: what its request for this record named (the stub Witness received these)
                kit = ORACLE["fixtures"][name]["kit_request"]
                self.assertEqual(payload, {"record_schema": "h0a.receipt/1", "record_sha256": kit["record_sha256"],
                                           "config_identity": kit["config_identity"],
                                           "reading_sha256": kit["reading_sha256"]})
                # and by hand
                bundle = json.loads(files["receipt.json"])
                config = [e["payload"]["config"] for e in bundle["runtime"]["events"] if e["kind"] == "CONFIGURED"][-1]
                self.assertEqual((payload["record_sha256"], payload["config_identity"], payload["reading_sha256"]),
                                 (sha(canon(bundle["runtime"])), sha(canon(config)), sha(files["reading.json"])))
                text = json.dumps(reference).lower()
                for word in ("witness", "authentic", "attest", "signed_by", "verified"):
                    self.assertNotIn(word, text)
        self.assertEqual(ORACLE["fixtures"]["witnessed"]["request_the_stub_received"],
                         ORACLE["fixtures"]["witnessed"]["kit_request"])

    def test_s7_the_reading_digest_is_null_only_without_a_reading_and_a_reading_not_this_records_is_refused(self):
        record = self.record()
        receipt, reading = fixture("witnessed")["receipt.json"], fixture("witnessed")["reading.json"]
        named = self.answer(record.build_reference, receipt, reading, agent_id="a")["payload"]["reading_sha256"]
        self.assertEqual(named, sha(reading))
        payload = self.answer(record.build_reference, receipt, None, agent_id="a")["payload"]
        self.assertEqual(sorted(payload), list(self.PAYLOAD))
        self.assertIsNone(payload["reading_sha256"])
        self.assertEqual(self.answer(record.build_reference, receipt, agent_id="a")["payload"], payload)
        # a reading that is supplied and is not this record's saved reading is never read as "no reading"
        for label, other in [("another record's reading", fixture("refused")["reading.json"]),
                             ("not a reading", b"{}"), ("empty", b""), ("not json", b"not json"),
                             ("not utf-8", b"\xff\xfe")]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.build_reference, receipt, other, agent_id="a"), READING_INVALID)

    def test_s7_the_reference_verifies_and_a_changed_payload_does_not(self):
        reference = self.reference()
        verdict = telos_receipt.verify_receipt(reference)
        self.assertIs(verdict["match"], True)
        self.assertIs(verdict["signature_verified"], False)
        self.assertEqual(reference["integrity_hash"], "sha256:" + sha(canon(reference["payload"])))
        reference["payload"]["record_sha256"] = "0" * 64
        self.assertIs(telos_receipt.verify_receipt(reference)["match"], False)

    def cases(self):
        reference = self.reference()
        action = telos_receipt.build_action_receipt("write_file", {"path": "x"}, "agent", "EXECUTE", 0.81,
                                                    {"purpose": 0.9}, "pa::agent::v1")
        valid = [("the reference", reference), ("the reference without a reading", self.reference(reading=False)),
                 ("an action receipt", action)]
        invalid = [("a signature that is not null", dict(reference, signature="AAAA")),
                   ("an added top-level field", dict(reference, authenticity="WITNESSED")),
                   ("another signing status", dict(reference, signing_status="signed")),
                   ("another version", dict(reference, receipt_version="telos/0.2")),
                   ("a field missing", {k: v for k, v in reference.items() if k != "engine"}),
                   ("a malformed hash", dict(reference, integrity_hash="sha256:xyz")),
                   ("the reference payload under the action kind", dict(reference, kind="action_governed")),
                   ("an action verdict outside the vocabulary",
                    dict(action, payload=dict(action["payload"], verdict="ALLOW")))]
        return valid, invalid

    def test_s7_the_reference_meets_every_constraint_the_published_schema_file_states(self):
        self.assertEqual(sha((TESTS / "receipt-spec.schema.json").read_bytes()),
                         "283ce3b9e6ffe32075c5c246031e0e77b389339e71846b42a1b1c35b87608c56")
        self.assertEqual((SCHEMA["additionalProperties"], sorted(SCHEMA["required"]),
                          SCHEMA["properties"]["signature"]["type"],
                          SCHEMA["properties"]["signing_status"]["const"],
                          SCHEMA["properties"]["receipt_version"]["const"]),
                         (False, list(self.ENVELOPE), "null", "unsigned_integrity_hash", "telos/0.1-unsigned"))
        valid, invalid = self.cases()
        for label, value in valid:
            with self.subTest(label):
                self.assertEqual(explicit_problems(SCHEMA, value), [])
        for label, value in invalid:
            with self.subTest(label):
                self.assertNotEqual(explicit_problems(SCHEMA, value), [])

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "jsonschema is not installed in this interpreter")
    def test_s7_the_reference_validates_against_the_published_schema_with_jsonschema(self):
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        validator = jsonschema.Draft202012Validator(SCHEMA)
        valid, invalid = self.cases()
        for label, value in valid:
            with self.subTest(label):
                self.assertEqual([e.message for e in validator.iter_errors(value)], [])
        for label, value in invalid:
            with self.subTest(label):
                self.assertNotEqual(list(validator.iter_errors(value)), [])
                self.assertNotEqual(explicit_problems(SCHEMA, value), [])  # the explicit check agrees

    def test_s7_a_structurally_invalid_receipt_is_refused_beside_the_valid_one(self):
        record = self.record()
        files = fixture("witnessed")
        self.assertEqual(self.reference()["kind"], "kit_record_reference")
        # its digest is the digest of its contents, so only the reader's structure check stands in the way
        invalid = self.restated(lambda bundle: bundle["runtime"].update(identity_assurance="unsupported"))
        report = self.answer(record.check_record, invalid)["report"]
        self.assertEqual((report["structure"], report["errors"]), ("INVALID", ["identity assurance unsupported"]))
        self.assertEqual(self.answer(record.build_reference, invalid, files["reading.json"], agent_id="a"), UNREADABLE)
        self.assertEqual(self.answer(record.build_reference, invalid, agent_id="a"), UNREADABLE)

    def test_s7_a_receipt_with_no_record_identity_is_refused_beside_the_valid_one(self):
        record = self.record()
        self.assertEqual(self.reference()["kind"], "kit_record_reference")
        # the reader calls this one VALID, yet the kit names no record digest for it (its schema is not the integer 1)
        unnamed = self.restated(lambda bundle: bundle.update(schema=True))
        self.assertEqual(self.answer(record.check_record, unnamed)["report"]["structure"], "VALID")
        self.assertEqual(self.answer(record.build_reference, unnamed, agent_id="a"), UNREADABLE)

    def test_s7_bytes_that_are_no_receipt_and_inputs_that_are_not_bytes_are_refused_beside_the_valid_one(self):
        record = self.record()
        files = fixture("witnessed")
        receipt, reading = files["receipt.json"], files["reading.json"]
        self.assertEqual(self.reference()["kind"], "kit_record_reference")
        for label, args in [("empty", (b"",)), ("not json", (b"not json",)), ("another schema", (b'{"schema":2}',))]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.build_reference, *args, agent_id="a"), UNREADABLE)
        for label, args in [("receipt None", (None,)), ("receipt str", (receipt.decode(),)),
                            ("receipt bytearray", (bytearray(receipt),)), ("reading str", (receipt, reading.decode())),
                            ("reading int", (receipt, 7))]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.build_reference, *args, agent_id="a"), INVALID_ARGUMENT)
        over = receipt + b" " * (1048577 - len(receipt))
        self.assertEqual(self.answer(record.build_reference, over, agent_id="a"), TOO_LARGE)
        self.assertEqual(self.answer(record.build_reference, receipt, reading + b" " * (32769 - len(reading)),
                                     agent_id="a"), TOO_LARGE)

    def test_s7_an_agent_id_that_is_not_a_string_is_refused_beside_one_that_is(self):
        record = self.record()
        receipt = fixture("witnessed")["receipt.json"]
        self.assertEqual(self.answer(record.build_reference, receipt, agent_id="a")["agent_id"], "a")
        for bad in (None, 7, b"a", ["a"], "a\ud800"):  # the last: a str no UTF-8 text can carry (a lone surrogate)
            with self.subTest(repr(bad)):
                self.assertEqual(self.answer(record.build_reference, receipt, agent_id=bad), INVALID_ARGUMENT)


class S8PythonFloor(Case):
    PREIMPORT = ("builtins", "hashlib", "json", "os", "re", "shutil", "stat", "tempfile", "threading", "types",
                 "typing")
    REFUSED = ("RuntimeError", "telos_receipt.record needs Python 3.11 or later")

    def test_s8_importing_record_under_python_3_10_raises_beside_3_11(self):
        self.record()
        for version, raised in [((3, 11, 0, "final", 0), None), ((3, 12, 1, "final", 0), None),
                                ((3, 10, 99, "final", 0), self.REFUSED), ((3, 9, 0, "final", 0), self.REFUSED)]:
            with self.subTest(version):
                out = self.probe({"version": version, "preimport": list(self.PREIMPORT)})
                self.assertEqual(out.get("import_raised"), raised and list(raised))
                self.assertIs(out["after_package"]["record"], False)  # the base package imports either way

    def test_s8_the_modules_own_source_is_within_the_python_3_10_grammar(self):
        # so that a real 3.10 reaches the RuntimeError instead of a SyntaxError (checked by the parser, not by a 3.10)
        path = PACKAGE / "record.py"
        if not path.is_file():
            self.fail("telos_receipt/record.py is missing")
        ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 10))

    def without_cryptography(self):
        import builtins
        real = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ModuleNotFoundError("synthetic missing optional dependency", name="cryptography")
            return real(name, *args, **kwargs)
        return mock.patch.object(builtins, "__import__", blocked)

    # the records whose row is a contract row for the canary pins, so that reading them reaches the signature
    REACHED = ("witnessed", "reading_byte", "receipt_byte", "signature_byte", "row_of_another_record")

    def test_s8_without_cryptography_a_row_that_reaches_the_signature_reads_verifier_unavailable_beside_with_it(self):
        self.record()
        cases = [(name, fixture(name), kit) for name, kit in ORACLE["fixtures"].items()]
        cases += [(variant["name"], changed(variant), variant) for variant in ORACLE["variants"]]
        reached = set()
        for name, files, kit in cases:
            with self.subTest(name):
                with_it = self.both(files, "with-" + name, pins=self.canary())
                with self.without_cryptography():
                    without = self.both(files, "without-" + name, pins=self.canary())
                for result in with_it:
                    self.assert_report(result, kit["canary_pins"])
                for result in without:  # what the kit reader itself answered without a verifier
                    self.assert_report(result, kit["canary_pins_no_verifier"])
                report = without[0]["report"]
                if report["witness_reason"] == "WITNESS_VERIFIER_UNAVAILABLE":
                    reached.add(name)
                    self.assertEqual((without[0]["ok"], without[0]["witness_state"], report["authenticity"]),
                                     (True, "NOT_WITNESSED", "NOT_WITNESSED"))
                else:  # refused before the signature: the same answer, reason included, with or without it
                    self.assertEqual(without, with_it)
        self.assertEqual(reached, set(self.REACHED))

    def test_s8_a_row_refused_before_the_signature_keeps_its_reason_without_cryptography_in_either_order(self):
        record = self.record()
        receipt, row, reading = (fixture("witnessed")[name] for name in NAMES)
        parsed = json.loads(row)
        over_its_hash = changed(next(v for v in ORACLE["variants"] if v["name"] == "row_byte"))["witness.json"]
        early = [("not json", b"not json"), ("no row", b"{}"),
                 ("a field missing", canon({k: v for k, v in parsed.items() if k != "row"})),
                 ("a signature that is not base64",
                  canon(dict(parsed, signature_envelope=dict(parsed["signature_envelope"], value="not base64!")))),
                 ("a row that is not the row its hash names", over_its_hash)]
        unavailable, invalid = ("NOT_WITNESSED", "WITNESS_VERIFIER_UNAVAILABLE"), ("NOT_WITNESSED",
                                                                                 "WITNESS_FILE_INVALID")

        def read(row_bytes, **pins):
            result = self.answer(record.check_record, receipt, row_bytes, reading, **pins)
            return result.get("witness_state"), result.get("report", result).get("witness_reason", result.get("reason"))
        self.assertEqual(read(row, pins=self.canary()), ("WITNESSED", None))
        for label, bad in early:
            with self.subTest(label, verifier=True):
                self.assertEqual(read(bad, pins=self.canary()), invalid)
        with self.without_cryptography():
            self.assertEqual(read(row, pins=self.canary()), unavailable)  # first the row that reaches the signature
            for label, bad in early:                                       # then the rows that do not
                with self.subTest(label, verifier=False):
                    self.assertEqual(read(bad, pins=self.canary()), invalid)
            # a row that is not a row for the pins it is read under (the canary row, the kit's pinned key)
            self.assertEqual(read(row), invalid)
            self.assertEqual(read(row, pins=self.canary()), unavailable)  # and after them, the first row again
        # nothing of that is remembered: with the verifier back the same row reads WITNESSED
        self.assertEqual(read(row, pins=self.canary()), ("WITNESSED", None))

    def test_s8_a_process_that_never_had_cryptography_reads_verifier_unavailable_and_raises_nothing(self):
        self.record()
        row_byte = self.directory(changed(next(v for v in ORACLE["variants"] if v["name"] == "row_byte")), "row-byte")
        for order in ([str(FIXTURES / "witnessed"), row_byte], [row_byte, str(FIXTURES / "witnessed")]):
            with self.subTest(first=os.path.basename(order[0])):
                out = self.probe({"pins": ORACLE["canary_pins"], "check": order, "no_cryptography": True})
                self.assertNotIn("import_raised", out)
                for directory, call in zip(order, out["calls"]):
                    kit = (ORACLE["fixtures"]["witnessed"] if directory.endswith("witnessed")
                           else next(v for v in ORACLE["variants"] if v["name"] == "row_byte"))
                    want = self.ok(kit["canary_pins_no_verifier"])
                    self.assertEqual((call["dir"], call["bytes"]), (want, want))
                    self.assertIs(call["cryptography"], False)
                    self.assertEqual(call["reference"].get("kind"), "kit_record_reference")
                reasons = sorted(call["dir"]["report"]["witness_reason"] for call in out["calls"])
                self.assertEqual(reasons, ["WITNESS_FILE_INVALID", "WITNESS_VERIFIER_UNAVAILABLE"])

    def test_a3_1_a_row_of_another_record_reaches_the_signature_and_other_rows_keep_their_reason(self):
        record = self.record()
        receipt, row, reading = (fixture("witnessed")[name] for name in NAMES)
        other = fixture("not_witnessed")  # another record; the witnessed record's row is put beside it
        rows = [("a valid row", (receipt, row, reading), {"pins": self.canary()}, ("WITNESSED", None)),
                ("a well-formed row of another record", (other["receipt.json"], row, other["reading.json"]),
                 {"pins": self.canary()}, ("NOT_WITNESSED", "WITNESS_NOT_THIS_RECORD")),
                ("a malformed row", (receipt, b"not json", reading), {"pins": self.canary()},
                 ("NOT_WITNESSED", "WITNESS_FILE_INVALID")),
                ("a row for other pins", (receipt, row, reading), {}, ("NOT_WITNESSED", "WITNESS_FILE_INVALID"))]
        unavailable = ("NOT_WITNESSED", "WITNESS_VERIFIER_UNAVAILABLE")

        def read(args, pins):
            result = self.answer(record.check_record, *args, **pins)
            return result.get("witness_state"), result.get("report", result).get("witness_reason", result.get("reason"))
        for label, args, pins, with_it in rows:
            with self.subTest(label):
                self.assertEqual(read(args, pins), with_it)  # the same input with cryptography present
                with self.without_cryptography():
                    without = read(args, pins)
                self.assertEqual(without, unavailable if label in ("a valid row", "a well-formed row of another "
                                                                   "record") else with_it)
                self.assertEqual(read(args, pins), with_it)

    A3_1 = ("`witness_verifier_unavailable` is returned for every row that reaches the reader's signature step, and "
            "only for those",
            "a row that is malformed, or is not a row for the pins in use, is refused earlier with its earlier "
            "reason, with or without `cryptography`",
            "a well-formed row for these pins that names another record reaches the signature step",
            "without `cryptography` it reads `witness_verifier_unavailable`, never `witness_not_this_record`",
            "the reader does not report on the content of a row it could not verify")

    def test_a3_1_the_module_and_the_readme_say_what_a_missing_cryptography_reads_as(self):
        for where, said in [("module", flat(self.record().__doc__)), ("readme", flat(readme_section())),
                            ("changelog", flat(changelog_unreleased()))]:  # (the changelog: A6.3)
            for sentence in self.A3_1:
                with self.subTest(where=where, sentence=sentence):
                    self.assertIn(sentence, said)


def flat(text):
    """Text with every run of white space as one space, lower case: what a sentence says, however it is wrapped."""
    return " ".join(text.split()).lower()


def readme_section():
    """The README's section on reading a kit record, heading included."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    start = text.index("## Reading a kit record (DRAFT)")
    return text[start:text.index("\n## ", start + 1)]


def changelog_unreleased():
    """The CHANGELOG's first entry: the unreleased one."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return text[:text.index("\n## ", text.index("## ") + 1)]


def vendored_pins():
    """The Witness key the vendored witness.py pins, read from its PINS line as text."""
    line = re.search(rb"^PINS = Pins\(public_key='([0-9a-f]{64})',\s+fingerprint='([0-9a-f]{64})',\s+"
                     rb"anchor='([0-9a-f]{64})'\)$", (VENDOR / "witness.py").read_bytes(), re.MULTILINE)
    return None if line is None else tuple(value.decode("ascii") for value in line.groups())


class R1ClosedReader(Case):
    """Amendment 1: the reader that runs is the pinned bytes, and what those bytes import is one closed list."""

    def setUp(self):
        super().setUp()
        self.record()

    SWALLOWED = (b"\n\n_pinned_check_record = check_record\n\n\ndef check_record(path, *, pins=witness.PINS):\n"
                 b"    try:\n        import ctypes\n    except Exception:\n        pass\n"
                 b"    return _pinned_check_record(path, pins=pins)\n")
    OUTSIDE = [("a standard library module off the list", "witness.py", b"\nimport socket\n"),
               ("the load-by-path module the kit falls back to", "receipt.py", b"\nimport importlib.util\n"),
               ("a package whose two listed modules are the only ones on the list", "receipt.py",
                b"\nimport cryptography\n"),
               ("another module of the kit", "reading.py", b"\nfrom h0a import store\n"),
               ("the kit package itself", "reading.py", b"\nimport h0a\n"),
               ("a name outside the listed names of a listed module", "reading.py", b"\nfrom json import tool\n"),
               ("a relative import", "witness.py", b"\nfrom . import reading as _again\n"),
               ("a relative import of a listed name", "witness.py", b"\nfrom .pathlib import Path as _Path\n"),
               ("a relative import of a sibling by the kit's name", "witness.py",
                b"\nfrom .h0a import reading as _again\n"),
               ("a relative import of a listed module by the import function", "reading.py",
                b"\n_json = __import__('json', globals(), None, (), 1)\n"),
               ("the import function called by name", "witness.py", b"\n_socket = __import__('socket')\n"),
               ("an import at call time whose failure the file swallows", "receipt.py", SWALLOWED)]

    def seamed(self, edits, matching=True):
        """(what the private loader answered, the three answers of two rounds of calls) in a fresh interpreter whose
        reader is the vendored bytes plus `edits` ({file name: bytes appended}), handed to the private loader with
        pins that are their own (matching) or the module's (stale). No file is changed anywhere."""
        out = self.probe({"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / "witnessed")] * 2,
                          "seam": {"edits": {f: added.decode("ascii") for f, added in edits.items()},
                                   "matching": matching}})
        self.assertNotIn("import_raised", out)
        return out["seam"], [(call["dir"], call["bytes"], call["reference"]) for call in out["calls"]]

    def test_a2_1_reader_bytes_that_match_their_pins_and_import_outside_the_closed_list_are_refused_beside_intact(self):
        want = self.ok(ORACLE["fixtures"]["witnessed"]["canary_pins"])
        for label, edits in [("the files as pinned", {}),
                             ("one more import of a listed module", {"witness.py": b"\nimport json\nimport hashlib\n",
                                                                     "reading.py": b"\nfrom pathlib import Path\n"})]:
            with self.subTest(label):
                seam, calls = self.seamed(edits)
                self.assertEqual(seam, "loaded")
                for by_dir, by_bytes, reference in calls:
                    self.assertEqual((by_dir, by_bytes), (want, want))
                    self.assertEqual(reference.get("kind"), "kit_record_reference")
        for label, f, added in self.OUTSIDE:
            with self.subTest(label):
                # the pin check passes (the pins are these bytes' own) and the import guard is what refuses
                seam, calls = self.seamed({f: added})
                if added is self.SWALLOWED:
                    self.assertEqual(seam, "loaded")  # the import is asked for at call time, not at load
                else:
                    self.assertEqual(seam.get("raised", [None])[0] if isinstance(seam, dict) else seam, "ImportError")
                self.assertEqual(calls, [(UNAVAILABLE, UNAVAILABLE, UNAVAILABLE)] * 2)
            with self.subTest(label, pins="the module's, which these bytes do not match"):
                seam, calls = self.seamed({f: added}, matching=False)
                self.assertEqual(seam, "kit_reader_modified")
                self.assertEqual(calls, [(MODIFIED, MODIFIED, MODIFIED)] * 2)
        # without the seam the same bytes on disk are a modified reader
        parent = self.copy_package("on-disk")
        with open(os.path.join(parent, "telos_receipt", "_kit_vendor", "witness.py"), "ab") as stream:
            stream.write(b"\nimport socket\n")
        self.assertEqual(self.calls(parent), [(MODIFIED, MODIFIED, MODIFIED)] * 2)
        self.assertEqual({name: sha((VENDOR / name.split("/")[1]).read_bytes()) for name in KIT_NAMES},
                         self.record().KIT_FILES)  # the real copies are as they were

    def test_a2_1_the_public_functions_cannot_reach_the_loader_seam(self):
        import inspect
        record = self.record()
        self.assertIn("_reader", inspect.signature(record._kit).parameters)  # the seam is there, and private
        self.assertIs(inspect.signature(record._kit).parameters["_reader"].kind, inspect.Parameter.KEYWORD_ONLY)
        want = {"check_record_dir": ["path", "pins"], "check_record": ["receipt", "witness", "reading", "pins"],
                "build_reference": ["receipt", "reading", "agent_id"]}
        for name, parameters in want.items():
            with self.subTest(name):
                self.assertEqual(list(inspect.signature(getattr(record, name)).parameters), parameters)
        self.assertNotIn("_kit", record.__all__)
        # in the source: `_reader` is named in the loader and its latch alone, and every other call of either
        # passes nothing at all
        tree = ast.parse((PACKAGE / "record.py").read_text(encoding="utf-8"))
        named, calls = set(), []
        for function in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
            for node in ast.walk(function):
                if "_reader" in (getattr(node, "id", None), getattr(node, "arg", None)):
                    named.add(function.name)
                if isinstance(node, ast.Call) and getattr(node.func, "id", None) in ("_kit", "_load"):
                    calls.append((function.name, node.func.id, len(node.args), [k.arg for k in node.keywords]))
        self.assertEqual(named, {"_load", "_kit"})
        self.assertEqual(sorted(calls), [("_build_reference", "_kit", 0, []), ("_check_record", "_kit", 0, []),
                                         ("_check_record_dir", "_kit", 0, []), ("_kit", "_load", 0, ["_reader"])])
        # handed in as an argument it is only a wrong argument, beside the same call without it
        home, seam = str(FIXTURES / "witnessed"), ({}, {})
        self.assertIs(self.answer(record.check_record_dir, home)["ok"], True)
        self.assertEqual(self.answer(record.check_record_dir, home, pins=seam), PINS_INVALID)
        self.assertEqual(self.answer(record.check_record_dir, seam), INVALID_ARGUMENT)

    POLLUTIONS = {  # the mark a stand-in loader leaves -> what the reading of that process then shows
        "h0a": {"h0a_added": ["h0a"], "private_entered": ["h0a"]},  # (a reader module, under an h0a name)
        "h0a_child": {"h0a_added": ["h0a.witness"], "private_entered": ["h0a.witness"]},
        "h0a_prefix": {"h0a_added": ["h0a_reader"]},
        "private_under_another_name": {"private_entered": ["innocent_name"]},
        "private_under_its_own_name": {"private_entered": ["telos_receipt._kit_vendor._pinned_witness"]},
        "replaced": {"replaced_or_removed": ["sk_s_bystander"]},
        "removed": {"replaced_or_removed": ["sk_s_bystander"]},
        "path_appended": {"path_same_contents": False},
        "path_rebound": {"path_same_object": False}}

    def test_a2_1_what_was_in_sys_modules_and_sys_path_is_as_it_was_beside_a_loader_that_leaves_a_mark(self):
        names = ("not_witnessed", "witnessed")
        spec = {"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / name) for name in names], "probe_h0a": False,
                "hygiene": True}
        want = [self.ok(ORACLE["fixtures"][name]["canary_pins"]) for name in names]
        clean = {"reader_loaded": 3, "replaced_or_removed": [], "h0a_added": [], "private_entered": [],
                 "path_same_object": True, "path_same_contents": True, "cryptography_added": True}
        for label, extra in [("the module's loader", {}), ("the module's loader, an h0a family planted", {"plant": 1})]:
            with self.subTest(label):
                out = self.probe(dict(spec, **extra))
                self.assertNotIn("import_raised", out)
                self.assertEqual([(call["dir"], call["bytes"]) for call in out["calls"]], [(w, w) for w in want])
                # cryptography is the one thing a call adds here that the module did not hold: a dependency
                self.assertEqual(out["hygiene"], clean)
                if extra:
                    self.assertEqual(out["planted"], {"same_objects": True, "same_names": True, "touched": [],
                                                      "h0a_modules": ["h0a", "h0a.reading", "h0a.receipt",
                                                                      "h0a.witness"]})
        for kind, shows in self.POLLUTIONS.items():
            with self.subTest(pollution=kind):  # the same reading of the same process catches each mark
                out = self.probe(dict(spec, pollute=kind))
                self.assertEqual([(call["dir"], call["bytes"]) for call in out["calls"]], [(w, w) for w in want])
                self.assertEqual(out["hygiene"], dict(clean, **shows))

    def test_a2_1_the_module_says_what_a_call_adds_to_sys_modules_and_what_it_never_does(self):
        said = flat(self.record().__doc__)
        for sentence in ("no entry that is already in `sys.modules` is replaced or removed",
                         "what the reader imports is added to `sys.modules`",
                         "`cryptography` at the first call that reaches the signature check",
                         "`sys.path` is not changed"):
            with self.subTest(sentence):
                self.assertIn(sentence, said)
        self.assertNotIn("nothing is added to `sys.path` or `sys.modules`", said)

    def test_r1_the_reader_files_import_exactly_the_closed_list_and_each_other(self):
        allowed = getattr(self.record(), "_ALLOWED_IMPORTS", None)
        if allowed is None:
            self.fail("telos_receipt.record names no closed list of what the reader may import")
        used, siblings, fallback = {}, set(), set()
        for f in ("receipt.py", "witness.py", "reading.py"):
            tree = ast.parse((VENDOR / f).read_bytes())
            in_fallback = {id(node) for handler in ast.walk(tree) if isinstance(handler, ast.ExceptHandler)
                           and isinstance(handler.type, ast.Name) and handler.type.id == "ImportError"
                           for node in ast.walk(handler)}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found = [(alias.name, set()) for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    self.assertEqual(node.level, 0, f)
                    found = [(node.module, {alias.name for alias in node.names})]
                else:
                    continue
                for name, names in found:
                    if id(node) in in_fallback:
                        fallback.add(name)
                    elif name == "h0a":
                        siblings |= names
                    else:
                        used.setdefault(name, set()).update(names)
        self.assertEqual(siblings, {"receipt", "witness", "reading"})
        # the two load-by-path fallbacks (`except ImportError`) are never reached here; reaching one is a refusal,
        # shown by the test above
        self.assertEqual(fallback, {"importlib.util"})
        self.assertEqual(used, {name: set(names) for name, names in allowed.items()})
        for name in ("importlib", "importlib.util", "socket", "h0a", "cryptography", "telos_receipt"):
            self.assertNotIn(name, allowed)

    def test_r1_an_h0a_already_in_sys_modules_is_never_used_and_is_left_as_it_was(self):
        names = ("witnessed", "not_witnessed")
        spec = {"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / name) for name in names], "probe_h0a": False}
        want = [self.ok(ORACLE["fixtures"][name]["canary_pins"]) for name in names]
        for label, plant in [("nothing planted", False), ("h0a and its three modules planted before first use", True)]:
            with self.subTest(label):
                out = self.probe(dict(spec, plant=plant))
                self.assertNotIn("import_raised", out)
                for call, expected in zip(out["calls"], want):
                    self.assertEqual((call["dir"], call["bytes"]), (expected, expected))
                    self.assertEqual(call["reference"].get("kind"), "kit_record_reference")
                    self.assertEqual(call["vendored"], [])
                if plant:
                    self.assertEqual(out["planted"], {"same_objects": True, "same_names": True, "touched": [],
                                                      "h0a_modules": ["h0a", "h0a.reading", "h0a.receipt",
                                                                      "h0a.witness"]})
                else:
                    self.assertEqual([call["h0a"] for call in out["calls"]], [[], []])

    def test_r1_the_check_is_latched_at_first_use_a_later_change_on_disk_is_neither_used_nor_detected(self):
        parent = self.copy_package("latched")
        path = os.path.join(parent, "telos_receipt", "_kit_vendor", "witness.py")
        want = self.ok(ORACLE["fixtures"]["witnessed"]["canary_pins"])
        out = self.probe({"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / "witnessed")] * 2, "flip": path,
                          "count_opens": True}, parent)
        self.assertEqual(out["reader_loaded"], [False, True, True])  # nothing is read or checked before the first call
        # each file was opened once in the life of that process: what was hashed is what was compiled
        self.assertEqual(out["opens"], [{"reading.py": 1, "witness.py": 1, "receipt.py": 1}] * 2)
        self.assertNotEqual(sha(Path(path).read_bytes()), sha((VENDOR / "witness.py").read_bytes()))
        # the file changed between the two calls of that process: the second call ran the bytes checked at the first
        self.assertEqual([(call["dir"], call["bytes"]) for call in out["calls"]], [(want, want)] * 2)
        # beside it: a process that starts after the change refuses every call
        self.assertEqual(self.calls(parent), [(MODIFIED, MODIFIED, MODIFIED)] * 2)

    def test_r1_the_module_and_the_readme_say_what_the_check_does_and_does_not_do(self):
        said = flat(self.record().__doc__)
        for sentence in ("verification is latched at first use", "the bytes verified are the bytes executed",
                         "neither used nor detected", "closed list"):
            with self.subTest(sentence):
                self.assertIn(sentence, said)
        self.assertIn("any change of reader bytes at a re-pin requires a delta review and refreshed oracle evidence",
                      flat(readme_section()))


class R2WitnessState(Case):
    """Amendment 2: `ok` says the reader ran; authenticity is the reader's own witness state and nothing else."""
    KEYS = ["kit_reader", "ok", "pins", "report", "witness_state"]

    def test_r2_the_result_carries_the_readers_witness_state_and_whose_pins_were_used(self):
        self.record()
        seen = set()
        for name, kit in ORACLE["fixtures"].items():
            for label, pins, oracle in [("caller", {"pins": self.canary()}, kit["canary_pins"]),
                                        ("default", {}, kit["pinned_key_cli"])]:
                with self.subTest(name=name, pins=label):
                    for result in self.both(fixture(name), name + "-" + label, **pins):
                        self.assertEqual(sorted(result), self.KEYS)
                        self.assertIs(result["ok"], True)
                        self.assertEqual(result["report"], oracle)
                        self.assertEqual((result["witness_state"], result["pins"]), (oracle["authenticity"], label))
                        seen.add((label, result["witness_state"]))
        self.assertEqual(seen, {("caller", "WITNESSED"), ("caller", "NOT_WITNESSED"), ("default", "NOT_WITNESSED")})

    def test_r2_pins_a_caller_supplies_are_named_caller_also_when_they_are_the_kits_own(self):
        record = self.record()
        kit_pins = vendored_pins()
        if kit_pins is None:
            self.fail("the vendored witness.py has no PINS line of the known form")
        home = str(FIXTURES / "witnessed")
        by_default = self.answer(record.check_record_dir, home)
        by_caller = self.answer(record.check_record_dir, home, pins=record.Pins(*kit_pins))
        self.assertEqual((by_default.get("pins"), by_caller.get("pins")), ("default", "caller"))
        self.assertEqual({key: value for key, value in by_caller.items() if key != "pins"},
                         {key: value for key, value in by_default.items() if key != "pins"})

    def test_a2_3_pins_none_is_the_same_call_as_no_pins_and_only_other_pins_are_named_caller(self):
        record = self.record()
        kit_pins = vendored_pins()
        if kit_pins is None:
            self.fail("the vendored witness.py has no PINS line of the known form")
        for name in ("witnessed", "not_witnessed"):
            with self.subTest(name):
                files, home = [fixture(name).get(f) for f in NAMES], str(FIXTURES / name)
                want = self.ok(ORACLE["fixtures"][name]["pinned_key_cli"], "default")
                for call, args in [(record.check_record_dir, [home]), (record.check_record, files)]:
                    omitted, none = self.answer(call, *args), self.answer(call, *args, pins=None)
                    self.assertEqual((omitted, none), (want, want))
                    for label, pins in [("the canary's", self.canary()), ("the kit's own", record.Pins(*kit_pins)),
                                        ("the kit's own as another object", types.SimpleNamespace(
                                            public_key=kit_pins[0], fingerprint=kit_pins[1], anchor=kit_pins[2]))]:
                        with self.subTest(call=call.__name__, pins=label):
                            self.assertEqual(self.answer(call, *args, pins=pins).get("pins"), "caller")
                    for label, pins in [("False", False), ("zero", 0), ("empty", ())]:
                        with self.subTest(call=call.__name__, pins=label):  # nothing but None stands for no pins
                            self.assertEqual(self.answer(call, *args, pins=pins), PINS_INVALID)

    def watched(self, fake=None):
        """The loaded reader, a patch of its check_record, and the (report, state) pairs the real one returned."""
        record = self.record()
        self.answer(record.check_record_dir, str(FIXTURES / "witnessed"))  # loads the reader
        reader = record._kit().receipt
        real, returned = reader.check_record, []

        def passing(path, *, pins):
            returned.append(real(path, pins=pins))
            return returned[-1] if fake is None else fake(*returned[-1])
        return mock.patch.object(reader, "check_record", passing), returned

    def test_r2_the_report_is_the_object_the_reader_returned_and_the_state_is_its_second_value(self):
        record = self.record()
        files = fixture("witnessed")
        patch, returned = self.watched()
        with patch:
            by_dir = self.answer(record.check_record_dir, str(FIXTURES / "witnessed"), pins=self.canary())
            by_bytes = self.answer(record.check_record, *(files[name] for name in NAMES), pins=self.canary())
        self.assertEqual(len(returned), 2)
        for result, (report, state) in zip((by_dir, by_bytes), returned):
            self.assertIs(result["report"], report)
            self.assertEqual(report, ORACLE["fixtures"]["witnessed"]["canary_pins"])  # and nothing in it was changed
            self.assertEqual((result.get("witness_state"), state["authenticity"]), ("WITNESSED", "WITNESSED"))

    def test_r2_a_reader_return_that_is_not_a_report_and_a_known_state_that_agree_is_refused_beside_the_real_one(self):
        from types import MappingProxyType
        record = self.record()
        files = fixture("witnessed")
        patch, _returned = self.watched()
        with patch:  # the real return, passed through the same patch
            self.assert_report(self.answer(record.check_record_dir, str(FIXTURES / "witnessed"), pins=self.canary()),
                               ORACLE["fixtures"]["witnessed"]["canary_pins"])
        not_witnessed = {"authenticity": "NOT_WITNESSED", "witness": None, "reason": "WITNESS_FILE_INVALID"}
        fakes = [("the report says WITNESSED and the state does not", lambda report, state: (report, not_witnessed)),
                 ("the state says WITNESSED and the report does not",
                  lambda report, state: (dict(report, authenticity="NOT_WITNESSED"), state)),
                 ("a state that is neither of the two",
                  lambda report, state: (dict(report, authenticity="MAYBE"), dict(state, authenticity="MAYBE"))),
                 ("no state", lambda report, state: (report, None)),
                 ("a state that is a mapping and no dict", lambda report, state: (report, MappingProxyType(state))),
                 ("a report that is a mapping and no dict", lambda report, state: (MappingProxyType(report), state)),
                 ("a state that is a word, not the reader's state", lambda report, state: (report, "WITNESSED")),
                 ("a report alone", lambda report, state: report),
                 ("no report", lambda report, state: (None, state)),
                 ("three values", lambda report, state: (report, state, state))]
        for label, fake in fakes:
            with self.subTest(label):
                patch, _returned = self.watched(fake)
                with patch:
                    by_dir = self.answer(record.check_record_dir, str(FIXTURES / "witnessed"), pins=self.canary())
                    by_bytes = self.answer(record.check_record, *(files[name] for name in NAMES), pins=self.canary())
                self.assertEqual((by_dir, by_bytes), (UNAVAILABLE, UNAVAILABLE))

    SAID = ("means the reader ran", "not that the record is authentic", "authenticity is the witness state only",
            "binds the supplied digests to a witness signature", "observed execution", "commissioning",
            "every reading")

    def test_r2_the_module_its_functions_and_the_readme_say_what_ok_and_witnessed_mean(self):
        record = self.record()
        texts = [("module", record.__doc__), ("check_record_dir", record.check_record_dir.__doc__),
                 ("check_record", record.check_record.__doc__), ("README", readme_section())]
        for where, text in texts:
            for sentence in self.SAID[:3] if where.startswith("check_record") else self.SAID:
                with self.subTest(where=where, sentence=sentence):
                    self.assertIn(sentence, flat(text))


class R3FixedRefusals(Case):
    """Amendment 3: every answer is a report or one of a closed tuple of refusals; nothing is raised or left behind."""

    def args(self, name="witnessed"):
        files = fixture(name)
        return [files.get(f) for f in NAMES]

    def temporary(self, label):
        root = os.path.join(self.tmp, "temporary-" + label)
        os.mkdir(root)
        return root, mock.patch.object(tempfile, "tempdir", root)

    def reader(self):
        record = self.record()
        self.answer(record.check_record_dir, str(FIXTURES / "witnessed"))  # loads the reader
        return record._kit()

    def test_r3_the_reasons_are_one_closed_tuple(self):
        record = self.record()
        self.assertEqual(getattr(record, "REASONS", None), REASONS)
        self.assertIn("REASONS", record.__all__)
        said, readme = flat(record.__doc__), flat(readme_section())
        for reason in REASONS:
            with self.subTest(reason):
                self.assertIn(reason, said)
                self.assertIn(reason, readme)

    def test_r3_an_argument_of_the_wrong_type_is_refused_in_each_function_beside_the_right_type(self):
        record = self.record()
        receipt, row, reading = self.args()
        home = str(FIXTURES / "witnessed")
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        for path in (home, os.fsencode(home), Path(home)):
            self.assert_report(self.answer(record.check_record_dir, path, pins=self.canary()), want)
        self.assert_report(self.answer(record.check_record, receipt, row, reading, pins=self.canary()), want)
        self.assertIs(self.answer(record.check_record, receipt, None, None)["ok"], True)
        self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="a").get("kind"),
                         "kit_record_reference")
        wrong = (7, 1.5, True, [receipt], {"receipt": receipt}, bytearray(receipt), memoryview(receipt), object())
        for bad in wrong + (None, receipt.decode()):
            with self.subTest(function="check_record", argument="receipt", type=type(bad).__name__):
                self.assertEqual(self.answer(record.check_record, bad, row, reading), INVALID_ARGUMENT)
            with self.subTest(function="build_reference", argument="receipt", type=type(bad).__name__):
                self.assertEqual(self.answer(record.build_reference, bad, reading, agent_id="a"), INVALID_ARGUMENT)
        for bad in wrong + (receipt.decode(),):
            with self.subTest(function="check_record", argument="witness", type=type(bad).__name__):
                self.assertEqual(self.answer(record.check_record, receipt, bad, reading), INVALID_ARGUMENT)
            with self.subTest(function="check_record", argument="reading", type=type(bad).__name__):
                self.assertEqual(self.answer(record.check_record, receipt, row, bad), INVALID_ARGUMENT)
            with self.subTest(function="build_reference", argument="reading", type=type(bad).__name__):
                self.assertEqual(self.answer(record.build_reference, receipt, bad, agent_id="a"), INVALID_ARGUMENT)
        for bad in (7, 1.5, True, [home], {}, object(), None, bytearray(os.fsencode(home))):
            with self.subTest(function="check_record_dir", argument="path", type=type(bad).__name__):
                self.assertEqual(self.answer(record.check_record_dir, bad), INVALID_ARGUMENT)
        for bad in (7, 1.5, True, ["a"], {}, object(), None, b"a"):
            with self.subTest(function="build_reference", argument="agent_id", type=type(bad).__name__):
                self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id=bad),
                                 INVALID_ARGUMENT)

    def test_r3_a_lone_surrogate_is_refused_or_read_and_never_raises_beside_the_same_call_without_it(self):
        record = self.record()
        receipt, row, reading = self.args()
        home = self.directory(fixture("witnessed"), "plain")
        lone = "\ud800"
        self.assertIs(self.answer(record.check_record_dir, home)["ok"], True)
        self.assertEqual(self.answer(record.check_record_dir, home + lone), INVALID_ARGUMENT)
        self.assertEqual(self.answer(record.check_record_dir, Path(home + lone)), INVALID_ARGUMENT)
        self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="agent").get("agent_id"),
                         "agent")
        self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="agent" + lone),
                         INVALID_ARGUMENT)
        # pins that carry one are no pins
        canary = ORACLE["canary_pins"]
        self.assertEqual(self.answer(record.check_record, receipt, row, reading,
                                     pins=record.Pins(**canary)).get("witness_state"), "WITNESSED")
        for name in ("public_key", "fingerprint", "anchor"):
            with self.subTest(pins=name):
                pins = record.Pins(**dict(canary, **{name: canary[name][:-1] + lone}))
                self.assertEqual(self.answer(record.check_record, receipt, row, reading, pins=pins), PINS_INVALID)
                self.assertEqual(self.answer(record.check_record_dir, home, pins=pins), PINS_INVALID)
        # bytes whose JSON text escapes one are a receipt the reader reads as no valid receipt
        escaped = b'{"schema":1,"runtime":"\\ud800","runtime_sha256":"\\ud800","review":null}'
        result = self.answer(record.check_record, escaped)
        self.assertEqual((result.get("ok"), result["report"]["structure"]), (True, "INVALID"))
        self.assertEqual(self.answer(record.build_reference, escaped, agent_id="a"), UNREADABLE)

    def test_r3_no_temporary_directory_is_a_refusal_beside_the_same_call_with_one(self):
        record = self.record()
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        self.assert_report(self.answer(record.check_record, *self.args(), pins=self.canary()), want)
        for error in (OSError(28, "No space left on device"), PermissionError(13, "Permission denied"),
                      FileNotFoundError(2, "No usable temporary directory"), RuntimeError("no directory")):
            with self.subTest(type(error).__name__):
                with mock.patch.object(tempfile, "mkdtemp", side_effect=error):
                    self.assertEqual(self.answer(record.check_record, *self.args(), pins=self.canary()), UNAVAILABLE)

    def test_r3_a_failure_after_the_directory_is_made_removes_it_and_is_a_refusal_beside_a_call_that_completes(self):
        record = self.record()
        real = getattr(record, "_put", None)
        if real is None:
            self.fail("telos_receipt.record has no _put: this test injects its failure there")
        for label, fail_at in [("completes", None), ("the first file", 1), ("the second file", 2),
                               ("the third file", 3)]:
            with self.subTest(label):
                root, in_root = self.temporary(label.replace(" ", "-"))
                written = []

                def putting(path, raw):
                    written.append(path)
                    if len(written) == fail_at:
                        raise OSError(28, "No space left on device")
                    return real(path, raw)
                with in_root, mock.patch.object(record, "_put", putting):
                    result = self.answer(record.check_record, *self.args(), pins=self.canary())
                if fail_at is None:
                    self.assert_report(result, ORACLE["fixtures"]["witnessed"]["canary_pins"])
                else:
                    self.assertEqual(result, UNAVAILABLE)
                self.assertEqual(len(written), fail_at or 3)  # the directory was made and written to
                self.assertTrue(all(os.path.dirname(path).startswith(os.path.join(root, "")) for path in written))
                self.assertEqual(os.listdir(root), [])

    def made(self):
        """A patch of tempfile.mkdtemp that notes each directory the module made."""
        real, homes = tempfile.mkdtemp, []

        def making(*args, **kwargs):
            homes.append(real(*args, **kwargs))
            return homes[-1]
        return homes, mock.patch.object(tempfile, "mkdtemp", making)

    def test_a2_2_after_an_internal_error_the_directory_is_removed_and_gone_beside_a_call_that_reports(self):
        record = self.record()
        reader = self.reader().receipt
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        real_put = record._put

        def failing_put(path, raw):
            real_put(path, raw)
            raise OSError(5, "Input/output error")
        faults = [("no fault", None), ("the reader raises", mock.patch.object(reader, "check_record",
                                                                              side_effect=RuntimeError("inside"))),
                  ("a write fails after it wrote", mock.patch.object(record, "_put", failing_put)),
                  ("the reader returns no report", mock.patch.object(reader, "check_record", return_value=None))]
        for label, fault in faults:
            with self.subTest(label):
                root, in_root = self.temporary(label.replace(" ", "-"))
                homes, noting = self.made()
                with in_root, noting, (fault or mock.patch.object(record, "_put", real_put)):
                    result = self.answer(record.check_record, *self.args(), pins=self.canary())
                if fault is None:
                    self.assert_report(result, want)
                else:
                    self.assertEqual(result, UNAVAILABLE)  # and no `residual`: nothing is left
                self.assertEqual(len(homes), 1)
                self.assertTrue(homes[0].startswith(os.path.join(root, "")))
                self.assertFalse(os.path.lexists(homes[0]))
                self.assertEqual(os.listdir(root), [])

    def removal(self, root, behaviour):
        """A patch of shutil.rmtree that, for directories under `root` only, raises ("fails"), raises the first time
        ("fails once") or returns having removed nothing ("does nothing"); every other removal is the real one."""
        real, asked = shutil.rmtree, []

        def removing(path, *args, **kwargs):
            if not os.fspath(path).startswith(os.path.join(root, "")):
                return real(path, *args, **kwargs)
            asked.append(path)
            if behaviour == "does nothing" or (behaviour == "fails" and kwargs.get("ignore_errors")):
                return None
            if behaviour == "fails" or (behaviour == "fails once" and len(asked) == 1):
                raise OSError(16, "Resource busy")
            return real(path, *args, **kwargs)
        return asked, mock.patch.object(shutil, "rmtree", removing)

    def test_a2_2_a_directory_that_cannot_be_removed_is_residual_true_and_no_report_beside_one_that_can(self):
        record = self.record()
        reader = self.reader().receipt
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        if os.geteuid() == 0:
            self.fail("run as an ordinary user: the superuser can remove what this test makes unremovable")
        for label, behaviour, fault, residual in [
                ("the removal works", None, False, False),
                ("the removal fails once and the second attempt removes it", "fails once", False, False),
                ("the removal fails every time", "fails", False, True),
                ("the removal returns and the directory is still there", "does nothing", False, True),
                ("the reader raises and the removal fails every time", "fails", True, True),
                ("the reader raises and the removal works", None, True, False)]:
            with self.subTest(label):
                root, in_root = self.temporary(label.replace(" ", "-"))
                homes, noting = self.made()
                asked, removing = self.removal(root, behaviour)
                raising = mock.patch.object(reader, "check_record", **({"side_effect": RuntimeError("inside")}
                                                                       if fault else {"wraps": reader.check_record}))
                with in_root, noting, removing, raising:
                    result = self.answer(record.check_record, *self.args(), pins=self.canary())
                self.assertEqual(len(homes), 1)
                if residual:
                    self.assertEqual(result, RESIDUAL)  # the reader had answered WITNESSED; that answer is not given
                    self.assertNotIn(root, json.dumps(result))
                    self.assertGreaterEqual(len(asked), 1)
                    self.assertTrue(os.path.isdir(homes[0]))
                    shutil.rmtree(homes[0])  # this test removes what the module could not
                elif fault:
                    self.assertEqual(result, UNAVAILABLE)
                else:
                    self.assert_report(result, want)
                self.assertFalse(os.path.lexists(homes[0]))
                self.assertEqual(os.listdir(root), [])

    def test_a2_2_a_genuine_removal_failure_is_residual_true_with_no_path_beside_the_same_call_unhindered(self):
        record = self.record()
        if os.geteuid() == 0:
            self.fail("run as an ordinary user: the superuser can remove what this test makes unremovable")
        want = ORACLE["fixtures"]["witnessed"]["canary_pins"]
        real = tempfile.mkdtemp
        for label, hinder in [("unhindered", False), ("its parent turns read-only once it is made", True)]:
            with self.subTest(label):
                root, in_root = self.temporary(label.split()[0])
                homes = []

                def making(*args, **kwargs):
                    homes.append(real(*args, **kwargs))
                    if hinder:
                        os.chmod(root, 0o500)  # the files inside can still go; the directory itself cannot
                    return homes[-1]
                try:
                    with in_root, mock.patch.object(tempfile, "mkdtemp", making):
                        result = self.answer(record.check_record, *self.args(), pins=self.canary())
                finally:
                    os.chmod(root, 0o700)
                self.assertEqual(len(homes), 1)
                if hinder:
                    self.assertEqual(result, RESIDUAL)
                    for part in (root, homes[0], os.path.basename(homes[0])):
                        self.assertNotIn(part, json.dumps(result))
                    self.assertTrue(os.path.isdir(homes[0]))
                    shutil.rmtree(homes[0])  # this test removes what the module could not
                else:
                    self.assert_report(result, want)
                self.assertFalse(os.path.lexists(homes[0]))
                self.assertEqual(os.listdir(root), [])

    def test_a2_2_after_a_breach_of_the_closed_list_a_directory_left_behind_is_still_residual_true(self):
        record = self.record()
        for label, breach, behaviour, want in [("no breach, removed", [], None, None),
                                               ("a breach, removed", ["'socket'"], None, UNAVAILABLE),
                                               ("a breach, not removed", ["'socket'"], "fails", RESIDUAL),
                                               ("no breach, not removed", [], "fails", RESIDUAL)]:
            with self.subTest(label):
                root, in_root = self.temporary(label.replace(", ", "-").replace(" ", "-"))
                homes, noting = self.made()
                _asked, removing = self.removal(root, behaviour)
                with in_root, noting, removing, mock.patch.object(record, "_OUTSIDE", breach):
                    result = self.answer(record.check_record, *self.args(), pins=self.canary())
                if want is None:
                    self.assert_report(result, ORACLE["fixtures"]["witnessed"]["canary_pins"])
                else:
                    self.assertEqual(result, want)
                if behaviour:
                    shutil.rmtree(homes[0])  # this test removes what the module could not
                self.assertEqual(os.listdir(root), [])

    def test_a2_2_no_other_refusal_says_residual_and_the_module_says_what_residual_means(self):
        record = self.record()
        receipt, row, reading = self.args()
        home = str(FIXTURES / "witnessed")
        refusals = [self.answer(record.check_record, 7), self.answer(record.check_record, receipt + b" " * (1 << 20)),
                    self.answer(record.check_record, receipt, row, reading, pins=7),
                    self.answer(record.check_record_dir, os.path.join(self.tmp, "nothing")),
                    self.answer(record.check_record_dir, 7), self.answer(record.check_record_dir, home, pins=7),
                    self.answer(record.build_reference, b"{}", agent_id="a"),
                    self.answer(record.build_reference, receipt, b"{}", agent_id="a"),
                    self.answer(record.build_reference, receipt, reading, agent_id=7)]
        with mock.patch.object(tempfile, "mkdtemp", side_effect=OSError(28, "No space left on device")):
            refusals.append(self.answer(record.check_record, receipt, row, reading))
        self.assertEqual(sorted({r["reason"] for r in refusals}), sorted(set(REASONS) - {"kit_reader_modified"}))
        for refusal in refusals:
            self.assertEqual(sorted(refusal), ["ok", "reason"])
        self.assertEqual(sorted(self.answer(record.check_record, receipt, row, reading)),
                         ["kit_reader", "ok", "pins", "report", "witness_state"])
        for where, said in [("module", flat(record.__doc__)), ("check_record", flat(record.check_record.__doc__)),
                            ("readme", flat(readme_section()))]:
            with self.subTest(where):
                self.assertIn('"residual": true', said)
                self.assertIn("could not be removed", said)

    def test_r3_whatever_the_reader_raises_is_a_refusal_and_the_directory_is_gone_beside_a_reader_that_answers(self):
        record = self.record()
        reader = self.reader().receipt
        home = str(FIXTURES / "witnessed")
        root, in_root = self.temporary("reader")
        with in_root:
            self.assert_report(self.answer(record.check_record, *self.args(), pins=self.canary()),
                               ORACLE["fixtures"]["witnessed"]["canary_pins"])
            for error in (RuntimeError("inside"), ValueError("inside"), KeyError("inside"), RecursionError("inside"),
                          MemoryError(), ImportError("inside"), AssertionError("inside"), TypeError("inside")):
                with self.subTest(type(error).__name__):
                    with mock.patch.object(reader, "check_record", side_effect=error):
                        self.assertEqual(self.answer(record.check_record_dir, home, pins=self.canary()), UNAVAILABLE)
                        self.assertEqual(self.answer(record.check_record, *self.args(), pins=self.canary()),
                                         UNAVAILABLE)
                    self.assertEqual(os.listdir(root), [])
            # the reader's OSError is its word for a receipt it could not open: unreadable in a directory the caller
            # named, and a failure of this module's own temporary directory when the caller gave bytes
            with mock.patch.object(reader, "check_record", side_effect=OSError(5, "Input/output error")):
                self.assertEqual(self.answer(record.check_record_dir, home, pins=self.canary()), UNREADABLE)
                self.assertEqual(self.answer(record.check_record, *self.args(), pins=self.canary()), UNAVAILABLE)
            self.assertEqual(os.listdir(root), [])
            # an interrupt is not an answer: it passes through, and the directory is still removed
            with mock.patch.object(reader, "check_record", side_effect=KeyboardInterrupt()):
                with self.assertRaises(KeyboardInterrupt):
                    record.check_record(*self.args(), pins=self.canary())
            self.assertEqual(os.listdir(root), [])

    PROCESS_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)

    def test_a6_2_an_interrupt_propagates_and_the_removal_is_attempted_also_when_the_removal_fails(self):
        record = self.record()
        reader = self.reader().receipt
        if os.geteuid() == 0:
            self.fail("run as an ordinary user")
        real_put = record._put

        def interrupted_put(raised):
            def put(path, raw):
                real_put(path, raw)
                raise raised
            return put
        # beside every row below: the same call, uninterrupted, is a report and leaves nothing
        root, in_root = self.temporary("uninterrupted")
        with in_root:
            self.assert_report(self.answer(record.check_record, *self.args(), pins=self.canary()),
                               ORACLE["fixtures"]["witnessed"]["canary_pins"])
        self.assertEqual(os.listdir(root), [])
        count = 0
        for error in self.PROCESS_CONTROL:
            for where in ("in the reader", "in a write"):
                for label, behaviour in [("the removal works", None), ("the removal fails every time", "fails"),
                                         ("the removal returns and the directory is still there", "does nothing")]:
                    with self.subTest(error=error.__name__, where=where, removal=label):
                        count += 1
                        root, in_root = self.temporary(f"interrupt-{count}")
                        homes, noting = self.made()
                        asked, removing = self.removal(root, behaviour)
                        raised = error()
                        if where == "in the reader":
                            fault = mock.patch.object(reader, "check_record", side_effect=raised)
                        else:
                            fault = mock.patch.object(record, "_put", interrupted_put(raised))
                        returned = []
                        with in_root, noting, removing, fault:
                            with self.assertRaises(error) as caught:  # it propagates: no answer, no `residual`
                                returned.append(record.check_record(*self.args(), pins=self.canary()))
                        self.assertIs(caught.exception, raised)  # the same exception object, not another in its place
                        self.assertIs(type(caught.exception), error)
                        self.assertEqual(returned, [])
                        self.assertEqual(len(homes), 1)
                        self.assertTrue(homes[0].startswith(os.path.join(root, "")))
                        self.assertGreaterEqual(len(asked), 1)  # the removal was attempted, on that directory
                        self.assertEqual(set(asked), {homes[0]})
                        if behaviour is None:
                            self.assertFalse(os.path.lexists(homes[0]))
                        else:  # the removal failed too: the directory is left, with the caller's bytes in it
                            self.assertTrue(os.path.isdir(homes[0]))
                            self.assertIn("receipt.json", os.listdir(homes[0]))
                            shutil.rmtree(homes[0])  # this test removes what the module could not
                        self.assertEqual(os.listdir(root), [])

    def test_a6_2_a_process_control_exception_propagates_from_each_function_beside_an_exception_which_is_refused(self):
        record = self.record()
        reader = self.reader().receipt
        home = str(FIXTURES / "witnessed")
        receipt, _row, reading = self.args()
        root, in_root = self.temporary("each")
        calls = [("check_record_dir", "check_record", lambda: record.check_record_dir(home, pins=self.canary())),
                 ("check_record", "check_record", lambda: record.check_record(*self.args(), pins=self.canary())),
                 ("build_reference", "check_receipt", lambda: record.build_reference(receipt, reading, agent_id="a"))]
        with in_root:
            for name, inside, call in calls:
                with self.subTest(name, error="RuntimeError"):
                    with mock.patch.object(reader, inside, side_effect=RuntimeError("inside")):
                        self.assertEqual(self.answer(call), UNAVAILABLE)
                for error in self.PROCESS_CONTROL:
                    with self.subTest(name, error=error.__name__):
                        returned, raised = [], error()
                        with mock.patch.object(reader, inside, side_effect=raised):
                            with self.assertRaises(error) as caught:
                                returned.append(call())
                        self.assertIs(caught.exception, raised)
                        self.assertEqual(returned, [])
                with self.subTest(name, error=None):  # and the function still answers afterwards
                    self.assertNotIn("reason", self.answer(call))
                self.assertEqual(os.listdir(root), [])

    def test_a6_2_a_call_that_does_not_fit_the_signature_is_pythons_typeerror_beside_one_that_fits(self):
        record = self.record()
        home = str(FIXTURES / "witnessed")
        receipt, row, reading = self.args()
        fits = [lambda: record.check_record_dir(home), lambda: record.check_record(receipt, row, reading),
                lambda: record.build_reference(receipt, reading, agent_id="a")]
        for call in fits:
            self.assertNotIn("reason", self.answer(call))
        misfits = {"check_record_dir, no argument": lambda: record.check_record_dir(),
                   "check_record_dir, two positional": lambda: record.check_record_dir(home, None),
                   "check_record_dir, unknown keyword": lambda: record.check_record_dir(home, nope=1),
                   "check_record, no argument": lambda: record.check_record(),
                   "check_record, four positional": lambda: record.check_record(receipt, row, reading, None),
                   "check_record, unknown keyword": lambda: record.check_record(receipt, nope=1),
                   "build_reference, no agent_id": lambda: record.build_reference(receipt, reading),
                   "build_reference, agent_id positional": lambda: record.build_reference(receipt, reading, "a"),
                   "build_reference, unknown keyword": lambda: record.build_reference(receipt, agent_id="a", nope=1)}
        for label, call in misfits.items():
            with self.subTest(label):
                with self.assertRaises(TypeError):
                    call()

    BOUNDARY = ("argument-binding errors (wrong arity or an unknown keyword) are raised by python before the function "
                "body runs",
                "process-control exceptions (`keyboardinterrupt`, `systemexit`, `generatorexit`) propagate")
    INTERRUPT = ("on a process-control exception the removal of the temporary directory is attempted",
                 "if that removal also fails, the exception still propagates, no `residual` answer follows, and a "
                 "directory may be left")
    SCOPE = ("no `exception` raised inside the three function bodies leaves them",)
    STALE = ("after the temporary directory is removed", "raise no exception for any argument value",
             "no exception leaves the three functions for any value", "never raises for any value")

    def test_a6_2_the_docstrings_readme_and_changelog_state_the_boundary_in_the_same_words(self):
        record = self.record()
        whole = self.SCOPE + self.BOUNDARY + self.INTERRUPT
        texts = [("module", record.__doc__, whole), ("readme", readme_section(), whole),
                 ("changelog", changelog_unreleased(), whole),
                 ("check_record_dir", record.check_record_dir.__doc__, self.BOUNDARY),
                 ("check_record", record.check_record.__doc__, self.BOUNDARY + self.INTERRUPT),
                 ("build_reference", record.build_reference.__doc__, self.BOUNDARY)]
        for where, text, sentences in texts:
            for sentence in sentences:
                with self.subTest(where=where, sentence=sentence):
                    self.assertIn(sentence, flat(text))
            for sentence in self.STALE:
                with self.subTest(where=where, stale=sentence):
                    self.assertNotIn(sentence, flat(text))
        # beside it: the same search does find a stale sentence where one is (this file's own source)
        self.assertIn(self.STALE[0], flat(Path(__file__).read_text(encoding="utf-8")))

    def test_r3_build_reference_refuses_whatever_the_reader_raises_or_misnames_beside_the_reader_as_it_is(self):
        record = self.record()
        kit = self.reader()
        receipt, _row, reading = self.args()
        self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="a").get("kind"),
                         "kit_record_reference")
        for error in (RuntimeError("inside"), KeyError("inside"), RecursionError("inside"), OSError(5, "inside")):
            with self.subTest(type(error).__name__):
                with mock.patch.object(kit.receipt, "check_receipt", side_effect=error):
                    self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="a"), UNAVAILABLE)
                with mock.patch.object(kit.witness, "request_bytes", side_effect=error):
                    self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="a"), UNAVAILABLE)
        named = json.loads(kit.witness.request_bytes(receipt, reading))
        for label, change in [("a digest in capitals", {"record_sha256": named["record_sha256"].upper()}),
                              ("a digest one character short", {"config_identity": named["config_identity"][:-1]}),
                              ("a digest that is not a string", {"record_sha256": 7}),
                              ("a reading digest in capitals", {"reading_sha256": named["reading_sha256"].upper()}),
                              ("a reading digest that is not the digest of the reading",
                               {"reading_sha256": "0" * 64}),
                              ("a record schema that is not a string", {"record_schema": 7})]:
            with self.subTest(label):
                with mock.patch.object(kit.witness, "request_bytes", return_value=canon(dict(named, **change))):
                    self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="a"), UNAVAILABLE)
        for label, value in [("bytes that are no JSON", b"not json"), ("JSON that is no object", b"[1]"),
                             ("an object without the names", b"{}")]:
            with self.subTest(label):
                with mock.patch.object(kit.witness, "request_bytes", return_value=value):
                    self.assertEqual(self.answer(record.build_reference, receipt, reading, agent_id="a"), UNAVAILABLE)

    def test_r3_each_digest_is_lowercase_64_hex_and_the_reading_digest_is_the_sha256_of_the_supplied_bytes(self):
        record = self.record()
        for name in ORACLE["fixtures"]:
            with self.subTest(name):
                receipt, _row, reading = self.args(name)
                payload = self.answer(record.build_reference, receipt, reading, agent_id="a")["payload"]
                for field in ("record_sha256", "config_identity", "reading_sha256"):
                    self.assertRegex(payload[field], r"\A[0-9a-f]{64}\Z")
                self.assertEqual(payload["reading_sha256"], hashlib.sha256(reading).hexdigest())
                # the record digest is the kit's: of its canonical bytes of the runtime segment, not of the file
                runtime = json.loads(receipt)["runtime"]
                self.assertEqual(payload["record_sha256"], hashlib.sha256(canon(runtime)).hexdigest())
                self.assertNotEqual(payload["record_sha256"], hashlib.sha256(receipt).hexdigest())
        # other bytes that are still this record's saved reading are named by their own digest, exactly
        receipt, _row, reading = self.args()
        spaced = reading + b"\n"
        named = self.answer(record.build_reference, receipt, spaced, agent_id="a")["payload"]["reading_sha256"]
        self.assertEqual(named, hashlib.sha256(spaced).hexdigest())
        self.assertNotEqual(named, hashlib.sha256(reading).hexdigest())
        said = flat(record.build_reference.__doc__)
        self.assertIn("lowercase 64-hex sha256 of the exact supplied bytes", said)
        self.assertIn("reading_invalid", said)

    def test_r3_build_reference_has_the_caps_of_check_record_each_refused_one_byte_over_beside_the_cap(self):
        record = self.record()
        receipt, row, reading = self.args()
        for label, at_cap, over in [("receipt", (receipt + b" " * (1048576 - len(receipt)), reading),
                                     (receipt + b" " * (1048577 - len(receipt)), reading)),
                                    ("reading", (receipt, reading + b" " * (32768 - len(reading))),
                                     (receipt, reading + b" " * (32769 - len(reading))))]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.build_reference, *at_cap, agent_id="a").get("kind"),
                                 "kit_record_reference")
                self.assertEqual(self.answer(record.build_reference, *over, agent_id="a"), TOO_LARGE)
                # the same bytes meet the same answer in check_record
                self.assertIs(self.answer(record.check_record, at_cap[0], row, at_cap[1])["ok"], True)
                self.assertEqual(self.answer(record.check_record, over[0], row, over[1]), TOO_LARGE)


class R4LazyImport(Case):
    """Amendment 4: the base package never loads this module or the reader; below 3.11 only this module refuses."""
    REFUSED = ["RuntimeError", "telos_receipt.record needs Python 3.11 or later"]

    def test_r4_importing_the_package_loads_neither_the_module_nor_the_reader(self):
        self.record()
        out = self.probe({"probe_h0a": False})
        self.assertEqual(out["after_package"], {"record": False, "h0a": [], "cryptography": False, "vendored": [],
                                                "bare": [], "attribute": False})
        imported = set()
        for node in ast.walk(ast.parse((PACKAGE / "__init__.py").read_bytes())):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imported |= {alias.name for alias in node.names} | {getattr(node, "module", None) or ""}
        self.assertEqual(sorted(name for name in imported if "record" in name or "_kit_vendor" in name), [])

    def test_r4_importing_the_module_reads_no_reader_file_until_the_first_call(self):
        self.record()
        out = self.probe({"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / "not_witnessed")]})
        self.assertNotIn("import_raised", out)
        self.assertEqual(out["reader_loaded"], [False, True])
        self.assertEqual((out["after_record"]["vendored"], out["calls"][0]["vendored"]), ([], []))

    def test_r4_below_3_11_the_module_refuses_by_its_one_line_and_the_package_still_works_beside_3_11(self):
        self.record()
        preimport = list(S8PythonFloor.PREIMPORT)
        for version, raised in [((3, 11, 0, "final", 0), None), ((3, 10, 14, "final", 0), self.REFUSED)]:
            with self.subTest(version):
                out = self.probe({"version": version, "preimport": preimport, "probe_h0a": False})
                self.assertEqual(out.get("import_raised"), raised)
                if raised:
                    self.assertEqual(out["after_refusal"], {"record": False, "h0a": [], "cryptography": False,
                                                            "vendored": [], "bare": [], "base_verifies": True})
                else:
                    self.assertIs(out["after_record"]["record"], True)

    OLD = "/usr/bin/python3"

    def old_python(self):
        """The version of the interpreter at OLD when it is older than 3.11, else None."""
        if not os.path.exists(self.OLD):
            return None
        done = subprocess.run([self.OLD, "-c", "import sys; print(list(sys.version_info[:2]))"], capture_output=True,
                              text=True, timeout=120, check=False, env={"PATH": "/usr/bin:/bin"})
        version = json.loads(done.stdout) if done.returncode == 0 else [9, 9]
        return version if version < [3, 11] else None

    def test_r4_on_a_real_interpreter_older_than_3_11_the_package_imports_and_the_module_raises_its_one_line(self):
        version = self.old_python()
        if version is None:
            self.skipTest(f"{self.OLD} is not an interpreter older than 3.11")
        code = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nimport telos_receipt\n"
                "built = telos_receipt.build_receipt('probe', {'a': 1}, 'probe-agent')\n"
                "out = {'base_verifies': telos_receipt.verify_receipt(built)['match']}\n"
                "try:\n    import telos_receipt.record\nexcept BaseException as e:\n"
                "    out['raised'] = [type(e).__name__, str(e)]\n"
                "out['record'] = 'telos_receipt.record' in sys.modules\n"
                "out['vendored'] = sorted(n for n in sys.modules if '_kit_vendor' in n)\nprint(json.dumps(out))\n")
        done = subprocess.run([self.OLD, "-B", "-c", code, str(ROOT)], capture_output=True, text=True, timeout=120,
                              check=False, cwd=self.tmp, env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
                                                              "HOME": self.tmp})
        self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
        self.assertEqual(json.loads(done.stdout), {"base_verifies": True, "raised": self.REFUSED, "record": False,
                                                   "vendored": []})


class R5ReferenceMeaning(Case):
    """Amendment 5: a reference names a record; it conveys neither identity nor attestation."""
    BANNED = ("enforce", "guarantee", "tamper-proof", "tamperproof", "tamper proof")

    def test_r5_kind_and_agent_id_are_not_covered_by_the_payload_hash_beside_the_payload_which_is(self):
        record = self.record()
        files = fixture("witnessed")
        reference = self.answer(record.build_reference, files["receipt.json"], files["reading.json"], agent_id="one")
        self.assertIs(telos_receipt.verify_receipt(reference)["match"], True)
        for label, change in [("another kind", {"kind": "action_governed"}), ("another agent", {"agent_id": "two"}),
                              ("both", {"kind": "anything", "agent_id": "anyone"})]:
            with self.subTest(label):
                other = dict(reference, **change)
                self.assertEqual(other["integrity_hash"], reference["integrity_hash"])
                self.assertIs(telos_receipt.verify_receipt(other)["match"], True)  # the change is not seen
        changed = dict(reference, payload=dict(reference["payload"], record_sha256="0" * 64))
        self.assertIs(telos_receipt.verify_receipt(changed)["match"], False)

    def test_r5_the_module_and_the_readme_say_a_reference_conveys_neither_identity_nor_attestation(self):
        record = self.record()
        for where, text in [("module", record.__doc__), ("build_reference", record.build_reference.__doc__),
                            ("README", readme_section())]:
            for sentence in ("neither identity nor attestation",
                             "`kind` and `agent_id` are not covered by the payload hash"):
                with self.subTest(where=where, sentence=sentence):
                    self.assertIn(sentence, flat(text))

    def test_r5_every_paragraph_of_the_readme_section_is_marked_draft_and_no_public_text_uses_a_banned_word(self):
        self.record()
        section = readme_section()
        prose = [block for block in re.sub(r"```.*?```", "", section, flags=re.DOTALL).split("\n\n") if block.strip()]
        self.assertGreaterEqual(len(prose), 6)
        for block in prose:
            with self.subTest(block[:40]):
                self.assertIn("DRAFT", block.strip().splitlines()[0])
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = changelog[:changelog.index("\n## ", changelog.index("## ") + 1)]
        lines = [line for line in unreleased.splitlines() if "record" in line.lower() or "kit" in line.lower()]
        self.assertGreaterEqual(len(lines), 3)
        for line in lines:
            with self.subTest(line[:40]):
                self.assertTrue(line.startswith("- DRAFT: "), line)
        texts = {"README section": section, "CHANGELOG": unreleased,
                 "record.py": (PACKAGE / "record.py").read_text(encoding="utf-8"),
                 "_kit_vendor/__init__.py": (VENDOR / "__init__.py").read_text(encoding="utf-8"),
                 "tools/vendor_kit_reader.py": SCRIPT.read_text(encoding="utf-8")}
        for where, text in texts.items():
            for word in self.BANNED:
                with self.subTest(where=where, word=word):
                    self.assertNotIn(word, text.lower())
        # beside it: the same search does find such a word in a file that has one (this file's own first lines)
        self.assertIn(self.BANNED[1], Path(__file__).read_text(encoding="utf-8").lower())


class A6FailedRead(Case):
    """Amendment 6.1 (S15): a vendored file that could not be read was not measured. Only a measured mismatch is
    `kit_reader_modified`, and only that and a successful load are latched."""

    FUNCTIONS = ("check_record_dir", "check_record", "build_reference")
    ORDER = ("reading.py", "witness.py", "receipt.py")  # the fixed order the files are taken in
    MODES = ("open", "read")
    ALL = {"reading.py": 1, "witness.py": 1, "receipt.py": 1}

    def setUp(self):
        super().setUp()
        self.record()

    def steps(self, function, steps, copy=None):
        """What each "call" step of S15_PROBE gave, in a fresh interpreter on this tree or on the copy `copy`.
        Every case is its own process, so no case meets a reader an earlier case loaded or a refusal it latched;
        the probe says what it found before its first step, and that is asserted here."""
        spec = {"path": [copy or str(ROOT)], "function": function, "record": str(FIXTURES / "witnessed"),
                "pins": ORACLE["canary_pins"], "steps": steps, "copy": copy}
        env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": self.tmp, "HOME": self.tmp}
        done = subprocess.run([sys.executable, "-B", "-c", S15_PROBE, json.dumps(spec)], capture_output=True,
                              text=True, env=env, cwd=self.tmp, timeout=120, check=False)
        self.assertEqual((done.returncode, done.stderr), (0, ""), done.stdout)
        said = json.loads(done.stdout)
        self.assertIs(said["fresh"], True)  # an unloaded reader and nothing latched when the case began
        calls = said["calls"]
        for call in calls:
            if "kind" in call["answer"]:  # a reference: its time of issue aside
                call["answer"] = {"kind": call["answer"]["kind"], "payload": call["answer"]["payload"]}
        return calls

    def intact(self, function):
        """By hand where the oracle has it: the normal answer of `function`, from a process with no fault."""
        first, second = self.steps(function, [["call"], ["call"]])
        self.assertEqual((first["opened"], second["opened"]), (self.ALL, {}))  # read once, then latched
        self.assertEqual((first["latched"], second["latched"]), (True, True))
        self.assertEqual(first["answer"], second["answer"])
        if function == "build_reference":
            self.assertEqual(first["answer"]["kind"], "kit_record_reference")
            self.assertEqual(sorted(first["answer"]["payload"]),
                             ["config_identity", "reading_sha256", "record_schema", "record_sha256"])
        else:
            self.assertEqual(first["answer"], self.ok(ORACLE["fixtures"]["witnessed"]["canary_pins"]))
        return first["answer"]

    def taken_up_to(self, name):
        return {f: 1 for f in self.ORDER[:self.ORDER.index(name) + 1]}

    def test_s15_an_oserror_opening_or_reading_a_vendored_file_is_reader_unavailable_not_latched_beside_intact(self):
        for function in self.FUNCTIONS:
            want = self.intact(function)
            for name in self.ORDER:
                for mode in self.MODES:
                    with self.subTest(function=function, file=name, fault=mode):
                        calls = self.steps(function, [["fault", name, mode], ["call"], ["call"], ["clear"], ["call"],
                                                      ["fault", name, mode], ["call"]])
                        # the fault: this call is refused, and so is the next, each having taken the files anew
                        self.assertEqual([c["answer"] for c in calls[:2]], [UNAVAILABLE, UNAVAILABLE])
                        self.assertEqual([c["latched"] for c in calls[:2]], [False, False])
                        self.assertEqual([c["opened"] for c in calls[:2]], [self.taken_up_to(name)] * 2)
                        # the fault removed: the normal answer, from all three files read again from the first
                        self.assertEqual(calls[2]["answer"], want)
                        self.assertEqual((calls[2]["opened"], calls[2]["latched"]), (self.ALL, True))
                        # and that load is latched: the fault, back again, is never met
                        self.assertEqual(calls[3]["answer"], want)
                        self.assertEqual((calls[3]["opened"], calls[3]["latched"]), ({}, True))

    def test_s15_a_real_byte_mismatch_is_kit_reader_modified_and_stays_so_after_the_file_is_restored(self):
        for function in self.FUNCTIONS:
            want = self.intact(function)
            for name in self.ORDER:
                with self.subTest(function=function, file=name):
                    parent = self.copy_package(f"mismatch-{function}-{name}")
                    path = Path(parent, "telos_receipt", "_kit_vendor", name)
                    calls = self.steps(function, [["fault", name, "open"], ["call"], ["fault", name, "read"], ["call"],
                                                  ["clear"], ["flip", name], ["call"], ["restore", name], ["call"],
                                                  ["fault", name, "open"], ["call"]], parent)
                    # neither failed read is latched, so the changed byte is then measured, and that is latched
                    self.assertEqual([c["answer"] for c in calls], [UNAVAILABLE, UNAVAILABLE, MODIFIED, MODIFIED,
                                                                    MODIFIED])
                    self.assertEqual([c["latched"] for c in calls], [False, False, True, True, True])
                    self.assertEqual(calls[2]["opened"], self.taken_up_to(name))
                    self.assertEqual([c["opened"] for c in calls[3:]], [{}, {}])  # restored on disk; never read again
                    # the restore was real: the file is the pinned file again, and a new process answers normally
                    self.assertEqual(sha(path.read_bytes()), sha((VENDOR / name).read_bytes()))
                    self.assertEqual(self.steps(function, [["call"]], parent)[0]["answer"], want)

    def test_s15_the_first_failure_in_the_fixed_order_decides(self):
        first, last = self.ORDER[0], self.ORDER[-1]
        for function in self.FUNCTIONS:
            want = self.intact(function)
            with self.subTest(function=function, order="a mismatch before an unreadable file"):
                parent = self.copy_package(f"order-mismatch-first-{function}")
                calls = self.steps(function, [["flip", first], ["fault", last, "open"], ["call"], ["clear"],
                                              ["restore", first], ["call"]], parent)
                self.assertEqual([c["answer"] for c in calls], [MODIFIED, MODIFIED])
                self.assertEqual([c["opened"] for c in calls], [{first: 1}, {}])
                self.assertEqual(self.steps(function, [["call"]], parent)[0]["answer"], want)
            with self.subTest(function=function, order="an unreadable file before a mismatch"):
                parent = self.copy_package(f"order-unreadable-first-{function}")
                calls = self.steps(function, [["fault", first, "read"], ["flip", last], ["call"], ["clear"], ["call"],
                                              ["restore", last], ["call"]], parent)
                self.assertEqual([c["answer"] for c in calls], [UNAVAILABLE, MODIFIED, MODIFIED])
                self.assertEqual([c["opened"] for c in calls], [{first: 1}, self.ALL, {}])
                self.assertEqual([c["latched"] for c in calls], [False, True, True])
                self.assertEqual(self.steps(function, [["call"]], parent)[0]["answer"], want)
            with self.subTest(function=function, order="an earlier file changes after a later one failed"):
                # the failed attempt had read `first` whole and intact; nothing of that is kept: the retry reads
                # `first` again and measures the byte changed since
                parent = self.copy_package(f"order-reread-{function}")
                calls = self.steps(function, [["fault", last, "read"], ["call"], ["flip", first], ["clear"], ["call"],
                                              ["restore", first], ["call"]], parent)
                self.assertEqual([c["answer"] for c in calls], [UNAVAILABLE, MODIFIED, MODIFIED])
                self.assertEqual([c["opened"] for c in calls], [self.ALL, {first: 1}, {}])
                self.assertEqual([c["latched"] for c in calls], [False, True, True])
                self.assertEqual(self.steps(function, [["call"]], parent)[0]["answer"], want)
            with self.subTest(function=function, order="a file that is gone, then back"):
                parent = self.copy_package(f"order-gone-{function}")
                calls = self.steps(function, [["remove", last], ["call"], ["restore", last], ["call"]], parent)
                self.assertEqual([c["answer"] for c in calls], [UNAVAILABLE, want])
                self.assertEqual([c["latched"] for c in calls], [False, True])

    FAILED_READ = ("a vendored file that could not be opened or read is `reader_unavailable` for that call and is "
                   "not latched",
                   "the next call reads and checks all three files again")

    def test_s15_the_module_readme_and_changelog_say_a_failed_read_is_not_latched(self):
        for where, text in [("module", self.record().__doc__), ("readme", readme_section()),
                            ("changelog", changelog_unreleased())]:
            for sentence in self.FAILED_READ:
                with self.subTest(where=where, sentence=sentence):
                    self.assertIn(sentence, flat(text))


class S9ExistingPackage(Case):
    def test_s9_every_module_of_0_1_1_is_byte_identical(self):
        for name, digest in MODULES_0_1_1.items():
            with self.subTest(name):
                self.assertEqual(sha((PACKAGE / name).read_bytes()), digest)

    def test_s9_the_package_surface_of_0_1_1_is_unchanged_and_record_is_not_imported_with_it(self):
        self.assertEqual(sorted(telos_receipt.__all__),
                         ["COVERED", "ENGINE_LABEL", "HASH_PREFIX", "MAX_DEPTH", "RECEIPT_VERSION", "SIGNING_STATUS",
                          "__version__", "build_action_receipt", "build_receipt", "compute_integrity_hash",
                          "verify_native_receipts", "verify_receipt"])
        self.assertEqual(self.probe({"probe_h0a": False})["after_package"]["record"], False)


if __name__ == "__main__":
    unittest.main()
