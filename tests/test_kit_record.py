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
S8 Python 3.10 is refused at import beside 3.11. (Its second half waits for the kit reader's next pin.)
S9 the existing modules are byte-identical to 0.1.1.

The fixtures under kit_record_fixtures/ were made once by the kit's own entry points with a loopback stub Witness
and a canary Ed25519 key that was never written to disk. `oracle.json` holds the canary PUBLIC pins and what the
kit reader answered for every fixture and every changed directory: `canary_pins` is the kit's
`check_record(path, pins=<canary>)`, `pinned_key_cli` is the line the kit reader command printed (it checks under
the pinned Witness key, so a canary row reads NOT_WITNESSED there). No test opens a socket or a real key.
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

    def assert_report(self, result, report):
        self.assertEqual(result, {"ok": True, "report": report, "kit_reader": self.kit_reader()})

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

def state():
    names = list(sys.modules)
    return {"record": "telos_receipt.record" in names,
            "h0a": sorted(n for n in names if n == "h0a" or n.startswith("h0a.")),
            "cryptography": "cryptography" in names,
            "vendored": sorted(n for n in names if "_kit_vendor" in (getattr(sys.modules[n], "__file__", None) or "")),
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
out["after_package"] = state()
if "version" in spec:
    sys.version_info = tuple(spec["version"])
before = list(sys.path)
try:
    import telos_receipt.record as record
except BaseException as e:
    out["import_raised"] = [type(e).__name__, str(e)]
    print(json.dumps(out))
    sys.exit(0)
out["after_record"] = dict(state(), sys_path_same=sys.path == before)
if spec.get("probe_h0a", True):
    out["after_record"]["h0a_importable"] = h0a_importable()
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
print(json.dumps(out))
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
                self.assert_report(by_dir, kit["pinned_key_cli"])
                self.assert_report(by_bytes, kit["pinned_key_cli"])
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
        self.assertEqual(sorted(result), ["kit_reader", "ok", "report"])
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
                self.assert_report(by_dir, variant["pinned_key_cli"])
                self.assert_report(by_bytes, variant["pinned_key_cli"])

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
                self.assertEqual(self.answer(record.check_record_dir, path), UNREADABLE)

    def test_c3_a_path_no_file_system_call_takes_is_refused_beside_the_same_path_without_the_fault(self):
        record = self.record()
        good = self.directory(fixture("not_witnessed"), "good")
        self.assertIs(self.answer(record.check_record_dir, good)["ok"], True)
        for label, path in [("a NUL", good + "\0"), ("a NUL in bytes", os.fsencode(good) + b"\0"),
                            ("a lone surrogate", good + "\ud800")]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.check_record_dir, path), UNREADABLE)

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
                self.assertEqual(self.answer(record.check_record, *args, pins=self.canary()), UNREADABLE)

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


class S3PinnedReader(Case):
    def setUp(self):
        super().setUp()
        self.record()  # nothing to pin, copy or vendor without the module: a failed guarantee, not a broken test

    def copy_package(self, name):
        parent = os.path.join(self.tmp, name)
        shutil.copytree(PACKAGE, os.path.join(parent, "telos_receipt"), ignore=shutil.ignore_patterns("__pycache__"))
        return parent

    def calls(self, parent):
        out = self.probe({"pins": ORACLE["canary_pins"], "check": [str(FIXTURES / "witnessed")] * 2}, parent)
        self.assertNotIn("import_raised", out)
        return [(call["dir"], call["bytes"], call["reference"]) for call in out["calls"]]

    def test_s3_one_changed_byte_in_any_vendored_file_refuses_every_call_beside_the_intact_files(self):
        intact = self.calls(self.copy_package("intact"))
        want = {"ok": True, "report": ORACLE["fixtures"]["witnessed"]["canary_pins"], "kit_reader": self.kit_reader()}
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

    def test_s3_a_vendored_file_that_is_gone_refuses_every_call_beside_the_intact_files(self):
        self.assertIs(self.calls(self.copy_package("intact"))[0][0]["ok"], True)
        for name in ("receipt.py", "witness.py", "reading.py"):
            with self.subTest(name):
                parent = self.copy_package("gone-" + name)
                os.unlink(os.path.join(parent, "telos_receipt", "_kit_vendor", name))
                self.assertEqual(self.calls(parent), [(MODIFIED, MODIFIED, MODIFIED)] * 2)

    def test_s3_the_pin_in_the_source_is_the_digest_of_each_vendored_file(self):
        record = self.record()
        self.assertEqual(record.KIT_FILES, self.kit_reader()["files"])
        self.assertEqual(record.KIT_COMMIT, ORACLE["kit_commit"])  # the fixtures' oracle is this pin's reader
        self.assertEqual(sorted(p.name for p in VENDOR.iterdir() if p.name != "__pycache__"),
                         ["__init__.py", "reading.py", "receipt.py", "witness.py"])

    # --- the vendoring script ---

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
                                                "bare": []})

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
        want = {"ok": True, "report": ORACLE["fixtures"]["not_witnessed"]["canary_pins"],
                "kit_reader": self.kit_reader()}
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
                        with self.assertRaisesRegex(RuntimeError, "the check raised inside"):
                            record.check_record(files["receipt.json"], files["witness.json"], files["reading.json"],
                                                pins=self.canary())
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

    def test_s7_the_reading_digest_is_null_unless_the_reading_is_this_records_saved_reading(self):
        record = self.record()
        receipt, reading = fixture("witnessed")["receipt.json"], fixture("witnessed")["reading.json"]
        named = self.answer(record.build_reference, receipt, reading, agent_id="a")["payload"]["reading_sha256"]
        self.assertEqual(named, sha(reading))
        for label, other in [("no reading", None), ("another record's reading", fixture("refused")["reading.json"]),
                             ("not a reading", b"{}")]:
            with self.subTest(label):
                payload = self.answer(record.build_reference, receipt, other, agent_id="a")["payload"]
                self.assertEqual(sorted(payload), list(self.PAYLOAD))
                self.assertIsNone(payload["reading_sha256"])

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
        for label, args in [("empty", (b"",)), ("not json", (b"not json",)), ("another schema", (b'{"schema":2}',)),
                            ("receipt None", (None,)), ("receipt str", (receipt.decode(),)),
                            ("reading str", (receipt, reading.decode()))]:
            with self.subTest(label):
                self.assertEqual(self.answer(record.build_reference, *args, agent_id="a"), UNREADABLE)
        over = receipt + b" " * (1048577 - len(receipt))
        self.assertEqual(self.answer(record.build_reference, over, agent_id="a"), TOO_LARGE)
        self.assertEqual(self.answer(record.build_reference, receipt, reading + b" " * (32769 - len(reading)),
                                     agent_id="a"), TOO_LARGE)

    def test_s7_an_agent_id_that_is_not_a_string_raises_beside_one_that_is(self):
        record = self.record()
        receipt = fixture("witnessed")["receipt.json"]
        self.assertEqual(self.answer(record.build_reference, receipt, agent_id="a")["agent_id"], "a")
        for bad in (None, 7, b"a", ["a"]):
            with self.subTest(repr(bad)):
                try:
                    result = record.build_reference(receipt, agent_id=bad)
                except TypeError as e:
                    self.assertEqual(str(e), "agent_id must be a str")
                else:
                    self.fail(f"no TypeError; returned {result!r}")


class S8PythonFloor(Case):
    PREIMPORT = ("builtins", "hashlib", "json", "os", "shutil", "stat", "tempfile", "threading", "types", "typing")
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

    WAITING = b"WITNESS_VERIFIER_UNAVAILABLE" not in (VENDOR / "witness.py").read_bytes() if VENDOR.is_dir() else True

    def without_cryptography(self):
        import builtins
        real = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ModuleNotFoundError("synthetic missing optional dependency", name="cryptography")
            return real(name, *args, **kwargs)
        return mock.patch.object(builtins, "__import__", blocked)

    @unittest.skipIf(WAITING, "waits for the kit re-pin: the pinned reader has no WITNESS_VERIFIER_UNAVAILABLE")
    def test_s8_without_cryptography_a_row_reads_verifier_unavailable_beside_witnessed_with_it(self):
        record = self.record()
        files = fixture("witnessed")
        args = [files[name] for name in NAMES]
        self.assertEqual(self.answer(record.check_record, *args, pins=self.canary())["report"]["authenticity"],
                         "WITNESSED")
        with self.without_cryptography():
            report = self.answer(record.check_record, *args, pins=self.canary())["report"]
        self.assertEqual((report["authenticity"], report["witness_reason"]),
                         ("NOT_WITNESSED", "WITNESS_VERIFIER_UNAVAILABLE"))

    @unittest.skipUnless(WAITING, "the pinned reader answers a missing verifier itself")
    def test_s8_until_the_re_pin_a_missing_cryptography_gives_no_report_at_all_and_never_witnessed(self):
        record = self.record()
        files = fixture("witnessed")
        args = [files[name] for name in NAMES]
        self.assertEqual(self.answer(record.check_record, *args, pins=self.canary())["report"]["authenticity"],
                         "WITNESSED")
        with self.without_cryptography():
            for call, call_args in [(record.check_record, args),
                                    (record.check_record_dir, [str(FIXTURES / "witnessed")])]:
                try:
                    result = call(*call_args, pins=self.canary())
                except ImportError:
                    continue
                self.fail(f"a result came back without the signature check: {result!r}")
            # a record with no row to check never needs it
            plain = fixture("not_witnessed")
            self.assert_report(self.answer(record.check_record, plain["receipt.json"], None, plain["reading.json"],
                                           pins=self.canary()), ORACLE["fixtures"]["not_witnessed"]["canary_pins"])


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
