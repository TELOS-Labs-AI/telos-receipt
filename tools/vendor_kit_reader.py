"""Copy the kit's record reader into this package and write its pin. The only way those files and that pin change.

    python tools/vendor_kit_reader.py <kit directory> <commit sha> [--package-dir DIR] [--check]

Copies h0a/receipt.py, h0a/witness.py and h0a/reading.py from the kit, byte for byte, to
telos_receipt/_kit_vendor/, and rewrites the pin block of telos_receipt/record.py: the kit commit and the sha256 of
each of the three files. A re-pin to a newer kit commit is this command again with the new directory and sha. Nothing
under _kit_vendor/ and nothing in the pin block is ever edited by hand.

<commit sha> is the full 40-character lowercase sha of the kit commit. When <kit directory> is a git checkout (it
holds `.git`), the three files are read from that commit's tree with `git show`, so a dirty working tree cannot
reach the copies, and a commit the checkout does not hold is refused. When it is an export of a commit (no `.git`),
the files are read from the directory and the sha is recorded as named: an export cannot show which commit it is,
and the printed "source" says which of the two happened.

--check writes nothing and exits 1 when the copies or the pin would change, 0 when they already match.

Prints one JSON object: commit, files (kit path: sha256), source ("git" or "export") and changed (the paths under
the package directory that differ, or that were rewritten). Exit 2 with a line on stderr for anything it cannot do:
a commit name that is not a full sha, a commit the checkout does not hold or that lacks one of the files, a kit
file that is not there, a package directory without record.py or without exactly one pin block.
Standard library only; the only process it starts is `git`, and only for a git checkout.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

NAMES = ("reading.py", "receipt.py", "witness.py")
PIN_BEGIN = "# --- kit reader pin: written by tools/vendor_kit_reader.py, never by hand ---"
PIN_END = "# --- end kit reader pin ---"
COMMIT = re.compile(r"[0-9a-f]{40}")


class Refused(Exception):
    """This command cannot do what was asked; its one argument is the line for stderr."""


def from_git(kit, commit):
    """{file name: bytes} as the named commit of the checkout at `kit` holds them."""
    def git(*args):
        done = subprocess.run(["git", "-C", kit, *args], capture_output=True, check=False)
        return done.returncode, done.stdout
    code, named = git("rev-parse", "--verify", "--quiet", commit + "^{commit}")
    if code != 0 or named.decode("ascii", "replace").strip() != commit:
        raise Refused("the kit checkout does not hold commit " + commit)
    found = {}
    for name in NAMES:
        code, found[name] = git("show", f"{commit}:h0a/{name}")
        if code != 0:
            raise Refused(f"commit {commit} holds no h0a/{name}")
    return found


def from_export(kit):
    """{file name: bytes} as the directory `kit` holds them. OSError for a file that is not there."""
    found = {}
    for name in NAMES:
        with open(os.path.join(kit, "h0a", name), "rb") as stream:
            found[name] = stream.read()
    return found


def pin_block(commit, files):
    """The lines between the two markers of record.py, the first marker included."""
    lines = [PIN_BEGIN, f'KIT_COMMIT = "{commit}"', "KIT_FILES = {"]
    lines += [f'    "h0a/{name}": "{hashlib.sha256(files[name]).hexdigest()}",' for name in NAMES]
    return "\n".join(lines + ["}", ""])


def pinned(source, commit, files):
    """The bytes of record.py with its pin block replaced."""
    begin, end = PIN_BEGIN.encode("ascii"), PIN_END.encode("ascii")
    if source.count(begin) != 1 or source.count(end) != 1 or source.index(begin) > source.index(end):
        raise Refused("record.py does not hold exactly one pin block")
    return source[:source.index(begin)] + pin_block(commit, files).encode("ascii") + source[source.index(end):]


def current(path):
    try:
        with open(path, "rb") as stream:
            return stream.read()
    except FileNotFoundError:
        return None


def replace(path, raw):
    """Write raw to path through a temporary name beside it, so a reader never sees half a file."""
    temporary = path + ".vendoring"
    with open(temporary, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def run(argv):
    parser = argparse.ArgumentParser(prog="vendor_kit_reader.py", description=__doc__.splitlines()[0])
    parser.add_argument("kit", help="the kit: a git checkout, or an export of one commit")
    parser.add_argument("commit", help="the full 40-character sha of the kit commit")
    parser.add_argument("--package-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                                                              "telos_receipt"))
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 when something would change")
    args = parser.parse_args(argv)
    if COMMIT.fullmatch(args.commit) is None:
        raise Refused("the commit must be the full 40-character lowercase sha")
    package = os.path.abspath(args.package_dir)
    source = current(os.path.join(package, "record.py"))
    if source is None:
        raise Refused("no record.py under " + package)
    git = os.path.lexists(os.path.join(args.kit, ".git"))
    files = from_git(args.kit, args.commit) if git else from_export(args.kit)
    wanted = {os.path.join("_kit_vendor", name): files[name] for name in NAMES}
    wanted["record.py"] = pinned(source, args.commit, files)
    changed = sorted(path for path, raw in wanted.items() if current(os.path.join(package, path)) != raw)
    if not args.check:
        for path in changed:
            replace(os.path.join(package, path), wanted[path])
    print(json.dumps({"commit": args.commit, "source": "git" if git else "export", "changed": changed,
                      "files": {"h0a/" + name: hashlib.sha256(files[name]).hexdigest() for name in NAMES}},
                     sort_keys=True))
    return 1 if args.check and changed else 0


def main(argv):
    try:
        return run(argv)
    except Refused as e:
        print(f"vendor_kit_reader.py: {e.args[0]}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"vendor_kit_reader.py: {e.filename}: {e.strerror}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
