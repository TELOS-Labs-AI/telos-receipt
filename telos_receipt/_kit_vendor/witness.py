"""The witness state of a first-run record: WITNESSED or NOT_WITNESSED, never absent.

A record is WITNESSED when `witness.json` beside its `receipt.json` holds one row that the TELOS Witness key signed
for this record: the row has the contract's shape, its hash is recomputed here, its signature is checked under the
public key pinned below, and its digest and configuration identity are this receipt's. The check is offline. The
row's time is the signer's statement, and the Witness received digests, not the record: this does not show that TELOS
observed the run.
Every other case is NOT_WITNESSED with one reason from REASONS. The last of them, WITNESS_VERIFIER_UNAVAILABLE, is
about this machine and this moment, not about the record: the signature check could not be run here (`cryptography`
is not installed, or it raised something that is not a plain invalid-signature result). It is never read from
`witness.json` and never written there, and a row that is there is left as it is.

`record()` asks for the row: one HTTP POST of three values (the record schema name, the receipt's runtime digest and
its configuration identity), and a fourth, the sha256 of the bytes of the `reading.json` beside the receipt, when
that file reads READING_SAVED for this receipt at that moment (h0a/reading.py). Nothing else is sent, and
`reading.json` is never written here. A request of four values is answered with a row of ROW_SCHEMA_READING, which
is the first schema's row plus `reading_sha256`; a row of either schema carrying the other's key set is not a row.
The request goes over https with the certificate checked, or over plain http when the
address is this machine. The call is made by a child process, this file run as a script. The
child holds only those values, the launcher's offline guard stays installed in the parent, and the parent stops
the child at BUDGET_SECONDS, which makes the budget a total one. What comes back is judged by the same `check()` the
reader uses, and `witness.json` then holds either the signed row or `{"reason": ..., "state": "NOT_WITNESSED"}`, so
a later read names why. A record that is already WITNESSED is not asked about again. When the check cannot be run
here nothing is written: the import is tried before the request, so nothing is asked when it fails, and an answer
that then cannot be checked is not kept.

Standard library only, with no import from the kit but the sibling reading module, loaded by its path when the
package is not there, so the standalone reader can load this file by its path. The signature check imports
`cryptography`, in one place (`_verified`), when there is a row to check or a request about to be made.
"""
import argparse
import base64
from datetime import datetime
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
from typing import NamedTuple
import urllib.parse


class Pins(NamedTuple):
    public_key: str   # the Witness key's raw Ed25519 public key, hex
    fingerprint: str  # sha256 of those bytes, hex
    anchor: str       # the commissioning chain head the witness log is anchored to


PINS = Pins(public_key='6698796ab058e76d699cf2d3628ed66f35014c7278f16042b6226207b1ecb8ee',
            fingerprint='12f4de3b7a839ce3c665deaff1922916fa39a52bbe239098662d440a283aaddf',
            anchor='1b5f5b48bb9eff758da07c74b69410b894e3d129a30e908ebe9cf9b24b1bd73a')
# The public address is set at release; until then this is the Studio's loopback page server.
WITNESS_URL = 'http://127.0.0.1:8660/api/witness/kit-record'
LOOPBACK = frozenset({'127.0.0.1', 'localhost', '::1'})
RECEIPT, WITNESS = 'receipt.json', 'witness.json'
RECORD_SCHEMA = 'h0a.receipt/1'
ROW_SCHEMA = 'telos.witness.kit_record/0.1'
ROW_SCHEMA_READING = 'telos.witness.kit_record/0.2'  # the same row, naming a reading digest as well
READING, MAX_READING_BYTES = 'reading.json', 32768  # h0a.reading.READING, h0a.reading.MAX_BYTES
ROW_FIELDS = frozenset({'schema_version', 'event_type', 'anchor_hash', 'parent_hash', 'row', 'timestamp',
                        'record_schema', 'record_sha256', 'config_identity', 'authorization', 'signature_envelope',
                        'this_hash'})
ENVELOPE_FIELDS = frozenset({'algorithm', 'covers', 'signer_key_id', 'value'})
COVERS = 'this_hash (ASCII bytes of the 64-character hex string)'
REFUSAL = b'{"error":"witness_unavailable"}'
REASONS = ('WITNESS_NOT_REQUESTED', 'WITNESS_UNREACHABLE', 'WITNESS_REFUSED', 'WITNESS_FILE_INVALID',
           'WITNESS_NOT_THIS_RECORD', 'WITNESS_VERIFIER_UNAVAILABLE')
UNAVAILABLE = REASONS[-1]  # a condition of this machine now: computed at each read, never stored (REASONS[1:-1] are)
MAX_RECEIPT_BYTES = 1048576  # h0a.receipt.MAX_BYTES
MAX_ROW_BYTES = 4096
BUDGET_SECONDS = 5
_HEX64 = re.compile(r'[0-9a-f]{64}')
_TIMESTAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z')


def _not(reason):
    return {'authenticity': 'NOT_WITNESSED', 'witness': None, 'reason': reason}


NOT_REQUESTED = _not('WITNESS_NOT_REQUESTED')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _hex64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _identity(receipt_raw):
    """(runtime digest, configuration identity) of a receipt whose digest is the digest of its contents, else None."""
    try:
        if len(receipt_raw) > MAX_RECEIPT_BYTES:
            return None
        bundle = json.loads(receipt_raw)
        digest = hashlib.sha256(_canonical(bundle['runtime'])).hexdigest()
        configured = [e['config_identity'] for e in bundle['runtime']['events'] if e['kind'] == 'CONFIGURED'][-1]
        if (set(bundle) == {'schema', 'runtime', 'runtime_sha256', 'review'} and type(bundle['schema']) is int
                and bundle['schema'] == 1 and bundle['runtime_sha256'] == digest and _hex64(configured)):
            return digest, configured
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        pass
    return None


def _reading():
    """The sibling reading module: the kit's own when this file is part of the package, else loaded by its path."""
    try:
        from h0a import reading
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location('reading', os.path.join(os.path.dirname(__file__), 'reading.py'))
        reading = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reading)
    return reading


def request_bytes(receipt_raw, reading_raw=None):
    """The one request for this receipt: exactly the three contract values, and reading_sha256, the sha256 of
    reading_raw, when those bytes read READING_SAVED for this receipt. None for a receipt that cannot be read."""
    identity = _identity(receipt_raw)
    if identity is None:
        return None
    request = {'record_schema': RECORD_SCHEMA, 'record_sha256': identity[0], 'config_identity': identity[1]}
    if reading_raw is not None and _reading().check(receipt_raw, reading_raw)[0] == 'READING_SAVED':
        request['reading_sha256'] = hashlib.sha256(reading_raw).hexdigest()
    return _canonical(request)


def _timestamp(value):
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value[:-1])
    except ValueError:
        return False
    return True


class VerifierUnavailable(Exception):
    """This machine could not run the Ed25519 check: it says nothing about the signature."""


def _verified(signature, message, public_key):
    """True when `signature` is an Ed25519 signature by public_key (hex) over message, False when it is not. With
    signature None nothing is checked and True says the verifier could be imported.
    The one place the verifier is imported and run. ValueError and InvalidSignature from the check are the plain
    not-signed result. Anything else the import or the check raises is VerifierUnavailable."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if signature is None:
            return True
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(signature, message)
        except (ValueError, InvalidSignature):
            return False
    except Exception:
        raise VerifierUnavailable() from None
    return True


def _signed(value, this_hash, public_key):
    """True when `value` is the canonical base64 of an Ed25519 signature by public_key over this_hash's ASCII bytes.
    A value that is not canonical base64 is not signed, and the verifier is not touched for it."""
    try:
        signature = base64.b64decode(value, validate=True)
    except ValueError:
        return False
    if base64.b64encode(signature).decode('ascii') != value:
        return False
    return _verified(signature, this_hash.encode('ascii'), public_key)


def _row_valid(row, pins):
    """True when `row` is one contract row, anchored and signed as pinned. Says nothing about which record it is for.
    The shape is checked first, so a row that is not a contract row is False whether or not the signature check can
    be run; VerifierUnavailable is raised only for a row that reaches that check."""
    if type(row) is not dict or row.get('schema_version') not in (ROW_SCHEMA, ROW_SCHEMA_READING):
        return False
    names_reading = row['schema_version'] == ROW_SCHEMA_READING
    if set(row) != (ROW_FIELDS | {'reading_sha256'} if names_reading else ROW_FIELDS):
        return False
    if names_reading and not _hex64(row['reading_sha256']):
        return False
    envelope = row['signature_envelope']
    if not (row['event_type'] == 'kit_record_witnessed'
            and row['authorization'] == 'automated_witness_attestation' and row['record_schema'] == RECORD_SCHEMA
            and row['anchor_hash'] == pins.anchor
            and all(_hex64(row[name]) for name in ('parent_hash', 'record_sha256', 'config_identity', 'this_hash'))
            and type(row['row']) is int and row['row'] >= 1 and _timestamp(row['timestamp'])
            and type(envelope) is dict and set(envelope) == ENVELOPE_FIELDS and envelope['algorithm'] == 'ed25519'
            and envelope['covers'] == COVERS and envelope['signer_key_id'] == 'sha256:' + pins.fingerprint
            and type(envelope['value']) is str):
        return False
    unsigned = {name: value for name, value in row.items() if name not in ('signature_envelope', 'this_hash')}
    if hashlib.sha256(_canonical(unsigned)).hexdigest() != row['this_hash']:
        return False
    return _signed(envelope['value'], row['this_hash'], pins.public_key)


def _checked(receipt_raw, witness_raw, pins):
    """(witness state, the row when the state is WITNESSED else None) of receipt bytes and witness.json bytes."""
    if witness_raw is None:
        return NOT_REQUESTED, None
    try:
        found = json.loads(witness_raw) if len(witness_raw) <= MAX_ROW_BYTES else None
    except (ValueError, RecursionError):
        found = None
    if (type(found) is dict and set(found) == {'state', 'reason'} and found['state'] == 'NOT_WITNESSED'
            and found['reason'] in REASONS[1:-1]):
        return _not(found['reason']), None  # what an earlier request recorded; UNAVAILABLE is never one of them
    try:
        valid = _row_valid(found, pins)
    except VerifierUnavailable:
        return _not(UNAVAILABLE), None
    if not valid:
        return _not('WITNESS_FILE_INVALID'), None
    if _identity(receipt_raw) != (found['record_sha256'], found['config_identity']):
        return _not('WITNESS_NOT_THIS_RECORD'), None
    return {'authenticity': 'WITNESSED', 'reason': None,
            'witness': {'key_fingerprint': pins.fingerprint, 'row': found['row'], 'timestamp': found['timestamp']}}, found


def check(receipt_raw, witness_raw, *, pins=PINS):
    """The witness state of receipt bytes and the bytes of the witness.json beside them (None when there is none):
    {'authenticity': 'WITNESSED', 'witness': {key_fingerprint, row, timestamp}, 'reason': None}, or
    {'authenticity': 'NOT_WITNESSED', 'witness': None, 'reason': one of REASONS}. A row of either schema is accepted.
    It does not raise when the signature check cannot be run here: the reason is then WITNESS_VERIFIER_UNAVAILABLE."""
    return _checked(receipt_raw, witness_raw, pins)[0]


def named_reading(receipt_raw, witness_raw, *, pins=PINS):
    """The reading digest the Witness row names, when the record is WITNESSED by a row of ROW_SCHEMA_READING; else
    None. A row that is not this record's signed row names nothing."""
    row = _checked(receipt_raw, witness_raw, pins)[1]
    return None if row is None else row.get('reading_sha256')


def reading_state(receipt_raw, witness_raw, reading_raw, *, pins=PINS):
    """The state of the reading.json bytes beside a receipt and its witness.json (h0a/reading.py check)."""
    return _reading().check(receipt_raw, reading_raw, named_reading(receipt_raw, witness_raw, pins=pins))[0]


def load(path, limit):
    """Up to limit+1 bytes of the regular file at path (one more than the limit shows it is oversize), else None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            return stream.read(limit + 1)
    except OSError:
        return None


def read(record_dir, *, pins=PINS):
    """check() over the receipt.json and witness.json of a record directory."""
    return check(load(os.path.join(record_dir, RECEIPT), MAX_RECEIPT_BYTES),
                 load(os.path.join(record_dir, WITNESS), MAX_ROW_BYTES), pins=pins)


def default_url(environ=os.environ):
    """The address a command asks when --witness-url is not given: H1R_WITNESS_URL when set, else WITNESS_URL."""
    return environ.get('H1R_WITNESS_URL') or WITNESS_URL


def _post(url, body):
    """The one network call, made in the child process: the answer's first MAX_ROW_BYTES+1 bytes. Any status but 200
    is the witness refusing. https anywhere, with the certificate and host name checked against the system's
    authorities; plain http to this machine only. Any other address raises before a socket is opened, and whatever
    else this cannot do raises too: the child then exits non-zero."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == 'https':
        connection = http.client.HTTPSConnection(parts.hostname, parts.port)
    elif parts.scheme == 'http' and parts.hostname in LOOPBACK:
        connection = http.client.HTTPConnection(parts.hostname, parts.port)
    else:
        raise ValueError('witness address')
    connection.request('POST', parts.path, body, {'Content-Type': 'application/json'})
    response = connection.getresponse()
    return response.read(MAX_ROW_BYTES + 1) if response.status == 200 else REFUSAL


def _ask(url, body):
    """One attempt, stopped at BUDGET_SECONDS in all: the bytes the witness answered, or None when there are none."""
    try:
        done = subprocess.run([sys.executable, '-I', '-B', os.path.abspath(__file__), url], input=body,
                              capture_output=True, timeout=BUDGET_SECONDS, env={}, check=False)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _write(path, raw):
    """Replace path with raw: written 0600 under a temporary name, synced, then renamed over the destination."""
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def record(record_dir, *, url=WITNESS_URL, pins=PINS):
    """Ask the witness to sign this record's digest, keep the outcome in witness.json, and return the state a reader
    of the directory now gets. It never raises for a witness or file failure and never writes receipt.json.
    When the signature check cannot be run here it returns WITNESS_VERIFIER_UNAVAILABLE and writes nothing: a row
    already in witness.json is left as it is and nothing is asked; with no row the import is tried before the
    request, and nothing is asked when it fails; an answer that then cannot be checked is not kept."""
    receipt_raw = load(os.path.join(record_dir, RECEIPT), MAX_RECEIPT_BYTES)
    state = check(receipt_raw, load(os.path.join(record_dir, WITNESS), MAX_ROW_BYTES), pins=pins)
    request = request_bytes(receipt_raw, load(os.path.join(record_dir, READING), MAX_READING_BYTES))
    if state['authenticity'] == 'WITNESSED' or request is None:
        return state
    if state['reason'] == UNAVAILABLE:  # a row is here that this machine cannot check: not asked about, not replaced
        return state
    try:
        _verified(None, None, None)  # before asking: an answer that could not be checked would be no use here
    except VerifierUnavailable:
        return _not(UNAVAILABLE)
    answer = _ask(url, request)
    if answer is None:
        outcome = _not('WITNESS_UNREACHABLE')
    elif answer.rstrip(b'\n') == REFUSAL:
        outcome = _not('WITNESS_REFUSED')
    else:
        outcome = check(receipt_raw, answer, pins=pins)
    if outcome['reason'] == UNAVAILABLE:  # the verifier failed at the check itself: the answer is not kept
        return outcome
    kept = json.loads(answer) if outcome['reason'] is None else {'state': 'NOT_WITNESSED', 'reason': outcome['reason']}
    try:
        _write(os.path.join(record_dir, WITNESS), _canonical(kept) + b'\n')
    except OSError:
        pass
    return read(record_dir, pins=pins)


def fields(state):
    """The two report fields of a state: authenticity, and witness (WITNESSED) or witness_reason (NOT_WITNESSED)."""
    if state['reason'] is None:
        return {'authenticity': state['authenticity'], 'witness': dict(state['witness'])}
    return {'authenticity': state['authenticity'], 'witness_reason': state['reason']}


def sentence(state):
    # Both sentences are the canon wording ruling kw-canon-20261111, word for word; do not reword them here.
    if state['reason'] is None:
        found = state['witness']
        return (f"The signature on Witness row {found['row']} verifies under TELOS Witness key "
                f"{found['key_fingerprint']}, and the row's record digest and configuration identity match this "
                f"record. The row reports {found['timestamp']}; that time is not independently verified. The Witness "
                'received digests, not the record: this does not establish that TELOS observed the run, that the '
                'record existed at that time, or that its contents are true.')
    return (f"This record has no valid matching Witness attestation available here ({state['reason']}). VALID means "
            "the covered record data passed the kit's internal checks; it does not establish who wrote it or that "
            'the record and its hashes were not rewritten together. To request a Witness attestation, run: '
            'run_h1r.py witness <record-dir>.')


def main(argv):
    """python -I run_h1r.py witness <record-dir> [--witness-url URL]: one JSON object on stdout, the sentence on
    stderr. Exit 0 WITNESSED, 1 NOT_WITNESSED (WITNESS_VERIFIER_UNAVAILABLE among its reasons: nothing was kept),
    2 usage or a directory with no readable receipt.json."""
    parser = argparse.ArgumentParser(prog='run_h1r.py witness')
    parser.add_argument('record_dir')
    parser.add_argument('--witness-url', default=default_url())
    args = parser.parse_args(argv)
    if request_bytes(load(os.path.join(args.record_dir, RECEIPT), MAX_RECEIPT_BYTES)) is None:
        print(json.dumps({'ok': False, 'reason': 'record_unreadable'}, sort_keys=True))
        return 2
    state = record(args.record_dir, url=args.witness_url)
    print(json.dumps({'ok': state['reason'] is None, **fields(state)}, sort_keys=True))
    print(sentence(state), file=sys.stderr)
    return 0 if state['reason'] is None else 1


if __name__ == '__main__':
    sys.stdout.buffer.write(_post(sys.argv[1], sys.stdin.buffer.read()))
