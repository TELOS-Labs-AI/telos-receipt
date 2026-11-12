"""The saved reading of a first-run record: `reading.json` beside `receipt.json`, composed once when the run closes.

The reading is the kit's plain-language account of one receipt. `compose` is a pure function of the receipt bytes
and the sentence stock: it reads no clock, no environment and no other file, and makes no model or network call.
Every sentence comes from the stock file (`reading_stock.json`, beside this module) by key; a value from the record
enters a sentence only through a named placeholder, with control characters removed and at most MAX_VALUE
characters, a cut value ending in CUT. A value outside its known set is shown behind RECORDED and never interpreted.

The file names the runtime digest its receipt declares. That is a declared association: it does not show who wrote
the file or that its text was derived correctly, and `stock_sha256` is a declared identifier nobody checks here. A
reader (`check`, `view`) accepts the file's shape and limits and compares that digest, nothing more, and never
composes: a record without an accepted file has no reading to show.

A Witness row of the second row schema names a reading digest beside the record's (h0a/witness.py). When such a row
is this record's, the caller passes that digest as `named`: the file reads WITNESSED when its exact bytes have that
digest and it would otherwise read SAVED, and CHANGED in every other case, the file being absent included. A
CHANGED file's lines are never returned.

LIMIT is the limit sentence of schema h0a.reading/1, a constant of that schema version and the one sentence kept
outside the stock file. A /1 file carrying any other limit is not a /1 file, whatever the stock file says today;
another limit sentence needs another schema version.

Standard library only at import, so a reader loaded by its path can load this file the same way. `compose` imports
the receipt reader when it is called.
"""
import hashlib
import json
import os
from pathlib import Path
import re

SCHEMA = 'h0a.reading/1'
LIMIT = (
    'This is TES’s saved reading of the record, not a new measurement or a judgment beyond what the record supports.')
RECEIPT_SCHEMA = 'h0a.receipt/1'
STOCK_SCHEMA = 'h0a.reading-stock/1'
READING = 'reading.json'
STOCK = Path(__file__).with_name('reading_stock.json')
FIELDS = frozenset({'schema', 'receipt_schema', 'receipt_runtime_sha256', 'stock_sha256', 'lines', 'limit'})
LINE_FIELDS = frozenset({'part', 'key', 'text'})
FRAME = ('heading', 'description', 'lead_in')
MAX_BYTES = 32768
MAX_STOCK_BYTES = 65536
MAX_RECEIPT_BYTES = 1048576  # h0a.receipt.MAX_BYTES
MAX_LINES = 200
MAX_TEXT = 600
MAX_VALUE = 200
PARTS = 7
CUT = ' […]'
RECORDED = 'Recorded value: '
SAVED, ABSENT, OTHER, INVALID = 'READING_SAVED', 'READING_ABSENT', 'READING_NOT_THIS_RECORD', 'READING_INVALID'
WITNESSED, CHANGED = 'READING_WITNESSED', 'READING_CHANGED'
# The stock sentence a viewer shows beside each state.
NOTES = {SAVED: 'binding_note', ABSENT: 'reading_absent', OTHER: 'reading_other', INVALID: 'reading_invalid',
         WITNESSED: 'binding_witnessed', CHANGED: 'reading_changed'}
LABELS = ('ALLOW', 'REVIEW', 'DENY', 'UNKNOWN')
DECISIONS = ('CONFIRM', 'REFUSE')
DISPOSITIONS = ('ALLOW', 'DENY', 'ERROR')
COVERAGES = ('COMPLETE_FOR_DECLARED_PROFILE', 'GAPS')
REVIEWS = ('MISSING', 'ACCEPT', 'HOLD', 'REJECT')
OUTCOMES = {'COMPLETED': 'outcome_completed', 'FAILED': 'outcome_failed', 'REFUSED': 'outcome_refused',
            'UNKNOWN': 'outcome_unknown'}
_HEX64 = re.compile(r'[0-9a-f]{64}')
_KEY = re.compile(r'[a-z_]{1,64}')
_SLOT = re.compile(r'\{([a-z_]+)\}')
# C0 and C1 controls, zero-width and direction marks, line and paragraph separators, the byte-order mark, surrogates.
_CONTROL = re.compile('[\x00-\x1f\x7f-\x9f​-‏ -‮⁠-⁯﻿\ud800-\udfff]')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _hex64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _pairs(items):
    found = dict(items)
    if len(found) != len(items):
        raise ValueError('duplicate JSON field')
    return found


def runtime_digest(receipt_raw):
    """The runtime digest these receipt bytes declare (their `runtime_sha256`), or None when they declare none."""
    try:
        if len(receipt_raw) > MAX_RECEIPT_BYTES:
            return None
        found = json.loads(receipt_raw)['runtime_sha256']
    except (ValueError, TypeError, KeyError, RecursionError):
        return None
    return found if _hex64(found) else None


def stock(raw):
    """The sentence stock these bytes hold. ValueError when they are not one h0a.reading-stock/1 file."""
    try:
        found = json.loads(raw) if len(raw) <= MAX_STOCK_BYTES else None
    except RecursionError:
        found = None
    if not (type(found) is dict and found.get('schema') == STOCK_SCHEMA and type(found.get('lines')) is dict
            and all(type(text) is str for text in found['lines'].values())
            and all(type(found.get(name)) is str for name in FRAME + ('limit',))):
        raise ValueError('sentence stock')
    return found


def _stock_bytes():
    with open(STOCK, 'rb') as stream:
        return stream.read(MAX_STOCK_BYTES + 1)


def _shown(value, known=None):
    """A record-supplied value as it enters a sentence: cleaned, marked when outside `known`, cut at MAX_VALUE."""
    text = _CONTROL.sub('', value if type(value) is str else json.dumps(value, sort_keys=True))
    if known is not None and value not in known:
        text = RECORDED + text
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE - len(CUT)] + CUT


def _select(report, receipt_raw):
    """[(part, stock key, {placeholder: value})] for a receipt and its check report, parts in order."""
    if report['structure'] != 'VALID':
        return [(1, 'run_invalid', {}), (PARTS, 'next_caution', {})]
    events = json.loads(receipt_raw)['runtime']['events']
    config = [e['payload']['config'] for e in events if e['kind'] == 'CONFIGURED'][-1]
    decisions = [e['payload']['decision'] for e in events if e['kind'] == 'CONFIGURATION_DECISION']
    actions = {}
    for e in events:
        if e['action_id'] is None:
            continue
        a = actions.setdefault(e['action_id'], {'measured': None, 'asked': False, 'approved': None, 'outcome': None,
                                                'post': None})
        kind, payload = e['kind'], e['payload']
        if kind == 'EVALUATED':
            a['measured'] = payload['label']
        elif kind == 'APPROVAL_PENDING':
            a['asked'] = True
        elif kind == 'APPROVAL_RESOLVED':
            a['asked'], a['approved'] = True, payload['approved']
        elif kind in OUTCOMES:
            a['outcome'] = kind
        elif kind == 'POST_CHECK':
            a['post'] = payload['disposition']
    job = config.get('job')
    lines = [(1, 'run_closed', {'work_id': _shown(config['work_id'])}),
             (2, 'task', {'job': _shown(job)}) if type(job) is str and job.strip() else (2, 'task_absent', {})]
    if not _hex64(config.get('purpose_hash')):
        lines.append((2, 'purpose_absent', {}))
    if decisions:
        lines.append((2, 'setup_decision', {'decision': _shown(decisions[-1], DECISIONS)}))
    count = len(actions)
    heads = [{'i': str(i), 'n': str(count), 'action_id': _shown(action_id)} for i, action_id in enumerate(actions, 1)]
    lines.append((3, 'steps_none' if count == 0 else 'steps_one' if count == 1 else 'steps_many', {'n': str(count)}))
    lines += [(3, 'step_head', head) for head in heads]
    # Parts stay in order, so with several actions each one's lines in parts 4 and 5 follow its own step_head again.
    for head, a in zip(heads, actions.values()):
        if count > 1:
            lines.append((4, 'step_head', head))
        lines.append((4, 'measured_absent', {}) if a['measured'] is None
                     else (4, 'measured', {'label': _shown(a['measured'], LABELS)}))
    for head, a in zip(heads, actions.values()):
        if count > 1:
            lines.append((5, 'step_head', head))
        lines.append((5, 'approval_asserted' if a['approved'] is True else
                      'approval_unresolved' if a['asked'] else 'approval_absent', {}))
        lines.append((5, OUTCOMES.get(a['outcome'], 'outcome_absent'), {}))
        lines.append((5, 'post_check_absent', {}) if a['post'] is None
                     else (5, 'post_check', {'disposition': _shown(a['post'], DISPOSITIONS)}))
    unknown = any(a['outcome'] in (None, 'UNKNOWN') for a in actions.values())
    return lines + [(6, 'coverage', {'coverage': _shown(report['coverage'], COVERAGES),
                                     'human_review': _shown(report['human_review'], REVIEWS)}),
                    (6, 'not_shown', {}), (6, 'witness_elsewhere', {}),
                    (PARTS, 'next_unknown' if unknown else 'next_none', {}), (PARTS, 'next_caution', {})]


def compose(receipt_bytes, stock_bytes):
    """The bytes of reading.json for these receipt bytes and these stock-file bytes: canonical JSON, the same bytes
    for the same inputs. ValueError when the stock is not a /1 stock carrying the /1 limit and every sentence the
    receipt selects, when the receipt declares no runtime digest, or when the result would pass a limit of the file."""
    from h0a import receipt
    found = stock(stock_bytes)
    digest = runtime_digest(receipt_bytes)
    if found['limit'] != LIMIT or digest is None:
        raise ValueError('reading cannot be composed')
    try:
        lines = [{'part': part, 'key': key, 'text': _SLOT.sub(lambda slot: values[slot.group(1)], found['lines'][key])}
                 for part, key, values in _select(receipt.check_receipt(receipt_bytes), receipt_bytes)]
    except KeyError:  # a sentence or a placeholder the stock and this composer do not share
        raise ValueError('sentence stock') from None
    raw = _canonical({'schema': SCHEMA, 'receipt_schema': RECEIPT_SCHEMA, 'receipt_runtime_sha256': digest,
                      'stock_sha256': hashlib.sha256(stock_bytes).hexdigest(), 'lines': lines, 'limit': LIMIT})
    if _accepted(raw) is None:
        raise ValueError('reading outside its limits')
    return raw


def save(record_dir, receipt_raw):
    """Compose the reading of these receipt bytes with the kit's stock and write it as reading.json in record_dir:
    0600 under a temporary name, synced, then renamed. One attempt. It raises when it cannot, leaving no file of
    its own behind; the caller decides that a record then simply has no reading."""
    raw = compose(receipt_raw, _stock_bytes())
    path = os.path.join(record_dir, READING)
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _accepted(raw):
    """The reading these bytes hold when they are one h0a.reading/1 file within its limits, else None."""
    try:
        if len(raw) > MAX_BYTES:
            return None
        found = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    except (ValueError, RecursionError):
        return None
    if not (type(found) is dict and set(found) == FIELDS and found['schema'] == SCHEMA
            and found['receipt_schema'] == RECEIPT_SCHEMA and _hex64(found['receipt_runtime_sha256'])
            and _hex64(found['stock_sha256']) and found['limit'] == LIMIT
            and type(found['lines']) is list and 1 <= len(found['lines']) <= MAX_LINES):
        return None
    last = 1
    for line in found['lines']:
        if not (type(line) is dict and set(line) == LINE_FIELDS and type(line['part']) is int
                and last <= line['part'] <= PARTS and type(line['key']) is str and _KEY.fullmatch(line['key'])
                and type(line['text']) is str and 1 <= len(line['text']) <= MAX_TEXT):
            return None
        last = line['part']
    return found


def check(receipt_raw, reading_raw, named=None):
    """(state, lines, limit) of receipt bytes and the bytes of the reading.json beside them (None when there is
    none). `named` is the reading digest this record's Witness row names, None when no such row applies. The lines
    and the limit are the file's own, and only in states SAVED and WITNESSED; otherwise ([], None)."""
    found = None if reading_raw is None else _accepted(reading_raw)
    if reading_raw is None:
        state = ABSENT
    elif found is None:
        state = INVALID
    elif found['receipt_runtime_sha256'] != runtime_digest(receipt_raw):
        state = OTHER
    else:
        state = SAVED
    if named is not None:
        state = WITNESSED if state == SAVED and hashlib.sha256(reading_raw).hexdigest() == named else CHANGED
    if state not in (SAVED, WITNESSED):
        return state, [], None
    return state, found['lines'], found['limit']


def view(receipt_raw, reading_raw, named=None):
    """What a viewer shows for a record: ({state, lines, limit, note}, {heading, description, lead_in}). The note
    and the frame are today's stock sentences; the lines and the limit are the saved file's. (None, None) when this
    kit's stock file cannot be read: the viewer then shows the record without a reading."""
    state, lines, limit = check(receipt_raw, reading_raw, named)
    try:
        found = stock(_stock_bytes())
        note = found['lines'][NOTES[state]]
    except (OSError, ValueError, KeyError):
        return None, None
    return ({'state': state, 'lines': lines, 'limit': limit, 'note': note}, {name: found[name] for name in FRAME})
