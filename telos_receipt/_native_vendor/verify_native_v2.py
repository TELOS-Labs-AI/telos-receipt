# MIT License
#
# Copyright (c) 2025 Nous Research
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Adapted from the TELOS-Labs-AI/hermes-agent fork.
# Local changes: package-only byte assessment; no host-specific loaders.

"""Bounded native byte integrity; no file discovery, signing or score validation."""
import hashlib
import json
import math
import re

ADAPTER_PIN = '6eb37e9f8018ff98a6d4546f707de17cb64b53038a6d7311bf7ba89ab79e24bf'
MAX_BYTES, MAX_ROW_BYTES, MAX_ROWS = 1048576, 65536, 32


class Refusal(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hexhash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _report(data=None):
    return {'report_version': 'verify.native_v2.integrity.v1', 'integrity_status': 'UNAVAILABLE',
            'consumed': {'receipts': None if data is None else sha(data), 'adapter': ADAPTER_PIN},
            'consumed_byte_lengths': {'receipts': None if data is None else len(data)},
            'per_record': [], 'trust_class': 'UNKNOWN', 'authenticity': 'NOT_CLAIMED',
            'origin': 'NOT_CLAIMED', 'problems': []}


def _problem(report, code, row=None):
    report['problems'].append({'code': code, 'row_index_or_null': row})


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal('DUPLICATE_MEMBER')
        result[key] = value
    return result


def _finite(value):
    n = float(value)
    if not math.isfinite(n):
        raise Refusal('NONFINITE_NUMBER')
    return n


def _constant(value):
    raise Refusal('NONFINITE_NUMBER')


def _json_bounds(value, depth=0):
    if depth > 24:
        raise Refusal('JSON_LIMIT')
    if type(value) in (dict, list):
        if len(value) > 4096:
            raise Refusal('JSON_LIMIT')
        if type(value) is dict:
            for key in value:
                if len(key) > 65536:
                    raise Refusal('JSON_LIMIT')
                key.encode('utf-8')
        for item in (value.values() if type(value) is dict else value):
            _json_bounds(item, depth + 1)
    elif type(value) is str:
        if len(value) > 65536:
            raise Refusal('JSON_LIMIT')
        value.encode('utf-8')


def _proof_present(row):
    gp = row.get('governance_proof', {})
    if type(gp) is not dict:
        raise Refusal('PROOF_SHAPE_INVALID')
    for container in (row, gp):
        if 'signature_available' in container and type(container['signature_available']) is not bool:
            raise Refusal('PROOF_SHAPE_INVALID')
        if any(k in container and type(container[k]) is not str for k in ('signature', 'hmac')):
            raise Refusal('PROOF_SHAPE_INVALID')
    return any('signature' in c or 'hmac' in c or c.get('signature_available') is True for c in (row, gp))


def _validate(raw):
    try:
        row = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_float=_finite, parse_constant=_constant)
        _json_bounds(row)
    except UnicodeError:
        raise Refusal('INVALID_UTF8') from None
    except (ValueError, RecursionError):
        raise Refusal('INVALID_JSON') from None
    if type(row) is not dict:
        raise Refusal('UNSUPPORTED_SCHEMA')
    if 'schema_version' not in row or 'version' not in row:
        raise Refusal('SCHEMA_INVALID')
    if row['schema_version'] != 'telos.operational.tool_call.v2' or type(row['version']) is not int or row['version'] != 2:
        raise Refusal('UNSUPPORTED_SCHEMA')
    strings = ('profile_id', 'tool_name', 'scorer_version')
    native_ids = ('session_id', 'task_id', 'turn_id', 'api_request_id', 'tool_call_id')
    hashes = ('pa_hash', 'config_hash', 'scorer_model_hash', 'canonical_input_hash', 'verdict_hash', 'receipt_hash')
    if any(type(row.get(k)) is not str or not row[k] for k in strings) or any(not hexhash(row.get(k)) for k in hashes):
        raise Refusal('SCHEMA_INVALID')
    if any(type(row.get(k)) is not str for k in native_ids):
        raise Refusal('SCHEMA_INVALID')
    classification = row.get('classification')
    if type(classification) is not dict or any(type(classification.get(k)) is not str for k in ('action_text', 'tool_group', 'risk_tier')) or type(classification.get('is_cross_group')) is not bool:
        raise Refusal('SCHEMA_INVALID')
    if type(row.get('args')) is not dict or type(row.get('verdict')) is not dict:
        raise Refusal('SCHEMA_INVALID')
    previous = row.get('previous_receipt_hash')
    if previous != '' and not hexhash(previous):
        raise Refusal('SCHEMA_INVALID')
    if 'chain_gap' in row and type(row['chain_gap']) is not dict:
        raise Refusal('SCHEMA_INVALID')
    if 'chain_lock_unavailable' in row and type(row['chain_lock_unavailable']) is not bool:
        raise Refusal('SCHEMA_INVALID')
    _proof_present(row)
    return row


def assess_bytes(data, expected_sha256, start_previous, A):
    """Pure assessment; caller supplies exact bytes and the checked native adapter."""
    if type(data) is not bytes:
        report = _report()
        _problem(report, 'INPUT_TYPE'); return report
    report = _report(data)
    if not hexhash(expected_sha256) or (start_previous != 'EMPTY' and not hexhash(start_previous)):
        _problem(report, 'CLI_ARGUMENTS'); return report
    if len(data) > MAX_BYTES:
        _problem(report, 'INPUT_TOO_LARGE'); return report
    if sha(data) != expected_sha256:
        _problem(report, 'RECEIPTS_PIN_MISMATCH'); report['integrity_status'] = 'FAIL'; return report
    if not data:
        _problem(report, 'EMPTY_INPUT'); return report
    rows = data.split(b'\n')
    if rows[-1] == b'':
        rows.pop()
    if len(rows) > MAX_ROWS:
        _problem(report, 'TOO_MANY_ROWS'); return report
    previous, cursor, failed, unavailable, proof = '' if start_previous == 'EMPTY' else start_previous, 0, False, False, False
    report['origin'] = 'INDETERMINATE' if start_previous == 'EMPTY' else 'NOT_CLAIMED'
    for index, content in enumerate(rows, 1):
        end = cursor + len(content) + (1 if cursor + len(content) < len(data) else 0)
        raw = data[cursor:end]
        bound = {'row_index': index, 'byte_start': cursor, 'byte_end': end, 'raw_row_sha256': sha(raw),
                 'consumed_receipts_sha256': report['consumed']['receipts'],
                 'native_checks': dict.fromkeys(('canonical_input_hash', 'verdict_hash', 'receipt_hash', 'previous_receipt_link'), 'INDETERMINATE')}
        cursor = end
        report['per_record'].append(bound)
        try:
            if len(raw) > MAX_ROW_BYTES:
                raise Refusal('ROW_TOO_LARGE')
            if not content.strip():
                raise Refusal('BLANK_ROW')
            row = _validate(raw)
            source = A.inspect_source(raw)
            claims = A.assess_nonbinding_source_claims(source)
            checks = {}
            checks['canonical_input_hash'] = A.verify_canonical_input_hash(source)
            checks['verdict_hash'] = A.verify_verdict_hash(source)
            checks['receipt_hash'] = A.verify_receipt_hash(source)
            checks['previous_receipt_link'] = A.verify_previous_receipt_link(source, previous)
            direct = bound['native_checks']
            reasons = list(claims['reasons'])
            computed = {}
            for field in ('canonical_input_hash', 'verdict_hash', 'receipt_hash'):
                direct[field] = checks[field][field]
                computed[field] = checks[field]['computed_' + field]
                reasons.extend(checks[field]['reasons'])
                if checks[field][field] != 'PASS':
                    failed = True; _problem(report, field.upper() + '_MISMATCH', index)
            direct['previous_receipt_link'] = checks['previous_receipt_link']['previous_receipt_link']
            reasons.extend(checks['previous_receipt_link']['reasons'])
            if previous is None:
                direct['previous_receipt_link'] = 'INDETERMINATE'
                unavailable = True; _problem(report, 'PREDECESSOR_UNAVAILABLE', index)
            elif row['previous_receipt_hash'] != previous and not (
                type(row.get('chain_gap')) is dict
                and row['previous_receipt_hash'] == ''
                and row['chain_gap'].get('reason') in ('read_error', 'no_parseable_predecessor')
            ):
                direct['previous_receipt_link'] = 'FAIL'
                reasons.append('previous-receipt-link-mismatch')
                failed = True; _problem(report, 'PREDECESSOR_MISMATCH', index)
            diagnostic_status = 'source-check-failed' if 'FAIL' in direct.values() else ('UNAVAILABLE' if previous is None else 'source-claims-nonbinding')
            direct['diagnostics'] = {'status': diagnostic_status, 'reasons': sorted(set(reasons)), 'computed_hashes': computed}
            previous = row['receipt_hash']
            if 'chain_gap' in row:
                unavailable = True; _problem(report, 'CHAIN_GAP', index)
            if row.get('chain_lock_unavailable'):
                unavailable = True; _problem(report, 'CHAIN_LOCK_UNAVAILABLE', index)
            proof |= _proof_present(row)
        except Refusal as exc:
            bound['native_checks']['diagnostics'] = {'status': 'UNAVAILABLE', 'reasons': []}
            _problem(report, exc.code, index); unavailable = True; previous = None
        except (ValueError, TypeError, RecursionError, OverflowError):
            bound['native_checks']['diagnostics'] = {'status': 'UNAVAILABLE', 'reasons': []}
            _problem(report, 'NATIVE_CHECK_UNAVAILABLE', index); unavailable = True; previous = None
    report['trust_class'] = 'PROOF_PRESENT_UNVERIFIED' if proof else ('UNKNOWN' if unavailable else 'UNSIGNED')
    report['integrity_status'] = 'FAIL' if failed else ('UNAVAILABLE' if unavailable else 'PASS')
    return report
