"""The README refusal table claims only what the cross-verifier tests cover.

For every row of "What the builders refuse", and for every builder its
"Applies to" cell names, ROW_CASES lists refusal cases that exist in
tests/test_cross_verifier.py. Runs without TELOS_VERIFY: it checks the claim's
bookkeeping, while the cases themselves run against the CLI in that module.
"""

import re
from pathlib import Path

import pytest
import test_cross_verifier as cv

import telos_receipt as t

README = Path(__file__).resolve().parent.parent / "README.md"

RB, AB = "build_receipt", "build_action_receipt"
GENERIC = {c[0] for c in cv.GENERIC_CASES if c[1] == "refuse"}
ACTION = {c[0] for c in cv.ACTION_CASES if c[1] == "refuse"}
ENVELOPE = {c[0] for c in cv.ENVELOPE_CASES if c[1] == "refuse"}
KIND = {"kind-int", "kind-none", "kind-bytes"}  # test_kind_must_be_str_and_telos_verify_agrees
KNOWN = {RB: GENERIC | ENVELOPE | KIND, AB: ACTION | ENVELOPE}

ROW_CASES = {
    "`kind`": {RB: ["kind-int", "kind-none"]},
    "`agent_id`, `engine`": {RB: ["refuse-agent_id-int", "refuse-engine-int"],
                             AB: ["refuse-agent_id-int", "refuse-engine-int"]},
    "`issued_at`": {RB: ["refuse-issued-at-no-zone", "refuse-issued-at-int"],
                    AB: ["refuse-issued-at-no-zone", "refuse-issued-at-int"]},
    "`payload`": {RB: ["refuse-generic-list", "refuse-generic-null"]},
    "`sequence`, `previous_receipt_integrity_hash`": {
        RB: ["refuse-generic-sequence-alone", "refuse-generic-previous-alone",
             "refuse-generic-sequence-bool", "refuse-ag-sequence-alone"]},
    "`action_governed` payload members": {
        RB: ["refuse-ag-empty", "refuse-ag-missing-pa_id", "refuse-ag-undeclared-member"]},
    "`action_params_hash`": {RB: ["refuse-ag-params-hash-form", "refuse-ag-params-hash-int"]},
    "`action_name`": {RB: ["refuse-ag-action_name-int"], AB: ["refuse-action-action_name-int"]},
    "`verdict`": {RB: ["refuse-ag-verdict-ALLOW", "refuse-ag-verdict-int"], AB: ["refuse-action-ALLOW", "refuse-action-verdict-int"]},
    "`composite_score`": {RB: ["refuse-ag-composite-bool"], AB: ["refuse-action-composite-bool"]},
    "`scores`": {RB: ["refuse-ag-scores-list", "refuse-ag-scores-bool", "refuse-ag-scores-empty-label"],
                 AB: ["refuse-action-scores-list", "refuse-action-empty-label"]},
    "`pa_id`": {RB: ["refuse-ag-pa_id-empty", "refuse-ag-pa_id-int"],
                AB: ["refuse-action-pa_id-empty", "refuse-action-pa_id-int"]},
    "every payload number": {RB: ["refuse-generic-domain-int", "refuse-generic-domain-negative-zero",
                                  "refuse-ag-domain-float"],
                             AB: ["refuse-action-1e-05", "refuse-action-2pow60"]},
    "every payload string and key": {RB: ["refuse-generic-surrogate-value", "refuse-generic-surrogate-key"],
                                     AB: ["refuse-action-surrogate-label",
                                          "refuse-action-surrogate-action_name"]},
}


def _table_rows():
    text = README.read_text()
    section = text.split("### What the builders refuse", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and cells[0] not in ("Input", "---"):
            rows.append((cells[0], cells[3], cells[4]))
    return rows


def _builders(applies):
    names = set(re.findall(r"build_action_receipt|build_receipt", applies))
    if applies.startswith("both"):
        names = {RB, AB}
    return names


def test_table_parses_and_every_row_is_mapped():
    rows = _table_rows()
    assert len(rows) == len(ROW_CASES)
    assert {r[0] for r in rows} == set(ROW_CASES)


def test_every_row_has_a_refusal_case_for_each_builder_it_names():
    rows = _table_rows()
    assert rows
    for row, applies, _raises in rows:
        builders = _builders(applies)
        assert builders, row
        assert set(ROW_CASES[row]) == builders, (row, applies)
        for builder, cases in ROW_CASES[row].items():
            assert cases, (row, builder)
            for case in cases:
                assert case in KNOWN[builder], (row, builder, case)


def _build(builder, case):
    """Run the named refusal case's builder call, without the CLI."""
    if case.startswith("kind-"):
        kind = {"kind-int": 7, "kind-none": None, "kind-bytes": b"note"}[case]
        return t.build_receipt(kind, {"v": 1}, "demo-agent", issued_at=cv.ISSUED)
    for c, _e, kind, payload in cv.GENERIC_CASES:
        if c == case and builder == RB:
            return t.build_receipt(kind, payload, "demo-agent", issued_at=cv.ISSUED)
    for c, _e, override in cv.ACTION_CASES:
        if c == case and builder == AB:
            return t.build_action_receipt(**{**cv.ACTION, **override})
    for c, _e, override in cv.ENVELOPE_CASES:
        if c == case:
            env = {"agent_id": "demo-agent", "issued_at": cv.ISSUED, "engine": t.ENGINE_LABEL, **override}
            if builder == RB:
                return t.build_receipt("action_governed", cv.AG, env["agent_id"],
                                       issued_at=env["issued_at"], engine=env["engine"])
            return t.build_action_receipt(**{**cv.ACTION, **env})
    raise AssertionError(f"no case {case} for {builder}")


def _raised(builder, case):
    with pytest.raises(Exception) as info:  # the class raised is what is under test
        _build(builder, case)
    return info.type.__name__


def test_raises_column_names_exactly_the_classes_the_cases_raise():
    # Each row's "Raises" cell must name every exception class its mapped cases
    # raise, and nothing they do not; so a mixed cell needs a case for each class.
    rows = _table_rows()
    assert rows
    for row, _applies, raises in rows:
        claimed = set(re.findall(r"`(TypeError|ValueError)`", raises))
        assert claimed, row
        seen = {_raised(b, c) for b, cases in ROW_CASES[row].items() for c in cases}
        assert seen == claimed, (row, raises, seen)
    text = README.read_text()
    assert "A wrong type raises `TypeError`; a value outside the rule raises `ValueError`." not in text


def _message(builder, case):
    with pytest.raises((TypeError, ValueError)) as info:
        _build(builder, case)
    return str(info.value)


def test_every_mapped_refusal_message_starts_with_its_rows_check_id():
    rows = _table_rows()
    assert rows
    text = README.read_text()
    for row, _applies, _raises in rows:
        line = next(ln for ln in text.splitlines() if ln.startswith(f"| {row} |"))
        ids = re.findall(r"TV-[A-Z0-9]+-\d{3}", line.split("|")[3])
        assert ids, row
        for builder, cases in ROW_CASES[row].items():
            for case in cases:
                msg = _message(builder, case)
                assert any(msg.startswith(f"{i}:") for i in ids), (row, case, msg)


# Raised while canonicalizing the payload for hashing (compute_integrity_hash),
# before any table check runs. These carry no verifier check id, and the README
# must say so rather than promise one.
CANON_ERRORS = [
    (RB, lambda: t.build_receipt("note", {"v": {1}}, "a", issued_at=cv.ISSUED), TypeError),
    (RB, lambda: t.build_receipt("note", {"v": float("nan")}, "a", issued_at=cv.ISSUED), ValueError),
    (RB, lambda: t.build_receipt("action_governed", {**cv.AG, "scores": {7: 0.5}}, "a",
                                 issued_at=cv.ISSUED), TypeError),
    (AB, lambda: t.build_action_receipt(**{**cv.ACTION, "scores": {7: 0.5}}), TypeError),
    (AB, lambda: t.build_action_receipt(**{**cv.ACTION, "composite_score": float("inf")}), ValueError),
]


@pytest.mark.parametrize("builder, call, exc", CANON_ERRORS)
def test_canonicalization_errors_carry_no_check_id_and_readme_says_so(builder, call, exc):
    # Valid neighbour: the same builder succeeds on an ordinary input.
    if builder == RB:
        t.build_receipt("action_governed", cv.AG, "a", issued_at=cv.ISSUED)
    else:
        t.build_action_receipt(**cv.ACTION)
    with pytest.raises(exc) as info:
        call()
    assert "TV-" not in str(info.value)
    text = " ".join(README.read_text().split())
    assert "Both classes carry the verifier check id" not in text
    assert "carry no check id" in text
