"""
test_report.py  -  Stage 5: PDF compilation and SHA-256 integrity.

TWO DIGESTS EXIST BY DESIGN -- do not conflate them:
* report.sha256_hash        = sha256_of_file(pdf)   -- the ARTEFACT (file) digest.
* the PDF footer carries      content_digest(report) -- the canonical committed-
  content digest, computable before the file exists.
A file cannot contain its own hash (fixed-point impossibility), so asserting the
file digest appears inside the PDF is unsatisfiable by construction. The footer
assertion below therefore targets content_digest.

Byte-stability is real and load-bearing: Agent 3 pinned ReportLab via invariant=1
plus SOURCE_DATE_EPOCH derived from report.generated_at, so two builds of the same
report object are byte-identical. That is asserted here, as is the converse: change
a committed field and both digests change.

PDF stream note: invariant-mode streams are /Filter [/ASCII85Decode /FlateDecode];
tests/helpers.extract_pdf_text ASCII85-decodes BEFORE inflating.

No src/ file was patched for these tests.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from src.report.integrity import (
    canonical_content,
    canonical_content_bytes,
    content_digest,
    effective_explanation_text,
    is_committed,
    is_escalated,
    sha256_of_bytes,
    sha256_of_file,
    stamp_report_hash,
)
from src.report.pdf_builder import build_and_hash, compile_pdf
from src.models import ComplianceReport, DecisionType

from tests.helpers import extract_pdf_text, make_decision

GENERATED_AT = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)


def _small_report(findings, explanations, count=6, report_id="RPT-TEST-0001"):
    """A deterministic report over the first `count` findings, all approved.
    Deep-copies so tests can mutate freely without touching the session fixtures."""
    chosen = findings[:count]
    fids = {f.finding_id for f in chosen}
    report = ComplianceReport(
        report_id=report_id,
        generated_at=GENERATED_AT,
        findings=[f.model_copy(deep=True) for f in chosen],
        explanations=[
            e.model_copy(deep=True) for e in explanations if e.finding_id in fids
        ],
        decisions=[
            make_decision(f.finding_id, DecisionType.APPROVE, minute=i)
            for i, f in enumerate(chosen)
        ],
    )
    return report


@pytest.fixture()
def report(findings, explanations):
    return _small_report(findings, explanations)


# ---------------------------------------------------------------------------------
# Basic artefact
# ---------------------------------------------------------------------------------

def test_compile_pdf_writes_a_real_pdf(report, tmp_path):
    out = tmp_path / "nested" / "dir" / "report.pdf"  # parent dirs get created
    returned = compile_pdf(report, str(out))
    assert returned == str(out)
    data = out.read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000


# ---------------------------------------------------------------------------------
# Determinism: byte-identical rebuilds
# ---------------------------------------------------------------------------------

def test_pdf_bytes_stable_across_two_builds(report, tmp_path):
    """Same report object -> byte-identical PDFs -> equal file digests."""
    p1, p2 = tmp_path / "a.pdf", tmp_path / "b.pdf"
    compile_pdf(report, str(p1))
    compile_pdf(report, str(p2))
    b1, b2 = p1.read_bytes(), p2.read_bytes()
    assert b1 == b2
    assert sha256_of_file(str(p1)) == sha256_of_file(str(p2))


def test_content_digest_stable_and_order_insensitive(report):
    d1 = content_digest(report)
    d2 = content_digest(report)
    assert d1 == d2
    # Canonical serialisation sorts by finding_id: input order must not matter.
    shuffled = report.model_copy(deep=True)
    shuffled.findings = list(reversed(shuffled.findings))
    shuffled.explanations = list(reversed(shuffled.explanations))
    shuffled.decisions = list(reversed(shuffled.decisions))
    assert content_digest(shuffled) == d1


def test_changing_a_committed_field_changes_both_digests(report, tmp_path):
    p1, p2 = tmp_path / "orig.pdf", tmp_path / "tampered.pdf"
    compile_pdf(report, str(p1))
    original_content = content_digest(report)

    tampered = report.model_copy(deep=True)
    tampered.decisions[0].analyst_note = "tampered after the fact"
    compile_pdf(tampered, str(p2))

    assert content_digest(tampered) != original_content
    assert p1.read_bytes() != p2.read_bytes()
    assert sha256_of_file(str(p1)) != sha256_of_file(str(p2))


def test_changing_explanation_text_changes_content_digest(report):
    original = content_digest(report)
    tampered = report.model_copy(deep=True)
    tampered.explanations[0].plain_english += " (altered)"
    assert content_digest(tampered) != original


# ---------------------------------------------------------------------------------
# The two-digest design
# ---------------------------------------------------------------------------------

def test_footer_carries_content_digest_not_file_digest(report, tmp_path):
    """The PDF text must contain content_digest(report). It CANNOT contain its own
    file digest -- that would be a hash fixed-point, which does not exist."""
    out = tmp_path / "footer.pdf"
    compile_pdf(report, str(out))
    pdf_bytes = out.read_bytes()
    text = extract_pdf_text(pdf_bytes)

    expected = content_digest(report)
    assert expected.encode("ascii") in text

    file_digest = sha256_of_bytes(pdf_bytes)
    assert file_digest.encode("ascii") not in text
    assert file_digest != expected


def test_build_and_hash_stamps_file_digest_onto_report(report, tmp_path):
    out = tmp_path / "stamped.pdf"
    digest = build_and_hash(report, str(out))
    assert report.sha256_hash == digest
    assert report.pdf_path == str(out)
    assert digest == sha256_of_file(str(out))
    assert len(digest) == 64 and int(digest, 16) >= 0
    # report.sha256_hash is the FILE digest; the footer's content digest differs.
    assert digest != content_digest(report)


def test_stamp_report_hash_matches_build_and_hash(report, tmp_path):
    out = tmp_path / "manual.pdf"
    compile_pdf(report, str(out))
    digest = stamp_report_hash(report, str(out))
    assert digest == sha256_of_file(str(out)) == report.sha256_hash


# ---------------------------------------------------------------------------------
# Committed-content semantics
# ---------------------------------------------------------------------------------

def test_escalated_and_undecided_findings_are_excluded_from_content(
    findings, explanations
):
    report = _small_report(findings, explanations, count=4)
    # Finding 0 escalated (later than its approve), finding 3 left undecided.
    escalated_id = report.findings[0].finding_id
    undecided_id = report.findings[3].finding_id
    report.decisions = [
        d for d in report.decisions if d.finding_id != undecided_id
    ] + [make_decision(escalated_id, DecisionType.ESCALATE, minute=90)]

    content = canonical_content(report)
    committed_ids = {c["finding_id"] for c in content["committed_findings"]}
    assert escalated_id not in committed_ids
    assert undecided_id not in committed_ids
    assert set(content["excluded_finding_ids"]) == {escalated_id, undecided_id}


def test_modified_explanation_overrides_generated_text(findings, explanations):
    report = _small_report(findings, explanations, count=2)
    target = report.findings[0].finding_id
    report.decisions = [
        make_decision(
            target, DecisionType.MODIFY, minute=1,
            modified_explanation="Analyst-corrected wording.",
        ),
        make_decision(report.findings[1].finding_id, DecisionType.APPROVE, minute=2),
    ]
    content = canonical_content(report)
    entry = next(
        c for c in content["committed_findings"] if c["finding_id"] == target
    )
    assert entry["explanation"] == "Analyst-corrected wording."


def test_is_committed_and_is_escalated_semantics():
    approve = make_decision("F-X", DecisionType.APPROVE)
    modify = make_decision("F-X", DecisionType.MODIFY)
    escalate = make_decision("F-X", DecisionType.ESCALATE)
    assert is_committed(approve) and is_committed(modify)
    assert not is_committed(escalate) and not is_committed(None)
    assert is_escalated(escalate)
    assert not is_escalated(approve) and not is_escalated(None)


def test_effective_explanation_text_rules(explanations):
    explanation = explanations[0]
    fid = explanation.finding_id
    assert (
        effective_explanation_text(explanation, make_decision(fid, DecisionType.APPROVE))
        == explanation.plain_english
    )
    modified = make_decision(
        fid, DecisionType.MODIFY, modified_explanation="Override."
    )
    assert effective_explanation_text(explanation, modified) == "Override."
    # MODIFY with blank replacement falls back to the generated text.
    blank = make_decision(fid, DecisionType.MODIFY, modified_explanation="   ")
    assert effective_explanation_text(explanation, blank) == explanation.plain_english


# ---------------------------------------------------------------------------------
# Hash primitives
# ---------------------------------------------------------------------------------

def test_sha256_primitives_match_hashlib(tmp_path):
    payload = b"compliance-tool integrity check"
    assert sha256_of_bytes(payload) == hashlib.sha256(payload).hexdigest()
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)
    assert sha256_of_file(str(path)) == hashlib.sha256(payload).hexdigest()


def test_canonical_content_bytes_deterministic(report):
    assert canonical_content_bytes(report) == canonical_content_bytes(report)
