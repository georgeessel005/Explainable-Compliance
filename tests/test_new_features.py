"""
test_new_features.py  -  The three controls added with the CompliancePilot reskin.

1. VOLUME SLIDERS. `generate(n, seed, malformed)` is now parameterised by the two
   sidebar sliders ("Synthetic findings to generate", "Deliberately malformed
   records"). The malformed count is clamped to 0..MAX_MALFORMED and selects the
   FIRST N canonical fixtures, so it is deterministic; the valid records are
   untouched by it. The DEFAULT arguments must remain byte-identical to the frozen
   dataset the whole suite pins by SHA-256 -- every count in conftest depends on it.

2. ORGANISATION NAME. `compile_pdf(report, out, organisation=...)` renders the name
   in the report header. Omitting it must be byte-identical to the pre-feature build,
   and a blank/whitespace name normalises to ABSENT (a deliberate backend decision:
   the Streamlit text input yields "" when never filled in, and that must hash the
   same as passing nothing).

3. TAMPER SEAL. `content_digest` / `verify_seal` commit to the organisation name, so
   re-sealing under a different name is detectable -- that is the tamper-evidence
   demonstration the Stage 5 panel advertises.

THE ARTICLE 22 GATE IS UNTOUCHED BY ALL THREE. Nothing here decides a finding, and
the app tests below still walk through the real Stage 4 gate before any PDF exists.

Dataset note: the app NEVER writes data/synthetic/assets.json. At the slider defaults
Stage 1 reads the committed file as-is; at any other setting it generates into a temp
file and loads from there. `python -m src.data.generate_synthetic` remains the sole
writer of the canonical path. No snapshot/restore fixture is needed here any more --
`test_app_sliders_never_write_the_committed_dataset` asserts that directly.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.data.generate_synthetic import (
    MAX_MALFORMED,
    generate,
    write_dataset,
)
from src.ingestion.loader import load_and_validate
from src.models import ComplianceReport, DecisionType
from src.report.integrity import (
    canonical_content,
    content_digest,
    normalise_organisation,
    verify_seal,
)
from src.report.pdf_builder import compile_pdf

from tests.conftest import ASSETS_JSON_SHA256, DATA_PATH
from tests.helpers import extract_pdf_text, make_decision

APP_PATH = Path(__file__).resolve().parents[1] / "streamlit_app.py"

GENERATED_AT = datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc)


def _valid_count(records) -> int:
    """Intended-valid records: the malformed fixtures live in the AST-90xx range."""
    return sum(1 for r in records if str(r.get("asset_id", "")) < "AST-9000")


@pytest.fixture()
def report(findings, explanations):
    """A small, fully-approved, deterministic report (deep-copied: safe to mutate)."""
    chosen = findings[:4]
    fids = {f.finding_id for f in chosen}
    return ComplianceReport(
        report_id="RPT-NEWFEAT-0001",
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


# =================================================================================
# 1. Volume sliders -> generate(n, seed, malformed)
# =================================================================================

def test_default_generate_is_byte_identical_to_the_frozen_dataset(tmp_path):
    """The pinned SHA-256 is the contract every downstream count rests on.

    The sliders default to (120, 7), so the app's Stage 1 regeneration must
    reproduce the committed file exactly.
    """
    out = tmp_path / "assets.json"
    write_dataset(generate(), out)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    assert digest == ASSETS_JSON_SHA256, (
        "default generate() no longer reproduces the frozen dataset -- every count "
        "in conftest.py is now wrong"
    )
    # And explicitly passing the slider defaults is the same thing again.
    out2 = tmp_path / "assets-explicit.json"
    write_dataset(generate(n=120, seed=42, malformed=7), out2)
    assert out2.read_bytes() == out.read_bytes()


def test_malformed_zero_produces_no_rejections(tmp_path):
    path = tmp_path / "clean.json"
    records = generate(n=40, seed=42, malformed=0)
    assert len(records) == 40 == _valid_count(records)
    write_dataset(records, path)

    ingestion = load_and_validate(str(path))
    assert len(ingestion.valid_records) == 40
    assert ingestion.rejected == []


def test_malformed_three_produces_exactly_three_rejections(tmp_path):
    path = tmp_path / "three.json"
    records = generate(n=40, seed=42, malformed=3)
    assert len(records) == 43
    write_dataset(records, path)

    ingestion = load_and_validate(str(path))
    assert len(ingestion.valid_records) == 40
    assert len(ingestion.rejected) == 3


@pytest.mark.parametrize(
    "requested,expected",
    [(99, MAX_MALFORMED), (7, 7), (0, 0), (-5, 0), (MAX_MALFORMED + 1, MAX_MALFORMED)],
)
def test_malformed_count_is_clamped(requested, expected):
    records = generate(n=30, seed=42, malformed=requested)
    assert len(records) - _valid_count(records) == expected


def test_malformed_count_does_not_perturb_the_valid_records():
    """Varying the malformed slider must change only the injected fixtures."""
    baseline = [r for r in generate(n=60, malformed=0)]
    for count in (1, 3, MAX_MALFORMED):
        records = generate(n=60, malformed=count)
        assert [r for r in records if str(r["asset_id"]) < "AST-9000"] == baseline


def test_record_count_slider_scales_the_valid_records():
    for n in (20, 50, 200):
        records = generate(n=n, seed=42, malformed=7)
        assert _valid_count(records) == n
        assert len(records) == n + 7


def test_generation_is_still_seed_deterministic():
    assert generate(n=35, seed=42, malformed=4) == generate(n=35, seed=42, malformed=4)


@pytest.mark.slow
def test_app_sliders_produce_a_correspondingly_sized_run():
    """Driving the real sliders changes the size of the whole Stage 1-3 run."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    # Defaults are the frozen dataset's shape.
    assert at.session_state["n_records"] == 120
    assert at.session_state["n_malformed"] == 7

    at.sidebar.slider(key="n_records").set_value(40)
    at.run()
    at.sidebar.slider(key="n_malformed").set_value(2)
    at.run()

    for button in at.button:
        if "Run Stages 1-3" in (button.label or ""):
            button.click()
            break
    else:  # pragma: no cover - the button must exist
        raise AssertionError("no Stage 1-3 button")
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    result = at.session_state["ingestion_result"]
    assert len(result.valid_records) == 40, "the record slider did not drive Stage 1"
    assert len(result.rejected) == 2, "the malformed slider did not drive Stage 1"

    # Stage 2/3 sized to match: fewer records => strictly fewer findings than the
    # 309 the frozen 120-record dataset yields, and one explanation each.
    findings = at.session_state["findings"]
    assert 0 < len(findings) < 309
    assert len(at.session_state["explanations"]) == len(findings)

    # The audit trail records what was asked for, not just what came back.
    detail = next(
        e.details for e in at.session_state["audit_log"].entries
        if e.action == "STAGE_1_INGESTION"
    )
    assert "n=40" in detail and "malformed=2" in detail


@pytest.mark.slow
def test_zero_malformed_slider_gives_an_empty_rejection_panel():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    at.sidebar.slider(key="n_records").set_value(20)
    at.run()
    at.sidebar.slider(key="n_malformed").set_value(0)
    at.run()
    for button in at.button:
        if "Run Stages 1-3" in (button.label or ""):
            button.click()
            break
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    result = at.session_state["ingestion_result"]
    assert len(result.valid_records) == 20
    assert result.rejected == []
    assert any("No records rejected" in s.value for s in at.success)


@pytest.mark.slow
def test_app_sliders_never_write_the_committed_dataset():
    """The running app must READ data/synthetic/assets.json, never rewrite it.

    That file is git-tracked, is the canonical demo dataset, and is pinned by SHA-256
    in conftest. Regenerating it from the sliders meant that merely moving a slider
    dirtied the repo and broke the pin for every test that ran afterwards. Stage 1 now
    loads the committed file at the default slider values, and generates into the OS
    temp directory at any other value.

    This replaces the snapshot/restore fixture that used to paper over the write.
    """
    from streamlit.testing.v1 import AppTest

    before = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    before_mtime = DATA_PATH.stat().st_mtime_ns
    assert before == ASSETS_JSON_SHA256

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    # Deliberately non-default on BOTH sliders: the regeneration path.
    at.sidebar.slider(key="n_records").set_value(30)
    at.run()
    at.sidebar.slider(key="n_malformed").set_value(4)
    at.run()
    for button in at.button:
        if "Run Stages 1-3" in (button.label or ""):
            button.click()
            break
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    result = at.session_state["ingestion_result"]
    assert len(result.valid_records) == 30
    assert len(result.rejected) == 4

    # The committed file is byte-for-byte untouched, and was not even rewritten with
    # identical bytes (which would still dirty a checkout's timestamps).
    assert hashlib.sha256(DATA_PATH.read_bytes()).hexdigest() == ASSETS_JSON_SHA256
    assert DATA_PATH.stat().st_mtime_ns == before_mtime

    # ...and the run genuinely loaded from somewhere else.
    detail = next(
        e.details for e in at.session_state["audit_log"].entries
        if e.action == "STAGE_1_INGESTION"
    )
    assert "data/synthetic/assets.json" not in detail.replace("\\", "/")


@pytest.mark.slow
def test_default_sliders_load_the_committed_dataset_without_regenerating():
    """At the defaults there is nothing to generate: the committed file IS the dataset."""
    from streamlit.testing.v1 import AppTest

    before_mtime = DATA_PATH.stat().st_mtime_ns

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    assert at.session_state["n_records"] == 120
    assert at.session_state["n_malformed"] == 7
    for button in at.button:
        if "Run Stages 1-3" in (button.label or ""):
            button.click()
            break
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    result = at.session_state["ingestion_result"]
    assert len(result.valid_records) == 120
    assert len(result.rejected) == 7
    assert hashlib.sha256(DATA_PATH.read_bytes()).hexdigest() == ASSETS_JSON_SHA256
    assert DATA_PATH.stat().st_mtime_ns == before_mtime

    detail = next(
        e.details for e in at.session_state["audit_log"].entries
        if e.action == "STAGE_1_INGESTION"
    )
    assert "data/synthetic/assets.json" in detail.replace("\\", "/")


# =================================================================================
# 2. Organisation name in the PDF
# =================================================================================

def test_organisation_is_rendered_in_the_pdf(report, tmp_path):
    out = tmp_path / "org.pdf"
    compile_pdf(report, str(out), organisation="Acme Ltd")
    text = extract_pdf_text(out.read_bytes())
    assert b"Acme Ltd" in text


def test_organisation_none_is_byte_identical_to_omitting_it(report, tmp_path):
    """Existing artefacts must not shift: the feature is additive."""
    without = tmp_path / "without.pdf"
    explicit_none = tmp_path / "none.pdf"
    compile_pdf(report, str(without))
    compile_pdf(report, str(explicit_none), organisation=None)
    assert without.read_bytes() == explicit_none.read_bytes()

    # ...and a report WITH an organisation is genuinely different (so the assertion
    # above is not vacuous).
    named = tmp_path / "named.pdf"
    compile_pdf(report, str(named), organisation="Acme Ltd")
    assert named.read_bytes() != without.read_bytes()


def test_blank_organisation_behaves_exactly_like_none(report, tmp_path):
    """Deliberate backend decision: a blank/whitespace name normalises to ABSENT.

    The Streamlit text input yields "" when the analyst never fills it in, and that
    must not produce a different artefact (or a different seal) from passing nothing.
    """
    assert normalise_organisation("") is None
    assert normalise_organisation("   ") is None
    assert normalise_organisation("  Acme Ltd  ") == "Acme Ltd"

    without = tmp_path / "without.pdf"
    blank = tmp_path / "blank.pdf"
    spaces = tmp_path / "spaces.pdf"
    compile_pdf(report, str(without), organisation=None)
    compile_pdf(report, str(blank), organisation="")
    compile_pdf(report, str(spaces), organisation="   ")
    assert blank.read_bytes() == without.read_bytes()
    assert spaces.read_bytes() == without.read_bytes()

    assert "organisation" not in canonical_content(report, organisation="")
    assert content_digest(report, organisation="") == content_digest(report)
    assert content_digest(report, organisation="   ") == content_digest(report)


def test_pdf_with_organisation_is_still_byte_stable_across_two_builds(
    report, tmp_path
):
    a, b = tmp_path / "a.pdf", tmp_path / "b.pdf"
    compile_pdf(report, str(a), organisation="Acme Ltd")
    compile_pdf(report, str(b), organisation="Acme Ltd")
    assert a.read_bytes() == b.read_bytes()

    # Whitespace around the name is normalised, so it cannot shift the bytes either.
    c = tmp_path / "c.pdf"
    compile_pdf(report, str(c), organisation="  Acme Ltd  ")
    assert c.read_bytes() == a.read_bytes()


def test_pdf_footer_seals_the_organisation(report, tmp_path):
    """The footer digest is the ORGANISATION-AWARE content digest."""
    out = tmp_path / "sealed.pdf"
    compile_pdf(report, str(out), organisation="Acme Ltd")
    text = extract_pdf_text(out.read_bytes())
    assert content_digest(report, organisation="Acme Ltd").encode("ascii") in text
    assert content_digest(report).encode("ascii") not in text


# =================================================================================
# 3. Tamper seal
# =================================================================================

def test_content_digest_unchanged_when_organisation_is_absent(report):
    """Reports sealed before the feature existed must still verify."""
    baseline = content_digest(report)
    assert content_digest(report, organisation=None) == baseline
    assert content_digest(report, organisation="") == baseline
    assert "organisation" not in canonical_content(report)


def test_content_digest_differs_per_organisation(report):
    digest_a = content_digest(report, organisation="A")
    digest_b = content_digest(report, organisation="B")
    assert digest_a != digest_b
    assert digest_a != content_digest(report)
    assert digest_b != content_digest(report)
    # Stable: the same name always hashes the same way.
    assert digest_a == content_digest(report, organisation="A")


def test_verify_seal_true_for_the_sealing_org_false_for_an_edited_one(report):
    sealed = content_digest(report, organisation="Acme Ltd")

    assert verify_seal(report, sealed, organisation="Acme Ltd") is True
    assert verify_seal(report, sealed, organisation="  Acme Ltd  ") is True
    # A single character of drift breaks it.
    assert verify_seal(report, sealed, organisation="Acme Ltd.") is False
    assert verify_seal(report, sealed, organisation="Acme Limited") is False
    # As does dropping the organisation entirely.
    assert verify_seal(report, sealed, organisation=None) is False
    assert verify_seal(report, sealed, organisation="") is False

    # And an unnamed seal still verifies unnamed / blank identically.
    unnamed = content_digest(report)
    assert verify_seal(report, unnamed, organisation=None) is True
    assert verify_seal(report, unnamed, organisation="") is True
    assert verify_seal(report, unnamed, organisation="Acme Ltd") is False


def test_verify_seal_still_catches_content_tampering_under_an_org(report):
    sealed = content_digest(report, organisation="Acme Ltd")
    report.explanations[0].plain_english = "Tampered narrative."
    assert verify_seal(report, sealed, organisation="Acme Ltd") is False


@pytest.mark.slow
def test_app_reports_a_broken_seal_after_the_org_name_is_edited():
    """Seal a report, rename the organisation, and Verify Integrity must say BROKEN.

    Driven entirely through the app: real Stage 1-3 button, the real Stage 4 gate
    (bulk approve writes an individual decision per finding), then the real Stage 5
    compile and Verify Integrity buttons.
    """
    from streamlit.testing.v1 import AppTest

    def button(at, label_part):
        for candidate in at.button:
            if label_part in (candidate.label or ""):
                return candidate
        raise AssertionError(f"No button labelled like {label_part!r}")

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    # A small run: this test is about the seal, not about volume.
    at.sidebar.slider(key="n_records").set_value(20)
    at.run()
    button(at, "Run Stages 1-3").click()
    at.run()
    assert not at.exception, [str(e) for e in at.exception]
    findings = at.session_state["findings"]
    assert findings

    # Stage 4 in full -- the gate is walked, not bypassed.
    button(at, "Approve all unreviewed matching").click()
    at.run()
    assert len(at.session_state["decisions"]) == len(findings)

    at.text_input(key="organisation").set_value("Acme Ltd")
    at.run()
    button(at, "Generate Sealed PDF Report").click()
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    report = at.session_state["report"]
    assert report is not None
    assert at.session_state["sealed_organisation"] == "Acme Ltd"
    sealed = at.session_state["sealed_digest"]
    assert sealed == content_digest(report, organisation="Acme Ltd")

    # Unedited: the seal verifies.
    button(at, "Verify Integrity").click()
    at.run()
    assert at.session_state["seal_check"][0] == "intact"
    assert any("Seal intact" in s.value for s in at.success)

    # Now edit the organisation name -- the classic tamper demonstration.
    at.text_input(key="organisation").set_value("Acme Holdings Ltd")
    at.run()
    button(at, "Verify Integrity").click()
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    assert at.session_state["seal_check"][0] == "broken", (
        "renaming the organisation after sealing must break the seal"
    )
    assert any("SEAL BROKEN" in e.value for e in at.error)
    # The sealed value itself is untouched: verification recomputes, it never re-seals.
    assert at.session_state["sealed_digest"] == sealed
    assert at.session_state["sealed_organisation"] == "Acme Ltd"

    # Both checks are in the audit trail.
    seal_entries = [
        e for e in at.session_state["audit_log"].entries if e.action == "SEAL_VERIFIED"
    ]
    assert len(seal_entries) == 2
