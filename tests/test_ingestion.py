"""
test_ingestion.py  -  Stage 1: loading, validation, rejection, generator determinism.

Ground truth: data/synthetic/assets.json holds 127 records -- 120 valid + 7
deliberately malformed, one per rejection path, INTERLEAVED mid-stream (stride 15)
so Stage 1 is demonstrably recovering mid-file rather than trimming a trailing block.

`generate(n=120)` returning 127 dicts is intentional (orchestrator ruling): n counts
VALID records, the 7 malformed fixtures are additional. Do not "fix" that here.
`generate()` is pure -- `main()` is the sole writer of assets.json.

No src/ file was patched for these tests.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from src.data.generate_synthetic import generate
from src.ingestion.loader import load_and_validate
from src.models import AssetRecord, IngestionResult

from tests.conftest import ASSETS_JSON_SHA256, DATA_PATH, REFERENCE_ASSET_IDS


# ---------------------------------------------------------------------------------
# The frozen dataset
# ---------------------------------------------------------------------------------

def test_dataset_hash_is_pinned():
    """assets.json must be the frozen Agent 1 output; regeneration drift fails here."""
    digest = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    assert digest == ASSETS_JSON_SHA256


def test_counts_120_valid_7_rejected(ingestion: IngestionResult):
    assert len(ingestion.valid_records) == 120
    assert len(ingestion.rejected) == 7
    assert len(ingestion.valid_records) + len(ingestion.rejected) == 127


def test_valid_count_meets_brief_minimum(ingestion: IngestionResult):
    """The brief requires 100+ valid records."""
    assert len(ingestion.valid_records) >= 100


def test_valid_records_are_typed_asset_records(ingestion: IngestionResult):
    assert all(isinstance(r, AssetRecord) for r in ingestion.valid_records)
    # Every valid record is fully usable downstream: id, date and issue codes present.
    for record in ingestion.valid_records:
        assert record.asset_id.startswith("AST-")
        assert record.assessment_date is not None
        assert record.issue_codes, f"{record.asset_id} has no issue codes"


def test_every_rejection_has_reason_and_original_payload(ingestion: IngestionResult):
    for rejection in ingestion.rejected:
        assert rejection.reason and rejection.reason.strip()
        assert isinstance(rejection.raw, dict) and rejection.raw


def test_all_seven_rejection_paths_are_exercised(ingestion: IngestionResult):
    """One rejected record per Stage 1 rejection path, each with a reason that names
    the offending field. Keyed by the malformed fixtures' asset ids (AST-9001..9007)."""
    by_id = {r.raw.get("asset_id"): r.reason for r in ingestion.rejected}
    expected_reason_fragment = {
        "AST-9001": "cve_id",             # malformed CVE identifier
        "AST-9002": "cvss_score",         # CVSS > 10
        "AST-9003": "issue_codes",        # unknown issue code
        "AST-9004": "hostname",           # missing required field
        "AST-9005": "owner_team",         # extra key on AssetRecord (extra=forbid)
        "AST-9006": "exploit_available",  # extra key on RawVulnerability (extra=forbid)
        "AST-9007": "assessment_date",    # unparseable date
    }
    assert set(by_id) == set(expected_reason_fragment)
    for asset_id, fragment in expected_reason_fragment.items():
        assert fragment in by_id[asset_id], (
            f"{asset_id}: rejection reason does not name '{fragment}': {by_id[asset_id]}"
        )


def test_malformed_records_are_interleaved_not_appended():
    """The 7 bad records sit mid-stream (deterministic stride), never as a trailing
    block -- Stage 1 must be shown recovering and continuing."""
    payload = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    assert len(payload) == 127
    bad_positions = [
        i for i, rec in enumerate(payload)
        if str(rec.get("asset_id", "")).startswith("AST-9")
    ]
    assert len(bad_positions) == 7
    # Not appended: every malformed record has valid records after it.
    assert max(bad_positions) < 120
    # And genuinely spread out, not clustered at one point.
    gaps = [b - a for a, b in zip(bad_positions, bad_positions[1:])]
    assert all(gap >= 2 for gap in gaps)


# ---------------------------------------------------------------------------------
# Reference (FINDING #017) assets at the data level
# ---------------------------------------------------------------------------------

def test_reference_assets_present_and_shaped_correctly(ingestion: IngestionResult):
    """8 reference assets: internet-facing Ubuntu, one unpatched CVSS 9.8 CVE whose
    vendor patch is exactly 14 days old at assessment, PATCH_MISSING emitted."""
    by_id = {r.asset_id: r for r in ingestion.valid_records}
    for asset_id in REFERENCE_ASSET_IDS:
        record = by_id[asset_id]
        assert record.internet_facing is True
        assert "Ubuntu" in record.operating_system
        assert "PATCH_MISSING" in [c.value for c in record.issue_codes]
        reference_vulns = [
            v for v in record.vulnerabilities
            if v.cvss_score == 9.8 and not v.patch_applied
        ]
        assert len(reference_vulns) == 1, f"{asset_id}: expected exactly one 9.8 CVE"
        vuln = reference_vulns[0]
        assert vuln.days_since_patch(record.assessment_date) == 14


# ---------------------------------------------------------------------------------
# Loader robustness (never crashes on bad input)
# ---------------------------------------------------------------------------------

def test_loader_never_crashes_on_garbage_entries(tmp_path):
    """Scalars, nulls, empty dicts and wrongly-typed dicts are all rejected with a
    reason -- none of them raise."""
    garbage = [42, "not-a-record", None, {}, {"asset_id": 123}, [1, 2]]
    path = tmp_path / "garbage.json"
    path.write_text(json.dumps(garbage), encoding="utf-8")

    result = load_and_validate(str(path))
    assert result.valid_records == []
    assert len(result.rejected) == len(garbage)
    assert all(r.reason for r in result.rejected)


def test_loader_mixed_good_and_bad(tmp_path, ingestion: IngestionResult):
    """A valid record surrounded by junk still validates."""
    good = ingestion.valid_records[0].model_dump(mode="json")
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps(["junk", good, {"nope": 1}]), encoding="utf-8")

    result = load_and_validate(str(path))
    assert len(result.valid_records) == 1
    assert result.valid_records[0].asset_id == good["asset_id"]
    assert len(result.rejected) == 2


def test_loader_accepts_wrapped_object_payload(tmp_path, ingestion: IngestionResult):
    good = ingestion.valid_records[0].model_dump(mode="json")
    path = tmp_path / "wrapped.json"
    path.write_text(json.dumps({"assets": [good]}), encoding="utf-8")
    result = load_and_validate(str(path))
    assert len(result.valid_records) == 1


def test_loader_missing_file_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        load_and_validate("data/synthetic/does-not-exist.json")


def test_loader_invalid_json_raises_valueerror(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_and_validate(str(path))


def test_loader_non_list_payload_raises_valueerror(tmp_path):
    path = tmp_path / "scalar.json"
    path.write_text('"just a string"', encoding="utf-8")
    with pytest.raises(ValueError):
        load_and_validate(str(path))


# ---------------------------------------------------------------------------------
# Generator contract
# ---------------------------------------------------------------------------------

def test_generate_returns_127_for_n_120():
    """n = VALID record count; the 7 malformed fixtures are ADDITIONAL by design.
    (Orchestrator ruling -- asserting len == 120 here would be wrong.)"""
    records = generate(n=120)
    assert len(records) == 127
    valid = [r for r in records if not str(r.get("asset_id", "")).startswith("AST-9")]
    assert len(valid) == 120


def test_generate_is_pure_and_deterministic():
    """generate() writes nothing (main() is the sole writer) and the same seed
    yields identical output."""
    before = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    first = generate(n=120, seed=42)
    second = generate(n=120, seed=42)
    after = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()

    assert before == after, "generate() must not touch assets.json"
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_generate_matches_the_shipped_dataset():
    """The dataset on disk is exactly generate()'s default output -- reproducibility
    of the whole downstream evaluation hangs off this."""
    records = generate()
    on_disk = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    assert records == on_disk


# ---------------------------------------------------------------------------
# describe_rejection: plain-English rendering of a stored ValidationError.
#
# Added after the project owner read the raw pydantic dumps in the sidebar as
# "error files" -- i.e. assumed the tool was broken. The validation behaviour was
# always correct; the presentation leaked "[type=string_pattern_mismatch]" and a
# link to errors.pydantic.dev, which reads as a stack trace. RejectionError.reason
# still stores the unedited string (models.py is frozen and the audit trail wants
# the full text); only the rendering changed.
# ---------------------------------------------------------------------------

def test_every_rejection_renders_without_pydantic_noise(ingestion):
    """No rejected record should surface validator internals to the reader."""
    from src.ingestion.loader import describe_rejection

    assert ingestion.rejected, "expected the seeded malformed records"
    for rejection in ingestion.rejected:
        summary = describe_rejection(rejection)
        headline = summary.headline

        assert headline.strip(), "empty headline"
        assert "[type=" not in headline
        assert "errors.pydantic.dev" not in headline
        assert "input_type=" not in headline
        assert "validation error" not in headline.lower()
        # The asset is always named, so a reader can find the offending record.
        assert summary.asset_id and summary.asset_id != "unknown asset"
        # And the unedited reason is preserved for the audit trail.
        assert summary.raw_reason == rejection.reason


def test_each_seeded_rejection_gets_its_specific_message(ingestion):
    """The seven seeded paths each render a distinct, recognisable explanation."""
    from src.ingestion.loader import describe_rejection

    by_asset = {
        describe_rejection(r).asset_id: describe_rejection(r)
        for r in ingestion.rejected
    }

    expected = {
        "AST-9001": "CVE identifier",
        "AST-9002": "CVSS score",
        "AST-9003": "recognised values",
        "AST-9004": "missing",
        "AST-9005": "Unexpected field",
        "AST-9006": "Unexpected field",
        "AST-9007": "valid date",
    }
    for asset_id, fragment in expected.items():
        assert asset_id in by_asset, f"{asset_id} no longer rejected"
        assert fragment.lower() in by_asset[asset_id].headline.lower(), (
            f"{asset_id}: {by_asset[asset_id].headline!r} lost its specific wording"
        )


@pytest.mark.parametrize(
    "reason",
    [
        "",
        "something entirely unexpected",
        "1 validation error for AssetRecord",  # truncated: no field line
        "KeyError: 'boom'",  # a non-ValidationError path
        "1 validation error for AssetRecord\nfield\n  msg [type=brand_new_code_2099]",
    ],
)
def test_describe_rejection_never_raises_on_odd_input(reason):
    """An unparseable reason must degrade to text, never explode.

    The parser reads a formatted string, so it has to survive pydantic changing
    that format or a non-validation error taking the same path.
    """
    from src.ingestion.loader import describe_rejection
    from src.models import RejectionError

    summary = describe_rejection(RejectionError(raw={"asset_id": "AST-X"}, reason=reason))
    assert summary.raw_reason == reason
    assert isinstance(summary.headline, str)
