"""
test_mapping.py  -  Stage 2: rule base, cross-framework mapping, matrix.

Ground truth (blueprint Section 7):
* 15 rules, one per IssueCode; zero unmapped codes; 309 findings from 120 records.
* finding_id == F-<asset_id>-<ISSUE_CODE>, stable across runs.
* FINDING #017 (CE-PATCH-001) carries exactly 4 mappings: CE Patch Management [P],
  CE+ Vulnerability Scan [P], ISO A.8.8 [P], ISO A.8.32 [S].
* Matrix: 7 CE pillar rows x 14 ISO control columns, cells "P"/"S"/"".

ACADEMIC INTEGRITY: George's full matrix has 47 intersections; only 15 are verified
here plus 9 flagged-unverified best-effort ones (24 total). The missing 23 are ABSENT
BY DESIGN. This suite deliberately does NOT assert that 47 mappings exist -- such a
test would pressure a future agent into fabricating unsourced mappings. What IS
asserted is that every unverified mapping carries its verified=False flag and is
enumerated in rules/UNVERIFIED_MAPPINGS.md.

No src/ file was patched for these tests.
"""
from __future__ import annotations

from datetime import date

import pytest

from src.mapping.engine import (
    RuleBaseError,
    build_finding_id,
    iso_intersections,
    load_rules,
    map_findings,
    unmapped_issue_codes,
    unverified_intersections,
    verification_report,
)
from src.mapping.matrix import CE_PILLARS, ISO_CONTROLS, build_matrix
from src.models import (
    AssetRecord,
    Framework,
    IssueCode,
    MappingType,
    RawVulnerability,
)

from tests.conftest import REFERENCE_ASSET_IDS, RULES_DIR

#: The 15 verified (CE pillar x ISO control) cells, transcribed from blueprint
#: Section 7 / Appendix Aii. P = Primary, S = Secondary.
VERIFIED_CELLS = {
    ("Patch Management", "A.8.8"): "P",
    ("Patch Management", "A.8.32"): "S",
    ("Secure Configuration", "A.8.9"): "P",
    ("Secure Configuration", "A.8.27"): "S",
    ("User Access Control", "A.5.15"): "P",
    ("User Access Control", "A.5.16"): "S",
    ("User Access Control", "A.5.17"): "P",
    ("User Access Control", "A.8.5"): "P",
    ("Firewalls", "A.8.20"): "P",
    ("Firewalls", "A.8.21"): "S",
    ("Firewalls", "A.8.22"): "S",
    ("Malware Protection", "A.8.7"): "P",
    ("Malware Protection", "A.8.16"): "S",
    ("CE+ Vulnerability Scan", "A.8.8"): "P",
    ("CE+ Authenticated Audit", "A.5.15"): "S",
}


# ---------------------------------------------------------------------------------
# Rule base
# ---------------------------------------------------------------------------------

def test_load_rules_parses_15_rules(rulebase):
    assert len(rulebase.rules) == 15


def test_every_issue_code_has_exactly_one_rule(rulebase):
    assert unmapped_issue_codes(rulebase) == []
    for code in IssueCode:
        rule = rulebase.by_issue(code)
        assert rule is not None, f"No rule for {code.value}"
        assert rule.control_mappings, f"{rule.rule_id} has no control mappings"
        assert rule.explanation_template.strip(), f"{rule.rule_id} has no template"
        assert rule.remediation_steps, f"{rule.rule_id} has no remediation steps"


def test_load_rules_rejects_iso_control_outside_universe(tmp_path):
    """The Annex A control universe is closed; a stray control must fail the load."""
    bad_yaml = """
rules:
  - rule_id: TEST-BAD-001
    issue_code: PATCH_MISSING
    title: Control outside the universe
    ce_pillar: Patch Management
    control_mappings:
      - framework: ISO/IEC 27001:2022
        control_id: A.9.9
        control_name: Not a real Annex A control here
        mapping_type: Primary
    explanation_template: "x"
    remediation_steps: ["y"]
"""
    (tmp_path / "ce_iso_mappings.yaml").write_text(bad_yaml, encoding="utf-8")
    try:
        with pytest.raises(RuleBaseError):
            load_rules(str(tmp_path))
    finally:
        # A failed load leaves the provenance index untouched, but re-anchor it to
        # the real rule base anyway so later matrix assertions can never see stale
        # state regardless of test ordering.
        load_rules(str(RULES_DIR))


def test_load_rules_rejects_duplicate_issue_code(tmp_path):
    dup_yaml = """
rules:
  - rule_id: TEST-DUP-001
    issue_code: MFA_ABSENT
    title: First
    ce_pillar: User Access Control
    control_mappings:
      - framework: Cyber Essentials
        control_id: User Access Control
        control_name: User Access Control
        mapping_type: Primary
    explanation_template: "x"
    remediation_steps: ["y"]
  - rule_id: TEST-DUP-002
    issue_code: MFA_ABSENT
    title: Second
    ce_pillar: User Access Control
    control_mappings:
      - framework: Cyber Essentials
        control_id: User Access Control
        control_name: User Access Control
        mapping_type: Primary
    explanation_template: "x"
    remediation_steps: ["y"]
"""
    (tmp_path / "ce_iso_mappings.yaml").write_text(dup_yaml, encoding="utf-8")
    try:
        with pytest.raises(RuleBaseError):
            load_rules(str(tmp_path))
    finally:
        load_rules(str(RULES_DIR))


# ---------------------------------------------------------------------------------
# map_findings
# ---------------------------------------------------------------------------------

def test_309_findings_from_120_records(ingestion, findings):
    assert len(ingestion.valid_records) == 120
    assert len(findings) == 309


def test_finding_shape_and_frameworks_breached(findings):
    for finding in findings:
        assert finding.control_mappings, f"{finding.finding_id}: empty control_mappings"
        expected_id = build_finding_id(finding.asset.asset_id, finding.issue_code)
        assert finding.finding_id == expected_id
        assert finding.finding_id == (
            f"F-{finding.asset.asset_id}-{finding.issue_code.value}"
        )
        # frameworks_breached == distinct mapping frameworks, first-appearance order.
        seen = []
        for mapping in finding.control_mappings:
            if mapping.framework not in seen:
                seen.append(mapping.framework)
        assert finding.frameworks_breached == seen, finding.finding_id


def test_finding_ids_unique(findings):
    ids = [f.finding_id for f in findings]
    assert len(ids) == len(set(ids))


def test_finding_ids_stable_across_two_runs(ingestion):
    """Fresh rule base + fresh mapping run must reproduce identical findings."""
    rb1 = load_rules(str(RULES_DIR))
    rb2 = load_rules(str(RULES_DIR))
    run1 = map_findings(ingestion.valid_records, rb1)
    run2 = map_findings(ingestion.valid_records, rb2)
    assert [f.finding_id for f in run1] == [f.finding_id for f in run2]
    assert [f.triggering_cve for f in run1] == [f.triggering_cve for f in run2]
    assert [f.rule_id for f in run1] == [f.rule_id for f in run2]


def test_duplicate_issue_code_on_one_asset_yields_one_finding(rulebase):
    record = AssetRecord(
        asset_id="AST-TEST",
        hostname="test-host",
        operating_system="Ubuntu 22.04 LTS",
        ip_address="10.0.0.1",
        assessment_date=date(2025, 6, 30),
        issue_codes=[IssueCode.MFA_ABSENT, IssueCode.MFA_ABSENT],
    )
    result = map_findings([record], rulebase)
    assert len(result) == 1  # a duplicate would break the audit log's key


# ---------------------------------------------------------------------------------
# FINDING #017 reference case
# ---------------------------------------------------------------------------------

def test_reference_patch_missing_maps_exactly_like_finding_017(findings_by_id):
    """AST-0002's PATCH_MISSING finding must reproduce the reference card:
    4 mappings across 3 frameworks, CVE-2025-21002 @ CVSS 9.8, patch 14 days old."""
    finding = findings_by_id["F-AST-0002-PATCH_MISSING"]
    assert finding.rule_id == "CE-PATCH-001"
    assert finding.triggering_cve == "CVE-2025-21002"
    assert finding.triggering_cvss == 9.8

    expected = [
        (Framework.CE, "Patch Management", MappingType.PRIMARY),
        (Framework.CE_PLUS, "Vulnerability Scan", MappingType.PRIMARY),
        (Framework.ISO27001, "A.8.8", MappingType.PRIMARY),
        (Framework.ISO27001, "A.8.32", MappingType.SECONDARY),
    ]
    actual = [
        (m.framework, m.control_id, m.mapping_type) for m in finding.control_mappings
    ]
    assert sorted(actual, key=str) == sorted(expected, key=str)
    assert len(finding.control_mappings) == 4
    assert finding.frameworks_breached == [
        Framework.CE, Framework.CE_PLUS, Framework.ISO27001,
    ]

    # The triggering CVE's patch is exactly 14 days old at assessment.
    vuln = next(
        v for v in finding.asset.vulnerabilities if v.cve_id == finding.triggering_cve
    )
    assert vuln.patch_applied is False
    assert vuln.days_since_patch(finding.asset.assessment_date) == 14


def test_all_eight_reference_assets_reproduce_the_scenario(findings_by_id):
    for asset_id in REFERENCE_ASSET_IDS:
        finding = findings_by_id[f"F-{asset_id}-PATCH_MISSING"]
        assert finding.rule_id == "CE-PATCH-001"
        assert finding.triggering_cvss == 9.8
        assert finding.asset.internet_facing is True
        assert "Ubuntu" in finding.asset.operating_system


def test_ast_0114_dual_patch_findings_cite_different_cves(findings_by_id):
    """AST-0114 carries PATCH_MISSING and PATCH_RECORD_ABSENT and each cites the CVE
    supporting its own claim: PM a *dated* unapplied patch, PRA the undated one.
    This is intended, deterministic behaviour -- do not 'correct' it."""
    pm = findings_by_id["F-AST-0114-PATCH_MISSING"]
    pra = findings_by_id["F-AST-0114-PATCH_RECORD_ABSENT"]

    assert pm.triggering_cve is not None
    assert pra.triggering_cve is not None
    assert pm.triggering_cve != pra.triggering_cve

    vulns = {v.cve_id: v for v in pm.asset.vulnerabilities}
    # PM's claim is "a vendor patch has been available for N days" -> needs a date.
    assert vulns[pm.triggering_cve].patch_released_date is not None
    assert vulns[pm.triggering_cve].patch_applied is False
    # PRA's claim is "no patch record exists" -> the undated vulnerability.
    assert vulns[pra.triggering_cve].patch_released_date is None


def test_vuln_linked_findings_carry_cvss_others_do_not(findings):
    vuln_linked = {
        IssueCode.PATCH_MISSING,
        IssueCode.PATCH_RECORD_ABSENT,
        IssueCode.AUTH_SCAN_FAILURE,
    }
    for finding in findings:
        if finding.issue_code not in vuln_linked:
            assert finding.triggering_cve is None, finding.finding_id
            assert finding.triggering_cvss is None, finding.finding_id
        elif finding.triggering_cve is not None:
            assert finding.triggering_cvss is not None, finding.finding_id


# ---------------------------------------------------------------------------------
# Matrix
# ---------------------------------------------------------------------------------

def test_matrix_shape_and_axes(rulebase):
    matrix = build_matrix(rulebase)
    assert matrix.shape == (7, 14)
    assert list(matrix.index) == list(CE_PILLARS)
    assert list(matrix.columns) == list(ISO_CONTROLS)


def test_matrix_cells_are_only_p_s_or_blank(rulebase):
    matrix = build_matrix(rulebase)
    assert set(matrix.values.ravel().tolist()) <= {"P", "S", ""}


def test_verified_only_matrix_matches_appendix_aii_exactly(rulebase):
    """verified_only=True must render the 15 sourced cells and nothing else."""
    matrix = build_matrix(rulebase, verified_only=True)
    populated = {
        (pillar, control): matrix.at[pillar, control]
        for pillar in matrix.index
        for control in matrix.columns
        if matrix.at[pillar, control] != ""
    }
    assert populated == VERIFIED_CELLS


def test_full_matrix_verified_cells_never_downgraded(rulebase):
    """An unverified restatement must not overwrite a sourced cell's P/S type."""
    matrix = build_matrix(rulebase)
    for (pillar, control), code in VERIFIED_CELLS.items():
        assert matrix.at[pillar, control] == code, f"{pillar} x {control}"


def test_full_matrix_has_24_mapped_cells(rulebase):
    matrix = build_matrix(rulebase)
    assert int((matrix.values != "").sum()) == 24  # 15 verified + 9 unverified


# ---------------------------------------------------------------------------------
# Mapping fidelity / academic integrity
# ---------------------------------------------------------------------------------

def test_verification_report_counts(rulebase):
    """15 verified + 9 unverified = 24 of George's 47. The other 23 are absent BY
    DESIGN (academic integrity) -- this suite must never demand 47 exist."""
    report = verification_report()
    assert report["verified"] == 15
    assert report["unverified"] == 9
    assert report["total_in_rulebase"] == 24
    assert report["target_total"] == 47
    assert report["still_to_source"] == 23


def test_every_unverified_intersection_carries_its_flag(rulebase):
    unverified = unverified_intersections()
    assert len(unverified) == 9
    for cell in unverified:
        assert cell["verified"] is False
        assert cell["mapping_type"] == MappingType.SECONDARY, (
            "Unverified mappings claim the weaker (Secondary) relationship only"
        )
    # Disjoint from the sourced set.
    verified_keys = {
        (c["ce_pillar"], c["iso_control"]) for c in iso_intersections(verified=True)
    }
    unverified_keys = {(c["ce_pillar"], c["iso_control"]) for c in unverified}
    assert not (verified_keys & unverified_keys)
    assert verified_keys == set(VERIFIED_CELLS)


def test_unverified_mappings_md_enumerates_every_unverified_cell(rulebase, repo_root):
    md = (repo_root / "rules" / "UNVERIFIED_MAPPINGS.md").read_text(encoding="utf-8")
    for cell in unverified_intersections():
        assert cell["ce_pillar"] in md and cell["iso_control"] in md, (
            f"UNVERIFIED_MAPPINGS.md is missing "
            f"{cell['ce_pillar']} x {cell['iso_control']}"
        )
    assert "UNVERIFIED" in md


# ---------------------------------------------------------------------------------
# Deterministic triggering-CVE selection
# ---------------------------------------------------------------------------------

def test_triggering_cve_selection_is_deterministic(rulebase):
    """Highest CVSS unpatched wins; cve_id breaks ties; input order is irrelevant."""
    def vuln(cve, score, patched=False):
        return RawVulnerability(
            cve_id=cve, cvss_score=score, description="d",
            published_date=date(2025, 1, 1),
            patch_released_date=date(2025, 5, 1), patch_applied=patched,
        )

    base = dict(
        asset_id="AST-ORD", hostname="h", operating_system="os",
        ip_address="10.0.0.9", assessment_date=date(2025, 6, 30),
        issue_codes=[IssueCode.AUTH_SCAN_FAILURE],
    )
    forward = AssetRecord(
        **base, vulnerabilities=[vuln("CVE-2025-1111", 5.0), vuln("CVE-2025-2222", 9.0)]
    )
    reverse = AssetRecord(
        **base, vulnerabilities=[vuln("CVE-2025-2222", 9.0), vuln("CVE-2025-1111", 5.0)]
    )
    f1 = map_findings([forward], rulebase)[0]
    f2 = map_findings([reverse], rulebase)[0]
    assert f1.triggering_cve == f2.triggering_cve == "CVE-2025-2222"

    tie = AssetRecord(
        **base, vulnerabilities=[vuln("CVE-2025-9999", 9.0), vuln("CVE-2025-0001", 9.0)]
    )
    assert map_findings([tie], rulebase)[0].triggering_cve == "CVE-2025-0001"
