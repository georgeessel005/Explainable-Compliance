"""
test_explain.py  -  Stage 3: plain-English explanations.

Contract (frozen interface + Agent 3's guarantees):
* explain(finding) -> Explanation, never raises on template content.
* plain_english always names the asset hostname and enumerates every breached
  control; linked_controls mirror the finding's control_mappings; remediation
  steps are always present.
* The FINDING #017 reference tone: internet-facing + "released 14 days" + A.8.8.
* Findings with no triggering CVE (the common case) read naturally -- no literal
  "None" leaking into prose.

TESTER PATCH (Agent 5), proven by test_reference_explanation_matches_finding_017_tone:
rules/ce_iso_mappings.yaml, rule CE-PATCH-001, explanation_template only -- the
rendered reference explanation omitted the causal exposure clause of the blueprint
Section 7 reference tone ("Because the asset is internet-facing and the vendor patch
was released N days ago ..."). Added "the asset is {exposure} and" to the template's
Because-clause. No control mapping was touched; the 15 verified mappings are intact.
No other src/ or rules/ content was patched for these tests.
"""
from __future__ import annotations

from datetime import date

from src.explain.explainer import clear_rulebase_cache, explain, set_rulebase
from src.models import (
    AssetRecord,
    Explanation,
    FindingStatus,
    IssueCode,
)


def _sample(findings, step=25):
    """A representative slice: every `step`th finding plus first and last."""
    picked = list(findings[::step])
    for edge in (findings[0], findings[-1]):
        if edge not in picked:
            picked.append(edge)
    return picked


# ---------------------------------------------------------------------------------
# Core guarantees
# ---------------------------------------------------------------------------------

def test_explanation_type_and_finding_id(findings, rulebase):
    for finding in _sample(findings):
        explanation = explain(finding, rulebase=rulebase)
        assert isinstance(explanation, Explanation)
        assert explanation.finding_id == finding.finding_id


def test_plain_english_names_asset_and_every_control(findings, rulebase):
    for finding in _sample(findings):
        explanation = explain(finding, rulebase=rulebase)
        text = explanation.plain_english
        assert text and text.strip()
        assert finding.asset.hostname in text, finding.finding_id
        for mapping in finding.control_mappings:
            assert mapping.control_id in text, (
                f"{finding.finding_id}: control {mapping.control_id} not cited"
            )


def test_linked_controls_match_the_finding(findings, rulebase):
    for finding in _sample(findings):
        explanation = explain(finding, rulebase=rulebase)
        assert explanation.linked_controls == finding.control_mappings


def test_remediation_steps_always_present(findings, rulebase):
    for finding in _sample(findings):
        explanation = explain(finding, rulebase=rulebase)
        assert explanation.remediation_steps
        assert all(isinstance(s, str) and s.strip() for s in explanation.remediation_steps)


def test_status_defaults_to_awaiting_review(findings, rulebase):
    """Stage 3 explains, it never decides -- only the Stage 4 human gate moves a
    finding beyond AWAITING_REVIEW."""
    explanation = explain(findings[0], rulebase=rulebase)
    assert explanation.status == FindingStatus.AWAITING_REVIEW


def test_explain_is_deterministic(findings, rulebase):
    for finding in _sample(findings, step=60):
        first = explain(finding, rulebase=rulebase)
        second = explain(finding, rulebase=rulebase)
        assert first.plain_english == second.plain_english
        assert first.remediation_steps == second.remediation_steps


# ---------------------------------------------------------------------------------
# FINDING #017 reference tone
# ---------------------------------------------------------------------------------

def test_reference_explanation_matches_finding_017_tone(findings_by_id, rulebase):
    finding = findings_by_id["F-AST-0002-PATCH_MISSING"]
    text = explain(finding, rulebase=rulebase).plain_english

    assert "internet-facing" in text
    assert "14 days" in text
    assert "CVE-2025-21002" in text
    assert "A.8.8" in text
    assert "A.8.32" in text
    assert "Patch Management" in text
    assert "9.8" in text


def test_all_reference_assets_read_14_days(findings, rulebase):
    reference = [
        f for f in findings
        if f.issue_code == IssueCode.PATCH_MISSING and f.triggering_cvss == 9.8
    ]
    assert len(reference) == 8
    for finding in reference:
        assert "14 days" in explain(finding, rulebase=rulebase).plain_english


# ---------------------------------------------------------------------------------
# Degradation paths
# ---------------------------------------------------------------------------------

def test_no_cve_finding_reads_naturally(findings, rulebase):
    """Most issue codes have no triggering CVE; prose must degrade, not leak None."""
    no_cve = [f for f in findings if f.triggering_cve is None]
    assert no_cve, "expected plenty of configuration/process findings"
    for finding in _sample(no_cve, step=40):
        text = explain(finding, rulebase=rulebase).plain_english
        assert text and finding.asset.hostname in text
        assert "None days" not in text
        assert "CVSS None" not in text


def test_explain_survives_hostile_template(findings):
    """A rule template with unknown/misapplied placeholders degrades to prose."""
    from src.models import IssueRule

    finding = findings[0]
    hostile = IssueRule(
        rule_id=finding.rule_id,
        issue_code=finding.issue_code,
        title="Hostile template",
        control_mappings=finding.control_mappings,
        explanation_template=(
            "{nonexistent} and {cvss_score:.1f} on {hostname} via {asset.bogus}"
        ),
        remediation_steps=["Fix it."],
    )
    explanation = explain(finding, rule=hostile)
    assert explanation.plain_english
    assert finding.asset.hostname in explanation.plain_english


def test_explain_standalone_without_injected_rulebase(findings):
    """The frozen single-argument interface: explain(finding) resolves the rule base
    from disk on its own."""
    clear_rulebase_cache()
    set_rulebase(None)
    try:
        explanation = explain(findings[0])
        assert explanation.plain_english
        assert findings[0].asset.hostname in explanation.plain_english
        # Disk rule base found -> rule remediation, not the generic fallback.
        assert explanation.remediation_steps
    finally:
        clear_rulebase_cache()
        set_rulebase(None)


# ---------------------------------------------------------------------------------
# Remediation-step rendering (regression: raw placeholders shipped to the PDF)
# ---------------------------------------------------------------------------------
#
# These tests close a gap the 142-test suite left open: every explain test above
# asserted on plain_english only, so remediation_steps were never rendered
# through the template formatter at all. The rule base authors its steps as
# templates ("Apply the vendor security update for {cve_id} to {hostname} ...")
# and explain() copied them verbatim, so 48/48 explanations in the submission
# artefact shipped literal {hostname} into the Stage 4 review cards and the
# compiled PDF (72 PDF lines with {hostname}, 4 with {cve_id}).

_PLACEHOLDER_MSG = (
    "unsubstituted template placeholder in a remediation step -- "
    "steps must be rendered through the same formatter as plain_english"
)


def _assert_step_is_clean(step, finding):
    assert isinstance(step, str) and step.strip(), f"{finding.finding_id}: empty step"
    assert "{" not in step and "}" not in step, (
        f"{finding.finding_id}: {_PLACEHOLDER_MSG}: {step!r}"
    )
    assert "None" not in step, (
        f"{finding.finding_id}: literal 'None' leaked into a remediation step: {step!r}"
    )


def test_no_remediation_step_contains_a_raw_placeholder(findings, rulebase):
    """Sweep the whole corpus: no step may carry a literal {...} or "None".

    Guards the defect where 48/48 explanations shipped raw ``{hostname}`` into
    the PDF because explain() copied rule remediation_steps verbatim instead of
    rendering them against the finding context.
    """
    assert findings, "expected a populated corpus"
    checked = 0
    for finding in findings:
        for step in explain(finding, rulebase=rulebase).remediation_steps:
            _assert_step_is_clean(step, finding)
            checked += 1
    assert checked > 0


def test_every_issue_code_renders_clean_remediation(findings, rulebase):
    """Per-IssueCode coverage, so a regression in one rule's steps is localised."""
    by_code = {}
    for finding in findings:
        by_code.setdefault(finding.issue_code, finding)
    assert by_code, "expected findings across the issue codes"

    for issue_code, finding in by_code.items():
        steps = explain(finding, rulebase=rulebase).remediation_steps
        assert steps, f"{issue_code.value}: no remediation steps"
        for step in steps:
            _assert_step_is_clean(step, finding)


def test_remediation_steps_substitute_the_asset_and_cve(findings, rulebase):
    """The placeholders must resolve to real values, not merely be stripped."""
    patch = [
        f for f in findings
        if f.issue_code == IssueCode.PATCH_MISSING and f.triggering_cve
    ]
    assert patch, "expected PATCH_MISSING findings with a triggering CVE"
    finding = patch[0]
    steps = explain(finding, rulebase=rulebase).remediation_steps
    joined = " ".join(steps)
    assert finding.asset.hostname in joined, (
        f"hostname never substituted into remediation steps: {steps!r}"
    )
    assert finding.triggering_cve in joined, (
        f"CVE never substituted into remediation steps: {steps!r}"
    )


def test_remediation_without_cve_cvss_or_patch_date_reads_cleanly(findings, rulebase):
    """The common case: most findings are configuration/process failures with no
    CVE, no CVSS and no patch date, so {cve_id}/{cvss_score}/{days} are
    unresolvable. Those steps must degrade to prose, not raise or emit "None"."""
    no_cve = [
        f for f in findings
        if f.triggering_cve is None and f.triggering_cvss is None
    ]
    assert len(no_cve) > 100, "expected the unscored findings to dominate the corpus"
    for finding in no_cve:
        for step in explain(finding, rulebase=rulebase).remediation_steps:
            _assert_step_is_clean(step, finding)


def test_hostile_remediation_template_degrades_to_prose(findings):
    """Unknown names, bad indices, dud attribute lookups and inapplicable format
    specs in a remediation step degrade exactly as they do in the explanation."""
    from src.models import IssueRule

    finding = findings[0]
    hostile = IssueRule(
        rule_id=finding.rule_id,
        issue_code=finding.issue_code,
        title="Hostile remediation",
        control_mappings=finding.control_mappings,
        explanation_template="Something happened on {hostname}.",
        remediation_steps=[
            "Patch {cve_id} on {hostname} scoring {cvss_score:.1f} within {days} days.",
            "Escalate to {nonexistent} and review {asset.bogus} plus {0}.",
        ],
    )
    explanation = explain(finding, rule=hostile)
    assert len(explanation.remediation_steps) == 2
    for step in explanation.remediation_steps:
        _assert_step_is_clean(step, finding)
    assert finding.asset.hostname in explanation.remediation_steps[0]


def test_no_cve_remediation_uses_the_fallback_prose(findings, rulebase):
    """A {cve_id} hole in a step for an unscored finding reads as prose."""
    from src.models import IssueRule

    no_cve = next(f for f in findings if f.triggering_cve is None)
    rule = IssueRule(
        rule_id=no_cve.rule_id,
        issue_code=no_cve.issue_code,
        title="No-CVE remediation",
        control_mappings=no_cve.control_mappings,
        explanation_template="Issue on {hostname}.",
        remediation_steps=["Remediate {cve_id} on {hostname}."],
    )
    step = explain(no_cve, rule=rule).remediation_steps[0]
    _assert_step_is_clean(step, no_cve)
    assert "no associated CVE" in step
    assert no_cve.asset.hostname in step


def test_remediation_rendering_does_not_alter_plain_english(findings, rulebase):
    """The explanation path was already correct; rendering steps must not touch it."""
    for finding in _sample(findings, step=25):
        explanation = explain(finding, rulebase=rulebase)
        assert finding.asset.hostname in explanation.plain_english
        assert "{" not in explanation.plain_english
        assert "}" not in explanation.plain_english


def test_explain_finding_with_no_vulnerabilities(rulebase):
    record = AssetRecord(
        asset_id="AST-EMPTY",
        hostname="bare-host",
        operating_system="Debian 12",
        ip_address="10.9.9.9",
        assessment_date=date(2025, 6, 30),
        issue_codes=[IssueCode.FLAT_NETWORK],
    )
    from src.mapping.engine import map_findings

    finding = map_findings([record], rulebase)[0]
    explanation = explain(finding, rulebase=rulebase)
    assert "bare-host" in explanation.plain_english
    assert explanation.remediation_steps
