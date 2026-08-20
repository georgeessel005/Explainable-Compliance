"""
test_end_to_end.py  -  The full pipeline, twice over.

1. Headless: ingest -> map -> explain -> mixed Approve/Modify/Escalate decisions
   (via the real Stage 4 apply_decision, so the audit trail is written the same way
   the UI writes it) -> report BLOCKED -> escalations resolved -> report UNBLOCKS ->
   PDF compiled -> hashed. Every decision must have a matching audit entry.

2. Through the Streamlit app itself with streamlit.testing.v1.AppTest: stage buttons
   clicked, decisions seeded, the compile click refused while an escalation stands
   (AppTest happily 'clicks' the disabled button -- which is the point: the disabled
   button is an affordance, the compile-path re-check is the control), then released
   after resolution.

   Modify is TWO-PHASE there and the app test proves it: selecting "Modify" records no
   decision and leaves the finding outstanding (it is not "reviewed" until an edit
   exists), and pressing Save records exactly one MODIFY carrying the real edited text.

No src/ file was patched for these tests.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.audit.log import AuditLog
from src.explain.explainer import explain
from src.gate import can_generate_report, escalated_finding_ids, gate_status
from src.ingestion.loader import load_and_validate
from src.mapping.engine import load_rules, map_findings
from src.models import (
    ComplianceReport,
    DecisionType,
    FindingStatus,
)
from src.report.integrity import content_digest, sha256_of_file
from src.report.pdf_builder import compile_pdf
from src.ui.review import apply_decision, edit_pending, status_of

from tests.conftest import RULES_DIR
from tests.helpers import extract_pdf_text

APP_PATH = Path(__file__).resolve().parents[1] / "streamlit_app.py"

ANALYST = "e2e-analyst"
#: Deterministic mixed-decision plan over the 309 findings.
ESCALATE_INDICES = {0, 150, 250}
MODIFY_EVERY = 50  # indices 7, 57, 107, ... get Modify with replacement prose


def _decide_all(findings, explanations_by_id, decisions, audit_log):
    """Walk every finding through the real Stage 4 decision path."""
    for index, finding in enumerate(findings):
        fid = finding.finding_id
        if index in ESCALATE_INDICES:
            apply_decision(
                fid, DecisionType.ESCALATE, decisions, audit_log,
                explanations_by_id, analyst_note="Needs senior review.",
                analyst_id=ANALYST,
            )
        elif index % MODIFY_EVERY == 7:
            apply_decision(
                fid, DecisionType.MODIFY, decisions, audit_log,
                explanations_by_id,
                modified_explanation=f"Analyst-corrected explanation for {fid}.",
                analyst_note="Reworded for the client.",
                analyst_id=ANALYST,
            )
        else:
            apply_decision(
                fid, DecisionType.APPROVE, decisions, audit_log,
                explanations_by_id, analyst_id=ANALYST,
            )


def test_full_pipeline_headless(data_path, tmp_path):
    # ---- Stage 1: ingest -------------------------------------------------------
    ingestion = load_and_validate(data_path)
    assert len(ingestion.valid_records) == 120
    assert len(ingestion.rejected) == 7

    # ---- Stage 2: map ----------------------------------------------------------
    rulebase = load_rules(str(RULES_DIR))
    findings = map_findings(ingestion.valid_records, rulebase)
    assert len(findings) == 309

    # ---- Stage 3: explain ------------------------------------------------------
    explanations = [explain(f, rulebase=rulebase) for f in findings]
    assert len(explanations) == 309
    assert all(e.plain_english for e in explanations)
    explanations_by_id = {e.finding_id: e for e in explanations}

    # ---- Stage 4: mixed human decisions (real review path, real audit log) ------
    decisions = []
    audit_log = AuditLog()
    _decide_all(findings, explanations_by_id, decisions, audit_log)
    assert len(decisions) == 309

    escalated_ids = {findings[i].finding_id for i in ESCALATE_INDICES}
    assert set(escalated_finding_ids(decisions)) == escalated_ids

    # Explanations track the decisions.
    for fid in escalated_ids:
        assert explanations_by_id[fid].status == FindingStatus.ESCALATED

    # ---- THE GATE: report BLOCKED while escalations stand -----------------------
    assert can_generate_report(decisions) is False
    status = gate_status(decisions, total_findings=len(findings))
    assert status["unlocked"] is False
    assert status["escalated_count"] == 3
    assert status["coverage_complete"] is True  # every finding decided...
    assert status["escalation_clear"] is False  # ...but escalations dominate

    # ---- Resolve the escalations (append-only: later Approve supersedes) --------
    for fid in sorted(escalated_ids):
        apply_decision(
            fid, DecisionType.APPROVE, decisions, audit_log,
            explanations_by_id,
            analyst_note="Escalation reviewed and cleared.", analyst_id=ANALYST,
        )
    assert len(decisions) == 312  # history retained, nothing overwritten

    # ---- Report UNBLOCKS ---------------------------------------------------------
    assert can_generate_report(decisions) is True
    status = gate_status(decisions, total_findings=len(findings))
    assert status["unlocked"] is True
    for fid in escalated_ids:
        assert status_of(fid, decisions) == FindingStatus.APPROVED

    # ---- Stage 5: compile and hash ----------------------------------------------
    report = ComplianceReport(
        report_id="RPT-E2E-0001",
        generated_at=datetime(2025, 7, 1, 12, 0, 0, tzinfo=timezone.utc),
        findings=findings,
        explanations=explanations,
        decisions=decisions,
    )
    out = tmp_path / "e2e-report.pdf"
    compile_pdf(report, str(out))
    pdf_bytes = out.read_bytes()
    assert pdf_bytes[:5] == b"%PDF-"

    digest = sha256_of_file(str(out))
    report.sha256_hash = digest
    report.pdf_path = str(out)
    assert len(digest) == 64

    # Determinism end-to-end: a second build of the same report is byte-identical.
    out2 = tmp_path / "e2e-report-rebuild.pdf"
    compile_pdf(report, str(out2))
    assert out2.read_bytes() == pdf_bytes

    # The footer commits to the CONTENT digest (the file digest cannot appear
    # inside the file it digests).
    text = extract_pdf_text(pdf_bytes)
    assert content_digest(report).encode("ascii") in text

    # Modified prose made it into the committed content.
    modified_fids = [
        findings[i].finding_id for i in range(len(findings))
        if i % MODIFY_EVERY == 7 and i not in ESCALATE_INDICES
    ]
    assert modified_fids
    assert f"Analyst-corrected explanation for {modified_fids[0]}.".encode() in text

    # ---- Audit trail: one entry per decision, nothing lost ----------------------
    finding_entries = [
        e for e in audit_log.entries if e.finding_id != AuditLog.SYSTEM_SCOPE
    ]
    assert len(finding_entries) == len(decisions) == 312

    decision_pairs = Counter((d.finding_id, d.decision.value) for d in decisions)
    audit_pairs = Counter((e.finding_id, e.action) for e in finding_entries)
    assert audit_pairs == decision_pairs

    # Every audit entry names the analyst and carries a timestamp.
    assert all(e.actor == ANALYST for e in finding_entries)
    assert all(e.timestamp is not None for e in finding_entries)

    # The escalate->approve resolution is visible in the trail for each escalated
    # finding: first Escalate, then Approve, in order.
    for fid in escalated_ids:
        actions = [e.action for e in audit_log.entries_for(fid)]
        assert actions == [DecisionType.ESCALATE.value, DecisionType.APPROVE.value]


# ---------------------------------------------------------------------------------
# Through the app itself (streamlit.testing.v1.AppTest)
# ---------------------------------------------------------------------------------

def _find_button(at, label_part: str):
    for button in at.button:
        if label_part in button.label:
            return button
    raise AssertionError(f"No button labelled like {label_part!r}")


def _decide(at, finding_id: str, label: str):
    """Take a REAL analyst decision through the per-finding Decision selectbox.

    The bare second ``at.run()`` flushes the ``st.rerun()`` that recording a decision
    ends on; without it the next button ``.click()`` is swallowed. Decisions are
    driven through the widget rather than injected into session_state, because the
    selectbox re-asserts its selection from the finding's status and would override
    an injected decision.

    NOTE for "Modify": selecting it records NOTHING. It only opens the editor. Use
    ``_save_modification`` to commit the edit — that is the act that decides.
    """
    at.selectbox(key=f"decision__{finding_id}").select(label)
    at.run()
    at.run()
    assert not at.exception, [str(e) for e in at.exception]


def _save_modification(at, finding_id: str, text: str):
    """Type a replacement explanation and press that card's Save button."""
    at.text_area(key=f"text__{finding_id}").set_value(text)
    at.run()
    at.button(key=f"commit__{finding_id}").click()
    at.run()
    at.run()
    assert not at.exception, [str(e) for e in at.exception]


@pytest.mark.slow
def test_apptest_full_flow_gate_blocks_then_releases():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    assert not at.exception, [str(e) for e in at.exception]

    # Stages 1-3 via the real sidebar button (one button since the reskin; each
    # stage still runs, and still records its own audit entry).
    _find_button(at, "Run Stages 1-3").click()
    at.run()
    assert not at.exception
    assert len(at.session_state["ingestion_result"].valid_records) == 120
    assert len(at.session_state["findings"]) == 309
    assert len(at.session_state["explanations"]) == 309
    stage_actions = [e.action for e in at.session_state["audit_log"].entries]
    assert "STAGE_1_INGESTION" in stage_actions
    assert "STAGE_2_MAPPING" in stage_actions
    assert "STAGE_3_EXPLAIN" in stage_actions

    # ---- Stage 4: MIXED decisions, every one of them a real UI interaction ------
    findings = at.session_state["findings"]
    escalated_fid = findings[0].finding_id
    modified_fid = findings[2].finding_id

    ids = [f.finding_id for f in findings]

    _decide(at, escalated_fid, "Escalate")
    assert len(at.session_state["decisions"]) == 1, "Escalate decides on selection"

    # ---- Selecting Modify is NOT a decision -------------------------------------
    # It opens the editor and nothing more. Recording a MODIFY here would count the
    # finding as REVIEWED before any edit existed, and a report could then be compiled
    # containing a finding labelled "Modified" whose explanation was never modified.
    _decide(at, modified_fid, "Modify")
    decisions = at.session_state["decisions"]
    assert len(decisions) == 1, (
        "selecting Modify must NOT record a decision — the edit has not been composed"
    )
    assert all(d.finding_id != modified_fid for d in decisions)
    assert status_of(modified_fid, decisions) == FindingStatus.AWAITING_REVIEW

    # ...so it does not count toward coverage: the finding is still outstanding.
    pending_status = gate_status(decisions, finding_ids=ids)
    assert pending_status["reviewed_count"] == 1
    assert pending_status["outstanding_count"] == 308
    assert modified_fid not in pending_status["escalated_ids"]
    assert pending_status["coverage_complete"] is False

    # ...and the pending state is real state, visible on screen, not just an absence.
    assert at.session_state[f"decision__{modified_fid}"] == "Modify"
    assert any(
        "no edit saved" in (c.value or "") for c in at.caption
    ), "the uncommitted edit must be called out in the UI"

    # A pending edit is also spared by bulk approve, so the count is 309 - 1
    # escalated - 1 mid-edit = 307.
    bulk = _find_button(at, "Approve all unreviewed matching")
    assert "(307)" in bulk.label, bulk.label
    bulk.click()
    at.run()
    assert not at.exception

    decisions = at.session_state["decisions"]
    assert len(decisions) == 308, "bulk approve must not decide the mid-edit finding"
    assert status_of(modified_fid, decisions) == FindingStatus.AWAITING_REVIEW
    status = gate_status(decisions, finding_ids=ids)
    assert status["coverage_complete"] is False
    assert status["outstanding_count"] == 1, "the uncommitted Modify is outstanding"

    # ---- Saving the edit is the decision ----------------------------------------
    edited_text = "Analyst-corrected explanation committed through the UI."
    _save_modification(at, modified_fid, edited_text)

    decisions = at.session_state["decisions"]
    assert len(decisions) == 309
    assert status_of(escalated_fid, decisions) == FindingStatus.ESCALATED
    assert status_of(modified_fid, decisions) == FindingStatus.MODIFIED
    counts = Counter(d.decision for d in decisions)
    assert counts[DecisionType.ESCALATE] == 1
    assert counts[DecisionType.MODIFY] == 1, "exactly ONE Modify, written on Save"
    assert counts[DecisionType.APPROVE] == 307

    # The one MODIFY carries the real edited prose, and the explanation was replaced.
    modify_decision = next(d for d in decisions if d.decision is DecisionType.MODIFY)
    assert modify_decision.finding_id == modified_fid
    assert modify_decision.modified_explanation == edited_text
    explanation = next(
        e for e in at.session_state["explanations"] if e.finding_id == modified_fid
    )
    assert explanation.plain_english == edited_text
    assert edit_pending(modified_fid, decisions) is False, (
        "a committed Modify carries real prose and is no longer pending"
    )

    # One audit entry for the Modify, and it claims an edit that actually happened.
    modify_entries = at.session_state["audit_log"].entries_for(modified_fid)
    assert [e.action for e in modify_entries] == [DecisionType.MODIFY.value]
    assert "edited by analyst" in (modify_entries[0].details or "")

    # Every finding is now decided, but one escalation is open: coverage complete,
    # gate still shut.
    status = gate_status(decisions, finding_ids=ids)
    assert status["coverage_complete"] is True
    assert status["escalation_clear"] is False
    assert status["unlocked"] is False
    assert can_generate_report(decisions) is False

    # ---- THE GATE: report BLOCKED while the escalation stands ------------------
    compile_button = _find_button(at, "Generate Sealed PDF Report")
    assert compile_button.disabled, "UI affordance: button should be disabled"

    # AppTest can still 'click' the disabled button -- exactly the bypass the
    # compile-path re-check exists for.
    compile_button.click()
    at.run()
    assert at.session_state["report"] is None, (
        "BLOCKING DEFECT: a report was compiled over an open escalation"
    )


    # ---- Resolve the escalation through the UI, then compile for real ----------
    _decide(at, escalated_fid, "Approve")
    decisions = at.session_state["decisions"]
    assert len(decisions) == 310, "append-only: the escalation history is retained"
    assert status_of(escalated_fid, decisions) == FindingStatus.APPROVED
    assert can_generate_report(decisions) is True

    compile_button = _find_button(at, "Generate Sealed PDF Report")
    assert not compile_button.disabled, "gate is clear: Stage 5 must be available"
    compile_button.click()
    at.run()
    assert not at.exception

    report = at.session_state["report"]
    assert report is not None
    assert report.sha256_hash and len(report.sha256_hash) == 64
    assert at.session_state["report_bytes"][:5] == b"%PDF-"
    assert at.session_state["report_hash"] == report.sha256_hash

    audit = at.session_state["audit_log"]
    actions = [e.action for e in audit.entries]
    assert "STAGE_5_REPORT" in actions

    # ---- Audit trail: one entry per decision, nothing lost ---------------------
    finding_entries = [
        e for e in audit.entries if e.finding_id != AuditLog.SYSTEM_SCOPE
    ]
    assert len(finding_entries) == len(decisions) == 310
    assert Counter((e.finding_id, e.action) for e in finding_entries) == Counter(
        (d.finding_id, d.decision.value) for d in decisions
    )
    # The escalate -> approve resolution is visible in the trail, in order.
    assert [e.action for e in audit.entries_for(escalated_fid)] == [
        DecisionType.ESCALATE.value,
        DecisionType.APPROVE.value,
    ]


@pytest.mark.slow
def test_apptest_boots_without_exception():
    """The deployed entry point must at least boot cleanly on a cold session."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP_PATH), default_timeout=300)
    at.run()
    assert not at.exception, [str(e) for e in at.exception]
    assert not at.error
