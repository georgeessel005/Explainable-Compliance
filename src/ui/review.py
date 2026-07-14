"""
ui/review.py  -  Stage 4: the human validation gate (HITL).

Every finding must be Approved, Modified or Escalated by a named analyst. Each click
appends an AnalystDecision and writes an AuditLogEntry — the two are written together
so the trail can never disagree with the decision history.

The decision list is append-only: revisiting a finding appends a new decision rather
than overwriting the old one, and `gate.resolve_decisions` takes the latest. That is
what makes "escalate, then resolve, then approve" auditable instead of invisible.
"""
from __future__ import annotations

from typing import Optional

from src.audit.log import AuditLog
from src.gate import can_generate_report, gate_status, resolve_decisions
from src.models import (
    AnalystDecision,
    ComplianceFinding,
    DecisionType,
    Explanation,
    FindingStatus,
    MappingType,
    Severity,
)

# Decision -> the status the finding lands in once that decision is taken.
_STATUS_FOR_DECISION = {
    DecisionType.APPROVE: FindingStatus.APPROVED,
    DecisionType.MODIFY: FindingStatus.MODIFIED,
    DecisionType.ESCALATE: FindingStatus.ESCALATED,
}

_SEVERITY_COLOUR = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange",
    Severity.MEDIUM: "blue",
    Severity.LOW: "green",
    Severity.NONE: "grey",
}


# ---------- state helpers ----------

def status_of(finding_id: str, decisions: list[AnalystDecision]) -> FindingStatus:
    """Current status of one finding, derived from its latest decision."""
    resolved = resolve_decisions(decisions)
    decision = resolved.get(finding_id)
    if decision is None:
        return FindingStatus.AWAITING_REVIEW
    return _STATUS_FOR_DECISION[decision.decision]


def apply_decision(
    finding_id: str,
    decision_type: DecisionType,
    decisions: list[AnalystDecision],
    audit_log: AuditLog,
    explanations_by_id: Optional[dict] = None,
    modified_explanation: Optional[str] = None,
    analyst_note: Optional[str] = None,
    analyst_id: str = "analyst",
) -> AnalystDecision:
    """Record one analyst decision: append to history, update status, write the audit entry.

    Mutates `decisions` and `audit_log` in place — both live in st.session_state, so the
    mutation is what survives the rerun. Returns the appended decision.
    """
    previous_status = status_of(finding_id, decisions)
    new_status = _STATUS_FOR_DECISION[decision_type]

    decision = AnalystDecision(
        finding_id=finding_id,
        decision=decision_type,
        modified_explanation=modified_explanation,
        analyst_note=analyst_note or None,
        analyst_id=analyst_id,
    )
    decisions.append(decision)

    if explanations_by_id and finding_id in explanations_by_id:
        explanation = explanations_by_id[finding_id]
        explanation.status = new_status
        if decision_type == DecisionType.MODIFY and modified_explanation:
            explanation.plain_english = modified_explanation

    details = analyst_note
    if decision_type == DecisionType.MODIFY and modified_explanation:
        details = (
            f"Explanation edited by analyst. {analyst_note}" if analyst_note
            else "Explanation edited by analyst."
        )
    if previous_status == FindingStatus.ESCALATED and decision_type != DecisionType.ESCALATE:
        resolution = "Escalation resolved; finding released to Stage 5."
        details = f"{details} {resolution}" if details else resolution

    audit_log.record(
        finding_id=finding_id,
        action=decision_type.value,
        actor=analyst_id,
        previous_status=previous_status,
        new_status=new_status,
        details=details,
    )
    return decision


# ---------- gate banner ----------

def render_gate_banner(
    decisions: list[AnalystDecision],
    total_findings: Optional[int] = None,
) -> bool:
    """Live Stage 5 gate banner. Returns the hard control's verdict (escalation clear).

    The returned value is `can_generate_report` and nothing else. Review coverage is
    displayed but deliberately not folded into the return, so a caller that trusts this
    banner still gets the Article 22 answer.
    """
    import streamlit as st

    status = gate_status(decisions, total_findings)

    if not status["escalation_clear"]:
        count = status["escalated_count"]
        st.error(
            f"**Stage 5 blocked: {count} finding(s) escalated.** "
            "Report compilation is disabled until every escalation is resolved by an "
            "analyst (UK GDPR Article 22 — no report may be produced over an open "
            "human objection).",
            icon="🚫",
        )
        st.caption("Escalated: " + ", ".join(status["escalated_ids"]))
    elif not status["coverage_complete"]:
        st.warning(
            f"**{status['outstanding_count']} finding(s) awaiting a decision.** "
            "No escalations are open, but every finding needs an analyst decision "
            "before the report can be compiled.",
            icon="⏳",
        )
    else:
        st.success(
            "**All findings resolved — Stage 5 unlocked.** "
            f"{status['reviewed_count']} finding(s) reviewed, none escalated.",
            icon="✅",
        )

    return can_generate_report(decisions)


# ---------- finding card ----------

def _badge(mapping_type: MappingType) -> str:
    if mapping_type == MappingType.PRIMARY:
        return ":blue-background[**Primary**]"
    return ":grey-background[Secondary]"


def _status_chip(status: FindingStatus) -> str:
    chips = {
        FindingStatus.AWAITING_REVIEW: ":grey-background[Awaiting decision]",
        FindingStatus.APPROVED: ":green-background[Approved]",
        FindingStatus.MODIFIED: ":violet-background[Modified]",
        FindingStatus.ESCALATED: ":red-background[Escalated]",
        FindingStatus.COMMITTED: ":blue-background[Committed to report]",
    }
    return chips.get(status, str(status.value))


def render_finding_card(
    finding: ComplianceFinding,
    explanation: Optional[Explanation],
    decisions: list[AnalystDecision],
    audit_log: AuditLog,
    explanations_by_id: dict,
    analyst_id: str = "analyst",
) -> None:
    """Render one finding as a reviewable card with Approve / Modify / Escalate."""
    import streamlit as st

    fid = finding.finding_id
    status = status_of(fid, decisions)
    asset = finding.asset

    with st.container(border=True):
        header_left, header_right = st.columns([3, 1])
        with header_left:
            st.markdown(f"#### {fid} — {finding.issue_code.value}")
            st.caption(f"Rule `{finding.rule_id}`")
        with header_right:
            st.markdown(_status_chip(status))

        # --- asset facts ---
        facts = st.columns(4)
        facts[0].markdown(f"**Asset**\n\n{asset.hostname}")
        facts[0].caption(f"{asset.asset_id} · {asset.ip_address}")
        facts[1].markdown(f"**OS**\n\n{asset.operating_system}")
        facts[1].caption(f"{asset.environment} · assessed {asset.assessment_date}")

        cve = finding.triggering_cve or "—"
        facts[2].markdown(f"**CVE**\n\n{cve}")
        exposure = "Internet-facing" if asset.internet_facing else "Internal only"
        facts[2].caption(exposure)

        cvss = finding.triggering_cvss
        colour = _SEVERITY_COLOUR.get(asset.criticality, "grey")
        facts[3].markdown(
            f"**CVSS**\n\n{cvss:.1f}" if cvss is not None else "**CVSS**\n\n—"
        )
        facts[3].caption(f":{colour}[Asset criticality: {asset.criticality.value}]")

        # --- Stage 3 explanation ---
        st.markdown("**Why this is a finding**")
        if explanation is not None:
            st.write(explanation.plain_english)
        else:
            st.info("No Stage 3 explanation available for this finding yet.")

        # --- linked controls ---
        mappings = (
            explanation.linked_controls if explanation and explanation.linked_controls
            else finding.control_mappings
        )
        if mappings:
            st.markdown("**Linked controls**")
            for mapping in mappings:
                st.markdown(
                    f"- {_badge(mapping.mapping_type)} &nbsp; "
                    f"`{mapping.framework.value}` — **{mapping.control_id}** "
                    f"{mapping.control_name}"
                )

        # --- remediation ---
        steps = explanation.remediation_steps if explanation else []
        if steps:
            with st.expander("Remediation steps"):
                for i, step in enumerate(steps, start=1):
                    st.markdown(f"{i}. {step}")

        # --- decision history ---
        history = [d for d in decisions if d.finding_id == fid]
        if history:
            with st.expander(f"Decision history ({len(history)})"):
                for d in history:
                    note = f" — {d.analyst_note}" if d.analyst_note else ""
                    st.caption(
                        f"{d.timestamp:%Y-%m-%d %H:%M:%S} UTC · **{d.decision.value}** "
                        f"by {d.analyst_id}{note}"
                    )
                st.caption("Latest decision is the effective one.")

        st.divider()

        # --- actions ---
        edit_key = f"edit_open__{fid}"
        if edit_key not in st.session_state:
            st.session_state[edit_key] = False

        note = st.text_input(
            "Analyst note (optional)",
            key=f"note__{fid}",
            placeholder="Rationale for this decision — recorded in the audit log",
        )

        action_cols = st.columns([1, 1, 1, 3])

        if action_cols[0].button(
            "✅ Approve", key=f"approve__{fid}", width="stretch"
        ):
            apply_decision(
                fid, DecisionType.APPROVE, decisions, audit_log,
                explanations_by_id, analyst_note=note, analyst_id=analyst_id,
            )
            st.session_state[edit_key] = False
            st.rerun()

        if action_cols[1].button(
            "✏️ Modify", key=f"modify__{fid}", width="stretch"
        ):
            st.session_state[edit_key] = not st.session_state[edit_key]
            st.rerun()

        if action_cols[2].button(
            "🚩 Escalate", key=f"escalate__{fid}", width="stretch"
        ):
            apply_decision(
                fid, DecisionType.ESCALATE, decisions, audit_log,
                explanations_by_id, analyst_note=note, analyst_id=analyst_id,
            )
            st.session_state[edit_key] = False
            st.rerun()

        if status == FindingStatus.ESCALATED:
            action_cols[3].caption(
                "Escalated — approve or modify this finding to resolve it and release "
                "Stage 5."
            )

        # --- modify panel ---
        if st.session_state[edit_key]:
            current_text = explanation.plain_english if explanation else ""
            edited = st.text_area(
                "Edit the plain-English explanation",
                value=current_text,
                key=f"text__{fid}",
                height=180,
                help="The edited text replaces the generated explanation in the report.",
            )
            commit_col, cancel_col, _ = st.columns([1, 1, 3])
            if commit_col.button(
                "Commit modification", key=f"commit__{fid}", type="primary",
                width="stretch",
            ):
                apply_decision(
                    fid, DecisionType.MODIFY, decisions, audit_log,
                    explanations_by_id, modified_explanation=edited,
                    analyst_note=note, analyst_id=analyst_id,
                )
                st.session_state[edit_key] = False
                st.rerun()
            if cancel_col.button(
                "Cancel", key=f"cancel__{fid}", width="stretch"
            ):
                st.session_state[edit_key] = False
                st.rerun()


# ---------- the stage ----------

def render_review_stage(
    findings: list[ComplianceFinding],
    explanations: list[Explanation],
    decisions: list[AnalystDecision],
    audit_log: AuditLog,
    analyst_id: str = "analyst",
    page_size: int = 10,
) -> bool:
    """Render Stage 4 in full. Returns the gate verdict (`can_generate_report`).

    Safe to call with empty lists on first load.
    """
    import streamlit as st

    st.subheader("Stage 4 — Human validation gate")

    if not findings:
        st.info(
            "No findings to review. Run Stage 1 → 2 → 3 from the sidebar to populate "
            "the review queue."
        )
        render_gate_banner(decisions, total_findings=None)
        return can_generate_report(decisions)

    explanations_by_id = {e.finding_id: e for e in (explanations or [])}

    gate_open = render_gate_banner(decisions, total_findings=len(findings))

    # --- filters ---
    filter_col, page_col = st.columns([2, 1])
    status_filter = filter_col.multiselect(
        "Filter by status",
        options=[s.value for s in FindingStatus],
        default=[],
        placeholder="All statuses",
        key="review_status_filter",
    )
    page_size = page_col.selectbox(
        "Findings per page", options=[5, 10, 25, 50], index=1, key="review_page_size"
    )

    visible = findings
    if status_filter:
        visible = [
            f for f in findings
            if status_of(f.finding_id, decisions).value in status_filter
        ]

    if not visible:
        st.info("No findings match the current filter.")
        return gate_open

    total_pages = max((len(visible) + page_size - 1) // page_size, 1)
    page = 1
    if total_pages > 1:
        page = st.number_input(
            f"Page (1–{total_pages})",
            min_value=1,
            max_value=total_pages,
            value=1,
            step=1,
            key="review_page",
        )
    start = (int(page) - 1) * page_size
    page_items = visible[start:start + page_size]

    st.caption(
        f"Showing {start + 1}–{start + len(page_items)} of {len(visible)} finding(s)"
        + (f" (filtered from {len(findings)})" if len(visible) != len(findings) else "")
    )

    for finding in page_items:
        render_finding_card(
            finding=finding,
            explanation=explanations_by_id.get(finding.finding_id),
            decisions=decisions,
            audit_log=audit_log,
            explanations_by_id=explanations_by_id,
            analyst_id=analyst_id,
        )

    return gate_open
