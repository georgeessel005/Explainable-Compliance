"""
ui/review.py  -  Stage 4: the human validation gate (HITL).

Every finding must be Approved, Modified or Escalated by a named analyst. Each click
appends an AnalystDecision and writes an AuditLogEntry — the two are written together
so the trail can never disagree with the decision history.

The decision list is append-only: revisiting a finding appends a new decision rather
than overwriting the old one, and `gate.resolve_decisions` takes the latest. That is
what makes "escalate, then resolve, then approve" auditable instead of invisible.

MODIFY IS TWO-PHASE, APPROVE AND ESCALATE ARE NOT
-------------------------------------------------
Approve and Escalate are complete the instant they are selected — there is nothing
left to compose — so they record immediately.

Modify is not. Selecting "Modify" only opens the editor: it records NO decision, the
finding stays AWAITING_REVIEW, and it does NOT count toward review coverage. Exactly
one MODIFY decision is appended, carrying the real replacement prose, when the analyst
presses Save. This is deliberate: recording a MODIFY on selection would let a report be
compiled containing a finding labelled "Modified" whose explanation was never modified,
which is a false statement in the submitted artefact. An UNDECIDED finding with an open,
uncommitted edit is shown as pending on its card and counted as outstanding in the gate
banner. Re-opening the editor on an already-decided finding is not pending: the recorded
decision stands, and still counts toward coverage, until a replacement is saved.
"""
from __future__ import annotations

from typing import Optional

from src.audit.log import AuditLog
from src.gate import can_generate_report, gate_status, resolve_decisions
from src.mapping.engine import is_verified_mapping
from src.models import (
    AnalystDecision,
    ComplianceFinding,
    DecisionType,
    Explanation,
    FindingStatus,
    Severity,
)

# Actor written to the trail when no analyst name has been entered. Deliberately not
# the plausible-looking literal "analyst": an unattributed decision must READ as
# unattributed in the exported CSV, not as a person called "analyst".
UNNAMED_ANALYST = "(unnamed analyst)"

# Decision -> the status the finding lands in once that decision is taken.
_STATUS_FOR_DECISION = {
    DecisionType.APPROVE: FindingStatus.APPROVED,
    DecisionType.MODIFY: FindingStatus.MODIFIED,
    DecisionType.ESCALATE: FindingStatus.ESCALATED,
}



# ---------- state helpers ----------

def _resolved_map(
    decisions: list[AnalystDecision], resolved: Optional[dict] = None
) -> dict:
    """The effective-decision map, resolving it only when the caller has not already.

    `gate.resolve_decisions` is the single source of truth for the effective decision
    and is never re-implemented here. It is O(len(decisions)), so calling it once per
    finding across a 500-finding set made every idle rerun O(n²). A render pass resolves
    once and threads the result through; every function keeps working unchanged when the
    argument is omitted (tests and headless callers pass nothing).
    """
    return resolve_decisions(decisions) if resolved is None else resolved


def status_of(
    finding_id: str,
    decisions: list[AnalystDecision],
    resolved: Optional[dict] = None,
) -> FindingStatus:
    """Current status of one finding, derived from its latest decision."""
    decision = _resolved_map(decisions, resolved).get(finding_id)
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
    analyst_id: str = UNNAMED_ANALYST,
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
    if decision_type == DecisionType.MODIFY:
        # Only claim an edit when replacement prose was actually supplied. The UI only
        # ever records a MODIFY from the Save button, so the first branch is the live
        # path; the second stays as an honest fallback for any caller that records a
        # MODIFY without prose, so the trail never asserts an edit that never happened.
        base = (
            "Explanation edited by analyst." if modified_explanation
            else "Modify recorded with no replacement prose; "
                 "generated explanation unchanged."
        )
        details = f"{base} {analyst_note}" if analyst_note else base
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


# ---------- small formatting helpers ----------

MAX_LISTED_IDS = 10


def format_id_list(ids: list[str], limit: int = MAX_LISTED_IDS) -> str:
    """`F-1, F-2, … and 240 more`.

    With 300+ findings an un-truncated join produces a ~10,000-character banner that
    is a screen of noise rather than information. The count is always exact.
    """
    ids = list(ids)
    if len(ids) <= limit:
        return ", ".join(ids)
    return ", ".join(ids[:limit]) + f" …and {len(ids) - limit} more"


#: session_state key holding the set of finding ids with an OPEN, uncommitted Modify.
#:
#: This deliberately does NOT live in the selectbox's own widget state. Streamlit
#: discards the state of any widget that is not instantiated during a script run, and a
#: bulk-approve click ends in st.rerun() before the cards are rendered — so the widget
#: state of every card selectbox is dropped on that pass. A decided finding survives that
#: because its selection is re-derived from its recorded decision; a PENDING modify has
#: no decision by design, so it needs a home of its own or it would silently vanish.
PENDING_MODIFY_KEY = "pending_modify"


def _pending_store() -> set:
    """The live pending-edit set from session_state, or an empty set with no session."""
    try:
        import streamlit as st

        store = st.session_state.get(PENDING_MODIFY_KEY)
        if not isinstance(store, set):
            store = set()
            st.session_state[PENDING_MODIFY_KEY] = store
        return store
    except Exception:  # noqa: BLE001 - headless caller (tests, scripts): no session.
        return set()


def _has_committed_modify(
    finding_id: str,
    decisions: list[AnalystDecision],
    resolved: Optional[dict] = None,
) -> bool:
    """True when this finding's effective decision is a Modify carrying real prose."""
    latest = _resolved_map(decisions, resolved).get(finding_id)
    return (
        latest is not None
        and latest.decision == DecisionType.MODIFY
        and bool((latest.modified_explanation or "").strip())
    )


def mark_edit_pending(finding_id: str) -> None:
    """Record that the analyst has an open, uncommitted edit on this finding."""
    _pending_store().add(finding_id)


def clear_edit_pending(finding_id: str) -> None:
    """Drop the open-edit marker (the edit was saved, or the selection changed)."""
    _pending_store().discard(finding_id)


def edit_open(finding_id: str) -> bool:
    """True when the Modify editor is open on this finding, decided or not.

    The raw marker, with no judgement about whether the finding is outstanding. Used to
    restore the "Modify" selection after Streamlit drops widget state, and to caption a
    finding that is being re-edited AFTER it was decided. `edit_pending` is the one that
    answers the accountability question ("does this carry no decision yet?").
    """
    return finding_id in _pending_store()


def edit_pending(
    finding_id: str,
    decisions: list[AnalystDecision],
    resolved: Optional[dict] = None,
) -> bool:
    """True when Modify is selected for this finding and it carries NO decision at all.

    Two ways that can happen:

    * The analyst has picked "Modify" in the card's selectbox on a finding that has never
      been decided, and has not yet pressed Save. No decision has been recorded at all,
      so the finding is still AWAITING_REVIEW and still outstanding for coverage — this
      function is what makes that visible.
    * A MODIFY decision exists but carries no replacement prose (not reachable from this
      UI any more, since only Save records a MODIFY; kept so such a decision arriving
      from anywhere else still reads as pending rather than as a completed edit).

    Re-opening the editor on an ALREADY-DECIDED finding is deliberately NOT pending. The
    recorded Approve / Escalate / committed Modify still stands and still counts toward
    coverage until a replacement is saved, so calling it "no decision yet, still
    outstanding" would be a false statement on the screen an assessor reads to judge the
    HITL control — while the gate itself (correctly) went on counting the decision.
    That state is captioned honestly on the card via `edit_open` instead.
    """
    latest = _resolved_map(decisions, resolved).get(finding_id)
    if latest is not None:
        # A prose-less MODIFY is not a completed edit, so it still reads as pending.
        return (
            latest.decision == DecisionType.MODIFY
            and not (latest.modified_explanation or "").strip()
        )
    return finding_id in _pending_store()


def pending_edit_ids(
    finding_ids: list[str],
    decisions: list[AnalystDecision],
    resolved: Optional[dict] = None,
) -> list[str]:
    """Findings with Modify selected but no committed edit, in finding order."""
    resolved = _resolved_map(decisions, resolved)
    return [fid for fid in finding_ids if edit_pending(fid, decisions, resolved)]


def sync_pending_edits(
    finding_ids: list[str],
    decisions: list[AnalystDecision],
    resolved: Optional[dict] = None,
) -> None:
    """Reconcile the pending-edit store with the live selectbox state, BEFORE rendering.

    The cards mark/clear the marker themselves, but they run after the gate banner and
    after their own status chip — so on the very frame the analyst picks "Modify" the
    marker did not exist yet and neither indicator showed it; both only appeared on the
    next interaction. Streamlit has already written the new selection into session_state
    by the time the script reruns, so reading it here makes the pending state visible on
    the same frame it is created.

    Only ids whose selectbox is actually present in session_state are touched: a finding
    on another page has no widget state, and its open edit must survive.
    """
    try:
        import streamlit as st
    except Exception:  # noqa: BLE001 - headless caller: nothing to sync.
        return

    resolved = _resolved_map(decisions, resolved)
    for fid in finding_ids:
        key = f"decision__{fid}"
        if key not in st.session_state:
            continue
        if (
            st.session_state[key] == "Modify"
            and not _has_committed_modify(fid, decisions, resolved)
        ):
            mark_edit_pending(fid)
        else:
            clear_edit_pending(fid)


# ---------- gate banner ----------

def render_gate_banner(
    decisions: list[AnalystDecision],
    finding_ids: Optional[list[str]] = None,
    pending_ids: Optional[list[str]] = None,
) -> bool:
    """Live Stage 5 gate banner. Returns the hard control's verdict (escalation clear).

    The returned value is `can_generate_report` and nothing else. Review coverage is
    displayed but deliberately not folded into the return, so a caller that trusts this
    banner still gets the Article 22 answer.

    `finding_ids` is the live finding set: coverage is measured by set containment, so a
    stray/orphan decision cannot inflate it (see `gate_status`).

    `pending_ids` are findings with "Modify" selected but no edit committed. They carry
    no decision, so `gate_status` already counts them as outstanding; they are called out
    separately because "you started an edit and never saved it" is a different instruction
    to the analyst from "you never looked at this finding".
    """
    import streamlit as st

    status = gate_status(decisions, finding_ids)

    if not finding_ids and not decisions:
        # Nothing loaded yet. "No escalations are open" is vacuously true here, so the
        # normal branches below would render the green "Stage 5 unlocked" banner on a
        # blank first load — which misrepresents the Article 22 control to anyone reading
        # the screen. Stage 5 is independently gated on findings existing (compile_report
        # refuses with no findings, and the button is disabled), so this branch is
        # presentation only: the verdict returned below is deliberately unchanged.
        st.info(
            "**Stage 5 locked — nothing to review yet.** "
            "Run Stage 1 → 2 → 3 from the sidebar to populate the review queue.",
            icon="⏳",
        )
    elif not status["escalation_clear"]:
        count = status["escalated_count"]
        st.error(
            f"**Stage 5 blocked: {count} finding(s) escalated.** "
            "Report compilation is disabled until every escalation is resolved by an "
            "analyst (UK GDPR Article 22 — no report may be produced over an open "
            "human objection).",
            icon="🚫",
        )
        st.caption("Escalated: " + format_id_list(status["escalated_ids"]))
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

    if pending_ids:
        # An uncommitted Modify is NOT a decision. Saying so here is what stops the
        # analyst reading "outstanding" as "untouched" and re-deciding a finding they
        # are halfway through editing.
        st.caption(
            f"✏️ {len(pending_ids)} finding(s) have **Modify selected but no edit "
            "saved** — they carry no decision yet and still count as outstanding: "
            + format_id_list(pending_ids)
        )

    return can_generate_report(decisions)


# ---------- finding card ----------

def _status_chip(status: FindingStatus) -> str:
    chips = {
        FindingStatus.AWAITING_REVIEW: ":grey-background[Awaiting decision]",
        FindingStatus.APPROVED: ":green-background[Approved]",
        FindingStatus.MODIFIED: ":violet-background[Modified]",
        FindingStatus.ESCALATED: ":red-background[Escalated]",
        FindingStatus.COMMITTED: ":blue-background[Committed to report]",
    }
    return chips.get(status, str(status.value))


SELECT_PLACEHOLDER = "— Select —"
DECISION_OPTIONS = [SELECT_PLACEHOLDER, "Approve", "Modify", "Escalate"]

_DECISION_FOR_LABEL = {
    "Approve": DecisionType.APPROVE,
    "Modify": DecisionType.MODIFY,
    "Escalate": DecisionType.ESCALATE,
}
_LABEL_FOR_STATUS = {
    FindingStatus.APPROVED: "Approve",
    FindingStatus.MODIFIED: "Modify",
    FindingStatus.ESCALATED: "Escalate",
    FindingStatus.COMMITTED: "Approve",
}


def severity_label(finding: ComplianceFinding) -> str:
    """Critical / High / Medium / Low for the chip in the accordion body.

    Derived from the triggering CVSS where one exists (CVSS v3 qualitative bands).
    Many findings carry no CVE/CVSS at all — a stale account or an absent MFA policy
    is not a scored vulnerability — so those fall back to the asset's criticality
    rather than inventing a score.
    """
    cvss = finding.triggering_cvss
    if cvss is not None:
        if cvss >= 9.0:
            return "Critical"
        if cvss >= 7.0:
            return "High"
        if cvss >= 4.0:
            return "Medium"
        return "Low"
    return {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
    }.get(finding.asset.criticality, "None")


_ABSENT_TOKENS = {"", "none", "nan", "null", "n/a"}


def accordion_title(finding: ComplianceFinding, display_no: int) -> str:
    """`FND-0001 • CVE-2023-20027 • CVSS 7.1 (High) • Asset AST-0021` for scored
    vulnerabilities; `FND-0003 • MFA_ABSENT • Medium • Asset AST-0001` for the rest.

    Most findings (a stale account, an absent MFA policy) have no CVE and no CVSS at
    all, so leading them with "no CVE" spends the most scannable part of the row saying
    what the finding is NOT. Those rows lead with the ISSUE CODE — the thing that
    actually distinguishes them — while CVE-backed rows keep the CVE/CVSS format.

    `display_no` is a presentation-only sequence number. `finding.finding_id` is the
    audit key and a stability contract — it is shown in the body and used for every
    widget key, and is never replaced by this label.
    """
    parts = [f"FND-{display_no:04d}"]
    cve = (finding.triggering_cve or "").strip()
    cvss = finding.triggering_cvss
    severity = severity_label(finding)
    if severity in _ABSENT_TOKENS or severity.lower() in _ABSENT_TOKENS:
        severity = "Unrated"

    if cve.lower() not in _ABSENT_TOKENS:
        parts.append(cve)
        if cvss is not None:
            parts.append(f"CVSS {cvss:.1f} ({severity})")
        else:
            parts.append(f"{severity} severity")
    else:
        # No CVE: the issue code is the identifying fact for this row.
        code = str(getattr(finding.issue_code, "value", finding.issue_code)).strip()
        if code.lower() not in _ABSENT_TOKENS:
            parts.append(code)
        parts.append(severity)

    parts.append(f"Asset {finding.asset.asset_id}")
    return " • ".join(parts)


def render_finding_card(
    finding: ComplianceFinding,
    explanation: Optional[Explanation],
    decisions: list[AnalystDecision],
    audit_log: AuditLog,
    explanations_by_id: dict,
    analyst_id: str = UNNAMED_ANALYST,
    display_no: int = 1,
    resolved: Optional[dict] = None,
) -> None:
    """Render one finding as a collapsed accordion with a Decision selectbox.

    Widget keys are derived from `finding.finding_id`, which is unique and stable
    across reruns — with 300+ accordions on screen a key collision would silently
    reset another finding's decision widget.

    `resolved` is the render pass's already-computed effective-decision map (see
    `_resolved_map`); omit it and the card resolves its own.
    """
    import streamlit as st
    from src.ui.chrome import severity_chip

    fid = finding.finding_id
    resolved = _resolved_map(decisions, resolved)
    status = status_of(fid, decisions, resolved)
    asset = finding.asset

    with st.expander(accordion_title(finding, display_no), expanded=False):
        body, panel = st.columns([3, 2])

        with body:
            st.markdown(
                f"{severity_chip(severity_label(finding))} "
                f"&nbsp;<span style='color:#718096;font-size:0.8rem;'>"
                f"{fid} · {finding.issue_code.value} · rule {finding.rule_id}</span>",
                unsafe_allow_html=True,
            )
            st.markdown(_status_chip(status))
            if edit_pending(fid, decisions, resolved):
                st.caption(
                    "⚠ **Modify selected, nothing saved yet.** No decision has been "
                    "recorded for this finding, so it still counts as outstanding at "
                    "the Stage 5 gate, and the generated text below is still what the "
                    "report would carry. Save the modified explanation in the Decision "
                    "panel to commit it."
                )
            elif edit_open(fid):
                # Already decided and re-opened for editing. Saying "no decision has been
                # recorded" here would contradict both the status chip above and the gate.
                st.caption(
                    "✏ **Editing a decided finding.** The recorded decision above stands "
                    "and still counts toward Stage 5 coverage until you save a "
                    "replacement explanation, which appends a new Modify decision."
                )
            st.caption(
                f"{asset.hostname} ({asset.asset_id}) · {asset.operating_system} · "
                f"{asset.ip_address} · {asset.environment} · "
                + ("Internet-facing" if asset.internet_facing else "Internal only")
                + f" · assessed {asset.assessment_date}"
            )

            if explanation is not None:
                st.write(explanation.plain_english)
            else:
                st.info("No Stage 3 explanation available for this finding yet.")

            mappings = (
                explanation.linked_controls
                if explanation and explanation.linked_controls
                else finding.control_mappings
            )
            if mappings:
                st.markdown("**Control Mappings:**")
                any_unverified = False
                for mapping in mappings:
                    # Provenance: is THIS intersection sourced from George's Appendix Aii?
                    # The `verified` flag is stripped when a ControlMapping is built
                    # (models.py frozen), so it is read back from the mapping engine's
                    # index by identity.
                    verified = is_verified_mapping(
                        finding.rule_id, mapping.framework, mapping.control_id
                    )
                    if verified is True:
                        provenance = " &nbsp; :green-background[✓ sourced]"
                    elif verified is False:
                        provenance = " &nbsp; :orange-background[⚠ unverified]"
                        any_unverified = True
                    else:
                        # None: cannot assert provenance — render no badge.
                        provenance = ""
                    # A CE / CE+ pillar has no identifier distinct from its name
                    # (control_id == control_name), unlike ISO where the id is a code
                    # like "A.8.8". Print the label once rather than stuttering
                    # "Patch Management Patch Management".
                    if mapping.control_id.strip() == mapping.control_name.strip():
                        label = f"**{mapping.control_id}**"
                    else:
                        label = f"**{mapping.control_id}** {mapping.control_name}"
                    st.markdown(
                        f"- `{mapping.framework.value}` → {label} "
                        f"*({mapping.mapping_type.value.title()})*{provenance}"
                    )
                if any_unverified:
                    st.caption(
                        "⚠ Mappings marked *unverified* are best-effort and not yet "
                        "sourced from George's Appendix Aii — confirm before citing them."
                    )

            steps = explanation.remediation_steps if explanation else []
            if steps:
                with st.expander("Remediation steps"):
                    for i, step in enumerate(steps, start=1):
                        st.markdown(f"{i}. {step}")

            history = [d for d in decisions if d.finding_id == fid]
            if history:
                with st.expander(f"Decision history ({len(history)})"):
                    for d in history:
                        note_text = f" — {d.analyst_note}" if d.analyst_note else ""
                        st.caption(
                            f"{d.timestamp:%Y-%m-%d %H:%M:%S} UTC · "
                            f"**{d.decision.value}** by {d.analyst_id}{note_text}"
                        )
                    st.caption("Latest decision is the effective one.")

        with panel:
            st.markdown("**Decision**")
            # A pending Modify has no decision to re-derive the selection from, so the
            # pending marker is what restores "Modify" if Streamlit dropped this
            # widget's state (see PENDING_MODIFY_KEY).
            default_label = _LABEL_FOR_STATUS.get(status, SELECT_PLACEHOLDER)
            if edit_open(fid) or edit_pending(fid, decisions, resolved):
                default_label = "Modify"
            default_index = DECISION_OPTIONS.index(default_label)
            choice = st.selectbox(
                "Decision",
                options=DECISION_OPTIONS,
                index=default_index,
                key=f"decision__{fid}",
                label_visibility="collapsed",
            )
            note = st.text_input(
                "Notes (optional)",
                key=f"note__{fid}",
                placeholder="Rationale — recorded in the audit log",
            )
            if status == FindingStatus.ESCALATED:
                st.caption(
                    "Escalated — set this to Approve or Modify to resolve it and "
                    "release Stage 5."
                )

        # Approve and Escalate record the instant they are selected: there is nothing
        # further for the analyst to compose, so the selection IS the decision.
        # Recording happens only when the selection differs from the finding's CURRENT
        # effective decision, so re-rendering an already-decided finding never appends
        # a duplicate, and re-selecting a different option records the change.
        #
        # "Modify" is deliberately absent from this branch. Selecting it composes
        # nothing and decides nothing — it opens the editor below. Recording a MODIFY
        # here would mark the finding REVIEWED for coverage before any edit existed, and
        # a report could then be compiled containing a finding labelled "Modified" whose
        # explanation was never modified. Exactly one MODIFY is appended, carrying the
        # real replacement prose, by the Save button below.
        # Track the open edit. Marking is what makes a Modify-in-progress survive a
        # rerun, show as pending on the card and in the gate banner, and be spared by
        # bulk approve. Any other selection clears it.
        if choice == "Modify" and not _has_committed_modify(fid, decisions, resolved):
            mark_edit_pending(fid)
        else:
            clear_edit_pending(fid)

        if choice not in (SELECT_PLACEHOLDER, "Modify"):
            wanted = _DECISION_FOR_LABEL[choice]
            current = _LABEL_FOR_STATUS.get(status)
            if current != choice:
                apply_decision(
                    fid, wanted, decisions, audit_log, explanations_by_id,
                    modified_explanation=None,
                    analyst_note=note, analyst_id=analyst_id,
                )
                st.rerun()

        # Modify reveals the editable explanation. Save is the only thing that decides.
        if choice == "Modify":
            with st.container(border=True):
                current_text = explanation.plain_english if explanation else ""
                edited = st.text_area(
                    "Edit the plain-English explanation",
                    value=current_text,
                    key=f"text__{fid}",
                    height=160,
                    help="The edited text replaces the generated explanation in the report.",
                )
                if edit_pending(fid, decisions, resolved):
                    st.caption(
                        "⚠ **No decision recorded yet.** Selecting Modify only opens "
                        "this editor — the finding is still outstanding at the gate "
                        "until you save. Save records one Modify decision carrying the "
                        "text above, and one audit entry."
                    )
                else:
                    st.caption(
                        f"This finding is already recorded as **{status.value}**. That "
                        "decision stands until you save; saving appends one new Modify "
                        "decision carrying the text above, and one audit entry. The "
                        "earlier decision stays in the history."
                    )
                if st.button(
                    "Save modified explanation",
                    key=f"commit__{fid}",
                    type="primary",
                ):
                    if not (edited or "").strip():
                        # An empty replacement is not an edit. Recording it would put a
                        # "Modified" finding with no explanation into the report.
                        st.warning(
                            "Nothing saved — the modified explanation is empty. Enter "
                            "the replacement text, or pick Approve/Escalate instead."
                        )
                    else:
                        apply_decision(
                            fid, DecisionType.MODIFY, decisions, audit_log,
                            explanations_by_id, modified_explanation=edited,
                            analyst_note=note, analyst_id=analyst_id,
                        )
                        clear_edit_pending(fid)
                        st.rerun()


# ---------- the stage ----------

def render_review_stage(
    findings: list[ComplianceFinding],
    explanations: list[Explanation],
    decisions: list[AnalystDecision],
    audit_log: AuditLog,
    analyst_id: str = UNNAMED_ANALYST,
    page_size: int = 10,
) -> bool:
    """Render Stage 4 in full. Returns the gate verdict (`can_generate_report`).

    Safe to call with empty lists on first load.
    """
    import streamlit as st
    from src.ui.chrome import render_callout

    st.markdown("### Every finding below requires an individual analyst decision")
    render_callout(
        "<b>Non-bypassable HITL gate — two separate rules.</b><br>"
        "<b>1. Coverage:</b> every finding listed here must carry an analyst decision "
        "(Approve, Modify or Escalate) recorded against a named analyst before a "
        "report can be compiled.<br>"
        "<b>2. Objection:</b> an <b>open Escalate blocks the report outright</b>. "
        "Escalating does <i>not</i> satisfy rule 1 for the purpose of generating a "
        "report — no report may be produced over an unresolved human objection. The "
        "escalation must be resolved by a later Approve or Modify first.<br>"
        "Both rules are enforced in the code — in the compile path and again at the "
        "PDF boundary — not just in this interface."
    )

    st.text_input(
        "Reviewing analyst name",
        key="analyst_id",
        placeholder="e.g. J. Okafor — Security Analyst",
        help="Recorded as the actor against every decision in the audit trail.",
    )
    # The callout above promises decisions are attributed to a NAMED analyst, so an
    # unnamed session must say plainly what will actually be written to the trail
    # rather than quietly recording a generic actor.
    if not (st.session_state.get("analyst_id") or "").strip():
        st.warning(
            "**No analyst name entered.** Decisions taken now are recorded against "
            f"`{UNNAMED_ANALYST}` in the audit trail, which is not an accountable "
            "attribution. Enter your name above before deciding.",
            icon="⚠️",
        )

    if not findings:
        # The gate banner carries the empty-state message on its own; a second info box
        # repeating "run Stage 1 -> 2 -> 3" just doubles the same sentence on first load.
        render_gate_banner(decisions, finding_ids=None)
        return can_generate_report(decisions)

    explanations_by_id = {e.finding_id: e for e in (explanations or [])}

    # ONE resolution of the append-only history for the whole render pass. Every
    # per-finding status/pending question below reads this map instead of re-resolving,
    # which is what keeps an idle rerun O(n) rather than O(n²) at 500 findings.
    resolved = resolve_decisions(decisions)

    all_ids = [f.finding_id for f in findings]
    # Pick up a Modify selected on THIS frame before anything that reports it renders.
    sync_pending_edits(all_ids, decisions, resolved)
    pending_ids = pending_edit_ids(all_ids, decisions, resolved)
    gate_open = render_gate_banner(
        decisions, finding_ids=all_ids, pending_ids=pending_ids
    )

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
            if status_of(f.finding_id, decisions, resolved).value in status_filter
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

    # --- bulk approve (Approve only; Modify and Escalate stay deliberate, per-finding) ---
    # 309 findings is unusable one click at a time, so approving the pending queue in bulk
    # is offered. Each approval below still writes its OWN AnalystDecision and its OWN audit
    # entry via apply_decision — the per-finding accountability trail is never collapsed into
    # a single record. Only AWAITING_REVIEW findings are targeted, so a bulk approve can never
    # silently override a deliberate Escalate or Modify.
    #
    # Findings with an OPEN, uncommitted Modify are excluded too. They are technically
    # AWAITING_REVIEW (selecting Modify records nothing), but the analyst has visibly
    # started composing an edit on them; sweeping an Approve over that would discard a
    # deliberate act just as surely as overriding a committed Modify would.
    pending_set = set(pending_ids)

    def _bulk_targets(candidates):
        return [
            f for f in candidates
            if status_of(f.finding_id, decisions, resolved) == FindingStatus.AWAITING_REVIEW
            and f.finding_id not in pending_set
        ]

    unreviewed_on_page = _bulk_targets(page_items)
    unreviewed_in_scope = _bulk_targets(visible)
    scope_label = "the current filter" if status_filter else "all findings"

    bulk_page_col, bulk_scope_col = st.columns(2)
    if bulk_page_col.button(
        f"✅ Approve all unreviewed on this page ({len(unreviewed_on_page)})",
        key="bulk_approve_page",
        disabled=not unreviewed_on_page,
        width="stretch",
        help="Records an individual Approve decision and audit entry for each finding.",
    ):
        for f in unreviewed_on_page:
            apply_decision(
                f.finding_id, DecisionType.APPROVE, decisions, audit_log,
                explanations_by_id,
                analyst_note="Bulk approval — all unreviewed on this page.",
                analyst_id=analyst_id,
            )
        st.rerun()

    if bulk_scope_col.button(
        f"✅ Approve all unreviewed matching {scope_label} ({len(unreviewed_in_scope)})",
        key="bulk_approve_scope",
        disabled=not unreviewed_in_scope,
        width="stretch",
        help="Records an individual Approve decision and audit entry for each finding.",
    ):
        for f in unreviewed_in_scope:
            apply_decision(
                f.finding_id, DecisionType.APPROVE, decisions, audit_log,
                explanations_by_id,
                analyst_note=f"Bulk approval — all unreviewed matching {scope_label}.",
                analyst_id=analyst_id,
            )
        st.rerun()

    # Display numbers are assigned over the FULL finding list, so FND-0007 stays
    # FND-0007 whatever filter or page it is viewed through.
    display_numbers = {f.finding_id: i for i, f in enumerate(findings, start=1)}

    for finding in page_items:
        render_finding_card(
            finding=finding,
            explanation=explanations_by_id.get(finding.finding_id),
            decisions=decisions,
            audit_log=audit_log,
            explanations_by_id=explanations_by_id,
            analyst_id=analyst_id,
            display_no=display_numbers.get(finding.finding_id, 1),
            resolved=resolved,
        )

    return gate_open
