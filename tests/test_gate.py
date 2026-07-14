"""
test_gate.py  -  THE ARTICLE 22 GATE. The single graded control in this project.

`can_generate_report(decisions)` must be False iff any EFFECTIVE decision is
ESCALATE. Decisions are an append-only history: duplicates resolve latest-by-
timestamp-wins, ties broken by list position.

`can_generate_report([]) == True` is DELIBERATE: the function is only the
escalation control. Review coverage ("has every finding been decided?") is the
separate, weaker `gate_status(decisions, total_findings)` check and must never be
folded into the Article 22 control -- doing so would change what the control means.

Defence in depth: `compile_report()` in streamlit_app.py re-checks the gate on the
compile path itself. The tests below BYPASS THE UI entirely -- they import the app
module and call the compile path directly with an escalation open -- because a
disabled button is an affordance, not a control.

If any test in this file fails, that is a BLOCKING DEFECT. Do not weaken, delete,
loosen or special-case the gate to make it pass.

No src/ file was patched for these tests.
"""
from __future__ import annotations

import glob
import os
import tempfile
from datetime import datetime, timezone

import pytest

from src.audit.log import AuditLog
from src.gate import (
    can_generate_report,
    escalated_finding_ids,
    gate_status,
    resolve_decisions,
)
from src.models import DecisionType

from tests.helpers import T0, make_decision

APPROVE = DecisionType.APPROVE
MODIFY = DecisionType.MODIFY
ESCALATE = DecisionType.ESCALATE


# ---------------------------------------------------------------------------------
# The core contract
# ---------------------------------------------------------------------------------

def test_empty_history_allows_report():
    """DELIBERATE: no decisions means no open escalations. Coverage is gate_status's
    job, not this function's."""
    assert can_generate_report([]) is True


def test_single_approve_allows():
    assert can_generate_report([make_decision("F-1", APPROVE)]) is True


def test_single_modify_allows():
    assert can_generate_report([make_decision("F-1", MODIFY)]) is True


def test_single_escalate_blocks():
    assert can_generate_report([make_decision("F-1", ESCALATE)]) is False


def test_one_escalation_among_many_approvals_blocks():
    decisions = [make_decision(f"F-{i}", APPROVE, minute=i) for i in range(50)]
    decisions.insert(25, make_decision("F-ESC", ESCALATE, minute=25))
    assert can_generate_report(decisions) is False
    assert escalated_finding_ids(decisions) == ["F-ESC"]


def test_all_approved_or_modified_allows():
    decisions = [
        make_decision(f"F-{i}", APPROVE if i % 2 else MODIFY, minute=i)
        for i in range(20)
    ]
    assert can_generate_report(decisions) is True
    assert escalated_finding_ids(decisions) == []


# ---------------------------------------------------------------------------------
# Append-only history resolution
# ---------------------------------------------------------------------------------

def test_escalate_superseded_by_later_approve_unblocks():
    decisions = [
        make_decision("F-1", ESCALATE, minute=0),
        make_decision("F-1", APPROVE, minute=10),
    ]
    assert can_generate_report(decisions) is True


def test_escalate_superseded_by_later_modify_unblocks():
    decisions = [
        make_decision("F-1", ESCALATE, minute=0),
        make_decision("F-1", MODIFY, minute=10),
    ]
    assert can_generate_report(decisions) is True


def test_approve_superseded_by_later_escalate_reblocks():
    decisions = [
        make_decision("F-1", APPROVE, minute=0),
        make_decision("F-1", ESCALATE, minute=10),
    ]
    assert can_generate_report(decisions) is False


def test_out_of_order_list_latest_timestamp_wins():
    """List position is NOT chronology: the newest timestamp is effective even when
    it appears first in the list."""
    approve_late = make_decision("F-1", APPROVE, minute=60)
    escalate_early = make_decision("F-1", ESCALATE, minute=0)
    assert can_generate_report([approve_late, escalate_early]) is True
    assert can_generate_report([escalate_early, approve_late]) is True

    escalate_late = make_decision("F-2", ESCALATE, minute=60)
    approve_early = make_decision("F-2", APPROVE, minute=0)
    assert can_generate_report([escalate_late, approve_early]) is False
    assert can_generate_report([approve_early, escalate_late]) is False


def test_timestamp_tie_broken_by_list_position():
    escalate = make_decision("F-1", ESCALATE, minute=5)
    approve = make_decision("F-1", APPROVE, minute=5)
    assert can_generate_report([escalate, approve]) is True   # approve appended last
    assert can_generate_report([approve, escalate]) is False  # escalate appended last


def test_findings_resolve_independently():
    decisions = [
        make_decision("F-A", ESCALATE, minute=0),
        make_decision("F-B", ESCALATE, minute=1),
        make_decision("F-A", APPROVE, minute=2),  # F-A resolved, F-B still open
    ]
    assert can_generate_report(decisions) is False
    assert escalated_finding_ids(decisions) == ["F-B"]

    decisions.append(make_decision("F-B", MODIFY, minute=3))
    assert can_generate_report(decisions) is True


def test_escalate_resolve_escalate_again_reblocks():
    decisions = [
        make_decision("F-1", ESCALATE, minute=0),
        make_decision("F-1", APPROVE, minute=1),
        make_decision("F-1", ESCALATE, minute=2),
    ]
    assert can_generate_report(decisions) is False


def test_naive_and_aware_timestamps_do_not_crash_the_gate():
    """A naive timestamp is read as UTC rather than raising TypeError on compare."""
    # Naive 12:00 escalate vs aware 12:30 approve: the approve is later in UTC, so
    # the gate opens -- in either list order, without crashing.
    naive_early_escalate = make_decision(
        "F-1", ESCALATE, ts=datetime(2025, 7, 1, 12, 0, 0)  # naive == T0 read as UTC
    )
    aware_approve = make_decision("F-1", APPROVE, minute=30)
    assert can_generate_report([naive_early_escalate, aware_approve]) is True
    assert can_generate_report([aware_approve, naive_early_escalate]) is True

    # Naive 13:00 escalate is LATER than the aware 12:30 approve: blocked either way.
    naive_late_escalate = make_decision(
        "F-1", ESCALATE, ts=datetime(2025, 7, 1, 13, 0, 0)
    )
    assert can_generate_report([aware_approve, naive_late_escalate]) is False
    assert can_generate_report([naive_late_escalate, aware_approve]) is False


def test_resolve_decisions_returns_effective_decision_per_finding():
    d1 = make_decision("F-1", ESCALATE, minute=0)
    d2 = make_decision("F-1", APPROVE, minute=5)
    d3 = make_decision("F-2", MODIFY, minute=1)
    resolved = resolve_decisions([d1, d2, d3])
    assert resolved["F-1"] is d2
    assert resolved["F-2"] is d3
    assert set(resolved) == {"F-1", "F-2"}


def test_escalated_finding_ids_sorted():
    decisions = [
        make_decision("F-ZULU", ESCALATE, minute=0),
        make_decision("F-ALPHA", ESCALATE, minute=1),
    ]
    assert escalated_finding_ids(decisions) == ["F-ALPHA", "F-ZULU"]


# ---------------------------------------------------------------------------------
# Coverage is a SEPARATE, weaker check -- never folded into the control
# ---------------------------------------------------------------------------------
# Migrated to the primary `finding_ids=` (set-containment) path per the fixer-app
# change to gate_status. `total_findings=` is now a deprecated count-only fallback;
# its backward compatibility is covered by test_gate_status_legacy_count_path below.

_TEN_IDS = [f"F-{i}" for i in range(10)]


def test_coverage_is_not_part_of_the_article_22_control():
    """3 of 10 findings decided, none escalated: the hard control passes (True) while
    gate_status separately reports incomplete coverage. Folding coverage into
    can_generate_report would change what the Article 22 control means."""
    decisions = [make_decision(f"F-{i}", APPROVE, minute=i) for i in range(3)]
    assert can_generate_report(decisions) is True

    status = gate_status(decisions, _TEN_IDS)
    assert status["escalation_clear"] is True
    assert status["coverage_complete"] is False
    assert status["outstanding_count"] == 7
    assert status["unlocked"] is False  # UI banner ANDs both, correctly


def test_gate_status_blocked_by_escalation_even_with_full_coverage():
    decisions = [make_decision(f"F-{i}", APPROVE, minute=i) for i in range(9)]
    decisions.append(make_decision("F-9", ESCALATE, minute=9))
    status = gate_status(decisions, _TEN_IDS)
    assert status["escalation_clear"] is False
    assert status["coverage_complete"] is True
    assert status["unlocked"] is False
    assert status["escalated_ids"] == ["F-9"]


def test_gate_status_green_when_all_reviewed_none_escalated():
    decisions = [make_decision(f"F-{i}", APPROVE, minute=i) for i in range(10)]
    status = gate_status(decisions, _TEN_IDS)
    assert status["unlocked"] is True
    assert status["escalation_clear"] is True
    assert status["coverage_complete"] is True
    assert status["orphan_ids"] == []


def test_gate_status_legacy_count_path_still_supported():
    """The deprecated `total_findings=` count fallback is retained for backwards
    compatibility. It cannot detect orphans (no ids to compare), so it is the weaker
    path -- but callers passing it must still get a coherent banner."""
    decisions = [make_decision(f"F-{i}", APPROVE, minute=i) for i in range(3)]
    status = gate_status(decisions, total_findings=10)
    assert status["reviewed_count"] == 3
    assert status["outstanding_count"] == 7
    assert status["coverage_complete"] is False
    assert status["escalation_clear"] is True
    assert status["unlocked"] is False


# ---------------------------------------------------------------------------------
# Defence in depth: the compile path itself, with the UI bypassed
# ---------------------------------------------------------------------------------

def _rpt_pdfs() -> set:
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "RPT-*.pdf")))


@pytest.fixture()
def app_session(findings, explanations):
    """Bare-mode streamlit_app with a small, fully-explained finding set seeded.

    Importing streamlit_app executes main() in Streamlit's bare mode (no server, a
    process-local session_state) -- exactly the 'future caller / stale widget' path
    the gate must survive. State is reset before and after each test.
    """
    import streamlit as st
    import streamlit_app  # noqa: F401  (module-level main() runs in bare mode)

    chosen = [f.model_copy(deep=True) for f in findings[:3]]
    fids = {f.finding_id for f in chosen}
    st.session_state["findings"] = chosen
    st.session_state["explanations"] = [
        e.model_copy(deep=True) for e in explanations if e.finding_id in fids
    ]
    st.session_state["decisions"] = []
    st.session_state["report"] = None
    st.session_state["report_bytes"] = None
    st.session_state["report_hash"] = None
    st.session_state["report_path"] = None
    st.session_state["last_error"] = None
    st.session_state["audit_log"] = AuditLog()

    yield st, __import__("streamlit_app"), chosen

    for key in (
        "findings", "explanations", "decisions", "report", "report_bytes",
        "report_hash", "report_path", "last_error",
    ):
        st.session_state[key] = [] if key in ("findings", "explanations", "decisions") else None
    st.session_state["audit_log"] = AuditLog()


def test_compile_path_refuses_while_escalation_open_ui_bypassed(app_session):
    """Call compile_report() DIRECTLY -- no button, no banner -- with an escalation
    open. It must refuse, produce no PDF, and audit the refusal (STAGE_5_BLOCKED)."""
    st, app, chosen = app_session
    st.session_state["decisions"] = [
        make_decision(f.finding_id, APPROVE, minute=i) for i, f in enumerate(chosen)
    ] + [make_decision(chosen[0].finding_id, ESCALATE, minute=99)]

    pdfs_before = _rpt_pdfs()
    result = app.compile_report()
    pdfs_after = _rpt_pdfs()

    assert result is None
    assert st.session_state["report"] is None
    assert st.session_state["report_bytes"] is None
    assert st.session_state["report_hash"] is None
    assert pdfs_after == pdfs_before, "a PDF was written despite the open escalation"
    assert "escalated" in (st.session_state["last_error"] or "")

    blocked = [
        e for e in st.session_state["audit_log"].entries
        if e.action == "STAGE_5_BLOCKED"
    ]
    assert len(blocked) == 1
    assert chosen[0].finding_id in (blocked[0].details or "")
    assert "Article 22" in (blocked[0].details or "")


def test_compile_path_unblocks_once_escalation_resolved(app_session):
    """Resolving the escalation (a LATER approve appended to the history) releases
    the same compile path: a real PDF with a real SHA-256, and the refusal remains
    in the audit trail."""
    st, app, chosen = app_session
    decisions = [
        make_decision(f.finding_id, APPROVE, minute=i) for i, f in enumerate(chosen)
    ] + [make_decision(chosen[0].finding_id, ESCALATE, minute=99)]
    st.session_state["decisions"] = decisions

    assert app.compile_report() is None  # blocked first

    decisions.append(make_decision(chosen[0].finding_id, APPROVE, minute=120))
    report = app.compile_report()

    assert report is not None
    assert report.sha256_hash and len(report.sha256_hash) == 64
    assert st.session_state["report_bytes"][:5] == b"%PDF-"
    assert os.path.isfile(report.pdf_path)

    actions = [e.action for e in st.session_state["audit_log"].entries]
    assert "STAGE_5_BLOCKED" in actions   # the refusal is retained
    assert "STAGE_5_REPORT" in actions

    os.remove(report.pdf_path)  # tidy the temp dir


def test_compile_path_requires_full_coverage_before_building(app_session):
    """The compile path also enforces the weaker coverage check -- separately from
    (and after) the Article 22 control."""
    st, app, chosen = app_session
    st.session_state["decisions"] = [
        make_decision(chosen[0].finding_id, APPROVE, minute=0)
    ]  # 1 of 3 reviewed, none escalated

    result = app.compile_report()
    assert result is None
    assert st.session_state["report"] is None
    assert "awaiting" in (st.session_state["last_error"] or "").lower()


def test_gate_module_docstring_still_forbids_weakening():
    """Tripwire: the gate module must keep declaring itself the Article 22 control.
    If someone strips the contract documentation, review what else changed."""
    import src.gate as gate_module

    text = (gate_module.__doc__ or "") + (gate_module.can_generate_report.__doc__ or "")
    assert "Article 22" in text
