"""
gate.py  -  The Stage 5 release gate (UK GDPR Article 22 design control).

This module is the single most important behaviour in the system. It is what makes the
tool *decision support* rather than *automated decision-making*: a report can never be
compiled while a human analyst still has an open escalation against any finding.

Do not weaken `can_generate_report`. If a test fails against it, the caller is wrong.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from src.models import AnalystDecision, DecisionType


# ---------- internal helpers ----------

def _normalised_timestamp(decision: AnalystDecision) -> datetime:
    """Return the decision timestamp as an aware UTC datetime.

    `AnalystDecision.timestamp` defaults to an aware UTC value, but a caller (or a test)
    may construct one with a naive datetime. Mixing naive and aware datetimes raises
    TypeError when compared, which would crash the gate. A naive timestamp is therefore
    interpreted as UTC rather than being allowed to blow up the ordering.
    """
    ts = decision.timestamp
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


# ---------- resolution ----------

def resolve_decisions(decisions: list[AnalystDecision]) -> dict[str, AnalystDecision]:
    """Collapse a decision history into the one effective decision per finding.

    The decision list is an append-only history, not a set: an analyst may escalate a
    finding and later replace that with Approve/Modify once the escalation is resolved.
    Both decisions stay in the list. The LATEST decision by timestamp is the effective
    one; where two decisions for the same finding share a timestamp, the one appearing
    later in the list wins (list order is the tie-break, since it is the true insertion
    order).

    Returns a mapping of finding_id -> effective AnalystDecision.
    """
    latest: dict[str, tuple[datetime, int, AnalystDecision]] = {}
    for index, decision in enumerate(decisions):
        key = (_normalised_timestamp(decision), index)
        current = latest.get(decision.finding_id)
        if current is None or key >= (current[0], current[1]):
            latest[decision.finding_id] = (key[0], key[1], decision)
    return {fid: entry[2] for fid, entry in latest.items()}


def escalated_finding_ids(decisions: list[AnalystDecision]) -> list[str]:
    """Finding ids whose EFFECTIVE (latest) decision is Escalate.

    A finding that was escalated and later approved/modified does not appear here — the
    escalation has been resolved. Sorted for deterministic output.
    """
    resolved = resolve_decisions(decisions)
    return sorted(
        fid for fid, decision in resolved.items()
        if decision.decision == DecisionType.ESCALATE
    )


# ---------- the control ----------

def can_generate_report(decisions: list[AnalystDecision]) -> bool:
    """Return False if ANY finding is still escalated. THE Article 22 control.

    Contract
    --------
    - Takes the full append-only decision history, `list[AnalystDecision]`.
    - A finding_id MAY appear more than once. Duplicates are resolved explicitly: the
      LATEST decision by timestamp wins, ties broken by position in the list. Only that
      effective decision is tested.
    - An escalation is therefore "resolved" when, and only when, the analyst replaces
      that finding's decision with Approve or Modify. Appending an Approve after an
      Escalate for the same finding_id unblocks it. Appending an Escalate after an
      Approve re-blocks it.
    - Returns False if the effective decision of any finding is DecisionType.ESCALATE.
    - Returns True otherwise, including for an empty list (no decisions means no open
      escalations). Note this is deliberately *only* the escalation control: it does not
      assert that every finding has been reviewed. Review coverage is a separate,
      weaker UI concern — see `gate_status` — and must never be folded into this
      function, because doing so would change what the Article 22 control means.

    This is re-checked on the compile path itself, not just used to disable the button.
    A disabled button is not a control.
    """
    return not escalated_finding_ids(decisions)


# ---------- UI convenience (never a substitute for the control above) ----------

def gate_status(
    decisions: list[AnalystDecision],
    finding_ids: Optional[Iterable[str]] = None,
    *,
    total_findings: Optional[int] = None,
) -> dict:
    """Summarise gate state for the UI banner.

    `unlocked` is the AND of the hard control (`can_generate_report`) and, when the live
    finding set is supplied, full review coverage. The hard control is reported separately
    as `escalation_clear` so the UI can distinguish "still to review" from "blocked by an
    escalation" — they are very different messages to an analyst.

    Coverage is computed by SET CONTAINMENT, not by counting decisions. Pass `finding_ids`
    (the ids of the findings currently in play). Reviewed = decided_ids ∩ finding_ids, so a
    finding is only "reviewed" when a decision actually references it. Orphan decisions
    (a decided finding_id that is NOT among the live findings — e.g. left behind after the
    finding set was rebuilt) do NOT count toward coverage, which is what stops a stray
    decision from inflating coverage to 100% while a real finding was never touched. Such
    orphans are surfaced as `orphan_ids` for the UI, but never treated as coverage.

    `total_findings` is a deprecated count-only fallback kept for backwards compatibility;
    it cannot detect orphans (it has no ids to compare against) and callers should pass
    `finding_ids` instead. When both are given, `finding_ids` wins.
    """
    resolved = resolve_decisions(decisions)
    decided_ids = set(resolved)
    escalated = escalated_finding_ids(decisions)
    escalation_clear = not escalated
    orphan_ids: list[str] = []

    if finding_ids is not None:
        # Dedupe while preserving first-appearance order for stable UI output.
        live_ordered = list(dict.fromkeys(finding_ids))
        live_set = set(live_ordered)
        reviewed = len(decided_ids & live_set)
        total = len(live_set)
        outstanding = total - reviewed
        coverage_complete = outstanding == 0
        orphan_ids = sorted(decided_ids - live_set)
    elif total_findings is not None:
        # Legacy count-based path: cannot assert set containment, so it may over-count
        # coverage if a decision references a finding that is no longer live.
        reviewed = len(decided_ids)
        total = total_findings
        outstanding = max(total_findings - reviewed, 0)
        coverage_complete = outstanding == 0
    else:
        reviewed = len(decided_ids)
        total = None
        outstanding = 0
        coverage_complete = True

    return {
        "escalation_clear": escalation_clear,
        "escalated_ids": escalated,
        "escalated_count": len(escalated),
        "reviewed_count": reviewed,
        "total_findings": total,
        "outstanding_count": outstanding,
        "coverage_complete": coverage_complete,
        "orphan_ids": orphan_ids,
        "unlocked": escalation_clear and coverage_complete,
    }
