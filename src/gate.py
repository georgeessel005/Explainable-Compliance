"""
gate.py  -  The Stage 5 release gate (UK GDPR Article 22 design control).

This module is the single most important behaviour in the system. It is what makes the
tool *decision support* rather than *automated decision-making*: a report can never be
compiled while a human analyst still has an open escalation against any finding.

Do not weaken `can_generate_report`. If a test fails against it, the caller is wrong.
"""
from __future__ import annotations

from datetime import datetime, timezone

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
    total_findings: int | None = None,
) -> dict:
    """Summarise gate state for the UI banner.

    `unlocked` is the AND of the hard control (`can_generate_report`) and, when
    `total_findings` is supplied, full review coverage. The hard control is reported
    separately as `escalation_clear` so the UI can distinguish "still to review" from
    "blocked by an escalation" — they are very different messages to an analyst.
    """
    resolved = resolve_decisions(decisions)
    escalated = escalated_finding_ids(decisions)
    reviewed = len(resolved)
    escalation_clear = not escalated

    if total_findings is None:
        coverage_complete = True
        outstanding = 0
    else:
        outstanding = max(total_findings - reviewed, 0)
        coverage_complete = outstanding == 0

    return {
        "escalation_clear": escalation_clear,
        "escalated_ids": escalated,
        "escalated_count": len(escalated),
        "reviewed_count": reviewed,
        "total_findings": total_findings,
        "outstanding_count": outstanding,
        "coverage_complete": coverage_complete,
        "unlocked": escalation_clear and coverage_complete,
    }
