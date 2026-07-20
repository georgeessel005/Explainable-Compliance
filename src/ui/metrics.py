"""
ui/metrics.py  -  The evaluation metrics dashboard.

Four metrics, each computed by a pure function so the tester can assert them without
touching Streamlit:

- Functional Correctness   share of findings matching an expected-output baseline
                           (N/A when no baseline is supplied)
- Cross-Mapping Fidelity   share of findings that reach every applicable framework
- Execution Velocity       pipeline wall-clock, ingestion -> report, timed live
- Human Interaction Load   override / escalate rate across analyst decisions
"""
from __future__ import annotations

from typing import Iterable, Optional

from src.gate import resolve_decisions
from src.models import (
    ComplianceFinding,
    DecisionType,
    Framework,
)

# Frameworks that a CE pillar mapping can carry.
_CE_FAMILY = {Framework.CE, Framework.CE_PLUS}


# ---------- Functional Correctness ----------

def functional_correctness(
    findings: list[ComplianceFinding],
    baseline: Optional[dict] = None,
) -> Optional[float]:
    """Share of findings that match an expected-output baseline.

    Returns None (rendered "N/A") when no baseline is supplied — the honest answer when
    there is nothing to compare against. Fabricating a correctness number without a
    baseline would misrepresent the evaluation.

    Also None when there are no findings at all: a baseline uploaded before the pipeline
    has run has nothing to score, and "0.0% correct" is a claim about output that does
    not exist yet. "Not evaluated" is the truthful answer; 0% is a failure report.

    `baseline` maps finding_id -> expected attributes, e.g.
        {"F-0001": {"issue_code": "PATCH_MISSING", "rule_id": "CE-PATCH-001"}}
    A finding matches when every supplied expected attribute equals the actual value.
    Only the keys present in the baseline entry are compared, so a baseline may assert
    as little or as much as it likes.
    """
    if not baseline:
        return None
    if not findings:
        return None

    by_id = {f.finding_id: f for f in findings}
    matched = 0
    for finding_id, expected in baseline.items():
        actual = by_id.get(finding_id)
        if actual is None:
            continue
        if _matches_baseline(actual, expected):
            matched += 1
    return matched / len(baseline) if baseline else None


def _matches_baseline(finding: ComplianceFinding, expected: dict) -> bool:
    for key, want in expected.items():
        got = getattr(finding, key, None)
        if hasattr(got, "value"):  # enum -> compare on its string value
            got = got.value
        if isinstance(want, list):
            got_list = [g.value if hasattr(g, "value") else g for g in (got or [])]
            if sorted(map(str, got_list)) != sorted(map(str, want)):
                return False
        elif str(got) != str(want):
            return False
    return True


# ---------- Cross-Mapping Fidelity ----------

def is_cross_mapped(finding: ComplianceFinding) -> bool:
    """Did this finding reach every framework it should have?

    Definition (documented because the metric is only as good as its definition):
    a finding is cross-mapped when BOTH hold —
      1. its control_mappings reach across the frameworks, i.e. at least one Cyber
         Essentials / CE Plus pillar AND at least one ISO/IEC 27001 Annex A control.
         A finding mapped to CE alone has not been cross-mapped at all; that is the
         whole point of the tool.
      2. `frameworks_breached` covers every framework actually present in
         control_mappings — i.e. the declared breach set is not under-reporting the
         mappings the engine attached.
    """
    mapped_frameworks = {m.framework for m in finding.control_mappings}
    if not mapped_frameworks:
        return False

    has_ce = bool(mapped_frameworks & _CE_FAMILY)
    has_iso = Framework.ISO27001 in mapped_frameworks
    if not (has_ce and has_iso):
        return False

    declared = set(finding.frameworks_breached)
    return mapped_frameworks.issubset(declared)


def cross_mapping_fidelity(findings: list[ComplianceFinding]) -> Optional[float]:
    """Share of findings that hit every applicable framework. None when no findings."""
    if not findings:
        return None
    return sum(1 for f in findings if is_cross_mapped(f)) / len(findings)


def unmapped_findings(findings: list[ComplianceFinding]) -> list[ComplianceFinding]:
    """The findings dragging fidelity down — surfaced so they can be inspected."""
    return [f for f in findings if not is_cross_mapped(f)]


# ---------- Execution Velocity ----------

def execution_velocity(stage_times: dict) -> dict:
    """Summarise live-timed pipeline stage durations (seconds).

    `stage_times` maps a stage label -> wall-clock seconds, written by the app as each
    stage runs. Total is the sum of the stages that have actually run, so a partially
    run pipeline reports honestly rather than reporting zero.
    """
    stages = {k: float(v) for k, v in (stage_times or {}).items()}
    return {
        "stages": stages,
        "total_seconds": sum(stages.values()) if stages else None,
        "stages_run": len(stages),
    }


def throughput(stage_times: dict, n_findings: int) -> Optional[float]:
    """Findings produced per second across the whole pipeline."""
    total = execution_velocity(stage_times)["total_seconds"]
    if not total or not n_findings:
        return None
    return n_findings / total


# ---------- Human Interaction Load ----------

def human_interaction_load(decisions: list, total_findings: Optional[int] = None) -> dict:
    """Override / escalate rates across the analyst's effective decisions.

    Uses the EFFECTIVE decision per finding (latest wins — see gate.resolve_decisions),
    so a finding escalated then approved counts once, as an approval. The raw history
    length is reported separately as `total_actions`, since revisiting a finding is
    itself interaction load: `actions_per_finding` is the honest measure of churn.
    """
    resolved = resolve_decisions(decisions) if decisions else {}
    effective = list(resolved.values())
    reviewed = len(effective)

    counts = {d.value: 0 for d in DecisionType}
    for decision in effective:
        counts[decision.decision.value] += 1

    approve = counts[DecisionType.APPROVE.value]
    modify = counts[DecisionType.MODIFY.value]
    escalate = counts[DecisionType.ESCALATE.value]

    def _rate(n: int) -> Optional[float]:
        return (n / reviewed) if reviewed else None

    return {
        "counts": counts,
        "reviewed_count": reviewed,
        "total_actions": len(decisions or []),
        "total_findings": total_findings,
        "approve_rate": _rate(approve),
        "modify_rate": _rate(modify),
        "escalate_rate": _rate(escalate),
        # Override = analyst did not accept the machine output as-is.
        "override_rate": _rate(modify + escalate),
        "actions_per_finding": (len(decisions) / reviewed) if reviewed else None,
        "review_coverage": (reviewed / total_findings) if total_findings else None,
    }


# ---------- rendering ----------

def _pct(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value * 100:.1f}%"


def render_metrics(
    findings: list[ComplianceFinding],
    decisions: list,
    stage_times: dict,
    baseline: Optional[dict] = None,
) -> None:
    """Draw the evaluation dashboard. Safe to call with empty state on first load."""
    import pandas as pd
    import streamlit as st

    st.subheader("Evaluation metrics")
    st.caption(
        "Computed live from the current session. Figures are only meaningful once the "
        "pipeline has run — see the sidebar."
    )

    findings = findings or []
    decisions = decisions or []

    fc = functional_correctness(findings, baseline)
    fidelity = cross_mapping_fidelity(findings)
    velocity = execution_velocity(stage_times)
    load = human_interaction_load(decisions, total_findings=len(findings) or None)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Functional correctness", _pct(fc))
        if not baseline:
            caption = "No expected-output baseline supplied"
        elif not findings:
            # A baseline can be uploaded before the pipeline runs. There is nothing to
            # score yet, so say so rather than implying a 0% result was measured.
            caption = (
                f"Baseline of {len(baseline)} finding(s) loaded — not evaluated until "
                "the pipeline has run"
            )
        else:
            caption = f"vs baseline of {len(baseline)} finding(s)"
        st.caption(caption)

    with col2:
        st.metric("Cross-mapping fidelity", _pct(fidelity))
        st.caption(
            f"{len(findings) - len(unmapped_findings(findings))}/{len(findings)} findings "
            "reach CE and ISO" if findings else "No findings yet"
        )

    with col3:
        total = velocity["total_seconds"]
        st.metric("Execution velocity", "N/A" if total is None else f"{total:.2f}s")
        tp = throughput(stage_times, len(findings))
        st.caption(
            f"{tp:.0f} findings/sec across {velocity['stages_run']} stage(s)" if tp
            else "Pipeline not yet run"
        )

    with col4:
        st.metric("Human interaction load", _pct(load["override_rate"]))
        st.caption(
            f"{load['reviewed_count']} reviewed, "
            f"{load['counts'][DecisionType.ESCALATE.value]} escalated"
        )

    st.divider()

    left, right = st.columns(2)

    with left:
        st.markdown("**Stage timings (execution velocity)**")
        if velocity["stages"]:
            st.dataframe(
                pd.DataFrame(
                    [{"Stage": k, "Seconds": round(v, 4)} for k, v in velocity["stages"].items()]
                ),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("Run the pipeline from the sidebar to time it.")

    with right:
        st.markdown("**Analyst decisions (human interaction load)**")
        if load["reviewed_count"]:
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Decision": k, "Count": v, "Share": _pct(v / load["reviewed_count"])}
                        for k, v in load["counts"].items()
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
            if load["actions_per_finding"]:
                st.caption(
                    f"{load['total_actions']} action(s) across {load['reviewed_count']} "
                    f"finding(s) — {load['actions_per_finding']:.2f} per finding "
                    "(revisits count as load)."
                )
        else:
            st.info("No analyst decisions recorded yet.")

    if findings:
        problem = unmapped_findings(findings)
        if problem:
            with st.expander(f"{len(problem)} finding(s) not fully cross-mapped"):
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Finding": f.finding_id,
                                "Issue": f.issue_code.value,
                                "Rule": f.rule_id,
                                "Frameworks mapped": ", ".join(
                                    sorted({m.framework.value for m in f.control_mappings})
                                ) or "none",
                                "Frameworks declared": ", ".join(
                                    sorted({fw.value for fw in f.frameworks_breached})
                                ) or "none",
                            }
                            for f in problem
                        ]
                    ),
                    hide_index=True,
                    width="stretch",
                )

    with st.expander("How each metric is defined"):
        st.markdown(
            """
- **Functional correctness** — share of findings matching a supplied expected-output
  baseline. Shows **N/A** when no baseline is loaded, and when no findings have been
  produced yet — no baseline (or nothing to score) means no claim.
- **Cross-mapping fidelity** — share of findings whose control mappings reach at least
  one Cyber Essentials (or CE Plus) pillar *and* at least one ISO/IEC 27001 Annex A
  control, with `frameworks_breached` covering every framework mapped.
- **Execution velocity** — wall-clock seconds per pipeline stage, timed live in this
  session, summed ingestion → report.
- **Human interaction load** — override rate = (Modify + Escalate) ÷ findings reviewed,
  using each finding's latest decision. Repeat visits to a finding are reported as
  actions per finding.
            """
        )
