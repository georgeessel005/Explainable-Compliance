"""
streamlit_app.py  -  Explainable Compliance Tool (Cyber Essentials x ISO/IEC 27001:2022).

Entry point for Streamlit Community Cloud. Drives the five-stage pipeline:

    Stage 1  Ingestion       load + validate synthetic scan records
    Stage 2  Mapping         issue codes -> cross-framework controls
    Stage 3  Explainability  plain-English rationale per finding
    Stage 4  HITL gate       analyst must Approve / Modify / Escalate every finding
    Stage 5  Report          ReportLab PDF + SHA-256, BLOCKED while anything is escalated

All cross-rerun state lives in st.session_state (Streamlit re-executes this whole script
on every interaction). No browser storage, no network calls.

Every stage below runs against the real sibling module. Imports are direct and at module
scope: a broken sibling must fail loudly at boot rather than degrade into stand-in data,
because an app that renders fake findings convincingly is worse than one that will not
start.
"""
from __future__ import annotations

import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import streamlit as st

from src.audit.log import AuditLog
from src.data.generate_synthetic import main as generate_dataset
from src.explain.explainer import explain
from src.gate import can_generate_report, escalated_finding_ids, gate_status
from src.ingestion.loader import load_and_validate
from src.mapping.engine import load_rules, map_findings
from src.mapping.matrix import build_matrix
from src.models import (
    AnalystDecision,
    ComplianceFinding,
    ComplianceReport,
    Explanation,
    FindingStatus,
    IngestionResult,
)
from src.report.integrity import sha256_of_file
from src.report.pdf_builder import compile_pdf
from src.ui.heatmap import render_heatmap
from src.ui.metrics import render_metrics
from src.ui.review import render_review_stage

DATA_PATH = "data/synthetic/assets.json"
RULES_DIR = "rules"


def _ensure_dataset() -> None:
    """Materialise Agent 1's synthetic dataset if it is not on disk yet.

    Runs the real generator. If it fails, the exception propagates to Stage 1's
    handler and is surfaced to the analyst: a dataset that cannot be built is a
    condition to report, not to paper over.
    """
    generate_dataset()


# ======================================================================================
# Session state
# ======================================================================================

def init_state() -> None:
    """Initialise every cross-rerun key. Guarded so first load never KeyErrors."""
    defaults = {
        "ingestion_result": None,
        "rulebase": None,
        "matrix": None,
        "findings": [],
        "explanations": [],
        "decisions": [],
        "stage_times": {},
        "baseline": None,
        "report": None,
        "report_bytes": None,
        "report_hash": None,
        "report_path": None,
        "analyst_id": "analyst",
        "last_error": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    if "audit_log" not in st.session_state:
        st.session_state["audit_log"] = AuditLog()


def _audit() -> AuditLog:
    return st.session_state["audit_log"]


def _analyst() -> str:
    return st.session_state.get("analyst_id") or "analyst"


def _reset_downstream(from_stage: int) -> None:
    """Drop state that a re-run stage invalidates.

    Re-running ingestion or mapping changes the finding set, so decisions taken against
    the old findings must not survive — a decision that no longer maps to a live finding
    would silently corrupt the gate. Discarding them is itself audited: an analyst
    decision disappearing without a trace is exactly what the trail exists to prevent.
    """
    if from_stage <= 2:
        st.session_state["findings"] = []
        st.session_state["matrix"] = None
    if from_stage <= 3:
        st.session_state["explanations"] = []
    if from_stage <= 4:
        discarded = st.session_state["decisions"]
        if discarded:
            _audit().record_stage(
                action="DECISIONS_DISCARDED",
                actor=_analyst(),
                details=(
                    f"{len(discarded)} analyst decision(s) discarded because an earlier "
                    "stage was re-run and the finding set was rebuilt. The decisions "
                    "themselves remain in this trail above."
                ),
            )
        st.session_state["decisions"] = []
    st.session_state["report"] = None
    st.session_state["report_bytes"] = None
    st.session_state["report_hash"] = None
    st.session_state["report_path"] = None


# ======================================================================================
# Stage runners
# ======================================================================================

def run_stage_1() -> None:
    started = time.perf_counter()
    try:
        if not os.path.exists(DATA_PATH):
            _ensure_dataset()
        result = load_and_validate(DATA_PATH)
    except FileNotFoundError:
        st.session_state["last_error"] = (
            f"Dataset not found at `{DATA_PATH}`. Generate it first:\n\n"
            "```\n./.venv/Scripts/python.exe -m src.data.generate_synthetic\n```"
        )
        return
    except Exception as exc:  # noqa: BLE001
        st.session_state["last_error"] = f"Stage 1 failed: {exc}"
        return

    elapsed = time.perf_counter() - started
    st.session_state["ingestion_result"] = result
    st.session_state["stage_times"]["Stage 1 — Ingestion"] = elapsed
    st.session_state["last_error"] = None
    _reset_downstream(from_stage=2)
    _audit().record_stage(
        action="STAGE_1_INGESTION",
        actor=_analyst(),
        details=(
            f"Loaded {len(result.valid_records)} valid record(s), "
            f"{len(result.rejected)} rejected, from {DATA_PATH} in {elapsed:.3f}s."
        ),
    )


def run_stage_2() -> None:
    result: Optional[IngestionResult] = st.session_state.get("ingestion_result")
    if result is None or not result.valid_records:
        st.session_state["last_error"] = "Run Stage 1 first — no validated records loaded."
        return

    started = time.perf_counter()
    try:
        rulebase = load_rules(RULES_DIR)
        findings = map_findings(result.valid_records, rulebase)
        matrix = build_matrix(rulebase)
    except Exception as exc:  # noqa: BLE001
        st.session_state["last_error"] = f"Stage 2 failed: {exc}"
        return

    elapsed = time.perf_counter() - started
    st.session_state["rulebase"] = rulebase
    st.session_state["findings"] = findings
    st.session_state["matrix"] = matrix
    st.session_state["stage_times"]["Stage 2 — Mapping"] = elapsed
    st.session_state["last_error"] = None
    _reset_downstream(from_stage=3)
    _audit().record_stage(
        action="STAGE_2_MAPPING",
        actor=_analyst(),
        details=(
            f"Mapped {len(findings)} finding(s) from {len(result.valid_records)} "
            f"record(s) against {len(rulebase.rules)} rule(s) in {elapsed:.3f}s."
        ),
    )


def run_stage_3() -> None:
    findings: list[ComplianceFinding] = st.session_state.get("findings") or []
    if not findings:
        st.session_state["last_error"] = "Run Stage 2 first — no findings to explain."
        return

    started = time.perf_counter()
    try:
        explanations = [explain(f) for f in findings]
    except Exception as exc:  # noqa: BLE001
        st.session_state["last_error"] = f"Stage 3 failed: {exc}"
        return

    elapsed = time.perf_counter() - started
    st.session_state["explanations"] = explanations
    st.session_state["stage_times"]["Stage 3 — Explainability"] = elapsed
    st.session_state["last_error"] = None
    _reset_downstream(from_stage=4)
    _audit().record_stage(
        action="STAGE_3_EXPLAIN",
        actor=_analyst(),
        details=f"Generated {len(explanations)} explanation(s) in {elapsed:.3f}s.",
    )


def compile_report() -> Optional[ComplianceReport]:
    """Stage 5. Re-checks the Article 22 gate on the compile path itself.

    The Stage 5 button is disabled while the gate is red, but a disabled button is a UI
    affordance, not a control: session state can be reached by a rerun race, a stale
    widget, or a future caller of this function. The gate is therefore re-checked HERE,
    immediately before the PDF is built, and a blocked attempt is itself audited.
    """
    decisions: list[AnalystDecision] = st.session_state["decisions"]
    findings: list[ComplianceFinding] = st.session_state.get("findings") or []
    explanations: list[Explanation] = st.session_state.get("explanations") or []

    # ---- THE ARTICLE 22 CONTROL. Do not remove, do not weaken. ----
    if not can_generate_report(decisions):
        blocked = escalated_finding_ids(decisions)
        _audit().record_stage(
            action="STAGE_5_BLOCKED",
            actor=_analyst(),
            details=(
                "Report compilation refused: "
                f"{len(blocked)} finding(s) still escalated ({', '.join(blocked)}). "
                "UK GDPR Article 22 control."
            ),
        )
        st.session_state["last_error"] = (
            f"Report compilation blocked: {len(blocked)} finding(s) still escalated."
        )
        return None

    if not findings:
        st.session_state["last_error"] = "Nothing to compile — no findings."
        return None

    status = gate_status(decisions, finding_ids=[f.finding_id for f in findings])
    if not status["coverage_complete"]:
        st.session_state["last_error"] = (
            f"{status['outstanding_count']} finding(s) still awaiting an analyst "
            "decision. Every finding must be reviewed before compilation."
        )
        return None

    started = time.perf_counter()
    # Second-granularity timestamps collide when two reports compile in the same second,
    # and the temp PDF path is derived from report_id, so a collision would overwrite the
    # other session's file on Streamlit Cloud's shared /tmp. A uuid4 suffix makes the id
    # (and therefore the path) unique per compile. This does not affect determinism:
    # compile_pdf is a pure function of the report OBJECT and report_id is one of its
    # fields — a fixed report still hashes stably.
    report_id = (
        f"RPT-{datetime.now(timezone.utc):%Y%m%d-%H%M%S-%f}-{uuid.uuid4().hex[:8]}"
    )
    report = ComplianceReport(
        report_id=report_id,
        findings=findings,
        explanations=explanations,
        decisions=decisions,
    )

    out_path = os.path.join(tempfile.gettempdir(), f"{report_id}.pdf")
    try:
        pdf_path = compile_pdf(report, out_path)
        digest = sha256_of_file(pdf_path)
        with open(pdf_path, "rb") as handle:
            pdf_bytes = handle.read()
    except Exception as exc:  # noqa: BLE001
        st.session_state["last_error"] = f"Stage 5 failed: {exc}"
        _audit().record_stage(
            action="STAGE_5_ERROR", actor=_analyst(), details=str(exc)
        )
        return None

    elapsed = time.perf_counter() - started
    report.sha256_hash = digest
    report.pdf_path = pdf_path

    # Findings that made it into the report are now committed.
    for explanation in explanations:
        explanation.status = FindingStatus.COMMITTED

    st.session_state["report"] = report
    st.session_state["report_bytes"] = pdf_bytes
    st.session_state["report_hash"] = digest
    st.session_state["report_path"] = pdf_path
    st.session_state["stage_times"]["Stage 5 — Report"] = elapsed
    st.session_state["last_error"] = None

    _audit().record_stage(
        action="STAGE_5_REPORT",
        actor=_analyst(),
        details=(
            f"Compiled {report_id} with {len(findings)} finding(s) in {elapsed:.3f}s. "
            f"SHA-256 {digest}."
        ),
    )
    return report


# ======================================================================================
# Baseline (optional, for Functional Correctness)
# ======================================================================================

def _normalise_baseline(payload) -> Optional[dict]:
    """Accept either {finding_id: {...}} or [{finding_id: ..., ...}, ...]."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        out = {}
        for row in payload:
            if isinstance(row, dict) and "finding_id" in row:
                fid = row["finding_id"]
                out[fid] = {k: v for k, v in row.items() if k != "finding_id"}
        return out or None
    return None


# ======================================================================================
# Sidebar
# ======================================================================================

def render_sidebar() -> None:
    import json

    with st.sidebar:
        st.title("Compliance pipeline")
        st.caption("Cyber Essentials × ISO/IEC 27001:2022")

        st.text_input(
            "Analyst ID",
            key="analyst_id",
            help="Recorded against every decision in the audit trail.",
        )

        st.divider()

        # ---- Stage 1 ----
        st.markdown("**Stage 1 — Ingestion**")
        if st.button("Load synthetic data", width="stretch", type="primary"):
            run_stage_1()
            st.rerun()

        result: Optional[IngestionResult] = st.session_state.get("ingestion_result")
        if result is not None:
            col_a, col_b = st.columns(2)
            col_a.metric("Valid", len(result.valid_records))
            col_b.metric("Rejected", len(result.rejected))
            if result.rejected:
                with st.expander(f"Rejected records ({len(result.rejected)})"):
                    for i, rejection in enumerate(result.rejected, start=1):
                        st.markdown(f"**{i}.** {rejection.reason}")
                        st.json(rejection.raw, expanded=False)
            else:
                st.caption("No records rejected.")

        st.divider()

        # ---- Stage 2 ----
        st.markdown("**Stage 2 — Mapping**")
        if st.button(
            "Run mapping engine",
            width="stretch",
            disabled=result is None,
        ):
            run_stage_2()
            st.rerun()
        findings = st.session_state.get("findings") or []
        if findings:
            st.caption(f"{len(findings)} finding(s) mapped.")

        st.divider()

        # ---- Stage 3 ----
        st.markdown("**Stage 3 — Explainability**")
        if st.button(
            "Generate explanations",
            width="stretch",
            disabled=not findings,
        ):
            run_stage_3()
            st.rerun()
        explanations = st.session_state.get("explanations") or []
        if explanations:
            st.caption(f"{len(explanations)} explanation(s) generated.")

        st.divider()

        with st.expander("Evaluation baseline (optional)"):
            st.caption(
                "Upload expected findings to compute Functional Correctness. "
                "Without one the metric honestly reports N/A."
            )
            uploaded = st.file_uploader(
                "Baseline JSON", type=["json"], key="baseline_upload"
            )
            if uploaded is not None:
                try:
                    st.session_state["baseline"] = _normalise_baseline(
                        json.load(uploaded)
                    )
                    st.success("Baseline loaded.")
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Could not parse baseline: {exc}")


# ======================================================================================
# Stage 5 panel
# ======================================================================================

def render_report_stage(gate_open: bool) -> None:
    st.subheader("Stage 5 — Report compilation")

    findings = st.session_state.get("findings") or []
    decisions = st.session_state["decisions"]
    status = gate_status(
        decisions,
        finding_ids=[f.finding_id for f in findings] if findings else None,
    )
    ready = bool(findings) and status["unlocked"]

    if not gate_open:
        st.caption(
            "Compilation is blocked while any finding is escalated. This is the UK GDPR "
            "Article 22 design control: the tool supports the analyst's decision, it "
            "does not overrule it."
        )

    col_button, col_info = st.columns([1, 3])
    with col_button:
        clicked = st.button(
            "📄 Compile report",
            type="primary",
            disabled=not ready,
            width="stretch",
        )
    with col_info:
        if not findings:
            st.caption("Run Stages 1–3 to populate the review queue.")
        elif not status["escalation_clear"]:
            st.caption(f"Blocked — {status['escalated_count']} escalation(s) open.")
        elif not status["coverage_complete"]:
            st.caption(f"{status['outstanding_count']} finding(s) awaiting a decision.")
        else:
            st.caption("Gate green — all findings resolved, none escalated.")

    if clicked:
        # The compile path re-checks the gate itself; the disabled button above is a
        # convenience, not the control. Rerun either way so the outcome (report or
        # refusal) renders immediately.
        compile_report()
        st.rerun()

    report: Optional[ComplianceReport] = st.session_state.get("report")
    if report is not None:
        st.success(f"Report **{report.report_id}** compiled.", icon="📄")
        st.markdown("**SHA-256 integrity hash**")
        st.code(report.sha256_hash or "", language="text")
        meta = st.columns(3)
        meta[0].metric("Findings", len(report.findings))
        meta[1].metric("Decisions", len(report.decisions))
        meta[2].metric(
            "Generated", f"{report.generated_at:%H:%M:%S}", help="UTC"
        )

        pdf_bytes = st.session_state.get("report_bytes")
        if pdf_bytes:
            st.download_button(
                "⬇️ Download PDF",
                data=pdf_bytes,
                file_name=f"{report.report_id}.pdf",
                mime="application/pdf",
            )
            st.caption(
                "Re-hash the downloaded file to verify integrity. "
                f"Windows: `certutil -hashfile {report.report_id}.pdf SHA256` · "
                f"Linux/macOS: `sha256sum {report.report_id}.pdf`"
            )

        audit_csv = _audit().to_csv()
        st.download_button(
            "⬇️ Download audit trail (CSV)",
            data=audit_csv,
            file_name=f"{report.report_id}-audit.csv",
            mime="text/csv",
        )


# ======================================================================================
# Audit tab
# ======================================================================================

def render_audit_tab() -> None:
    st.subheader("Audit trail")
    st.caption(
        "Append-only record of every stage transition and analyst decision "
        "(Data Protection Act 2018 accountability). Superseded decisions are retained."
    )

    audit = _audit()
    frame = audit.to_dataframe()

    if frame.empty:
        st.info("No audit entries yet. Actions appear here as you work through the stages.")
        return

    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Entries", len(frame))
    col_b.metric(
        "Analyst actions",
        int((frame["finding_id"] != AuditLog.SYSTEM_SCOPE).sum()),
    )
    col_c.metric(
        "Stage transitions",
        int((frame["finding_id"] == AuditLog.SYSTEM_SCOPE).sum()),
    )

    st.dataframe(
        frame.sort_values("timestamp", ascending=False),
        width="stretch",
        hide_index=True,
    )
    st.download_button(
        "⬇️ Download audit trail (CSV)",
        data=audit.to_csv(),
        file_name="audit-trail.csv",
        mime="text/csv",
        key="audit_tab_download",
    )


# ======================================================================================
# Main
# ======================================================================================

def main() -> None:
    st.set_page_config(
        page_title="Explainable Compliance Tool",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_state()

    st.title("🛡️ Explainable Compliance Tool")
    st.caption(
        "Rule-based mapping of security findings to Cyber Essentials, CE Plus and "
        "ISO/IEC 27001:2022 — with a mandatory human validation gate before any report "
        "is produced."
    )

    render_sidebar()

    # Errors are set during the run that caused them, then surfaced on the rerun that
    # follows and cleared, so they read as a one-shot message rather than sticking
    # around after the condition has been fixed. Persistent state (the gate banner)
    # does the persistent messaging.
    error = st.session_state.get("last_error")
    if error:
        st.error(error)
        st.session_state["last_error"] = None

    review_tab, report_tab, heatmap_tab, metrics_tab, audit_tab = st.tabs(
        [
            "① Review (Stage 4)",
            "② Report (Stage 5)",
            "③ Mapping matrix",
            "④ Evaluation metrics",
            "⑤ Audit trail",
        ]
    )

    with review_tab:
        gate_open = render_review_stage(
            findings=st.session_state.get("findings") or [],
            explanations=st.session_state.get("explanations") or [],
            # MUST be the live list object under "decisions" (guaranteed by init_state):
            # render_review_stage appends decisions in place, so a fresh `... or []` throwaway
            # would silently drop every analyst decision and the gate would never unlock.
            decisions=st.session_state["decisions"],
            audit_log=_audit(),
            analyst_id=_analyst(),
        )

    with report_tab:
        render_report_stage(gate_open=gate_open)

    with heatmap_tab:
        render_heatmap(st.session_state.get("matrix"))

    with metrics_tab:
        render_metrics(
            findings=st.session_state.get("findings") or [],
            decisions=st.session_state["decisions"],
            stage_times=st.session_state.get("stage_times") or {},
            baseline=st.session_state.get("baseline"),
        )

    with audit_tab:
        render_audit_tab()


main()
