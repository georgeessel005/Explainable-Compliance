"""
streamlit_app.py  -  CompliancePilot (Cyber Essentials / CE+ x ISO/IEC 27001:2022).

Entry point for Streamlit Community Cloud. Drives the five-stage pipeline:

    Stage 1  Ingestion       load + validate synthetic scan records
    Stage 2  Mapping         issue codes -> cross-framework controls
    Stage 3  Explainability  plain-English rationale per finding
    Stage 4  HITL gate       analyst must Approve / Modify / Escalate every finding
    Stage 5  Report          ReportLab PDF + SHA-256 seal, BLOCKED while anything is escalated

Stages 1-3 are mechanical and run from one sidebar button. Stage 4 cannot be skipped or
batched away from the analyst, and Stage 5 re-checks the Article 22 gate on the compile
path itself — a disabled button is an affordance, not a control.

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

# ─────────────────────────────────────────────────────────────────────────────
# MAINTENANCE SWITCH.
# While True, the deployed app renders a blank page and stops before loading
# anything else. To bring the app back: set this to False and push (or
# `git revert` the commit that set it), and Streamlit Cloud auto-redeploys in
# ~1-2 minutes. Placed before the app's own imports on purpose, so the holding
# page can never be broken by the rest of the code.
# ─────────────────────────────────────────────────────────────────────────────
MAINTENANCE_MODE = True
if MAINTENANCE_MODE:
    st.set_page_config(page_title="", layout="centered")
    st.stop()

from src.audit.log import AuditLog
from src.data.generate_synthetic import generate as generate_records
from src.data.generate_synthetic import write_dataset
from src.explain.explainer import explain
from src.gate import can_generate_report, escalated_finding_ids, gate_status
from src.ingestion.loader import describe_rejection, load_and_validate
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
from src.report.integrity import content_digest, verify_seal
from src.report.pdf_builder import build_and_hash
from src.ui.chrome import (
    current_step,
    render_header,
    render_seal_panel,
    render_stepper,
)
from src.ui.heatmap import render_heatmap
from src.ui.metrics import render_metrics
from src.ui.review import (
    PENDING_MODIFY_KEY,
    UNNAMED_ANALYST,
    format_id_list,
    render_review_stage,
)

DATA_PATH = "data/synthetic/assets.json"
RULES_DIR = "rules"
SEED = 42

#: Slider defaults. These are exactly the arguments that produced the COMMITTED
#: data/synthetic/assets.json, so at these values Stage 1 reads that file rather than
#: regenerating anything (see `_dataset_for`).
DEFAULT_N_RECORDS = 120
DEFAULT_N_MALFORMED = 7

#: Plain (non-widget) mirror of the Stage 5 "Organisation name" input.
#:
#: Streamlit DISCARDS the state of any widget that is not instantiated during a script
#: run. Every Stage 4 decision path ends in `st.rerun()`, which aborts the script inside
#: the review tab — before the Stage 5 tab, and therefore before the organisation
#: text_input, is ever created. Without a home outside widget state the analyst's typed
#: organisation is silently wiped by the first Approve: the PDF loses its ORGANIZATION
#: block, and a seal taken over that name later reports a FALSE "SEAL BROKEN" against a
#: name that vanished on its own. The value is therefore mirrored into this ordinary key
#: on every change and the widget is re-seeded from it at the top of every run. Exactly
#: the defence src/ui/review.PENDING_MODIFY_KEY documents for uncommitted edits.
ORG_MEMO_KEY = "organisation_value"


def _dataset_for(n: int, malformed: int) -> str:
    """Path to the dataset for the requested shape. NEVER writes into the repo.

    `data/synthetic/assets.json` is a git-tracked artefact: it is the canonical demo
    dataset, it is pinned by SHA-256 in the test suite, and `python -m
    src.data.generate_synthetic` is its only writer. The running app must therefore
    READ it and never overwrite it — otherwise moving a slider silently rewrites a
    committed file, dirties the working tree and breaks the pinned determinism hash.

    At the slider defaults the committed file already IS the requested dataset, so it is
    loaded as-is. At any other slider setting the dataset is generated to a file under
    the OS temp directory and loaded from there. Generation is seeded, so the temp file
    for a given (n, malformed) is byte-identical every time; it is written to a unique
    name and atomically renamed so two sessions cannot read a half-written file.
    """
    if n == DEFAULT_N_RECORDS and malformed == DEFAULT_N_MALFORMED:
        return DATA_PATH

    target = os.path.join(
        tempfile.gettempdir(), f"compliancepilot-assets-{SEED}-{n}-{malformed}.json"
    )
    scratch = f"{target}.{uuid.uuid4().hex}.tmp"
    write_dataset(generate_records(n=n, seed=SEED, malformed=malformed), scratch)
    os.replace(scratch, target)
    return target


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
        # Findings with "Modify" selected but no edit saved yet. They carry NO decision
        # and do not count as reviewed — see src/ui/review.PENDING_MODIFY_KEY.
        PENDING_MODIFY_KEY: set(),
        "stage_times": {},
        "baseline": None,
        "report": None,
        "report_bytes": None,
        "report_hash": None,
        "report_path": None,
        "sealed_digest": None,
        "sealed_organisation": None,
        "seal_check": None,
        # The organisation name the LAST integrity check was computed under. A verdict
        # is only ever about the name it was checked against, so this is what makes a
        # later edit retire the banner instead of leaving it standing under a new name.
        "seal_check_org": None,
        "organisation": "",
        ORG_MEMO_KEY: "",
        "n_records": DEFAULT_N_RECORDS,
        "n_malformed": DEFAULT_N_MALFORMED,
        # Deliberately EMPTY, not the literal "analyst": the Stage 4 callout promises
        # decisions are attributed to a named analyst, so the field starts blank with a
        # placeholder and Stage 4 warns until it is filled in. Anything recorded before
        # then is attributed to UNNAMED_ANALYST, which reads as unattributed in the CSV.
        "analyst_id": "",
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
    return (st.session_state.get("analyst_id") or "").strip() or UNNAMED_ANALYST


def _organisation_text() -> str:
    """The organisation the analyst typed — from widget state, else from the memo.

    The widget's own state is the live value while Stage 5 is on screen; the memo is
    what survives a rerun that never rendered Stage 5. Reading both, in that order,
    means the value is correct whichever of the two a given run happens to have.
    """
    return (
        st.session_state.get("organisation")
        or st.session_state.get(ORG_MEMO_KEY)
        or ""
    )


def _remember_organisation() -> None:
    """`on_change` for the organisation input: mirror it, and retire any seal verdict.

    The mirror is what makes the typed name survive Stage 4 (see ORG_MEMO_KEY). Clearing
    `seal_check` is a separate obligation: the organisation is sealed over, so an
    "intact" banner is a statement about the name it was checked under and stops being
    true the instant that name is edited.
    """
    st.session_state[ORG_MEMO_KEY] = st.session_state.get("organisation") or ""
    st.session_state["seal_check"] = None
    st.session_state["seal_check_org"] = None


def _restore_organisation() -> None:
    """Re-seed the Stage 5 input from the memo, before any widget is instantiated.

    Only fills a blank: a value the analyst has actually typed on this run is never
    overwritten, and a deliberately cleared field stays cleared (the on_change callback
    empties the memo at the same time).
    """
    remembered = st.session_state.get(ORG_MEMO_KEY) or ""
    if remembered and not (st.session_state.get("organisation") or ""):
        st.session_state["organisation"] = remembered


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
        # Uncommitted edits belong to findings that no longer exist.
        st.session_state[PENDING_MODIFY_KEY] = set()
        # Decision widgets are keyed per finding and would otherwise survive the rebuild,
        # showing an "Approve" selection for a decision that no longer exists.
        for key in [k for k in st.session_state if k.startswith("decision__")]:
            st.session_state[key] = "— Select —"
    # A sealed report is an artefact, and it is about to be thrown away because the
    # findings underneath it no longer exist. Discarded decisions are audited; a
    # discarded REPORT disappearing silently would be the same hole in the same trail.
    stale_report: Optional[ComplianceReport] = st.session_state.get("report")
    if stale_report is not None:
        _audit().record_stage(
            action="REPORT_DISCARDED",
            actor=_analyst(),
            details=(
                f"Sealed report {stale_report.report_id} discarded because an earlier "
                "stage was re-run and the finding set was rebuilt. Its content seal "
                f"{st.session_state.get('sealed_digest') or '(none)'} no longer has a "
                "live report behind it. Any copy already downloaded remains valid "
                "against that seal; recompile to seal the rebuilt findings."
            ),
        )
    st.session_state["report"] = None
    st.session_state["report_bytes"] = None
    st.session_state["report_hash"] = None
    st.session_state["report_path"] = None
    st.session_state["sealed_digest"] = None
    st.session_state["sealed_organisation"] = None
    st.session_state["seal_check"] = None
    st.session_state["seal_check_org"] = None


# ======================================================================================
# Stage runners
# ======================================================================================

def run_stage_1() -> None:
    started = time.perf_counter()
    n = int(st.session_state.get("n_records") or DEFAULT_N_RECORDS)
    malformed = int(st.session_state.get("n_malformed") or 0)
    path = DATA_PATH
    try:
        # The dataset shape is analyst-chosen (record count + deliberately malformed
        # count). At the defaults that is the committed dataset, read as-is; anything
        # else is generated into a temp file. The app never writes into the repo.
        path = _dataset_for(n, malformed)
        result = load_and_validate(path)
    except FileNotFoundError:
        st.session_state["last_error"] = (
            f"Dataset not found at `{path}`. Generate it first, from the project "
            "root with the project's Python:\n\n"
            "```\npython -m src.data.generate_synthetic\n```"
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
            f"{len(result.rejected)} rejected, from {path} in {elapsed:.3f}s "
            f"(requested n={n}, malformed={malformed}, seed={SEED})."
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


def run_stages_1_3() -> None:
    """Run ingestion, mapping and explainability in one click.

    Stages 1-3 are deterministic machine work with no decision in them, so chaining
    them costs nothing in accountability: each still records its own audit entry and
    each still aborts the chain on failure. Stage 4 is deliberately NOT part of this —
    the human gate is the one thing that cannot be automated away.
    """
    run_stage_1()
    if st.session_state.get("last_error"):
        return
    run_stage_2()
    if st.session_state.get("last_error"):
        return
    run_stage_3()


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
    # DEEP copies, not the live session objects. Pydantic copies the list but not the
    # models inside it, so `report.explanations[0] is st.session_state["explanations"][0]`
    # would be True — and Stage 4 edits `explanation.plain_english` IN PLACE when a
    # Modify is committed. A sealed report would therefore change its own content
    # retroactively and report a FALSE "SEAL BROKEN" for review activity that happened
    # after it was sealed. A seal is only meaningful over content that cannot move, so
    # the report takes its own snapshot here and later review cannot reach into it.
    report = ComplianceReport(
        report_id=report_id,
        findings=[f.model_copy(deep=True) for f in findings],
        explanations=[e.model_copy(deep=True) for e in explanations],
        decisions=[d.model_copy(deep=True) for d in decisions],
    )

    organisation = _organisation_text().strip() or None
    out_path = os.path.join(tempfile.gettempdir(), f"{report_id}.pdf")
    try:
        artefact_digest = build_and_hash(report, out_path, organisation=organisation)
        sealed = content_digest(report, organisation=organisation)
        with open(out_path, "rb") as handle:
            pdf_bytes = handle.read()
    except Exception as exc:  # noqa: BLE001
        st.session_state["last_error"] = f"Stage 5 failed: {exc}"
        _audit().record_stage(
            action="STAGE_5_ERROR", actor=_analyst(), details=str(exc)
        )
        return None
    finally:
        # The temp PDF is scratch space for ReportLab, nothing more: every byte of it is
        # now held in `pdf_bytes` and served straight from memory by the download button,
        # and `artefact_digest` was taken from those same bytes, so the file has no
        # remaining reader. Left behind it accumulates forever in a shared /tmp (QA
        # measured 91 files / 33 MB). Removed in `finally` so a failed build cleans up
        # its half-written file too. Best-effort: a locked or already-gone file must
        # never turn a successfully sealed report into a Stage 5 error.
        try:
            os.unlink(out_path)
        except OSError:
            pass
        # `build_and_hash` stamped the path onto the report. The file it names is gone,
        # so the field would be a dangling reference; the artefact now lives in
        # session_state["report_bytes"] and its digest in report.sha256_hash (still the
        # SHA-256 of exactly those bytes — the hash is NOT recomputed or weakened here).
        report.pdf_path = None

    elapsed = time.perf_counter() - started

    # Findings that made it into the report are now committed.
    for explanation in explanations:
        explanation.status = FindingStatus.COMMITTED

    st.session_state["report"] = report
    st.session_state["report_bytes"] = pdf_bytes
    st.session_state["report_hash"] = artefact_digest
    # No path: the temp file is gone (see the `finally` above) and the bytes above are
    # the artefact. Keeping a path here would invite a later reader to open a file that
    # no longer exists. `report.pdf_path` still records where it was built.
    st.session_state["report_path"] = None
    st.session_state["sealed_digest"] = sealed
    # The organisation name AT THE MOMENT OF SEALING. Verification compares the seal
    # against the CURRENT name, so keeping the sealed one is what makes a later edit
    # detectable rather than silently re-sealed.
    st.session_state["sealed_organisation"] = organisation
    st.session_state["seal_check"] = None
    st.session_state["seal_check_org"] = None
    st.session_state["stage_times"]["Stage 5 — Report"] = elapsed
    st.session_state["last_error"] = None

    _audit().record_stage(
        action="STAGE_5_REPORT",
        actor=_analyst(),
        details=(
            f"Compiled {report_id} with {len(findings)} finding(s) in {elapsed:.3f}s "
            f"for organisation {organisation or '(unnamed)'}. "
            f"Content seal {sealed}. PDF SHA-256 {artefact_digest}."
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
# Sidebar — Pipeline Control
# ======================================================================================

def render_sidebar() -> None:
    import json

    with st.sidebar:
        st.title("Pipeline Control")
        st.caption("Stages 1-3 run here. Stage 4 (below) cannot be skipped.")

        # ASSET RECORDS, not findings: one record can breach several rules, so 20
        # records yield ~48 findings. Labelling it "findings" made the sidebar
        # contradict itself ("Findings awaiting review: 48" beside a slider on 20).
        st.slider(
            "Synthetic asset records to generate",
            min_value=20,
            max_value=200,
            step=10,
            key="n_records",
            help=(
                "Number of valid synthetic asset records the generator produces. "
                "Stage 2 raises one finding per rule each record breaches, so the "
                "finding count is higher than this."
            ),
        )
        st.slider(
            "Deliberately malformed records",
            min_value=0,
            max_value=7,
            step=1,
            key="n_malformed",
            help="Invalid records injected so Stage 1's rejection behaviour is visible.",
        )
        if (
            st.session_state["n_records"] == DEFAULT_N_RECORDS
            and st.session_state["n_malformed"] == DEFAULT_N_MALFORMED
        ):
            st.caption(
                f"Reading the committed dataset `{DATA_PATH}` unchanged "
                f"({DEFAULT_N_RECORDS} valid + {DEFAULT_N_MALFORMED} malformed)."
            )
        else:
            st.caption(
                "Non-default volumes are generated into a temporary file — the "
                f"committed `{DATA_PATH}` is never overwritten by the app."
            )

        if st.button(
            "Run Stages 1-3 (Ingest → Map → Explain)",
            width="stretch",
            type="primary",
            key="run_pipeline",
        ):
            run_stages_1_3()
            st.rerun()

        result: Optional[IngestionResult] = st.session_state.get("ingestion_result")
        if result is not None:
            st.success(
                f"Accepted {len(result.valid_records)} / "
                f"Rejected {len(result.rejected)}"
            )

        st.divider()

        findings = st.session_state.get("findings") or []
        decisions = st.session_state["decisions"]
        status = gate_status(
            decisions,
            finding_ids=[f.finding_id for f in findings] if findings else None,
        )
        st.metric("Findings awaiting review", status["outstanding_count"] if findings else 0)
        st.metric("Rejected at Stage 1", len(result.rejected) if result else 0)
        # "0 / 0" on a cold load reads as a ratio of a real workload. With no findings
        # loaded there is nothing to be reviewed out of, so say so with a dash.
        st.metric(
            "Reviewed at Stage 4",
            f"{status['reviewed_count']} / {len(findings)}" if findings else "—",
        )

        st.divider()

        if (st.session_state.get("analyst_id") or "").strip():
            st.caption(f"Analyst on record: **{_analyst()}** (set in the Stage 4 tab).")
        else:
            st.caption(
                f"Analyst on record: **{UNNAMED_ANALYST}** — enter your name in the "
                "Stage 4 tab so decisions are accountably attributed."
            )

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
# Stage 1 rejections tab
# ======================================================================================

def render_rejections_tab() -> None:
    st.markdown("### Stage 1 — rejected records")
    result: Optional[IngestionResult] = st.session_state.get("ingestion_result")

    if result is None:
        st.info("Run Stages 1-3 from the sidebar to populate this panel.")
        return

    cols = st.columns(2)
    cols[0].metric("Accepted", len(result.valid_records))
    cols[1].metric("Rejected", len(result.rejected))

    if not result.rejected:
        st.success("No records rejected.")
        return

    st.caption(
        "These records are **deliberately malformed** seed data. Stage 1 rejects "
        "anything that fails validation instead of guessing at it, and carries on with "
        "the rest — that refusal is the behaviour being demonstrated, not a failure."
    )
    for i, rejection in enumerate(result.rejected, start=1):
        summary = describe_rejection(rejection)
        with st.container(border=True):
            st.markdown(f"**{i}. {summary.asset_id}** — {summary.headline}")
            if summary.field:
                st.caption(f"field: `{summary.field}`")
            # The unedited validator output stays one click away: the audit story
            # depends on the full reason remaining available.
            with st.expander("Raw validator output"):
                st.code(summary.raw_reason, language="text")
                st.json(rejection.raw, expanded=False)


# ======================================================================================
# Stage 5 panel
# ======================================================================================

def render_report_stage() -> None:
    """Stage 5 panel.

    Takes no gate argument on purpose: the verdict is recomputed here from the live
    decision list via `gate_status`, so this panel cannot be handed a stale or
    hand-made "gate is open" from a caller. `compile_report` re-checks it a third
    time on the compile path itself.
    """
    st.markdown("### Stage 5 — Sealed report")

    findings = st.session_state.get("findings") or []
    decisions = st.session_state["decisions"]
    status = gate_status(
        decisions,
        finding_ids=[f.finding_id for f in findings] if findings else None,
    )
    ready = bool(findings) and status["unlocked"]

    if not findings:
        st.warning(
            "**Blocked — nothing to report.** Run Stages 1-3 from the sidebar, then "
            "review every finding in the Stage 4 tab.",
            icon="⏳",
        )
    elif not status["escalation_clear"]:
        st.warning(
            f"**Blocked — {status['escalated_count']} finding(s) still escalated:** "
            + format_id_list(status["escalated_ids"])
            + ". No report may be produced over an open human objection "
            "(UK GDPR Article 22).",
            icon="🚫",
        )
    elif not status["coverage_complete"]:
        st.warning(
            f"**Blocked — {status['outstanding_count']} finding(s) still awaiting an "
            "analyst decision.** Every finding needs an Approve, Modify or Escalate "
            "before the report can be sealed.",
            icon="⏳",
        )
    else:
        st.success(
            f"**Unlocked — {status['reviewed_count']} finding(s) reviewed, none "
            "escalated.** The report may be generated and sealed.",
            icon="✅",
        )

    # `on_change` is not cosmetic. It mirrors the typed name into ORG_MEMO_KEY, which is
    # the only copy that survives a Stage 4 rerun (this tab is not rendered on those
    # runs, so Streamlit discards this widget's state), and it retires any standing seal
    # verdict, which stops being true the moment the sealed-over name changes.
    st.text_input(
        "Organisation name for report header",
        key="organisation",
        placeholder="e.g. Northwind Manufacturing Ltd",
        on_change=_remember_organisation,
        help=(
            "Rendered on the report title page and sealed into the content digest. "
            "Kept across Stage 4 decisions."
        ),
    )

    if st.button(
        "Generate Sealed PDF Report",
        type="primary",
        disabled=not ready,
        key="generate_report",
    ):
        # The compile path re-checks the gate itself; the disabled button above is a
        # convenience, not the control. Rerun either way so the outcome (report or
        # refusal) renders immediately.
        with st.spinner("Building and sealing the PDF report…"):
            compile_report()
        st.rerun()

    report: Optional[ComplianceReport] = st.session_state.get("report")
    if report is None:
        return

    if not status["escalation_clear"]:
        # A report sealed BEFORE this escalation was raised is still an honest artefact
        # (it deep-copies the decisions it was built from, so it cannot be retro-fitted),
        # but showing it and a live Download button underneath a red "no report may be
        # produced" banner makes the screen contradict itself. It is withheld, not
        # discarded: session state keeps it and it returns unchanged once the escalation
        # is resolved.
        st.info(
            "A previously sealed report exists but is **withheld while an escalation "
            "is open**. Resolve the escalation(s) in Stage 4 and the same sealed "
            "report and its download reappear unchanged.",
            icon="🔒",
        )
        return

    st.success(f"Report **{report.report_id}** compiled.", icon="📄")
    render_seal_panel(
        st.session_state.get("sealed_digest") or "",
        artefact_digest=st.session_state.get("report_hash"),
    )

    verify_col, result_col = st.columns([1, 3])
    if verify_col.button("Verify Integrity", key="verify_seal"):
        sealed = st.session_state.get("sealed_digest") or ""
        current_org = _organisation_text().strip() or None
        try:
            intact = verify_seal(report, sealed, organisation=current_org)
        except Exception as exc:  # noqa: BLE001
            st.session_state["seal_check"] = ("error", str(exc))
        else:
            st.session_state["seal_check"] = (
                ("intact", content_digest(report, organisation=current_org))
                if intact
                else ("broken", content_digest(report, organisation=current_org))
            )
        # The verdict is a statement about THIS name. Recorded alongside it so the
        # banner can retire itself if the name moves on.
        st.session_state["seal_check_org"] = current_org
        _audit().record_stage(
            action="SEAL_VERIFIED",
            actor=_analyst(),
            details=(
                f"Integrity check for {report.report_id}: "
                f"{st.session_state['seal_check'][0]} "
                f"(organisation at check: {current_org or '(unnamed)'})."
            ),
        )
        st.rerun()

    check = st.session_state.get("seal_check")
    # A verdict outlives its subject if the organisation is edited afterwards: the
    # caption two lines below invites exactly that edit, so a green "Seal intact" left
    # standing under a name it was never computed against is a lie the UI told itself.
    # The on_change callback clears it; this is the belt-and-braces check for any path
    # that changes the name without firing the callback.
    if check and st.session_state.get("seal_check_org") != (
        _organisation_text().strip() or None
    ):
        result_col.info(
            "**Not verified since the last change** — the organisation name changed "
            "after the previous check. Click Verify Integrity again.",
            icon="↻",
        )
        check = None
    if check:
        outcome, detail = check
        if outcome == "intact":
            result_col.success(
                "**Seal intact** — the recomputed digest matches the sealed value.",
                icon="✅",
            )
        elif outcome == "broken":
            result_col.error(
                "**SEAL BROKEN — content has changed since sealing.** "
                f"Recomputed digest `{detail}` does not match the sealed value.",
                icon="🚨",
            )
        else:
            result_col.error(f"Verification failed: {detail}")

    st.caption(
        "Try editing the organisation name above, then click Verify Integrity — the "
        "recomputed hash will no longer match the sealed value, demonstrating tamper "
        "detection."
    )

    meta = st.columns(3)
    meta[0].metric("Findings", len(report.findings))
    meta[1].metric("Decisions", len(report.decisions))
    meta[2].metric("Generated", f"{report.generated_at:%H:%M:%S}", help="UTC")

    pdf_bytes = st.session_state.get("report_bytes")
    if pdf_bytes:
        st.download_button(
            "⬇️ Download PDF",
            data=pdf_bytes,
            file_name=f"{report.report_id}.pdf",
            mime="application/pdf",
        )
        st.caption(
            "Re-hash the downloaded file and compare it with the **PDF artefact "
            "SHA-256** in the seal panel above — not the large content seal, which "
            "covers the findings and organisation rather than the PDF bytes. "
            f"Windows: `certutil -hashfile {report.report_id}.pdf SHA256` · "
            f"Linux/macOS: `sha256sum {report.report_id}.pdf`"
        )

    st.download_button(
        "⬇️ Download audit trail (CSV)",
        data=_audit().to_csv(),
        file_name=f"{report.report_id}-audit.csv",
        mime="text/csv",
    )


# ======================================================================================
# Audit tab
# ======================================================================================

def render_audit_tab() -> None:
    st.markdown("### Audit trail")
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
        page_title="CompliancePilot",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_state()
    # BEFORE any widget is instantiated: re-seed the Stage 5 organisation input from its
    # memo, so a value typed before a Stage 4 decision is still there afterwards.
    _restore_organisation()

    render_header()

    findings = st.session_state.get("findings") or []
    explanations = st.session_state.get("explanations") or []
    decisions = st.session_state["decisions"]
    stepper_status = gate_status(
        decisions,
        finding_ids=[f.finding_id for f in findings] if findings else None,
    )
    render_stepper(
        current_step(
            has_data=st.session_state.get("ingestion_result") is not None,
            has_findings=bool(findings),
            has_explanations=bool(explanations),
            # `unlocked` is the gate's own verdict (escalations clear AND every finding
            # decided), so the stepper can never advance past Approve while the gate is
            # red. Presentation only — nothing here is a control.
            review_complete=bool(findings) and stepper_status["unlocked"],
            has_report=st.session_state.get("report") is not None,
        )
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

    (
        review_tab,
        rejections_tab,
        report_tab,
        heatmap_tab,
        metrics_tab,
        audit_tab,
    ) = st.tabs(
        [
            "Stage 4: Analyst Review Gate",
            "Stage 1 Rejections",
            "Stage 5: Report",
            "Mapping matrix",
            "Evaluation metrics",
            "Audit trail",
        ]
    )

    with review_tab:
        # The returned verdict is intentionally not carried across to Stage 5: that
        # panel recomputes the gate from the live decision list itself, so there is no
        # wire along which a stale "open" could travel between tabs.
        render_review_stage(
            findings=st.session_state.get("findings") or [],
            explanations=st.session_state.get("explanations") or [],
            # MUST be the live list object under "decisions" (guaranteed by init_state):
            # render_review_stage appends decisions in place, so a fresh `... or []` throwaway
            # would silently drop every analyst decision and the gate would never unlock.
            decisions=st.session_state["decisions"],
            audit_log=_audit(),
            analyst_id=_analyst(),
        )

    with rejections_tab:
        render_rejections_tab()

    with report_tab:
        render_report_stage()

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
