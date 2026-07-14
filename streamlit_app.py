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

--------------------------------------------------------------------------------------
PARALLEL BUILD NOTE
Sibling modules (ingestion, mapping, explain, report) are built concurrently. Every
cross-module import below is defensive: if the real module is absent or half-written,
a thin local mock marked `# MOCK:` keeps the app booting. Grep `# MOCK:` — the
integration pass removes each one.
--------------------------------------------------------------------------------------
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from typing import Optional

import streamlit as st

from src.audit.log import AuditLog
from src.gate import can_generate_report, escalated_finding_ids, gate_status
from src.models import (
    AnalystDecision,
    AssetRecord,
    ComplianceFinding,
    ComplianceReport,
    ControlMapping,
    Explanation,
    FindingStatus,
    Framework,
    IngestionResult,
    IssueCode,
    IssueRule,
    MappingType,
    RawVulnerability,
    RejectionError,
    RuleBase,
    Severity,
)
from src.ui.heatmap import render_heatmap
from src.ui.metrics import render_metrics
from src.ui.review import render_review_stage

DATA_PATH = "data/synthetic/assets.json"
RULES_DIR = "rules"

#: Populated by the defensive imports below; surfaced in the sidebar so it is obvious
#: when the app is running on mock data rather than a sibling's real implementation.
MOCKED: list[str] = []


# ======================================================================================
# Defensive imports.  Real module -> use it.  Missing/half-written -> thin local mock.
# `except Exception` (not just ImportError) is deliberate: a module being written right
# now can raise SyntaxError, NameError or AttributeError at import, and none of those
# may take the app down mid-build.
# ======================================================================================

# ---------- Stage 1: ingestion ----------
try:
    from src.ingestion.loader import load_and_validate  # type: ignore
except Exception:  # noqa: BLE001
    MOCKED.append("src.ingestion.loader.load_and_validate")

    # MOCK: src.ingestion.loader.load_and_validate (Agent 1) — remove at integration.
    def load_and_validate(path: str) -> IngestionResult:  # type: ignore[misc]
        """Deterministic stand-in producing a small valid set plus one rejection."""
        import random

        rng = random.Random(42)
        assessment = date(2025, 6, 1)
        hosts = [
            ("web", "Ubuntu 22.04 LTS", True),
            ("db", "Windows Server 2019", False),
            ("app", "Ubuntu 20.04 LTS", False),
            ("dmz", "Debian 12", True),
            ("file", "Windows Server 2022", False),
        ]
        codes = list(IssueCode)
        records: list[AssetRecord] = []
        for i in range(12):
            prefix, os_name, facing = hosts[i % len(hosts)]
            picks = rng.sample(codes, rng.randint(1, 3))
            vulns = []
            if IssueCode.PATCH_MISSING in picks or rng.random() < 0.5:
                score = round(rng.uniform(4.0, 9.8), 1)
                vulns.append(
                    RawVulnerability(
                        cve_id=f"CVE-2024-{1000 + i}",
                        cvss_score=score,
                        description="Remote code execution in an unpatched component.",
                        published_date=assessment - timedelta(days=rng.randint(30, 90)),
                        patch_released_date=assessment - timedelta(days=rng.randint(7, 28)),
                        patch_applied=False,
                    )
                )
            records.append(
                AssetRecord(
                    asset_id=f"AST-{i + 1:03d}",
                    hostname=f"{prefix}-{i + 1:02d}.example.internal",
                    operating_system=os_name,
                    ip_address=f"10.0.{i // 10}.{10 + i}",
                    internet_facing=facing,
                    environment="production" if i % 3 else "staging",
                    criticality=rng.choice(list(Severity)[1:]),
                    assessment_date=assessment,
                    issue_codes=picks,
                    vulnerabilities=vulns,
                )
            )
        rejected = [
            RejectionError(
                raw={"asset_id": "AST-999", "hostname": "broken-01", "cvss_score": 44.0},
                reason="MOCK sample rejection: cvss_score 44.0 exceeds the 0-10 bound; "
                       "required field 'assessment_date' missing.",
            )
        ]
        return IngestionResult(valid_records=records, rejected=rejected)


# ---------- Stage 2: mapping ----------
try:
    from src.mapping.engine import load_rules, map_findings  # type: ignore
except Exception:  # noqa: BLE001
    MOCKED.append("src.mapping.engine.load_rules / map_findings")

    # MOCK: the 15 verified rows from blueprint Section 7, used only to keep the app
    # runnable until Agent 2's YAML rule base lands. NOT authoritative — remove at
    # integration; rules/ce_iso_mappings.yaml is the real source.
    _MOCK_ROWS = [
        # issue code, rule id, title, CE framework, CE pillar, ISO id, ISO name, ISO type
        (IssueCode.PATCH_MISSING, "CE-PATCH-001", "Missing security patch",
         Framework.CE, "Patch Management", "A.8.8",
         "Management of technical vulnerabilities", MappingType.PRIMARY),
        (IssueCode.PATCH_RECORD_ABSENT, "CE-PATCH-002", "No patch record held",
         Framework.CE, "Patch Management", "A.8.32",
         "Change management", MappingType.SECONDARY),
        (IssueCode.DEFAULT_CREDENTIALS, "CE-CONF-001", "Default credentials in use",
         Framework.CE, "Secure Configuration", "A.8.9",
         "Configuration management", MappingType.PRIMARY),
        (IssueCode.INSECURE_PROTOCOL, "CE-CONF-002", "Insecure protocol enabled",
         Framework.CE, "Secure Configuration", "A.8.27",
         "Secure system architecture", MappingType.SECONDARY),
        (IssueCode.EXCESSIVE_PRIVILEGES, "CE-UAC-001", "Excessive privileges granted",
         Framework.CE, "User Access Control", "A.5.15",
         "Access control", MappingType.PRIMARY),
        (IssueCode.STALE_ACCOUNT, "CE-UAC-002", "Stale account active",
         Framework.CE, "User Access Control", "A.5.16",
         "Identity management", MappingType.SECONDARY),
        (IssueCode.PASSWORD_POLICY_NONCOMPLIANCE, "CE-UAC-003",
         "Password policy non-compliance",
         Framework.CE, "User Access Control", "A.5.17",
         "Authentication information", MappingType.PRIMARY),
        (IssueCode.MFA_ABSENT, "CE-UAC-004", "Multi-factor authentication absent",
         Framework.CE, "User Access Control", "A.8.5",
         "Secure authentication", MappingType.PRIMARY),
        (IssueCode.UNRESTRICTED_INBOUND, "CE-FW-001", "Unrestricted inbound access",
         Framework.CE, "Firewalls", "A.8.20",
         "Networks security", MappingType.PRIMARY),
        (IssueCode.UNMANAGED_SERVICE_EXPOSED, "CE-FW-002", "Unmanaged service exposed",
         Framework.CE, "Firewalls", "A.8.21",
         "Security of network services", MappingType.SECONDARY),
        (IssueCode.FLAT_NETWORK, "CE-FW-003", "Flat network, no segregation",
         Framework.CE, "Firewalls", "A.8.22",
         "Segregation of networks", MappingType.SECONDARY),
        (IssueCode.AV_SIGNATURE_OUTDATED, "CE-MAL-001", "Anti-malware signatures outdated",
         Framework.CE, "Malware Protection", "A.8.7",
         "Protection against malware", MappingType.PRIMARY),
        (IssueCode.NO_EDR_INGESTION, "CE-MAL-002", "No EDR telemetry ingestion",
         Framework.CE, "Malware Protection", "A.8.16",
         "Monitoring activities", MappingType.SECONDARY),
        (IssueCode.AUTH_SCAN_FAILURE, "CEP-VS-001", "Authenticated scan failure",
         Framework.CE_PLUS, "Vulnerability Scan", "A.8.8",
         "Management of technical vulnerabilities", MappingType.PRIMARY),
        (IssueCode.INSUFFICIENT_SCAN_CREDENTIALS, "CEP-AA-001",
         "Insufficient scan credentials",
         Framework.CE_PLUS, "Authenticated Audit", "A.5.15",
         "Access control", MappingType.SECONDARY),
    ]

    # MOCK: src.mapping.engine.load_rules (Agent 2) — remove at integration.
    def load_rules(rules_dir: str = "rules") -> RuleBase:  # type: ignore[misc]
        rules: list[IssueRule] = []
        for code, rule_id, title, ce_fw, pillar, iso_id, iso_name, iso_type in _MOCK_ROWS:
            mappings = [
                ControlMapping(
                    framework=ce_fw,
                    control_id=pillar,
                    control_name=pillar,
                    mapping_type=MappingType.PRIMARY,
                ),
                ControlMapping(
                    framework=Framework.ISO27001,
                    control_id=iso_id,
                    control_name=iso_name,
                    mapping_type=iso_type,
                ),
            ]
            # FINDING #017 reference card: one issue code carrying several controls.
            if code == IssueCode.PATCH_MISSING:
                mappings.insert(
                    1,
                    ControlMapping(
                        framework=Framework.CE_PLUS,
                        control_id="Vulnerability Scan",
                        control_name="Vulnerability Scan",
                        mapping_type=MappingType.PRIMARY,
                    ),
                )
                mappings.append(
                    ControlMapping(
                        framework=Framework.ISO27001,
                        control_id="A.8.32",
                        control_name="Change management",
                        mapping_type=MappingType.SECONDARY,
                    )
                )
            rules.append(
                IssueRule(
                    rule_id=rule_id,
                    issue_code=code,
                    title=title,
                    control_mappings=mappings,
                    explanation_template=(
                        "{title} was detected on {hostname}. This fails the Cyber "
                        "Essentials {pillar} requirement and ISO/IEC 27001:2022 Annex "
                        "{iso_id}."
                    ),
                    remediation_steps=[
                        f"Investigate {title.lower()} on the affected asset.",
                        f"Apply the control required by {pillar}.",
                        f"Evidence the fix against ISO/IEC 27001:2022 {iso_id}.",
                    ],
                )
            )
        return RuleBase(rules=rules)

    # MOCK: src.mapping.engine.map_findings (Agent 2) — remove at integration.
    def map_findings(  # type: ignore[misc]
        records: list[AssetRecord], rulebase: RuleBase
    ) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        counter = 0
        for record in records:
            worst = max(
                record.vulnerabilities, key=lambda v: v.cvss_score, default=None
            )
            for code in record.issue_codes:
                rule = rulebase.by_issue(code)
                if rule is None:
                    continue
                counter += 1
                frameworks: list[Framework] = []
                for mapping in rule.control_mappings:
                    if mapping.framework not in frameworks:
                        frameworks.append(mapping.framework)
                findings.append(
                    ComplianceFinding(
                        finding_id=f"F-{counter:04d}",
                        asset=record,
                        issue_code=code,
                        rule_id=rule.rule_id,
                        triggering_cve=worst.cve_id if worst else None,
                        triggering_cvss=worst.cvss_score if worst else None,
                        control_mappings=list(rule.control_mappings),
                        frameworks_breached=frameworks,
                    )
                )
        return findings


try:
    from src.mapping.matrix import build_matrix  # type: ignore
except Exception:  # noqa: BLE001
    MOCKED.append("src.mapping.matrix.build_matrix")

    # MOCK: src.mapping.matrix.build_matrix (Agent 2) — remove at integration.
    def build_matrix(rulebase: RuleBase):  # type: ignore[misc]
        import pandas as pd

        iso_universe = [
            "A.5.15", "A.5.16", "A.5.17", "A.8.5", "A.8.7", "A.8.8", "A.8.9",
            "A.8.16", "A.8.20", "A.8.21", "A.8.22", "A.8.23", "A.8.27", "A.8.32",
        ]
        pillars: list[str] = []
        for rule in rulebase.rules:
            for mapping in rule.control_mappings:
                if mapping.framework in (Framework.CE, Framework.CE_PLUS):
                    label = mapping.control_id
                    if mapping.framework == Framework.CE_PLUS:
                        label = f"CE+ {label}"
                    if label not in pillars:
                        pillars.append(label)

        matrix = pd.DataFrame("", index=pillars, columns=iso_universe)
        for rule in rulebase.rules:
            ce_labels = [
                (f"CE+ {m.control_id}" if m.framework == Framework.CE_PLUS
                 else m.control_id)
                for m in rule.control_mappings
                if m.framework in (Framework.CE, Framework.CE_PLUS)
            ]
            iso_controls = [
                m for m in rule.control_mappings if m.framework == Framework.ISO27001
            ]
            for label in ce_labels:
                for iso in iso_controls:
                    if iso.control_id not in matrix.columns or label not in matrix.index:
                        continue
                    code = "P" if iso.mapping_type == MappingType.PRIMARY else "S"
                    # Primary wins if an intersection is reached by two rules.
                    if matrix.at[label, iso.control_id] != "P":
                        matrix.at[label, iso.control_id] = code
        return matrix


# ---------- Stage 3: explainability ----------
try:
    from src.explain.explainer import explain  # type: ignore
except Exception:  # noqa: BLE001
    MOCKED.append("src.explain.explainer.explain")

    # MOCK: src.explain.explainer.explain (Agent 3) — remove at integration.
    def explain(finding: ComplianceFinding) -> Explanation:  # type: ignore[misc]
        asset = finding.asset
        exposure = (
            "The asset is internet-facing, which raises the exposure of this issue."
            if asset.internet_facing
            else "The asset is internal-only."
        )
        cve_text = ""
        if finding.triggering_cve:
            cve_text = (
                f" The finding was triggered by {finding.triggering_cve} "
                f"(CVSS {finding.triggering_cvss})."
            )
        controls = ", ".join(
            f"{m.framework.value} {m.control_id} ({m.mapping_type.value})"
            for m in finding.control_mappings
        )
        return Explanation(
            finding_id=finding.finding_id,
            plain_english=(
                f"[MOCK EXPLANATION] {finding.issue_code.value} was detected on "
                f"{asset.hostname} ({asset.operating_system}) during the assessment "
                f"dated {asset.assessment_date}.{cve_text} {exposure} Because the "
                f"control expectation is not met, this finding breaches: {controls}."
            ),
            linked_controls=list(finding.control_mappings),
            remediation_steps=[
                f"Remediate {finding.issue_code.value} on {asset.hostname}.",
                "Re-scan the asset to evidence closure.",
                "Record the change under your change-management process.",
            ],
            status=FindingStatus.AWAITING_REVIEW,
        )


# ---------- Stage 5: report ----------
try:
    from src.report.pdf_builder import compile_pdf  # type: ignore
except Exception:  # noqa: BLE001
    MOCKED.append("src.report.pdf_builder.compile_pdf")

    # MOCK: src.report.pdf_builder.compile_pdf (Agent 3) — remove at integration.
    def compile_pdf(report: ComplianceReport, out_path: str) -> str:  # type: ignore[misc]
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        pdf = canvas.Canvas(out_path, pagesize=A4)
        width, height = A4
        y = height - 60
        pdf.setFont("Helvetica-Bold", 15)
        pdf.drawString(50, y, "[MOCK] Compliance Report")
        y -= 22
        pdf.setFont("Helvetica", 9)
        pdf.drawString(50, y, f"Report {report.report_id} — {len(report.findings)} findings")
        y -= 14
        pdf.drawString(50, y, f"Generated {report.generated_at:%Y-%m-%d %H:%M:%S} UTC")
        for finding in report.findings:
            if y < 80:
                pdf.showPage()
                y = height - 60
                pdf.setFont("Helvetica", 9)
            y -= 16
            pdf.setFont("Helvetica-Bold", 9)
            pdf.drawString(
                50, y, f"{finding.finding_id} — {finding.issue_code.value} — "
                       f"{finding.asset.hostname}"
            )
            pdf.setFont("Helvetica", 8)
            for mapping in finding.control_mappings:
                y -= 11
                pdf.drawString(
                    62, y,
                    f"{mapping.framework.value}: {mapping.control_id} "
                    f"({mapping.mapping_type.value})",
                )
        pdf.save()
        return out_path


try:
    from src.report.integrity import sha256_of_bytes, sha256_of_file  # type: ignore
except Exception:  # noqa: BLE001
    MOCKED.append("src.report.integrity.sha256_of_file / sha256_of_bytes")

    # MOCK: src.report.integrity (Agent 3) — remove at integration.
    def sha256_of_bytes(data: bytes) -> str:  # type: ignore[misc]
        return hashlib.sha256(data).hexdigest()

    # MOCK: src.report.integrity (Agent 3) — remove at integration.
    def sha256_of_file(path: str) -> str:  # type: ignore[misc]
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()


def _try_generate_dataset() -> bool:
    """Ask Agent 1's generator to materialise the dataset if it is missing.

    Best effort: the generator may not exist yet during the parallel build, in which
    case Stage 1 falls back to whatever `load_and_validate` resolved to.
    """
    try:
        from src.data.generate_synthetic import main as generate_main  # type: ignore

        generate_main()
        return os.path.exists(DATA_PATH)
    except Exception:  # noqa: BLE001
        return False


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
        discarded = st.session_state.get("decisions") or []
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
    if not os.path.exists(DATA_PATH):
        _try_generate_dataset()

    started = time.perf_counter()
    try:
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
    decisions: list[AnalystDecision] = st.session_state.get("decisions") or []
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

    status = gate_status(decisions, total_findings=len(findings))
    if not status["coverage_complete"]:
        st.session_state["last_error"] = (
            f"{status['outstanding_count']} finding(s) still awaiting an analyst "
            "decision. Every finding must be reviewed before compilation."
        )
        return None

    started = time.perf_counter()
    report_id = f"RPT-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
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

        if MOCKED:
            st.divider()
            st.warning(
                "**Running on mocks.** These modules were unavailable at import and "
                "are stubbed locally:\n\n"
                + "\n".join(f"- `{m}`" for m in MOCKED),
                icon="🧪",
            )


# ======================================================================================
# Stage 5 panel
# ======================================================================================

def render_report_stage(gate_open: bool) -> None:
    st.subheader("Stage 5 — Report compilation")

    findings = st.session_state.get("findings") or []
    decisions = st.session_state.get("decisions") or []
    status = gate_status(decisions, total_findings=len(findings) or None)
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
                "Re-hash the downloaded file to verify integrity: "
                f"`certutil -hashfile {report.report_id}.pdf SHA256`"
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
            decisions=st.session_state.get("decisions") or [],
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
            decisions=st.session_state.get("decisions") or [],
            stage_times=st.session_state.get("stage_times") or {},
            baseline=st.session_state.get("baseline"),
        )

    with audit_tab:
        render_audit_tab()


main()
