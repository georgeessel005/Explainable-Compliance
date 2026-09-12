# CompliancePilot
Explainable Cybersecurity Compliance Mapping for UK SMEs
Cyber Essentials / Cyber Essentials Plus ↔ ISO/IEC 27001:2022

CompliancePilot is a rule-based cybersecurity compliance artefact developed as part of an MSc Cybersecurity research project. It processes structured security findings, maps them across Cyber Essentials, Cyber Essentials Plus and selected ISO/IEC 27001:2022 Annex A controls, produces plain-English explanations and requires Human-in-the-Loop review before a final report can be generated.

The system deliberately uses deterministic rules rather than machine learning so that each implemented recommendation can be traced to explicit rule logic and reviewed by an analyst.

## Live Artefact

Streamlit application: https://explainable-compliance-qpvbphrthjc8gxfgrsbdxo.streamlit.app/

Source repository:
https://github.com/georgeessel005/Explainable-Compliance

The application can also be run locally using the instructions below.

## Run locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Generate the synthetic dataset first if `data/synthetic/assets.json` is absent (the app
will also attempt this automatically on Stage 1):

```bash
python -m src.data.generate_synthetic
```

Run the tests:

```bash
pip install -r requirements-dev.txt
pytest -v
```

On this machine, use the project virtualenv for every command:

```bash
./.venv/Scripts/python.exe -m streamlit run streamlit_app.py
./.venv/Scripts/python.exe -m pytest -v
```

---

## The five stages

| Stage | What it does | Where |
|---|---|---|
| **1. Ingestion** | Loads synthetic scan records, validates them with Pydantic, rejects malformed input rather than guessing. Rejected records and their reasons are shown in the sidebar. | `src/ingestion/loader.py` |
| **2. Mapping** | Matches issue codes against the YAML rule base and produces cross-framework findings with Primary/Secondary control designations. | `src/mapping/engine.py` |
| **3. Explainability** | Fills plain-English templates, attaching linked controls and remediation steps to each finding. | `src/explain/explainer.py` |
| **4. Human validation gate (HITL)** | The analyst must Approve, Modify or Escalate every finding. Modify opens the explanation for editing. Every action is written to a timestamped audit log. | `src/ui/review.py` |
| **5. Report compilation** | ReportLab PDF with a SHA-256 integrity hash, downloadable alongside the audit trail. | `src/report/pdf_builder.py` |

Work through the stages using the sidebar (1 → 3), review in the **Review** tab (4), then
compile in the **Report** tab (5).

### Verifying report integrity

The compiled PDF carries a SHA-256 integrity hash, shown in the **Report** tab and printed
in the report footer. To confirm a downloaded PDF has not been altered, re-hash it and
compare against that value. Use whichever command matches your platform:

```bash
# Linux / macOS / Streamlit Cloud
sha256sum <report>.pdf

# Windows (PowerShell / cmd)
certutil -hashfile <report>.pdf SHA256
```

---

## Human-in-the-Loop Release Gate

Stage 5 cannot generate the final report until all findings have been reviewed and no unresolved escalation remains.

Analysts can Approve, Modify or Escalate each finding. Approve and Modify are treated as resolved review states, while an unresolved Escalate blocks report generation. If an analyst later resolves an escalation through Approve or Modify, the earlier decision remains in the append-only audit history.

The release condition is enforced at more than one level. The Streamlit interface prevents report generation while the review conditions remain unresolved, and the report-generation path performs a further check before compiling the PDF. This prevents the final report from depending only on the state of a visible interface button.

Human review is implemented as an accountability and quality-control feature. It should not be interpreted as a claim that CompliancePilot automatically satisfies a particular legal requirement or that human review guarantees the correctness of every compliance recommendation.

---

## Audit trail (Data Protection Act 2018)

Every stage transition and every analyst decision appends a timestamped `AuditLogEntry`
recording who did what, when, and the status transition. The trail is append-only:
superseded decisions are retained, since the point of the artefact is to show how a
conclusion was reached. Exportable as CSV from the **Audit trail** tab.

---

## Evaluation metrics

Surfaced live on the **Evaluation metrics** tab (`src/ui/metrics.py`):

- **Functional Correctness** — share of findings matching an expected-output baseline.
  Reports **N/A** unless a baseline JSON is uploaded; no baseline means no claim.
- **Cross-Mapping Fidelity** — share of findings whose control mappings reach at least one
  CE (or CE Plus) pillar *and* at least one ISO/IEC 27001 Annex A control, with
  `frameworks_breached` covering every framework mapped.
- **Execution Velocity** — wall-clock seconds per pipeline stage, timed live, summed
  ingestion → report.
- **Human Interaction Load** — override rate = (Modify + Escalate) ÷ findings reviewed,
  using each finding's latest decision. Repeat visits are reported as actions per finding.

The **Mapping matrix** tab renders the CE pillar × ISO control heatmap :
P = Primary, S = Secondary, blank = no mapping.

---

## Academic integrity note

The wider research analysis produced 47 classified Cyber Essentials / ISO/IEC 27001 relationships. The executable CompliancePilot rule base implements a smaller subset.

The executable implementation contains 25 relationship-level entries: 15 project-verified/source-backed relationships and 10 best-effort relationships. When duplicate framework intersections are collapsed for matrix display, these produce 24 unique cells: 15 project-verified/source-backed and 9 best-effort.

Best-effort mappings are deliberately identified as such and should not be interpreted as independently validated mappings. Cross-Mapping Fidelity measures structural implementation coverage within the rule set; it does not establish independent mapping accuracy.

Detailed mapping evidence and provenance are documented in Appendix D.2 of the dissertation..

---

## Project structure

```
├── streamlit_app.py              # entry point (Streamlit Cloud)
├── src/
│   ├── models.py                 # frozen shared Pydantic contracts
│   ├── gate.py                   # the Article 22 release gate
│   ├── ingestion/loader.py       # Stage 1
│   ├── data/generate_synthetic.py
│   ├── mapping/{engine,matrix}.py  # Stage 2
│   ├── explain/explainer.py      # Stage 3
│   ├── audit/log.py              # accountability trail
│   ├── ui/{review,heatmap,metrics}.py  # Stage 4 + dashboards
│   └── report/{pdf_builder,integrity}.py  # Stage 5
├── rules/                        # YAML rule base + UNVERIFIED_MAPPINGS.md
├── data/synthetic/assets.json    # generated, deterministic (fixed seed)
└── tests/
```

### Design constraints

- **State** lives in `st.session_state` only — never browser storage. Streamlit re-executes
  the whole script on every interaction, so anything that must persist is initialised
  behind an `if "key" not in st.session_state` guard.
- **Determinism** — the synthetic generator uses a fixed seed and all date comparisons run
  against `assessment_date`, so identical input produces an identical report hash.
- **No external APIs, no network calls, no ML.**
