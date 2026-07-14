# Explainable Compliance Tool — Cyber Essentials × ISO/IEC 27001:2022

A rule-based, explainable compliance mapping tool with a mandatory human-in-the-loop
validation gate. Deliberately no ML: every finding traces back to a declarative rule, so
every output can be explained to an auditor.

The tool ingests synthetic security scan data, maps each issue to Cyber Essentials,
Cyber Essentials Plus and ISO/IEC 27001:2022 Annex A controls, generates a plain-English
explanation per finding, requires an analyst to Approve / Modify / Escalate each one, and
only then compiles a SHA-256 hashed PDF report.

---

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

## The Article 22 gate — the core design control

**Stage 5 cannot fire while any finding is still escalated.**

This is the single most important behaviour in the system. It is what makes the tool
*decision support* rather than *automated decision-making*, and it is the design response
to UK GDPR Article 22 (the right not to be subject to a solely automated decision).

How it works — `src/gate.py`:

- `can_generate_report(decisions: list[AnalystDecision]) -> bool` returns `False` if **any**
  finding's effective decision is Escalate.
- The decision list is an **append-only history**, not a set. A finding may appear in it
  more than once. Duplicates are resolved explicitly: the **latest decision by timestamp
  wins**, with list order breaking ties. Only that effective decision is tested.
- An escalation is therefore *resolved* when, and only when, the analyst replaces that
  finding's decision with Approve or Modify. Approving after escalating unblocks the
  report; escalating after approving re-blocks it. The superseded decision stays in the
  audit trail — resolution is recorded, never erased.
- **Defence in depth:** the Stage 5 button is disabled while the gate is red, but a
  disabled button is a UI affordance, not a control. `compile_report()` re-checks
  `can_generate_report` immediately before building the PDF, and audits any refused
  attempt as `STAGE_5_BLOCKED`.

The gate deliberately covers escalations only. "Has every finding been reviewed?" is a
separate, weaker coverage check (`gate_status`) surfaced in the UI — folding it into
`can_generate_report` would change what the Article 22 control means.

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

The **Mapping matrix** tab renders the CE pillar × ISO control heatmap (Appendix Ai):
P = Primary, S = Secondary, blank = no mapping.

---

## Academic integrity note

George's full matrix has **47 mapped intersections**, of which only the **15 rows verified
against the interim report (Appendix Aii)** are authoritative. Every other intersection in
the rule base is a clearly-flagged, best-effort mapping and is listed in
`rules/UNVERIFIED_MAPPINGS.md`. **Confirm each against the framework documentation before
submission** — unverified mappings must not be presented as sourced.

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
