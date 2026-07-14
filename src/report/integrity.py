"""
integrity.py  -  Stage 5 SHA-256 integrity.

Two distinct digests exist in this system. Keep them straight:

1. **Content digest** - ``content_digest(report)``.
   SHA-256 over a canonical, deterministic JSON serialisation of the *committed*
   content of a report (the approved/modified findings, their effective
   explanations, linked controls, remediation steps and analyst decisions).
   It is computable BEFORE the PDF exists, which is why it is what the PDF
   footer commits to on every page.

2. **Artefact digest** - ``sha256_of_file(pdf_path)``.
   SHA-256 over the finished PDF bytes. This is what gets stamped into
   ``ComplianceReport.sha256_hash`` by :func:`stamp_report_hash`.

Why the footer shows the *content* digest and not the artefact digest:
a file cannot contain its own SHA-256. Printing the artefact digest inside the
artefact would change the artefact and therefore change the digest - a hash
fixed-point, which does not exist. The content digest breaks the circularity:
it covers everything the report asserts, and it is stable before the render.

Determinism guarantee
---------------------
Re-hashing the same committed content yields the same digest. Both digests are
pure functions of the committed content:

* ``content_digest`` sorts findings by ``finding_id``, serialises with sorted
  keys and fixed separators, and reads no clock.
* ``sha256_of_file`` is stable because :mod:`src.report.pdf_builder` renders the
  PDF in ReportLab's ``invariant`` mode with the embedded timestamp derived from
  ``report.generated_at`` rather than wall-clock time at build.

Conversely, changing any committed field changes both digests.
"""
from __future__ import annotations

import hashlib
import json
from typing import Optional

from src.gate import resolve_decisions
from src.models import (
    AnalystDecision,
    ComplianceReport,
    DecisionType,
    Explanation,
)

__all__ = [
    "sha256_of_file",
    "sha256_of_bytes",
    "COMMITTED_DECISIONS",
    "is_committed",
    "is_escalated",
    "effective_explanation_text",
    "canonical_content",
    "canonical_content_bytes",
    "content_digest",
    "stamp_report_hash",
]

_CHUNK_SIZE = 65536

#: Canonical-content schema tag. Bump if the serialisation shape ever changes,
#: so that digests from different schema versions are never confused.
CONTENT_SCHEMA = "compliance-report-content/v1"

#: Decisions whose findings are committed to the compliance conclusion.
#: ESCALATE is deliberately absent - an escalated finding is excluded from the
#: conclusion (and the Article 22 gate in src/gate.py stops the report firing
#: at all while any escalation is outstanding).
COMMITTED_DECISIONS = (DecisionType.APPROVE, DecisionType.MODIFY)


# ---------- primitive hashing ----------

def sha256_of_bytes(data: bytes) -> str:
    """Return the SHA-256 hexdigest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_of_file(path: str) -> str:
    """Return the SHA-256 hexdigest of the file at ``path``, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------- committed-content selection ----------

def is_committed(decision: Optional[AnalystDecision]) -> bool:
    """True if ``decision`` commits its finding to the compliance conclusion.

    A finding with no decision is still awaiting review and is not committed.
    """
    return decision is not None and decision.decision in COMMITTED_DECISIONS


def is_escalated(decision: Optional[AnalystDecision]) -> bool:
    """True if ``decision`` escalates its finding out of the conclusion."""
    return decision is not None and decision.decision is DecisionType.ESCALATE


def effective_explanation_text(
    explanation: Optional[Explanation],
    decision: Optional[AnalystDecision],
) -> str:
    """The explanation text that actually goes in the report.

    An analyst who chose MODIFY and supplied replacement prose overrides the
    generated Stage 3 explanation; otherwise the generated text stands.
    """
    if decision is not None and decision.decision is DecisionType.MODIFY:
        modified = (decision.modified_explanation or "").strip()
        if modified:
            return modified
    if explanation is not None:
        return explanation.plain_english
    return ""


# ---------- canonical serialisation ----------

def canonical_content(report: ComplianceReport) -> dict:
    """Build the canonical, deterministic view of a report's committed content.

    Ordering is by ``finding_id`` so that the digest does not depend on the
    order findings happened to arrive in. Nothing here reads the clock: the only
    timestamps present are ones already fixed on the report and its decisions.

    The one effective decision per finding is resolved by
    :func:`src.gate.resolve_decisions` (latest-by-timestamp, ties by list index) —
    the SAME resolution the Article 22 gate uses — so a reordered decision history
    can never make this canonical content disagree with the gate. Using last-in-list
    here instead would diverge on a non-append-only history.
    """
    decisions = resolve_decisions(report.decisions)
    explanations = {e.finding_id: e for e in report.explanations}

    committed: list[dict] = []
    excluded: list[str] = []

    for finding in sorted(report.findings, key=lambda f: f.finding_id):
        decision = decisions.get(finding.finding_id)
        if not is_committed(decision):
            # Escalated or still awaiting review: named, but its content does
            # not feed the compliance conclusion.
            excluded.append(finding.finding_id)
            continue

        explanation = explanations.get(finding.finding_id)
        committed.append(
            {
                "finding_id": finding.finding_id,
                "asset": finding.asset.model_dump(mode="json"),
                "issue_code": finding.issue_code.value,
                "rule_id": finding.rule_id,
                "triggering_cve": finding.triggering_cve,
                "triggering_cvss": finding.triggering_cvss,
                "control_mappings": [
                    cm.model_dump(mode="json") for cm in finding.control_mappings
                ],
                "frameworks_breached": [fw.value for fw in finding.frameworks_breached],
                "explanation": effective_explanation_text(explanation, decision),
                "remediation_steps": (
                    list(explanation.remediation_steps) if explanation else []
                ),
                "decision": decision.decision.value,
                "analyst_id": decision.analyst_id,
                "analyst_note": decision.analyst_note,
                "decided_at": decision.timestamp.isoformat(),
            }
        )

    return {
        "schema": CONTENT_SCHEMA,
        "report_id": report.report_id,
        "generated_at": report.generated_at.isoformat(),
        "committed_findings": committed,
        "excluded_finding_ids": sorted(excluded),
    }


def canonical_content_bytes(report: ComplianceReport) -> bytes:
    """Canonical content as deterministic UTF-8 JSON bytes.

    ``sort_keys`` plus fixed separators plus ``ensure_ascii`` mean identical
    committed content always produces identical bytes on any platform.
    """
    return json.dumps(
        canonical_content(report),
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def content_digest(report: ComplianceReport) -> str:
    """SHA-256 hexdigest of the report's canonical committed content.

    Stable across runs for identical committed content, and sensitive to any
    change in it. This is the digest printed in the PDF footer.
    """
    return sha256_of_bytes(canonical_content_bytes(report))


# ---------- caller helper ----------

def stamp_report_hash(report: ComplianceReport, pdf_path: str) -> str:
    """Hash a freshly-built PDF and record it on the report.

    Sets ``report.sha256_hash`` to the SHA-256 of the PDF bytes and
    ``report.pdf_path`` to ``pdf_path``, then returns the digest.

    Intended use (see also :func:`src.report.pdf_builder.build_and_hash`, which
    wraps both steps)::

        compile_pdf(report, out_path)
        digest = stamp_report_hash(report, out_path)
    """
    digest = sha256_of_file(pdf_path)
    report.sha256_hash = digest
    report.pdf_path = pdf_path
    return digest
