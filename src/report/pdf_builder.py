"""
pdf_builder.py  -  Stage 5 PDF compilation (ReportLab).

Renders a :class:`ComplianceReport` to a PDF whose bytes are a pure function of
the report's content.

Determinism
-----------
ReportLab normally embeds wall-clock ``CreationDate``/``ModDate`` and derives the
trailer ``/ID`` from a signature seeded with that timestamp, so two builds of
identical content produce different bytes and different file digests. Two
mechanisms are combined here (see :func:`_deterministic_build`):

* ``invariant=1`` on the document, which switches ReportLab onto a fixed
  timestamp and a content-derived ``/ID`` instead of a time-derived one.
* ``SOURCE_DATE_EPOCH`` set to ``report.generated_at``. ReportLab's
  ``TimeStamp`` reads this at build time, so the embedded timestamp comes from
  the report itself rather than the clock. Without it, ``invariant`` alone would
  pin every report to 2000-01-01.

Net effect: the same report object built twice yields byte-identical PDFs and an
equal ``sha256_of_file``, while changing any committed field changes the digest
(the ``/ID`` signature is fed by document content).

The footer prints the *content* digest, not the file digest - a file cannot
contain its own hash. See :mod:`src.report.integrity` for the distinction.
"""
from __future__ import annotations

import calendar
import contextlib
import os
import unicodedata
from datetime import datetime
from typing import Iterator, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab import rl_config

from src.gate import (
    can_generate_report,
    escalated_finding_ids,
    resolve_decisions,
)
from src.mapping.engine import is_verified_mapping
from src.models import (
    AnalystDecision,
    ComplianceFinding,
    ComplianceReport,
    DecisionType,
    Explanation,
)
from src.report.integrity import (
    content_digest,
    effective_explanation_text,
    is_committed,
    is_escalated,
    normalise_organisation,
    sha256_of_file,
)

__all__ = ["compile_pdf", "build_and_hash", "GateError"]


class GateError(RuntimeError):
    """Raised when a report with an open escalation reaches the PDF boundary.

    The Article 22 control (:func:`src.gate.can_generate_report`) is re-checked
    here, at the artefact-producing boundary, not only in the Streamlit app. A
    report may not be compiled while any finding's *effective* (latest) decision
    is still Escalate; an escalation that was later resolved to Approve/Modify is
    fine and the finding legitimately appears in the report.
    """

_PAGE_SIZE = A4
_MARGIN = 18 * mm

_ACCENT = colors.HexColor("#1F3A5F")
_MUTED = colors.HexColor("#5A6672")
_RULE = colors.HexColor("#C9D2DB")
_BAND = colors.HexColor("#EEF2F6")
_ESCALATED = colors.HexColor("#B3261E")
_CAVEAT_BG = colors.HexColor("#FBEDEC")

_DECISION_LABELS = {
    DecisionType.APPROVE: "Approve",
    DecisionType.MODIFY: "Modify",
    DecisionType.ESCALATE: "Escalate",
}


# ---------- deterministic build environment ----------

def _epoch_for(generated_at: datetime) -> int:
    """Seconds since the epoch for ``generated_at``, naive values read as UTC.

    Clamped at zero: ReportLab feeds this to ``time.gmtime``, which rejects
    negative values on Windows.
    """
    return max(0, calendar.timegm(generated_at.utctimetuple()))


@contextlib.contextmanager
def _deterministic_build(generated_at: datetime) -> Iterator[None]:
    """Pin ReportLab's clock to ``generated_at`` for the duration of a build.

    Both settings are process-global, so they are restored on exit to avoid
    leaking invariant mode into anything else in the host process (the Streamlit
    app builds reports in-process).
    """
    previous_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    previous_invariant = rl_config.invariant
    os.environ["SOURCE_DATE_EPOCH"] = str(_epoch_for(generated_at))
    rl_config.invariant = 1
    try:
        yield
    finally:
        rl_config.invariant = previous_invariant
        if previous_epoch is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous_epoch


# ---------- styles ----------

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "RptTitle", parent=base["Title"], fontSize=22, leading=26,
            textColor=_ACCENT, spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "RptSubtitle", parent=base["Normal"], fontSize=11, leading=15,
            textColor=_MUTED, alignment=TA_LEFT, spaceAfter=4,
        ),
        # Title-page ORGANIZATION block. Only instantiated into the story when an
        # organisation was supplied, so a report without one is unchanged.
        "orglabel": ParagraphStyle(
            "RptOrgLabel", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=11, textColor=_MUTED, spaceAfter=2,
        ),
        "org": ParagraphStyle(
            "RptOrg", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=17, leading=21, textColor=_ACCENT, spaceAfter=2,
        ),
        "h2": ParagraphStyle(
            "RptH2", parent=base["Heading2"], fontSize=13, leading=17,
            textColor=_ACCENT, spaceBefore=10, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "RptH3", parent=base["Heading3"], fontSize=11, leading=14,
            textColor=_ACCENT, spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "RptBody", parent=base["Normal"], fontSize=9.5, leading=13.5,
            spaceAfter=4,
        ),
        "cell": ParagraphStyle(
            "RptCell", parent=base["Normal"], fontSize=8, leading=10.5,
        ),
        # Wrapping style for the metadata table's value column. Matches the 9pt
        # Helvetica the table's own FONTSIZE gives its raw cells, so a wrapped value
        # sits flush with the unwrapped rows above and below it.
        "metacell": ParagraphStyle(
            "RptMetaCell", parent=base["Normal"], fontSize=9, leading=12,
        ),
        "mono": ParagraphStyle(
            "RptMono", parent=base["Normal"], fontName="Courier", fontSize=7.5,
            leading=10, textColor=_MUTED,
        ),
        "note": ParagraphStyle(
            "RptNote", parent=base["Normal"], fontSize=9, leading=12.5,
            textColor=_ESCALATED, spaceAfter=4,
        ),
        "caveat": ParagraphStyle(
            "RptCaveat", parent=base["Normal"], fontSize=8.5, leading=12,
            textColor=_ESCALATED, backColor=_CAVEAT_BG,
            borderColor=_ESCALATED, borderWidth=0.6, borderPadding=6,
            spaceBefore=4, spaceAfter=4,
        ),
    }


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    """Paragraph from arbitrary text, XML-escaped so stray '&'/'<' cannot break it."""
    return Paragraph(escape("" if text is None else str(text)), style)


# ---------- honest rendering of non-Latin-1 text ----------
#
# ReportLab's built-in Type1 faces (Helvetica, Courier, Times) are single-byte
# fonts: they can only draw the ~224 characters of their encoding vector. Anything
# outside it is NOT drawn - ReportLab silently substitutes a fallback face and emits
# visually meaningless glyphs (an organisation named "... Ltd <CJK>" printed as
# "... Ltd nn"). That is a correctness problem specific to this report, because the
# tamper-seal demonstration invites the reader to compare the PRINTED organisation
# name against the SEALED one. The digest always covers the true string, so the seal
# itself was never wrong - but a page that cannot show what was sealed makes that
# comparison misleading.
#
# The obvious fix - embed a TrueType face with wider coverage - was evaluated and
# rejected. The only TTFs ReportLab bundles are Vera/VeraBd/VeraIt/VeraBI (283
# glyphs: Latin-1 plus a fragment of Latin Extended-A) and a 9-glyph HarfBuzz test
# font. None carries Cyrillic, Greek or CJK, so embedding Vera would still drop the
# realistic non-Latin cases while adding an embedded-font-subsetting step to a build
# whose byte-for-byte determinism is a hard requirement. Instead the name is degraded
# HONESTLY: every character the face cannot draw is replaced by a visible marker and
# the page states that the rendering is lossy and prints the exact sealed value in an
# unambiguous ASCII form. Nothing is ever dropped silently.

#: Codec matching the encoding vector ReportLab gives the built-in Type1 faces.
#: WinAnsi is the default; MacRoman is the only other option ReportLab offers.
_TYPE1_CODEC = "mac_roman" if "MacRoman" in rl_config.defaultEncoding else "cp1252"


def _is_renderable(char: str) -> bool:
    """True if a built-in Type1 face can actually draw ``char``.

    cp1252 leaves five slots undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D); Python's
    codec rejects them, which is exactly the answer we want.
    """
    try:
        char.encode(_TYPE1_CODEC)
    except UnicodeEncodeError:
        return False
    return True


def _codepoint_marker(char: str) -> str:
    """``'東'`` -> ``'[U+6771]'``. Visible, unambiguous, reversible by the reader."""
    return f"[U+{ord(char):04X}]"


def _transliterate(char: str) -> str:
    """Best readable Type1-drawable stand-in for one unrenderable character.

    Tries canonical decomposition first, so an accented Latin letter degrades to its
    base letter (``'ź'`` -> ``'z'``) rather than to a codepoint escape. Characters
    with no drawable base - Cyrillic, Greek, CJK, emoji - fall back to the marker.
    """
    base = "".join(
        c
        for c in unicodedata.normalize("NFKD", char)
        if not unicodedata.combining(c) and _is_renderable(c)
    )
    return base or _codepoint_marker(char)


def _render_safe(text: str) -> tuple[str, bool]:
    """``text`` reduced to what the page can draw, plus whether anything was lost.

    Returns ``(displayable_text, lossy)``. When ``lossy`` is False the text is
    returned unchanged, so the common all-Latin-1 case is byte-for-byte what it was
    before this function existed.
    """
    if all(_is_renderable(c) for c in text):
        return text, False
    return "".join(c if _is_renderable(c) else _transliterate(c) for c in text), True


def _ascii_escape(text: str) -> str:
    """``text`` with every non-printable-ASCII character shown as ``[U+XXXX]``.

    The exact sealed value in a form that survives a Latin-1 font, so a reader can
    still compare the printed name against the string the digest committed to.
    """
    return "".join(
        c if 0x20 <= ord(c) < 0x7F else _codepoint_marker(c) for c in text
    )


# ---------- footer ----------

class _Footer:
    """Draws the per-page footer carrying the content SHA-256."""

    def __init__(self, report: ComplianceReport, digest: str) -> None:
        self.report = report
        self.digest = digest

    def __call__(self, canvas, doc) -> None:
        canvas.saveState()
        width, _ = _PAGE_SIZE
        y = _MARGIN - 6 * mm
        canvas.setStrokeColor(_RULE)
        canvas.setLineWidth(0.5)
        canvas.line(_MARGIN, y + 5 * mm, width - _MARGIN, y + 5 * mm)
        canvas.setFont("Courier", 6.5)
        canvas.setFillColor(_MUTED)
        canvas.drawString(_MARGIN, y + 1.5 * mm, f"Content SHA-256: {self.digest}")
        canvas.setFont("Helvetica", 6.5)
        canvas.drawRightString(
            width - _MARGIN, y + 1.5 * mm, f"{self.report.report_id}  |  page {doc.page}"
        )
        canvas.restoreState()


# ---------- sections ----------

def _decision_label(decision: Optional[AnalystDecision]) -> str:
    if decision is None:
        return "Awaiting decision"
    return _DECISION_LABELS.get(decision.decision, decision.decision.value)


def _title_block(report, digest, counts, styles, organisation=None) -> list:
    committed, escalated, pending = counts
    flowables: list = [
        _p("Compliance Assessment Report", styles["title"]),
        _p(
            "Cyber Essentials, Cyber Essentials Plus and ISO/IEC 27001:2022 Annex A",
            styles["subtitle"],
        ),
    ]

    # The organisation the assessment was carried out for, as a headline field. Omitted
    # entirely when not supplied, so the title page is byte-identical to before.
    org_display, org_lossy = (
        _render_safe(organisation) if organisation is not None else ("", False)
    )
    if organisation is not None:
        flowables += [
            Spacer(1, 6 * mm),
            _p("ORGANIZATION", styles["orglabel"]),
            _p(org_display, styles["org"]),
            _p(
                "This report is issued in respect of the organisation named above. "
                "The name forms part of the sealed content covered by the SHA-256 "
                "below, so altering it invalidates the seal.",
                styles["subtitle"],
            ),
        ]
        if org_lossy:
            # Say so on the page rather than letting the reader assume the printed
            # name IS the sealed name. Without this the tamper-seal comparison the
            # report invites would be made against a silently truncated string.
            flowables += [
                _p(
                    "Lossy rendering: the organisation name contains characters this "
                    "report's font cannot draw. The name shown above is a transliteration "
                    "in which each such character appears either as its unaccented base "
                    "letter or as a [U+XXXX] codepoint marker. The SHA-256 seal covers "
                    "the ORIGINAL name exactly as supplied, not this rendering. The exact "
                    "sealed value is printed below for comparison.",
                    styles["note"],
                ),
                _p(_ascii_escape(organisation), styles["mono"]),
            ]

    flowables.append(Spacer(1, 8 * mm))

    meta_rows = [["Report ID", report.report_id]]
    if organisation is not None:
        # Paragraph, not a raw string: raw Table cells are a single unwrapped text
        # run, so a long organisation name measured wider than the 105mm column and
        # ran straight off the right edge of the page instead of wrapping.
        meta_rows.append(["Organisation", _p(org_display, styles["metacell"])])
    meta_rows += [
        ["Generated at", report.generated_at.isoformat()],
        ["Findings assessed", str(len(report.findings))],
        ["Committed to conclusion", str(committed)],
        ["Escalated (excluded)", str(escalated)],
        ["Awaiting decision (excluded)", str(pending)],
    ]

    meta = Table(
        meta_rows,
        colWidths=[55 * mm, 105 * mm],
    )
    meta.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), _ACCENT),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _BAND]),
                ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    flowables += [meta, Spacer(1, 8 * mm)]

    flowables.append(_p("Integrity", styles["h3"]))
    flowables.append(
        _p(
            "The SHA-256 below covers the canonical serialisation of this report's "
            "committed content: the approved and modified findings, their explanations, "
            "linked controls, remediation steps and analyst decisions. It is reproduced "
            "in the footer of every page. Re-hashing the same committed content yields "
            "the same digest, so any alteration to a committed field is detectable.",
            styles["body"],
        )
    )
    flowables.append(_p(digest, styles["mono"]))
    flowables.append(Spacer(1, 6 * mm))

    flowables.append(_p("Basis of this report", styles["h3"]))
    flowables.append(
        _p(
            "Every finding in this report was generated by a deterministic rule base and "
            "reviewed by a human analyst, who approved, modified or escalated it. No "
            "finding reaches the compliance conclusion without that decision. Escalated "
            "findings are listed for completeness but are excluded from the conclusion "
            "and remain open.",
            styles["body"],
        )
    )
    return flowables


def _summary_table(report, decisions, styles) -> list:
    header = ["Finding", "Asset", "Issue", "CVE", "CVSS", "Decision"]
    rows = [[_p(h, styles["cell"]) for h in header]]
    escalated_rows: list[int] = []

    for index, finding in enumerate(report.findings, start=1):
        decision = decisions.get(finding.finding_id)
        if is_escalated(decision):
            escalated_rows.append(index)
        rows.append(
            [
                _p(finding.finding_id, styles["cell"]),
                _p(finding.asset.hostname, styles["cell"]),
                _p(finding.issue_code.value, styles["cell"]),
                _p(finding.triggering_cve or "n/a", styles["cell"]),
                _p(
                    "n/a" if finding.triggering_cvss is None else f"{finding.triggering_cvss:.1f}",
                    styles["cell"],
                ),
                _p(_decision_label(decision), styles["cell"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[22 * mm, 30 * mm, 44 * mm, 30 * mm, 13 * mm, 25 * mm],
        repeatRows=1,
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _BAND]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]
    for row in escalated_rows:
        style.append(("TEXTCOLOR", (5, row), (5, row), _ESCALATED))
    table.setStyle(TableStyle(style))

    return [
        _p("1. Findings summary", styles["h2"]),
        _p(
            "Every finding assessed, with the analyst decision recorded against it.",
            styles["body"],
        ),
        Spacer(1, 3 * mm),
        table,
    ]


def _mapping_provenance(finding: ComplianceFinding, mapping) -> Optional[bool]:
    """Provenance of one control mapping: True verified, False unverified, None unknown.

    Delegates to :func:`src.mapping.engine.is_verified_mapping` so the PDF marks the
    best-effort mappings with the same authority the heatmap tab uses. ``finding.rule_id``
    is the key the engine indexes provenance by. Returns None (render no marker) when the
    engine cannot assert - e.g. the rule base was not loaded in this process.
    """
    return is_verified_mapping(finding.rule_id, mapping.framework, mapping.control_id)


def _finding_has_unverified_mapping(finding: ComplianceFinding) -> bool:
    """True if any of this finding's control mappings is a flagged best-effort mapping."""
    return any(
        _mapping_provenance(finding, m) is False for m in finding.control_mappings
    )


_PROVENANCE_LABEL = {True: "Verified", False: "Unverified", None: ""}


def _controls_table(finding: ComplianceFinding, styles) -> Table:
    header = ["Framework", "Control", "Control name", "Type", "Provenance"]
    rows = [[_p(h, styles["cell"]) for h in header]]
    unverified_rows: list[int] = []
    for row_index, mapping in enumerate(finding.control_mappings, start=1):
        provenance = _mapping_provenance(finding, mapping)
        if provenance is False:
            unverified_rows.append(row_index)
        # A CE / CE+ pillar has no identifier distinct from its name (control_id ==
        # control_name), unlike ISO where the id is a code like "A.8.8". Printing both
        # repeated the same string in adjacent cells, and the narrow Control column is
        # sized for a code, not a pillar name. Show the code column as "-" and let the
        # wide name column carry the label.
        stutters = mapping.control_id.strip() == mapping.control_name.strip()
        control_code = "-" if stutters else mapping.control_id
        rows.append(
            [
                _p(mapping.framework.value, styles["cell"]),
                _p(control_code, styles["cell"]),
                _p(mapping.control_name, styles["cell"]),
                _p(mapping.mapping_type.value, styles["cell"]),
                _p(_PROVENANCE_LABEL[provenance], styles["cell"]),
            ]
        )
    table = Table(
        rows,
        colWidths=[34 * mm, 20 * mm, 62 * mm, 22 * mm, 26 * mm],
        repeatRows=1,
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _BAND),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]
    for row in unverified_rows:
        # Make the best-effort mappings visibly distinct from the sourced ones.
        style.append(("TEXTCOLOR", (4, row), (4, row), _ESCALATED))
        style.append(("FONTNAME", (4, row), (4, row), "Helvetica-Bold"))
    table.setStyle(TableStyle(style))
    return table


def _finding_section(
    finding: ComplianceFinding,
    explanation: Optional[Explanation],
    decision: Optional[AnalystDecision],
    index: int,
    styles,
) -> list:
    """One finding card: asset, CVE, CVSS, explanation, controls, remediation."""
    asset = finding.asset
    flowables: list = [
        _p(f"{index}. {finding.finding_id} - {finding.issue_code.value}", styles["h3"])
    ]

    facts = Table(
        [
            ["Asset", f"{asset.hostname} ({asset.asset_id})"],
            ["Address / OS", f"{asset.ip_address}  |  {asset.operating_system}"],
            [
                "Exposure",
                f"{'Internet-facing' if asset.internet_facing else 'Internal-only'}"
                f"  |  {asset.environment}  |  criticality {asset.criticality.value}",
            ],
            ["Assessed", asset.assessment_date.isoformat()],
            ["CVE", finding.triggering_cve or "None - configuration or process finding"],
            [
                "CVSS",
                "n/a" if finding.triggering_cvss is None else f"{finding.triggering_cvss:.1f}",
            ],
            ["Rule", finding.rule_id],
            ["Decision", _decision_label(decision)],
        ],
        colWidths=[26 * mm, 138 * mm],
    )
    facts.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), _ACCENT),
                ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    flowables += [facts, Spacer(1, 3 * mm)]

    flowables.append(_p("Explanation", styles["h3"]))
    text = effective_explanation_text(explanation, decision)
    flowables.append(_p(text or "No explanation recorded for this finding.", styles["body"]))

    if decision is not None and decision.decision is DecisionType.MODIFY:
        flowables.append(
            _p(
                f"This explanation was modified by analyst {decision.analyst_id} during review.",
                styles["mono"],
            )
        )
    if decision is not None and decision.analyst_note:
        flowables.append(_p(f"Analyst note: {decision.analyst_note}", styles["mono"]))

    flowables.append(Spacer(1, 2 * mm))
    flowables.append(_p("Linked controls", styles["h3"]))
    if finding.control_mappings:
        flowables.append(_controls_table(finding, styles))
    else:
        flowables.append(_p("No controls mapped to this finding.", styles["body"]))

    steps = explanation.remediation_steps if explanation else []
    flowables.append(Spacer(1, 2 * mm))
    flowables.append(_p("Remediation", styles["h3"]))
    if steps:
        for number, step in enumerate(steps, start=1):
            flowables.append(_p(f"{number}. {step}", styles["body"]))
    else:
        flowables.append(_p("No remediation steps recorded.", styles["body"]))

    flowables.append(Spacer(1, 5 * mm))
    return flowables


def _escalated_section(report, decisions, explanations, styles) -> list:
    escalated = [f for f in report.findings if is_escalated(decisions.get(f.finding_id))]
    pending = [
        f
        for f in report.findings
        if not is_committed(decisions.get(f.finding_id))
        and not is_escalated(decisions.get(f.finding_id))
    ]
    if not escalated and not pending:
        return []

    flowables: list = [_p("3. Findings excluded from the conclusion", styles["h2"])]

    if escalated:
        flowables.append(
            _p(
                "The findings below were escalated by the reviewing analyst. They are "
                "recorded here for completeness and are excluded from the compliance "
                "conclusion; each remains open pending further investigation.",
                styles["body"],
            )
        )
        for finding in escalated:
            decision = decisions.get(finding.finding_id)
            line = (
                f"{finding.finding_id} ({finding.asset.hostname}, "
                f"{finding.issue_code.value}) - Escalated, excluded from compliance "
                "conclusion."
            )
            flowables.append(_p(line, styles["note"]))
            if decision is not None and decision.analyst_note:
                flowables.append(_p(f"Analyst note: {decision.analyst_note}", styles["mono"]))

    if pending:
        flowables.append(Spacer(1, 3 * mm))
        flowables.append(
            _p(
                "The findings below had no analyst decision recorded and are therefore "
                "excluded from the compliance conclusion.",
                styles["body"],
            )
        )
        for finding in pending:
            flowables.append(
                _p(
                    f"{finding.finding_id} ({finding.asset.hostname}, "
                    f"{finding.issue_code.value}) - Awaiting analyst decision, excluded "
                    "from compliance conclusion.",
                    styles["body"],
                )
            )
    return flowables


# ---------- public API ----------

def compile_pdf(
    report: ComplianceReport,
    out_path: str,
    *,
    organisation: Optional[str] = None,
) -> str:
    """Render ``report`` to a PDF at ``out_path`` and return ``out_path``.

    The PDF bytes are a pure function of the report's content: building the same
    report twice produces byte-identical files (and therefore an equal
    ``sha256_of_file``), while changing any committed field changes them.

    Findings are rendered in the order the mapping engine produced. Only
    committed findings (Approve / Modify) get a full card; escalated and
    undecided findings are listed as excluded from the compliance conclusion.

    Raises :class:`GateError` if any finding's effective decision is still an open
    escalation. This is the Article 22 control re-checked at the artefact boundary
    (the same predicate the Streamlit app uses), so no compliant-looking PDF can be
    produced over an unresolved human objection, whatever the caller. Nothing is
    written to disk when the gate blocks.

    ``organisation`` is keyword-only and optional. When supplied it is rendered as a
    headline field on the title page AND folded into the content digest, so the
    footer SHA-256 seals the organisation name along with the findings: editing the
    name and re-verifying breaks the seal. When omitted, the PDF is byte-identical
    to what this function produced before the parameter existed.
    """
    if not can_generate_report(report.decisions):
        open_ids = escalated_finding_ids(report.decisions)
        raise GateError(
            f"Cannot compile report {report.report_id!r}: "
            f"{len(open_ids)} finding(s) have an open escalation "
            f"({', '.join(open_ids)}). Resolve each to Approve/Modify before "
            "generating the report (UK GDPR Article 22 gate)."
        )

    directory = os.path.dirname(os.path.abspath(out_path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    styles = _styles()
    org = normalise_organisation(organisation)
    decisions = resolve_decisions(report.decisions)
    explanations = {e.finding_id: e for e in report.explanations}
    digest = content_digest(report, organisation=org)

    committed = [f for f in report.findings if is_committed(decisions.get(f.finding_id))]
    escalated_count = sum(
        1 for f in report.findings if is_escalated(decisions.get(f.finding_id))
    )
    pending_count = len(report.findings) - len(committed) - escalated_count

    story: list = []
    story += _title_block(
        report,
        digest,
        (len(committed), escalated_count, pending_count),
        styles,
        organisation=org,
    )
    story.append(PageBreak())
    story += _summary_table(report, decisions, styles)
    story.append(PageBreak())

    story.append(_p("2. Committed findings", styles["h2"]))
    if committed:
        story.append(
            _p(
                "Each finding below was approved or modified by the reviewing analyst and "
                "forms part of the compliance conclusion.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 3 * mm))
        for index, finding in enumerate(committed, start=1):
            section = _finding_section(
                finding,
                explanations.get(finding.finding_id),
                decisions.get(finding.finding_id),
                index,
                styles,
            )
            # Keep the card header with its facts table; let the rest reflow.
            story.append(KeepTogether(section[:2]))
            story += section[2:]
    else:
        story.append(
            _p(
                "No findings were committed to the compliance conclusion.",
                styles["body"],
            )
        )

    if any(_finding_has_unverified_mapping(f) for f in committed):
        story.append(Spacer(1, 3 * mm))
        story.append(
            _p(
                "Academic integrity: controls marked \"Unverified\" in the Linked "
                "controls tables above are best-effort mappings not sourced from "
                "Appendix Aii. They are enumerated in rules/UNVERIFIED_MAPPINGS.md; "
                "confirm each against the framework documentation before relying on "
                "them.",
                styles["caveat"],
            )
        )

    excluded = _escalated_section(report, decisions, explanations, styles)
    if excluded:
        story.append(Spacer(1, 4 * mm))
        story += excluded

    with _deterministic_build(report.generated_at):
        doc = SimpleDocTemplate(
            out_path,
            pagesize=_PAGE_SIZE,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=_MARGIN,
            bottomMargin=_MARGIN + 4 * mm,
            title=f"Compliance Report {report.report_id}",
            author="Explainable Compliance Tool",
            subject="Cyber Essentials / ISO IEC 27001:2022 compliance findings",
            creator="Explainable Compliance Tool - Stage 5",
            producer="Explainable Compliance Tool - ReportLab invariant build",
            invariant=1,
        )
        footer = _Footer(report, digest)
        doc.build(story, onFirstPage=footer, onLaterPages=footer)

    return out_path


def build_and_hash(
    report: ComplianceReport,
    out_path: str,
    *,
    organisation: Optional[str] = None,
) -> str:
    """Compile the PDF, hash its bytes and stamp the result onto ``report``.

    Convenience wrapper over :func:`compile_pdf` plus
    :func:`src.report.integrity.sha256_of_file`. Sets ``report.sha256_hash`` to
    the SHA-256 of the PDF bytes and ``report.pdf_path`` to ``out_path``, then
    returns the digest.

    Note ``report.sha256_hash`` is the *artefact* digest (the PDF file), whereas
    the footer carries the *content* digest, which is computable before the file
    exists. A file cannot contain its own hash.

    ``organisation`` is forwarded verbatim to :func:`compile_pdf`; omitting it
    reproduces the pre-existing behaviour exactly.
    """
    compile_pdf(report, out_path, organisation=organisation)
    digest = sha256_of_file(out_path)
    report.sha256_hash = digest
    report.pdf_path = out_path
    return digest
