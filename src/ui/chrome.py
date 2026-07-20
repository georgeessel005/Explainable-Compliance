"""
ui/chrome.py  -  Presentation chrome for the CompliancePilot skin.

Pure presentation. Nothing in this module reads or writes pipeline state, makes a
gate decision, or changes what the app is allowed to do: it renders the dark header
banner, the five-step stepper and the small styled callouts/panels used by the tabs.

The stepper's current step is DERIVED from session state (data loaded? findings?
explanations? everything reviewed? report compiled?). It never sets state, so a
mis-drawn step can never unlock anything — the Article 22 gate lives in src/gate.py
and is re-checked on the compile path itself.
"""
from __future__ import annotations

from typing import Optional

# Palette (owner's prototype).
NAVY = "#102a43"
NAVY_DEEP = "#0b1f33"
BLUE = "#2b6cb0"
GREEN = "#2f855a"
AMBER = "#b7791f"
AMBER_BG = "#fffaf0"
GREY = "#cbd5e0"
GREY_TEXT = "#718096"

_STEPS = ["Upload", "Map", "Explain", "Approve", "Generate"]

#: Returned by `current_step` when the pipeline is FINISHED: the gate is open and a
#: report has been sealed. One past the last step, so every step — Generate included —
#: renders complete. Without it "Generate" could never turn green, because step 5 means
#: "you are here".
COMPLETED_STEP = len(_STEPS) + 1

_SEVERITY_STYLE = {
    "Critical": ("#c53030", "#fff5f5"),
    "High": ("#c05621", "#fffaf0"),
    "Medium": ("#2b6cb0", "#ebf8ff"),
    "Low": ("#2f855a", "#f0fff4"),
    "None": ("#4a5568", "#edf2f7"),
}


# ---------- header ----------

def render_header(status_text: str = "Engine deterministic · v1.0") -> None:
    """Dark navy banner: product mark, subtitle, right-aligned engine status."""
    import streamlit as st

    st.markdown(
        f"""
<div style="
    background:linear-gradient(135deg,{NAVY} 0%,{NAVY_DEEP} 100%);
    border-radius:14px;padding:1.15rem 1.5rem;margin-bottom:1.1rem;
    display:flex;align-items:center;justify-content:space-between;
    flex-wrap:wrap;gap:0.75rem;">
  <div style="display:flex;align-items:center;gap:0.85rem;min-width:0;">
    <div style="font-size:2rem;line-height:1;">&#128737;</div>
    <div style="min-width:0;">
      <div style="color:#ffffff;font-size:1.55rem;font-weight:800;
                  letter-spacing:-0.01em;line-height:1.15;">CompliancePilot</div>
      <div style="color:#bcccdc;font-size:0.86rem;margin-top:0.2rem;">
        Rule-Based Cross-Compliance Harmonisation Pipeline &mdash;
        Cyber Essentials / CE+ &harr; ISO/IEC 27001:2022
      </div>
    </div>
  </div>
  <div style="color:#9fb3c8;font-size:0.78rem;white-space:nowrap;
              text-align:right;font-family:ui-monospace,'Cascadia Code',monospace;">
    {status_text}
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


# ---------- stepper ----------

def current_step(
    *,
    has_data: bool,
    has_findings: bool,
    has_explanations: bool,
    review_complete: bool,
    has_report: bool,
) -> int:
    """1-based index of the step the analyst is currently on, or `COMPLETED_STEP`.

    Presentation only. Derived strictly from what already exists in session state;
    `review_complete` is supplied by the caller from `gate_status`, never recomputed
    here, so the stepper cannot disagree with the gate.

    The LIVE gate is tested before `has_report`, and deliberately so. A report compiled
    earlier does not survive a later escalation as a claim about the present: with the
    gate red, Stage 5 renders "blocked" and withholds the report, so a stepper still
    ticking Approve and highlighting Generate would contradict the control on the same
    screen. Going backwards is the honest reading — the analyst really does have review
    work in hand again.
    """
    if review_complete and has_explanations:
        # Gate open. A sealed report on top of that is the finished state; without one,
        # Generate is the step in hand.
        return COMPLETED_STEP if has_report else 5
    if has_explanations:
        return 4
    if has_findings:
        return 3
    if has_data:
        return 2
    return 1


def render_stepper(step: int) -> None:
    """Numbered 5-step progress rail. `step` is 1-based; earlier steps read complete.

    `step == COMPLETED_STEP` (6) is past every step, so the whole rail reads complete.
    """
    import streamlit as st

    cells: list[str] = []
    for index, label in enumerate(_STEPS, start=1):
        if index < step:
            circle_bg, circle_border, circle_fg = GREEN, GREEN, "#ffffff"
            glyph = "&#10003;"
            label_colour, weight = GREEN, "600"
        elif index == step:
            circle_bg, circle_border, circle_fg = BLUE, BLUE, "#ffffff"
            glyph = str(index)
            label_colour, weight = NAVY, "700"
        else:
            circle_bg, circle_border, circle_fg = "#ffffff", GREY, GREY_TEXT
            glyph = str(index)
            label_colour, weight = GREY_TEXT, "500"

        line_colour = GREEN if index < step else GREY
        connector = (
            ""
            if index == 1
            else f'<div style="flex:1;height:2px;background:{line_colour};'
                 'margin:0 0.35rem;"></div>'
        )
        cells.append(
            connector
            + f"""<div style="display:flex;align-items:center;gap:0.45rem;white-space:nowrap;">
  <div style="width:26px;height:26px;border-radius:50%;background:{circle_bg};
              border:2px solid {circle_border};color:{circle_fg};font-size:0.8rem;
              font-weight:700;display:flex;align-items:center;justify-content:center;">
    {glyph}</div>
  <div style="color:{label_colour};font-size:0.85rem;font-weight:{weight};">{label}</div>
</div>"""
        )

    # The rail sits on an explicit WHITE card. Two reasons, one change: the label
    # colours are fixed dark values (#102a43 for the active step), so on a transparent
    # background a dark-theme viewer loses the active label entirely; and the owner's
    # prototype puts the stepper on a white bar. Owning the background makes the
    # contrast deterministic instead of theme-dependent.
    st.markdown(
        '<div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;'
        'box-shadow:0 1px 2px rgba(16,42,67,0.06);'
        'padding:0.7rem 1rem;margin:0 0 1.1rem 0;overflow-x:auto;">'
        '<div style="display:flex;align-items:center;min-width:max-content;">'
        + "".join(cells)
        + "</div></div>",
        unsafe_allow_html=True,
    )


# ---------- small styled blocks ----------

def render_callout(body_html: str, *, colour: str = AMBER, background: str = AMBER_BG) -> None:
    """Dashed-border callout used for the non-bypassable-gate notice."""
    import streamlit as st

    st.markdown(
        f"""<div style="border:2px dashed {colour};background:{background};
        border-radius:10px;padding:0.85rem 1rem;margin:0.35rem 0 1rem 0;
        color:#2d3748;font-size:0.9rem;line-height:1.5;">{body_html}</div>""",
        unsafe_allow_html=True,
    )


def severity_chip(label: str) -> str:
    """Inline HTML severity pill (Critical / High / Medium / Low)."""
    fg, bg = _SEVERITY_STYLE.get(label, _SEVERITY_STYLE["None"])
    return (
        f'<span style="background:{bg};color:{fg};border:1px solid {fg}33;'
        'border-radius:999px;padding:0.12rem 0.6rem;font-size:0.75rem;'
        f'font-weight:700;letter-spacing:0.02em;">{label}</span>'
    )


def render_seal_panel(digest: str, *, artefact_digest: Optional[str] = None) -> None:
    """TAMPER-EVIDENT SEAL panel: the sealed content digest in monospace.

    Two different digests appear here and each says which it is. The headline value is
    the CONTENT seal (findings, decisions and the organisation name — the thing the PDF
    footer commits to); the small value underneath is the SHA-256 of the PDF file. An
    analyst re-hashing a downloaded PDF must compare it with the second, so labelling
    the headline only "SHA-256" left the two silently interchangeable.
    """
    import streamlit as st

    extra = (
        f'<div style="color:#829ab1;font-size:0.72rem;margin-top:0.6rem;">'
        f"PDF artefact SHA-256 (the downloaded file) &middot; {artefact_digest}</div>"
        if artefact_digest
        else ""
    )
    st.markdown(
        f"""<div style="background:{NAVY};border-radius:12px;padding:1rem 1.15rem;
        margin:0.5rem 0 0.75rem 0;">
  <div style="color:#9fb3c8;font-size:0.74rem;font-weight:700;letter-spacing:0.09em;">
    TAMPER-EVIDENT SEAL &middot; CONTENT SHA-256</div>
  <div style="color:#829ab1;font-size:0.72rem;margin-top:0.15rem;font-weight:400;
              letter-spacing:0;">
    Covers the committed findings, decisions and organisation name &mdash;
    not the PDF bytes.</div>
  <div style="color:#ffffff;font-family:ui-monospace,'Cascadia Code',Consolas,monospace;
              font-size:0.8rem;word-break:break-all;margin-top:0.45rem;">{digest}</div>
  {extra}
</div>""",
        unsafe_allow_html=True,
    )
