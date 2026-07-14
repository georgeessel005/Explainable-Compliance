"""
ui/heatmap.py  -  Cross-framework mapping matrix as an Altair heatmap.

Renders `mapping.matrix.build_matrix` output (CE pillar x ISO control, cells P/S/blank)
and reproduces Appendix Ai. Blank cells mean *no mapping* and are drawn as empty grid
space, never as a third colour — an unmapped intersection is an absence, not a category.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    import pandas

# Cell value -> mapping type label. build_matrix may emit either the short P/S codes or
# the full MappingType values; both are accepted so the UI never fights the engine.
_CELL_LABELS = {
    "P": "Primary",
    "S": "Secondary",
    "PRIMARY": "Primary",
    "SECONDARY": "Secondary",
}

_COLOURS = {
    "Primary": "#1f4e79",   # deep blue, matches the app primaryColor
    "Secondary": "#8fb8de",  # lighter blue - clearly subordinate at a glance
}


def normalise_cell(value) -> str | None:
    """Map a raw matrix cell to 'Primary' / 'Secondary' / None (no mapping)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "-"}:
        return None
    return _CELL_LABELS.get(text.upper(), text if text in _COLOURS else None)


def matrix_to_long(matrix: "pandas.DataFrame") -> "pandas.DataFrame":
    """Melt the wide CE-pillar x ISO-control matrix into tidy rows for Altair.

    Returns columns: ce_pillar, iso_control, mapping_type (None where unmapped).
    Every intersection is emitted, mapped or not, so the chart keeps a full grid and
    the axes do not silently collapse to only the populated rows/columns.
    """
    import pandas as pd

    if matrix is None or matrix.empty:
        return pd.DataFrame(columns=["ce_pillar", "iso_control", "mapping_type"])

    rows = []
    for pillar in matrix.index:
        for control in matrix.columns:
            rows.append(
                {
                    "ce_pillar": str(pillar),
                    "iso_control": str(control),
                    "mapping_type": normalise_cell(matrix.at[pillar, control]),
                }
            )
    return pd.DataFrame(rows, columns=["ce_pillar", "iso_control", "mapping_type"])


def build_chart(matrix: "pandas.DataFrame"):
    """Build the Altair heatmap. Separated from render() so it can be tested headless."""
    import altair as alt

    long = matrix_to_long(matrix)
    pillars = [str(p) for p in matrix.index]
    controls = [str(c) for c in matrix.columns]

    mapped = long[long["mapping_type"].notna()]

    base = alt.Chart(long).encode(
        x=alt.X(
            "iso_control:N",
            title="ISO/IEC 27001:2022 Annex A control",
            sort=controls,
            scale=alt.Scale(domain=controls),
            axis=alt.Axis(labelAngle=-45, labelFontSize=11, titleFontSize=12),
        ),
        y=alt.Y(
            "ce_pillar:N",
            title="Cyber Essentials pillar",
            sort=pillars,
            scale=alt.Scale(domain=pillars),
            axis=alt.Axis(labelFontSize=11, titleFontSize=12),
        ),
    )

    # Full grid, including unmapped intersections, drawn as faint empty cells.
    grid = base.mark_rect(
        fill="#ffffff", stroke="#e6e9ef", strokeWidth=1
    )

    cells = (
        alt.Chart(mapped)
        .mark_rect(stroke="#ffffff", strokeWidth=1)
        .encode(
            x=alt.X("iso_control:N", sort=controls, scale=alt.Scale(domain=controls)),
            y=alt.Y("ce_pillar:N", sort=pillars, scale=alt.Scale(domain=pillars)),
            color=alt.Color(
                "mapping_type:N",
                title="Mapping",
                scale=alt.Scale(
                    domain=list(_COLOURS.keys()),
                    range=list(_COLOURS.values()),
                ),
                legend=alt.Legend(orient="top"),
            ),
            tooltip=[
                alt.Tooltip("ce_pillar:N", title="CE pillar"),
                alt.Tooltip("iso_control:N", title="ISO control"),
                alt.Tooltip("mapping_type:N", title="Mapping"),
            ],
        )
    )

    labels = (
        alt.Chart(mapped)
        .mark_text(fontSize=11, fontWeight="bold")
        .encode(
            x=alt.X("iso_control:N", sort=controls, scale=alt.Scale(domain=controls)),
            y=alt.Y("ce_pillar:N", sort=pillars, scale=alt.Scale(domain=pillars)),
            text=alt.Text("cell_label:N"),
            color=alt.condition(
                alt.datum.mapping_type == "Primary",
                alt.value("#ffffff"),
                alt.value("#12324f"),
            ),
        )
        # Calculated into a NEW field: overwriting mapping_type here would break the
        # colour condition above, which is evaluated after the transform.
        .transform_calculate(
            cell_label="datum.mapping_type == 'Primary' ? 'P' : 'S'"
        )
    )

    return (
        (grid + cells + labels)
        .properties(height=max(240, 42 * len(pillars)), width="container")
        .configure_view(strokeWidth=0)
    )


def render_heatmap(matrix: "pandas.DataFrame") -> None:
    """Draw the mapping matrix. Safe to call before Stage 2 has run."""
    import streamlit as st

    st.subheader("Cross-framework mapping matrix")
    st.caption(
        "Cyber Essentials pillars against ISO/IEC 27001:2022 Annex A controls. "
        "P = Primary, S = Secondary, blank = no mapping. Reproduces Appendix Ai."
    )

    if matrix is None or getattr(matrix, "empty", True):
        st.info("Run Stage 2 (mapping) from the sidebar to build the matrix.")
        return

    st.altair_chart(build_chart(matrix), width="stretch")

    long = matrix_to_long(matrix)
    mapped = long[long["mapping_type"].notna()]
    primary = int((mapped["mapping_type"] == "Primary").sum())
    secondary = int((mapped["mapping_type"] == "Secondary").sum())
    total_cells = len(long)

    col1, col2, col3 = st.columns(3)
    col1.metric("Mapped intersections", len(mapped))
    col2.metric("Primary", primary)
    col3.metric("Secondary", secondary)
    st.caption(
        f"{len(mapped)} of {total_cells} intersections mapped across "
        f"{len(matrix.index)} pillar(s) and {len(matrix.columns)} control(s)."
    )

    with st.expander("View as a table"):
        st.dataframe(matrix, width="stretch")

    st.warning(
        "**Academic integrity:** only the 15 intersections verified against the interim "
        "report (Appendix Aii) are authoritative. Any other cell is a best-effort mapping "
        "and is flagged in `rules/UNVERIFIED_MAPPINGS.md` — confirm each against the "
        "framework documentation before submission.",
        icon="⚠️",
    )
