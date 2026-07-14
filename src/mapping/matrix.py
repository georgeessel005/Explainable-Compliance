"""
mapping/matrix.py  -  the CE x ISO cross-mapping matrix (Appendix Ai).

Turns the loaded rule base into a DataFrame the Streamlit heatmap can render:
rows are Cyber Essentials pillars, columns are ISO/IEC 27001:2022 Annex A controls,
and each cell holds "P" (Primary), "S" (Secondary) or "" (no mapping).

A blank cell means the intersection is NOT mapped. It is an absence, never a third
category, and it must not be read as "mapped, unverified" - unverified mappings are
present in the matrix and are listed in rules/UNVERIFIED_MAPPINGS.md. Use
verified_only=True to render just the 15 intersections sourced from Appendix Aii.

No Streamlit imports here; pandas is imported lazily so the module stays cheap to
import for callers that only want the axis constants.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import MappingType, RuleBase
from .engine import ISO_CONTROL_UNIVERSE, iso_intersections

if TYPE_CHECKING:  # pragma: no cover
    import pandas

# Row axis: the five Cyber Essentials pillars in scheme order, then the two CE Plus
# assessment activities. Mirrors `ce_pillars` in rules/ce_iso_mappings.yaml. Held
# here as well so the axis is stable even for a rule base that maps nothing onto a
# given row - the heatmap must show the empty row rather than collapse it.
CE_PILLARS: tuple[str, ...] = (
    "Firewalls",
    "Secure Configuration",
    "User Access Control",
    "Malware Protection",
    "Patch Management",
    "CE+ Vulnerability Scan",
    "CE+ Authenticated Audit",
)

# Column axis: the closed Annex A control universe, in the blueprint's order.
ISO_CONTROLS: tuple[str, ...] = ISO_CONTROL_UNIVERSE

_CELL_CODE = {
    MappingType.PRIMARY: "P",
    MappingType.SECONDARY: "S",
}

NO_MAPPING = ""


def _cell_code(mapping_type) -> str:
    """MappingType -> 'P'/'S'. Accepts the raw enum or its string value."""
    if isinstance(mapping_type, MappingType):
        return _CELL_CODE[mapping_type]
    return _CELL_CODE.get(MappingType(str(mapping_type)), NO_MAPPING)


def build_matrix(rulebase: RuleBase, verified_only: bool = False) -> "pandas.DataFrame":
    """Build the CE pillar x ISO control matrix.

    Cells are "P", "S" or "" - the contract src/ui/heatmap.py normalises against.
    Rows and columns are the full fixed axes, so an unmapped pillar or control still
    appears as an empty line in the heatmap instead of vanishing from it.

    `rulebase` is accepted to keep the frozen signature honest and to fail loudly if a
    caller passes an unloaded rule base; the intersection data itself comes from the
    provenance index that load_rules() populated from the same YAML.
    """
    import pandas as pd

    if rulebase is None or not rulebase.rules:
        raise ValueError(
            "build_matrix() needs a loaded RuleBase - call load_rules() first"
        )

    matrix = pd.DataFrame(NO_MAPPING, index=list(CE_PILLARS), columns=list(ISO_CONTROLS))

    cells = iso_intersections(verified=True if verified_only else None)
    for cell in cells:
        pillar = cell["ce_pillar"]
        control = cell["iso_control"]
        if pillar not in matrix.index or control not in matrix.columns:
            # Guarded rather than silently dropped: a mapping onto an axis we do not
            # know about means the YAML and these constants have drifted apart.
            raise ValueError(
                f"Rule base maps {pillar!r} x {control!r}, which is outside the matrix "
                f"axes. Reconcile rules/ce_iso_mappings.yaml with matrix.CE_PILLARS / "
                f"engine.ISO_CONTROL_UNIVERSE."
            )
        matrix.at[pillar, control] = _cell_code(cell["mapping_type"])

    matrix.index.name = "CE pillar"
    matrix.columns.name = "ISO/IEC 27001:2022 Annex A"
    return matrix


def matrix_coverage(rulebase: RuleBase) -> dict[str, int]:
    """Counts behind the heatmap's footer and the integrity banner."""
    every = iso_intersections()
    verified = [c for c in every if c["verified"]]
    primary = [c for c in every if _cell_code(c["mapping_type"]) == "P"]
    return {
        "rows": len(CE_PILLARS),
        "columns": len(ISO_CONTROLS),
        "total_cells": len(CE_PILLARS) * len(ISO_CONTROLS),
        "mapped": len(every),
        "verified": len(verified),
        "unverified": len(every) - len(verified),
        "primary": len(primary),
        "secondary": len(every) - len(primary),
    }
